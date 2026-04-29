#!/bin/bash
# ==============================================================================
# ufw-utils.sh v1.7.3
# 描述: UFW 防火墙与 Fail2ban 一键管理脚本 (单页菜单版)
# 支持: Ubuntu/Debian (需支持 UFW)
# 作者: Agent (Based on user request)
# ------------------------------------------------------------------------------
# 变更记录:
# [2026-04-29] v1.7.3 [Feature] 增加 SSH 端口修复模式 (允许输入同端口强制重置并清理冲突配置)
# [2026-04-29] v1.7.2 [Fix] 修复部分系统下手跑 sshd -t 报 Missing privilege separation directory 错误的问题
# [2026-04-29] v1.7.1 [Fix] 终极防御性审查加固 SSH 端口更改逻辑:
#                           1. 修复 Subshell 导致的回滚变量作用域丢失问题
#                           2. 增加对 sed, cat, mkdir, printf, ufw 等核心操作的全局异常捕获
#                           3. 为 Fail2ban 配置同步增加容错避免 set -e 崩溃
# [2026-04-29] v1.7.0 [Fix] 二次深度修复 SSH 端口更换后双端口失联问题:
#                           1. detect_ssh_port() 增加 sshd_config.d/ 子目录扫描
#                           2. 改为创建 00-custom-port.conf 子配置（利用 first-match-wins）
#                           3. 遍历所有子配置处理 Port 冲突（不再 break 遗漏）
#                           4. 新增全流程回滚机制（任何步骤失败自动恢复）
#                           5. Socket 重启失败时执行完整回滚而非仅打印警告
#                           6. 修复端口占用检测正则（:80 不再误匹配 :8080）
# [2026-04-28] v1.6.0 [Fix] 修复 SSH 端口更换后无法连接的 6 个 bug:
#                           1. 修正操作顺序: UFW 放行新端口 → 重启 SSH（避免锁死）
#                           2. 补充 ufw reload 确保 iptables 内核规则同步
#                           3. 新增 sshd_config.d/ 子配置 Port 冲突检测与处理
#                           4. 重启前执行 sshd -t 语法验证，失败自动回滚
#                           5. 修正 socket 激活模式重启顺序（先停服务再重启 socket）
#                           6. 自动同步 Fail2ban 监控端口
# [2026-04-24] v1.5.0 [Fix] 修复 UFW 放行端口后仍需 iptables 才能生效的问题:
#                           1. 新增 Docker 环境检测与 DOCKER-USER 链兼容性修复
#                           2. 初始化时检查 /etc/default/ufw 的 IPV6 设置并自动修正
#                           3. 放行端口后强制 ufw reload 确保 iptables 立即同步
#                           4. 新增 iptables 同步诊断功能，排查规则不一致问题
# [2026-04-07] v1.4.5 [Fix] 修复 socket drop-in 只监听 IPv6: ListenStream 只写端口号时
#                           systemd 默认绑定 [::]，IPv4 客户端无法连接。改为显式双栈监听
# [2026-04-07] v1.4.4 [Fix] 修复 UFW 状态误报: oneshot 服务下 systemctl is-active 始终
#                           返回 inactive，改用 ufw status 自身输出判断真实运行状态
# [2026-04-07] v1.4.3 [Fix] 完整修复 SSH 端口更换: 自动检测 systemd socket 激活模式，
#                           创建 drop-in 来同步更新 socket 监听端口，修复远程监听旧端口问题
# [2026-04-07] v1.4.2 [Fix] 修复 SSH 重启逻辑不可靠: 改为强制尝试两个服务名并用 ss 验证新端口监听
# [2026-04-07] v1.4.1 [Fix] 全面审查修复: 菜单版本号、apt-get错误检测、date空值崩溃、
#                           ((count++)) 零值退出、echo -e可移植性、sort_rules pipefail隐患
# [2026-04-07] v1.4.0 [Feature] 增加自助更换服务器SSH端口功能
# [2026-04-07] v1.4.0 [Fix] 全面修复 set -e 模式下管道与grep导致的意外退出隐患
# [2026-01-30] v1.3.1 [Fix] 修复 Fail2ban 状态查看导致脚本退出的 bug (移除管道子shell的local声明)
# [2026-01-30] v1.3 [Feature] 增加详细运行状态(PID/内存/时长)与日志智能翻译
# [2026-01-30] v1.2 [Enhance] 优化输入容错(中文逗号)与状态颜色显示
# [2026-01-30] v1.1 [Refactor] 简化菜单结构为单页设计，删除冗余子菜单
# ==============================================================================

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'

# 全局变量
SSH_CONFIG="/etc/ssh/sshd_config"
FAIL2BAN_JAIL="/etc/fail2ban/jail.local"
UFW_DEFAULT="/etc/default/ufw"
UFW_BEFORE_RULES="/etc/ufw/before.rules"

# ==============================================================================
# 基础检查函数
# ==============================================================================

# 检测 Docker 环境并修复 DOCKER-USER 链与 UFW 冲突
# Docker 会在 iptables FORWARD 链中插入自己的规则，绕过 UFW 的管理
# 当 Docker 容器映射端口到宿主机时，外部流量走 nat PREROUTING -> FORWARD 链
# 而 UFW 只管理 INPUT 链，导致 UFW 声称已放行的端口实际不可达
check_docker_compat() {
    # 未安装 Docker 则无需处理
    if ! command -v docker &> /dev/null && ! systemctl list-unit-files 2>/dev/null | grep -q 'docker.service'; then
        return 0
    fi

    echo -e "${YELLOW}检测到 Docker 环境，正在检查 UFW/Docker 兼容性...${PLAIN}"

    # 检查 DOCKER-USER 链是否存在
    if ! iptables -L DOCKER-USER -n &>/dev/null; then
        echo -e "${YELLOW}DOCKER-USER 链尚不存在（Docker 可能未启动），暂时跳过。${PLAIN}"
        return 0
    fi

    # 检查 /etc/ufw/after.rules 是否已配置 DOCKER-USER 链的回落规则
    local after_rules="/etc/ufw/after.rules"
    if [ -f "$after_rules" ] && grep -q 'DOCKER-USER' "$after_rules"; then
        echo -e "${GREEN}Docker 兼容配置已存在于 after.rules 中。${PLAIN}"
        return 0
    fi

    echo -e "${RED}发现 Docker 绕过 UFW 问题！${PLAIN}"
    echo -e "${YELLOW}Docker 的 DOCKER-USER 链会在 UFW INPUT 链之前匹配 FORWARD 流量，"
    echo -e "导致 UFW 放行的端口对 Docker 容器无效。${PLAIN}"
    echo -e ""
    read -p "是否自动修复 Docker/UFW 兼容性? [y/N]: " fix_docker
    if [[ "$fix_docker" != "y" && "$fix_docker" != "Y" ]]; then
        echo -e "${YELLOW}跳过 Docker 兼容修复。如端口不通，请手动配置 DOCKER-USER 链。${PLAIN}"
        return 0
    fi

    # 备份
    cp -p "$after_rules" "${after_rules}.bak.$(date +%Y%m%d%H%M%S)"

    # 在 after.rules 尾部追加 DOCKER-USER 链规则
    # 这些规则确保 Docker 容器端口也受 UFW 管控
    cat >> "$after_rules" <<'DOCKER_EOF'

# ============================================================
# Docker/UFW 兼容: 将 DOCKER-USER 链的流量引导至 UFW 过滤
# 原理: Docker 的 FORWARD 链绕过 UFW 的 INPUT 管理，
#       通过在 DOCKER-USER 链中插入 RETURN 前的 DROP 默认策略
#       并显式放行 ESTABLISHED 连接和已 UFW 放行的端口
# ============================================================
*filter
:DOCKER-USER - [0:0]
# 已建立的连接直接放行（回包流量）
-A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# 容器间通信（docker0 网桥）直接放行
-A DOCKER-USER -i docker0 -j ACCEPT
# 来自外部网卡的 FORWARD 流量交由跳转到 ufw-user-input 链进行过滤
# 这样 UFW 的 allow 规则才能对 Docker 映射端口生效
-A DOCKER-USER -j ufw-user-input
# 默认丢弃未匹配的 FORWARD 流量（安全兜底）
-A DOCKER-USER -j DROP
COMMIT
DOCKER_EOF

    echo -e "${GREEN}Docker 兼容规则已写入 ${after_rules}${PLAIN}"
    echo -e "${YELLOW}正在重载 UFW 使规则生效...${PLAIN}"
    ufw reload
    echo -e "${GREEN}Docker/UFW 兼容修复完成！${PLAIN}"
}

# 检查 /etc/default/ufw 中 IPV6 是否启用（仅提示，不强制修改）
# IPV6=no 会导致 UFW 不生成 ip6tables 规则，
# 如果服务器确实不使用 IPv6 则无需处理，仅供知悉
check_ipv6_setting() {
    if [ ! -f "$UFW_DEFAULT" ]; then
        return 0
    fi

    local ipv6_val
    ipv6_val=$(grep -E '^IPV6=' "$UFW_DEFAULT" | cut -d= -f2 | tr -d '[:space:]' || true)

    if [[ "$ipv6_val" == "no" ]]; then
        echo -e "${YELLOW}提示: /etc/default/ufw 中 IPV6=no，UFW 未管理 IPv6 流量。${PLAIN}"
        echo -e "${YELLOW}如服务器使用 IPv6，可手动修改为 IPV6=yes 后执行 ufw reload。${PLAIN}"
    fi
}

# 诊断 UFW 规则与实际 iptables 状态的同步性
# 用途: 当用户报告"UFW 显示放行但端口不通"时，此函数提供排查信息
check_iptables_sync() {
    echo -e "${SKYBLUE}>>> UFW / iptables 同步诊断${PLAIN}"
    echo -e "========================================"

    # 1. 检测 UFW 声明放行的端口
    echo -e "\n${SKYBLUE}[1] UFW 已声明放行的端口:${PLAIN}"
    ufw status | grep -E 'ALLOW' || echo "  (无)"

    # 2. 检测 iptables 中 ufw-user-input 链的实际规则
    echo -e "\n${SKYBLUE}[2] iptables ufw-user-input 链实际规则:${PLAIN}"
    if iptables -L ufw-user-input -n --line-numbers 2>/dev/null; then
        true
    else
        echo -e "  ${RED}ufw-user-input 链不存在！UFW 规则未加载到内核。${PLAIN}"
        echo -e "  ${YELLOW}原因: UFW 可能未启用，或 iptables 被其他工具重置。${PLAIN}"
    fi

    # 3. 检测 Docker 相关链
    echo -e "\n${SKYBLUE}[3] Docker 相关 iptables 链:${PLAIN}"
    if iptables -L DOCKER-USER -n 2>/dev/null; then
        true
    else
        echo "  DOCKER-USER 链不存在（非 Docker 环境或 Docker 未启动）"
    fi

    # 4. 检测 FORWARD 链默认策略
    echo -e "\n${SKYBLUE}[4] FORWARD 链默认策略:${PLAIN}"
    local fw_policy
    fw_policy=$(iptables -L FORWARD -n 2>/dev/null | head -1 || true)
    echo "  $fw_policy"
    if echo "$fw_policy" | grep -q 'DROP'; then
        echo -e "  ${YELLOW}FORWARD 默认 DROP — Docker 容器端口需要显式放行。${PLAIN}"
    fi

    # 5. 检测 raw 表 PREROUTING 链（某些 NAT VPS 的限制）
    echo -e "\n${SKYBLUE}[5] raw 表 PREROUTING 链（NAT VPS conntrack 限制检测）:${PLAIN}"
    if iptables -t raw -L PREROUTING -n 2>/dev/null | grep -vE '^(Chain|target)' | head -5; then
        true
    else
        echo "  raw 表 PREROUTING 为空（正常）"
    fi

    # 6. 检测 conntrack 表状态
    echo -e "\n${SKYBLUE}[6] conntrack 连接追踪表使用情况:${PLAIN}"
    if [ -f /proc/sys/net/netfilter/nf_conntrack_count ]; then
        local ct_count ct_max
        ct_count=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
        ct_max=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
        echo "  当前连接数: ${ct_count} / 最大值: ${ct_max}"
        # conntrack 表满会导致新连接被静默丢弃
        if [ "$ct_count" -gt $((ct_max * 80 / 100)) ]; then
            echo -e "  ${RED}警告: conntrack 表使用率超过 80%！可能导致新连接被丢弃。${PLAIN}"
            echo -e "  ${YELLOW}建议: sysctl -w net.netfilter.nf_conntrack_max=$((ct_max * 2))${PLAIN}"
        fi
    else
        echo "  conntrack 模块未加载"
    fi

    echo -e "\n${SKYBLUE}[7] IPV6 支持状态:${PLAIN}"
    if [ -f "$UFW_DEFAULT" ]; then
        local ipv6_val
        ipv6_val=$(grep -E '^IPV6=' "$UFW_DEFAULT" | cut -d= -f2 | tr -d '[:space:]' || true)
        if [[ "$ipv6_val" == "yes" ]]; then
            echo -e "  IPV6=${GREEN}yes${PLAIN}（正常）"
        else
            echo -e "  IPV6=${RED}${ipv6_val:-未设置}${PLAIN}（IPv6 流量不受 UFW 管控）"
        fi
    fi

    echo -e "\n========================================"
    read -p "按回车键继续..."
}

# 检查系统类型 (仅 Debian/Ubuntu)
check_system() {
    if [ ! -f /etc/debian_version ]; then
        echo -e "${RED}错误：本脚本仅支持 Debian/Ubuntu 系统！${PLAIN}"
        exit 1
    fi
}

# 检查 Root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误：必须使用 root 用户运行此脚本！${PLAIN}"
        exit 1
    fi
}

# 检查并安装 UFW
# 注意: set -e 下不能用 cmd && cmd2; if [ $? ]; 模式，需独立检测
check_ufw() {
    if ! command -v ufw &> /dev/null; then
        echo -e "${YELLOW}未检测到 ufw，正在安装...${PLAIN}"
        apt-get update
        apt-get install -y ufw
        # 安装后再次检测，而非依赖退出码（set -e 已保证命令失败时退出）
        if ! command -v ufw &> /dev/null; then
            echo -e "${RED}ufw 安装失败，请检查网络或源！${PLAIN}"
            exit 1
        fi
        echo -e "${GREEN}ufw 安装成功！${PLAIN}"
    fi
}

# 检测 SSH 端口
# 优先扫描 sshd_config.d/ 子配置（OpenSSH first-match-wins 规则下子配置优先级更高）
# 然后回退到主配置文件检测
detect_ssh_port() {
    local port=22
    local found_explicit=0

    # 优先检查 sshd_config.d/ 子配置目录
    # Debian 12+ 在 sshd_config 顶部 Include sshd_config.d/*.conf
    # 按文件名字典序加载，first-match-wins，所以子配置中的 Port 优先级高于主配置
    if [ -d /etc/ssh/sshd_config.d ]; then
        local conf_file detected_sub_port
        for conf_file in /etc/ssh/sshd_config.d/*.conf; do
            [ -f "$conf_file" ] || continue
            detected_sub_port=$(grep -E '^[[:space:]]*Port[[:space:]]+[0-9]+' "$conf_file" | head -n 1 | awk '{print $2}' || true)
            if [[ -n "$detected_sub_port" ]]; then
                port=$detected_sub_port
                found_explicit=1
                break  # first-match-wins: 按文件名排序第一个生效
            fi
        done
    fi

    # 如果子配置中未找到，再检查主配置
    if [[ "$found_explicit" -eq 0 ]] && [ -f "$SSH_CONFIG" ]; then
        local detected_port
        detected_port=$(grep -E "^[[:space:]]*Port [0-9]+" "$SSH_CONFIG" | head -n 1 | awk '{print $2}' || true)
        if [[ -n "$detected_port" ]]; then
            port=$detected_port
            found_explicit=1
        fi

        # 如果未显式检测到端口且存在 Include 指令，提示风险
        if [[ "$found_explicit" -eq 0 ]] && grep -q "^Include" "$SSH_CONFIG"; then
            echo -e "${YELLOW}警告: SSH 配置包含 Include 指令但未找到显式 Port 定义 (回退默认 22)。${PLAIN}" >&2
        fi
    fi
    echo "$port"
}

# 获取服务详细运行信息
get_service_info() {
    local svc=$1
    if systemctl is-active --quiet "$svc"; then
        # 获取 PID, 内存 (RSS), 启动时间
        local pid mem uptime
        pid=$(systemctl show -p MainPID --value "$svc")
        # 内存单位转换 (KB -> MB)
        if [[ -n "$pid" && "$pid" -ne 0 ]]; then
            mem=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{printf "%.1f MB", $1/1024}' || true)
        else
            mem="未知"
        fi
        [ -z "$mem" ] && mem="未知"
        
        # 运行时长：防御 ActiveEnterTimestamp 返回空值导致的 date 崩溃
        local start_ts now_ts diff ts_raw
        ts_raw=$(systemctl show -p ActiveEnterTimestamp --value "$svc" 2>/dev/null || true)
        now_ts=$(date +%s)
        if [[ -n "$ts_raw" ]]; then
            start_ts=$(date -d "$ts_raw" +%s 2>/dev/null || true)
        fi
        if [[ -n "${start_ts:-}" && "$start_ts" -gt 0 ]]; then
            diff=$((now_ts - start_ts))
            # 简单格式化为 "Xd Xh Xm"
            uptime=$(awk -v t="$diff" 'BEGIN{printf "%dd %dh %dm", t/86400, (t%86400)/3600, (t%3600)/60}')
        else
            uptime="未知"
        fi
        
        echo -e "状态详情: ${GREEN}运行中${PLAIN} | PID: ${pid} | 内存: ${mem} | 运行时长: ${uptime}"
    else
        echo -e "状态详情: ${RED}未运行${PLAIN}"
    fi
}

# 配置日志轮转
setup_logrotate() {
    echo -e "${YELLOW}>>> 正在配置日志轮转 (保留7天, 每日轮转, 压缩)...${PLAIN}"
    
    # Fail2ban Logrotate
    cat > "/etc/logrotate.d/fail2ban-custom" <<EOF
/var/log/fail2ban.log {
    daily
    rotate 7
    missingok
    compress
    delaycompress
    notifempty
    postrotate
        fail2ban-client flushlogs >/dev/null || true
    endscript
}
EOF

    # UFW Logrotate (针对 /var/log/ufw.log)
    cat > "/etc/logrotate.d/ufw-custom" <<EOF
/var/log/ufw.log {
    daily
    rotate 7
    missingok
    compress
    delaycompress
    notifempty
}
EOF
    echo -e "${GREEN}日志轮转策略已应用。${PLAIN}"
}


# ==============================================================================
# UFW 功能函数
# ==============================================================================

# UFW: 基础配置初始化
ufw_basic_setup() {
    echo -e "${YELLOW}>>> 正在初始化 UFW 基础配置...${PLAIN}"
    
    local ssh_port
    ssh_port=$(detect_ssh_port)
    echo -e "检测到 SSH 端口为: ${GREEN}${ssh_port}${PLAIN}"
    
    # 检查 UFW 是否已有规则
    # 注意: pipefail 下 grep 不匹配返回 1 会触发退出，故用 grep ... || true
    local ufw_has_config
    ufw_has_config=$(ufw status 2>/dev/null | grep -E "Status: active|To" || true)
    if [[ -n "$ufw_has_config" ]]; then
        echo -e "${YELLOW}检测到 UFW 已有配置或处于活动状态。${PLAIN}"
        read -p "是否重置所有规则并重新初始化? [y/N]: " reset_confirm
        if [[ "$reset_confirm" == "y" || "$reset_confirm" == "Y" ]]; then
             echo -e "${RED}正在重置规则...${PLAIN}"
             ufw --force disable
             ufw --force reset
        else
             echo -e "${GREEN}保留现有规则，仅检查基础项...${PLAIN}"
        fi
    fi

    ufw default deny incoming
    ufw default allow outgoing
    echo -e "确保放行 SSH 端口: ${ssh_port}"
    ufw allow "${ssh_port}/tcp"
    
    # 初始化时检查 IPv6 支持状态，避免 IPv6 流量绕过 UFW
    check_ipv6_setting
    
    # 检测 Docker 兼容性，修复 DOCKER-USER 链绕过 UFW 的问题
    check_docker_compat
    
    echo -e "${GREEN}基础配置完成。${PLAIN}"
    if ! ufw status | grep -q "Status: active"; then
        echo -e "提示: UFW 目前处于 ${RED}inactive${PLAIN} 状态，请选择 [5] 启用。"
    fi

    
    setup_logrotate
    read -p "按回车键继续..."
}

# UFW: 放行端口 (支持多端口)
ufw_allow_port() {
    echo -e "${SKYBLUE}请输入要放行的端口，支持格式：${PLAIN}"
    echo -e "  单端口: 80 或 80/tcp"
    echo -e "  多端口: 80, 443 或 80 443"
    echo -e "  Web快捷: 输入 'web' 放行 80+443"
    read -p "端口: " port_input
    if [[ -z "$port_input" ]]; then echo "已取消"; return; fi
    
    # 快捷命令处理
    if [[ "$port_input" == "web" ]]; then
        ufw allow 80/tcp
        ufw allow 443/tcp
        # Web 快捷命令同样需要 reload 确保立即生效
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            ufw reload
        fi
        echo -e "${GREEN}已放行 80/tcp 和 443/tcp${PLAIN}"
        read -p "按回车键继续..."
        return
    fi
    
    # 将逗号替换为空格 (支持中文逗号)
    port_input=${port_input//，/ }
    port_input=${port_input//,/ }
    
    for port in $port_input; do
        if [[ -n "$port" ]]; then
            echo -e "正在添加规则: ${GREEN}${port}${PLAIN}"
            ufw allow "$port"
        fi
    done
    
    # 强制重载 UFW 确保 iptables 规则立即同步到内核
    # 某些发行版 (如 Debian 12) 的 UFW 后端在 allow 命令后不会
    # 立即刷新内核 netfilter 规则表，导致新规则"纸面生效"但流量仍被拦截
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        echo -e "${YELLOW}正在重载 UFW 以同步 iptables 规则...${PLAIN}"
        ufw reload
    fi
    
    echo -e "${GREEN}操作完成！${PLAIN}"
    read -p "按回车键继续..."
}

# UFW: 删除规则 (支持按编号或按端口批量删除)
ufw_delete_rule() {
    if ! ufw status | grep -q "Status: active"; then
        echo -e "${RED}错误: UFW 未运行，请先启用 [5]。${PLAIN}"
        read -p "按回车键返回..."
        return
    fi
    
    echo -e "${SKYBLUE}当前规则列表 (带编号):${PLAIN}"
    ufw status numbered
    
    echo ""
    echo -e "删除模式: ${GREEN}1${PLAIN}=按编号  ${GREEN}2${PLAIN}=按端口"
    read -p "选择模式 [1/2]: " mode
    
    case "$mode" in
        1)
            # 按编号删除
            echo -e "输入要删除的规则编号，支持多选 (如: 3 5 7 或 3,5,7)"
            read -p "编号 (q取消): " input
            
            if [[ "$input" == "q" || -z "$input" ]]; then return; fi
            
            input=${input//，/ }
            input=${input//,/ }
            local -a nums=($input)
            
            # 从大到小排序 (避免删除后编号错位)
            IFS=$'\n' sorted=($(sort -rn <<<"${nums[*]}")); unset IFS
            
            echo -e "${YELLOW}将按以下顺序删除: ${sorted[*]}${PLAIN}"
            read -p "确认删除? [y/N]: " confirm
            [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return
            
            for n in "${sorted[@]}"; do
                if [[ "$n" =~ ^[0-9]+$ ]]; then
                    echo -e "删除规则 #${n}..."
                    echo "y" | ufw delete "$n"
                fi
            done
            ;;
        2)
            # 按端口删除
            echo -e "输入要删除的端口，支持多选 (如: 80 443 或 80,443)"
            echo -e "可指定协议 (如: 80/tcp 443/udp)"
            read -p "端口 (q取消): " input
            
            if [[ "$input" == "q" || -z "$input" ]]; then return; fi
            
            input=${input//，/ }
            input=${input//,/ }
            
            echo -e "${YELLOW}将删除以下端口规则: ${input}${PLAIN}"
            read -p "确认删除? [y/N]: " confirm
            [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return
            
            for port in $input; do
                if [[ -n "$port" ]]; then
                    echo -e "删除端口 ${port} 的规则..."
                    # ufw delete allow 会删除匹配的规则
                    ufw delete allow "$port" 2>/dev/null || echo -e "${YELLOW}端口 ${port} 未找到或已删除${PLAIN}"
                fi
            done
            ;;
        *)
            echo "无效选择"
            return
            ;;
    esac
    
    echo -e "${GREEN}删除完成${PLAIN}"
    read -p "按回车键继续..."
}



# UFW: 规则排序与重载
ufw_sort_rules() {
    echo -e "${YELLOW}>>> 正在整理 UFW 规则...${PLAIN}"
    
    if ! ufw status | grep -q "Status: active"; then
        echo -e "${RED}错误: UFW 未运行，请先启用。${PLAIN}"
        read -p "按回车键返回..."
        return
    fi

    local rule_file="/tmp/ufw_rules.tmp"
    ufw show added | grep '^ufw ' > "$rule_file" || true
    
    if [ ! -s "$rule_file" ]; then
        echo -e "${YELLOW}当前没有自定义规则，无需排序。${PLAIN}"
        rm -f "$rule_file"
        read -p "按回车键返回..."
        return
    fi
    
    echo -e "${SKYBLUE}当前发现以下规则:${PLAIN}"
    cat "$rule_file"
    echo -e "--------------------------------"
    
    echo -e "${RED}注意: 这将短暂中断连接 (数秒)。${PLAIN}"
    read -p "是否继续? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        rm -f "$rule_file"
        echo "已取消。"
        return
    fi
    
    # 排序并去重
    sort -k 3 -V "$rule_file" | uniq > "${rule_file}.sorted"
    
    # 智能去重: 如果存在宽泛规则，则移除特定规则
    awk '
    {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
        lines[NR] = $0
        seen[$0] = 1
        base = $0
        if (sub(/\/(tcp|udp)([[:space:]]|$)/, "", base)) {
            if (base != $0) {
                 gsub(/[[:space:]]+$/, "", base)
                 has_base[$0] = base
            }
        }
    }
    END {
        for (i = 1; i <= NR; i++) {
            line = lines[i]
            skip = 0
            if (line in has_base) {
                base_cmd = has_base[line]
                if (base_cmd in seen) {
                    skip = 1
                }
            }
            if (skip == 0) { print line }
        }
    }
    ' "${rule_file}.sorted" > "${rule_file}.final"
    
    mv "${rule_file}.final" "${rule_file}.sorted"
    
    echo -e "${GREEN}排序后的规则预览:${PLAIN}"
    cat "${rule_file}.sorted"
    sleep 2
    
    # 备份
    local bk_ts
    bk_ts=$(date +%Y%m%d_%H%M%S)
    cp /etc/ufw/user.rules "/etc/ufw/user.rules.bak.${bk_ts}" 2>/dev/null
    cp /etc/ufw/user6.rules "/etc/ufw/user6.rules.bak.${bk_ts}" 2>/dev/null
    
    # 重置与应用
    ufw --force disable
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    local count=0
    while read -r rule_cmd; do
        if [[ -n "$rule_cmd" ]]; then
            echo "Applying: $rule_cmd"
            # 安全执行（eval 可处理带引号的参数）; 直接 $rule_cmd 对带空格参数有风险
            eval "$rule_cmd" >/dev/null
            # ((count++)) 在 count=0 时其算术结果为 0（false），会触发 set -e 退出
            # 改用 count=$((count + 1)) 规避此陷阱
            count=$((count + 1))
        fi
    done < "${rule_file}.sorted"
    
    echo "y" | ufw enable
    rm -f "$rule_file" "${rule_file}.sorted"
    
    echo -e "${GREEN}成功! 共重新加载了 $count 条规则。${PLAIN}"
    read -p "按回车键继续..."
}

# UFW: 卸载
ufw_uninstall() {
    echo -e "${RED}警告：此操作将禁用并卸载 UFW，且清除所有防火墙规则！${PLAIN}"
    read -p "确认卸载? [y/N]: " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        ufw disable
        ufw --force reset
        apt-get remove --purge -y ufw
        rm -rf /etc/ufw
        echo -e "${GREEN}UFW 已卸载。${PLAIN}"
    else
        echo "已取消。"
    fi
    read -p "按回车键继续..."
}

# ==============================================================================
# Fail2ban 功能函数
# ==============================================================================

# Fail2ban: 安装与配置
fail2ban_install() {
    if command -v fail2ban-client &> /dev/null; then
        echo -e "${GREEN}检测到 Fail2ban 已安装。${PLAIN}"
        if systemctl is-active --quiet fail2ban; then
             echo -e "${GREEN}Fail2ban 服务正在运行。${PLAIN}"
             if ! ufw status | grep -q "Status: active"; then
                 echo -e "${RED}注意: UFW 未启用！Fail2ban 无法执行封禁动作。${PLAIN}"
             fi
             read -p "按回车键继续..."
             return
        fi
        echo -e "${YELLOW}Fail2ban 未运行，正在尝试配置并启动...${PLAIN}"
    else
        echo -e "${YELLOW}>>> 正在安装 Fail2ban...${PLAIN}"
        apt-get update
        apt-get install -y fail2ban python3-systemd
        
        if ! command -v fail2ban-client &> /dev/null; then
            echo -e "${RED}Fail2ban 安装失败！${PLAIN}"
            return
        fi
    fi
    
    echo -e "${YELLOW}>>> 配置 Jail...${PLAIN}"
    
    # 智能检测后端
    local backend_mode="auto"
    if [ ! -f /var/log/auth.log ]; then
        echo -e "${YELLOW}提示: 未检测到 /var/log/auth.log，将使用 systemd 后端。${PLAIN}"
        backend_mode="systemd"
    fi

    if [ ! -f "$FAIL2BAN_JAIL" ]; then
        echo -e "${GREEN}创建默认 jail.local...${PLAIN}"
        cat > "$FAIL2BAN_JAIL" <<EOF
[DEFAULT]
banaction = ufw

[sshd]
enabled = true
backend = ${backend_mode}
EOF
        sed -i 's/\r//' "$FAIL2BAN_JAIL"
    else
        # 确保 banaction = ufw
        if grep -q "^banaction =" "$FAIL2BAN_JAIL"; then
            sed -i 's/^banaction =.*/banaction = ufw/' "$FAIL2BAN_JAIL"
        else
            if grep -q "^\[DEFAULT\]" "$FAIL2BAN_JAIL"; then
                sed -i '/^\[DEFAULT\]/a banaction = ufw' "$FAIL2BAN_JAIL"
            else
                echo -e "[DEFAULT]\nbanaction = ufw" >> "$FAIL2BAN_JAIL"
            fi
        fi
        
        # 确保 [sshd] 启用
        if ! grep -q "^\[sshd\]" "$FAIL2BAN_JAIL"; then
            echo -e "\n[sshd]\nenabled = true\n" >> "$FAIL2BAN_JAIL"
        fi
        
        # 针对 Debian 12 强制修正 backend
        if [[ "$backend_mode" == "systemd" ]]; then
            if grep -q "backend" "$FAIL2BAN_JAIL"; then
                 sed -i 's/backend = auto/backend = systemd/' "$FAIL2BAN_JAIL"
            else
                 if grep -q "^\[sshd\]" "$FAIL2BAN_JAIL"; then
                     sed -i '/^\[sshd\]/a backend = systemd' "$FAIL2BAN_JAIL"
                 fi
            fi
        fi
    fi

    echo -e "${YELLOW}正在启动 Fail2ban...${PLAIN}"
    systemctl restart fail2ban
    systemctl enable fail2ban &>/dev/null
    
    sleep 2
    if systemctl is-active --quiet fail2ban; then
        echo -e "${GREEN}Fail2ban 启动成功！${PLAIN}"
    else
        echo -e "${RED}Fail2ban 启动失败！尝试重置配置...${PLAIN}"
        mv "$FAIL2BAN_JAIL" "${FAIL2BAN_JAIL}.bak.$(date +%s)"
        cat > "$FAIL2BAN_JAIL" <<EOF
[DEFAULT]
banaction = ufw

[sshd]
enabled = true
backend = ${backend_mode}
EOF
        sed -i 's/\r//' "$FAIL2BAN_JAIL"
        systemctl restart fail2ban
        
        if systemctl is-active --quiet fail2ban; then
             echo -e "${GREEN}Fail2ban 修复并启动成功！${PLAIN}"
        else
             echo -e "${RED}最终启动失败。请检查: systemctl status fail2ban${PLAIN}"
        fi
    fi
    
    if ! ufw status | grep -q "Status: active"; then
        echo -e "${RED}注意: UFW 未启用！Fail2ban 无法执行封禁动作。${PLAIN}"
    fi



    setup_logrotate
    read -p "按回车键继续..."
}

# Fail2ban: 修改配置
fail2ban_config() {
    if [ ! -f "$FAIL2BAN_JAIL" ]; then
        echo -e "${RED}错误：配置文件不存在！请先安装 [9]。${PLAIN}"
        read -p "按回车键返回..."
        return
    fi

    echo -e "${SKYBLUE}=== 修改 Fail2ban 默认策略 ===${PLAIN}"
    
    # 读取当前值
    get_val() {
        local k=$1 f=$2
        [ ! -f "$f" ] && return
        local val
        if grep -q "^\[DEFAULT\]" "$f"; then
             val=$(sed -n '/^\[DEFAULT\]/,/^\[/p' "$f" | grep -E "^[[:space:]]*${k}[[:space:]]*=" | tail -n 1 | cut -d = -f 2- | tr -d '[:space:]' || true)
        else
             val=$(grep -E "^[[:space:]]*${k}[[:space:]]*=" "$f" | tail -n 1 | cut -d = -f 2- | tr -d '[:space:]' || true)
        fi
        echo "$val"
    }
    
    local cur_bantime cur_findtime cur_maxretry
    cur_bantime=$(get_val "bantime" "$FAIL2BAN_JAIL")
    cur_findtime=$(get_val "findtime" "$FAIL2BAN_JAIL")
    cur_maxretry=$(get_val "maxretry" "$FAIL2BAN_JAIL")
    
    [ -z "$cur_bantime" ] && cur_bantime="10m(默认)"
    [ -z "$cur_findtime" ] && cur_findtime="10m(默认)"
    [ -z "$cur_maxretry" ] && cur_maxretry="5(默认)"

    echo -e "提示: 输入空值则保留当前值"
    printf "封禁时长 (bantime) [当前: ${GREEN}${cur_bantime}${PLAIN}]: "
    read -r new_bantime
    printf "检测窗口 (findtime) [当前: ${GREEN}${cur_findtime}${PLAIN}]: "
    read -r new_findtime
    printf "最大尝试 (maxretry) [当前: ${GREEN}${cur_maxretry}${PLAIN}]: "
    read -r new_maxretry
    
    if [[ -z "$new_bantime" && -z "$new_findtime" && -z "$new_maxretry" ]]; then
        echo "未输入任何值，取消操作。"
        read -p "按回车键返回..."
        return
    fi

    cp "$FAIL2BAN_JAIL" "${FAIL2BAN_JAIL}.bak.$(date +%H%M%S)"
    
    update_key() {
        local k=$1 v=$2 f=$3
        if grep -q "^${k}[[:space:]]*=" "$f"; then
            sed -i "s/^${k}[[:space:]]*=.*/${k} = ${v}/" "$f"
        elif grep -q "^#[[:space:]]*${k}[[:space:]]*=" "$f"; then
            sed -i "0,/^#[[:space:]]*${k}[[:space:]]*=/s//${k} = ${v}/" "$f"
        else
            if grep -q "^\[DEFAULT\]" "$f"; then
                sed -i "/^\[DEFAULT\]/a ${k} = ${v}" "$f"
            else
                echo -e "[DEFAULT]\n${k} = ${v}" >> "$f"
            fi
        fi
    }
    
    [ -n "$new_bantime" ] && update_key "bantime" "$new_bantime" "$FAIL2BAN_JAIL"
    [ -n "$new_findtime" ] && update_key "findtime" "$new_findtime" "$FAIL2BAN_JAIL"
    [ -n "$new_maxretry" ] && update_key "maxretry" "$new_maxretry" "$FAIL2BAN_JAIL"
    
    echo -e "${GREEN}配置已更新，重启服务...${PLAIN}"
    systemctl restart fail2ban
    sleep 1
    if systemctl is-active --quiet fail2ban; then
        echo -e "${GREEN}Fail2ban 重启成功！${PLAIN}"
    else
        echo -e "${RED}Fail2ban 重启失败！请检查配置。${PLAIN}"
        journalctl -u fail2ban --no-pager -n 10
    fi
    read -p "按回车键继续..."
}

# Fail2ban: 卸载
fail2ban_uninstall() {
    echo -e "${RED}警告：此操作将卸载 Fail2ban 并清除所有配置！${PLAIN}"
    read -p "确认卸载? [y/N]: " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        systemctl stop fail2ban 2>/dev/null
        apt-get remove --purge -y fail2ban
        rm -rf /etc/fail2ban /var/lib/fail2ban
        echo -e "${GREEN}Fail2ban 已卸载。${PLAIN}"
    else
        echo "已取消。"
    fi
    read -p "按回车键继续..."
}

# 查看 UFW 详细状态与日志
ufw_status_detailed() {
    echo -e "${SKYBLUE}>>> UFW 运行状态${PLAIN}"
    # 注意: UFW 的 systemd 服务是 oneshot 类型——加载完 iptables 规则后进程即退出
    # 因此 systemctl is-active ufw 始终返回 inactive，不能用来判断 UFW 是否生效
    # 正确做法：直接解析 ufw status 的输出
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        echo -e "状态详情: ${GREEN}运行中 (防火墙规则已加载至内核)${PLAIN}"
    else
        echo -e "状态详情: ${RED}未启用${PLAIN}"
    fi
    echo -e "----------------------------------------"
    ufw status verbose
    
    echo -e "\n${SKYBLUE}>>> 最近拦截记录 (日志摘要)${PLAIN}"
    if [ -f /var/log/ufw.log ]; then
        tail -n 10 /var/log/ufw.log | while read -r line; do
             # 提取时间
            ts=$(echo "$line" | awk '{print $1, $2, $3}' || true)
            # 提取 SRC IP
            src_ip=$(echo "$line" | grep -oP 'SRC=\K[\d\.]+' || true)
            # 提取 DST Port
            dst_port=$(echo "$line" | grep -oP 'DPT=\K\d+' || true)
            proto=$(echo "$line" | grep -oP 'PROTO=\K\w+' || true)
            
            if [[ -n "$src_ip" ]]; then
                 echo -e "${ts} -> ${RED}拦截${PLAIN} 来自 ${src_ip} (目标: ${dst_port}/${proto})"
            fi
        done || true
    else
        # 尝试 dmesg
        echo "日志文件未找到，尝试系统消息(dmesg)..."
        dmesg 2>/dev/null | grep '\[UFW BLOCK\]' | tail -n 5 | while read -r line; do
             src_ip=$(echo "$line" | grep -oP 'SRC=\K[\d\.]+' || true)
             [[ -n "$src_ip" ]] && echo -e "${RED}拦截${PLAIN} 来自 ${src_ip}"
        done || true
    fi
    read -p "按回车继续..." 
}

# 查看 Fail2ban 详细状态与日志
fail2ban_status_detailed() {
    echo -e "${SKYBLUE}>>> Fail2ban 运行状态${PLAIN}"
    get_service_info fail2ban
    echo -e "----------------------------------------"
    
    if systemctl is-active --quiet fail2ban; then
        fail2ban-client status sshd
    else
        echo -e "${RED}Fail2ban 未运行${PLAIN}"
    fi
    
    echo -e "\n${SKYBLUE}>>> 最近安全事件 (日志摘要)${PLAIN}"
    if [ -f /var/log/fail2ban.log ]; then
        # 读取最后 10 行并分析（避免在管道子shell中使用 local）
        tail -n 10 /var/log/fail2ban.log | while read -r line; do
            # 提取时间 (前两列)
            ts=$(echo "$line" | awk '{print $1, $2}' || true)
            # 提取 Jail 和 IP
            jail=$(echo "$line" | grep -oP '\[.*?\]' | head -1 || true)
            ip=$(echo "$line" | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' || true)
            
            # 翻译行为（不使用 local，避免子shell问题）
            action=""
            if [[ "$line" == *"Ban"* ]]; then
                action="${RED}封禁${PLAIN}"
            elif [[ "$line" == *"Unban"* ]]; then
                action="${GREEN}解封${PLAIN}"
            elif [[ "$line" == *"Found"* ]]; then
                action="${YELLOW}发现攻击${PLAIN}"
            elif [[ "$line" == *"Restore Ban"* ]]; then
                action="${RED}恢复封禁${PLAIN}"
            fi
            
            if [[ -n "$action" && -n "$ip" ]]; then
                echo -e "${ts} ${jail} -> ${action} IP: ${ip}"
            elif [[ -n "$action" ]]; then
                # 部分日志可能没 IP (如启动信息)
                echo -e "${ts} ${jail} -> ${action}"
            fi
        done || true  # 确保管道失败不会导致脚本退出
    else
        echo "暂无日志文件 (/var/log/fail2ban.log)。"
    fi
    
    read -p "按回车继续..." 
}

# ==============================================================================
# SSH 功能函数
# ==============================================================================

# 更换 SSH 端口
change_ssh_port() {
    echo -e "${YELLOW}>>> 准备更换 SSH 端口...${PLAIN}"
    local old_port
    old_port=$(detect_ssh_port)
    echo -e "当前检测到 SSH 端口为: ${GREEN}${old_port}${PLAIN}"

    read -p "请输入新的 SSH 端口 (1024-65535, q取消): " new_port
    if [[ "$new_port" == "q" || -z "$new_port" ]]; then echo "已取消"; return; fi

    if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1024 ] || [ "$new_port" -gt 65535 ]; then
        echo -e "${RED}错误：请输入 1024 到 65535 之间的有效端口号！${PLAIN}"
        read -p "按回车键返回..."
        return 1
    fi

    local is_repair_mode=0
    if [ "$new_port" -eq "$old_port" ]; then
        echo -e "${YELLOW}提示：您输入的新端口与当前检测到的端口 ($old_port) 相同。${PLAIN}"
        read -p "是否要强制重新应用此端口的配置 (进入修复模式，重置所有 SSH 端口相关设置)？[y/N]: " force_repair
        if [[ "$force_repair" == "y" || "$force_repair" == "Y" ]]; then
            is_repair_mode=1
        else
            echo "已取消"
            return 1
        fi
    fi

    # 只有在非修复模式下才检测端口占用，修复模式下该端口本就被 SSH 占用
    if [[ "$is_repair_mode" -eq 0 ]]; then
        if ss -tlnp 2>/dev/null | awk 'NR>1 {split($4,a,":"); if(a[length(a)]==port) found=1} END{exit !found}' port="$new_port"; then
            echo -e "${RED}错误: 端口 ${new_port} 已被以下进程占用:${PLAIN}"
            ss -tlnp 2>/dev/null | head -1
            ss -tlnp 2>/dev/null | awk 'NR>1 {split($4,a,":"); if(a[length(a)]==port) print}' port="$new_port"
            read -p "按回车键返回..."
            return 1
        fi
    fi

    echo -e "${RED}警告：此操作可能导致当前 SSH 连接中断！${PLAIN}"
    echo -e "${YELLOW}提示：请务必确保新端口通畅，或具有备用登录通道。${PLAIN}"
    read -p "确认将 SSH 端口更换为 $new_port ? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then echo "已取消"; return; fi

    if [ ! -f "$SSH_CONFIG" ]; then
        echo -e "${RED}错误: 找不到 SSH 配置文件 ${SSH_CONFIG}！${PLAIN}"
        read -p "按回车键返回..."
        return 1
    fi

    # ==================================================================
    # 回滚基础设施: 任何步骤失败时恢复所有已修改的文件
    # ==================================================================
    local -a _rollback_backups=()   # 格式: "备份路径|原始路径"
    local -a _rollback_created=()   # 本次新创建的文件（回滚时删除）
    local _rollback_ts
    _rollback_ts=$(date +%Y%m%d%H%M%S)

    # 注册已有文件的备份（回滚时恢复）
    _reg_backup() {
        local orig="$1"
        local bak="${orig}.rollback.${_rollback_ts}"
        if ! cp -p "$orig" "$bak"; then
            echo -e "${RED}警告: 备份 ${orig} 失败！${PLAIN}" >&2
            return 1
        fi
        _rollback_backups+=("${bak}|${orig}")
    }

    # 注册本次新创建的文件（回滚时删除）
    _reg_created() {
        _rollback_created+=("$1")
    }

    # 执行完整回滚
    _full_rollback() {
        echo -e "${RED}>>> 正在执行完整回滚以恢复配置...${PLAIN}"
        local entry bak orig
        # 恢复备份的文件
        for entry in "${_rollback_backups[@]}"; do
            bak="${entry%%|*}"
            orig="${entry##*|}"
            if [ -f "$bak" ]; then
                if cp -p "$bak" "$orig"; then
                    echo -e "  已恢复: ${orig}"
                else
                    echo -e "  ${RED}恢复失败: ${orig}${PLAIN}"
                fi
            fi
        done
        # 删除本次新创建的文件
        for entry in "${_rollback_created[@]}"; do
            if [ -f "$entry" ]; then
                if rm -f "$entry"; then
                    echo -e "  已删除: ${entry}"
                else
                    echo -e "  ${RED}删除失败: ${entry}${PLAIN}"
                fi
            fi
        done
        systemctl daemon-reload 2>/dev/null || true
        echo -e "${GREEN}回滚完成。${PLAIN}"
    }

    # === 步骤 1: 备份主配置 ===
    if ! _reg_backup "$SSH_CONFIG"; then
        echo -e "${RED}备份主配置失败，已取消操作。${PLAIN}"
        read -p "按回车键返回..."
        return 1
    fi
    echo -e "已备份主配置。"

    # === 步骤 2: 扫描并注释 sshd_config.d/ 中所有 Port 指令 ===
    local -a conflict_files=()
    if [ -d /etc/ssh/sshd_config.d ]; then
        local conf_file
        for conf_file in /etc/ssh/sshd_config.d/*.conf; do
            [ -f "$conf_file" ] || continue
            if grep -qE '^[[:space:]]*Port[[:space:]]+[0-9]+' "$conf_file"; then
                conflict_files+=("$conf_file")
            fi
        done
    fi

    if [ ${#conflict_files[@]} -gt 0 ]; then
        echo -e "${YELLOW}检测到以下子配置包含 Port 指令:${PLAIN}"
        local f
        for f in "${conflict_files[@]}"; do
            echo -e "  - ${f}: $(grep -E '^[[:space:]]*Port[[:space:]]+[0-9]+' "$f")"
        done
        echo -e "${YELLOW}OpenSSH first-match-wins 规则下，这些指令会覆盖新端口配置。${PLAIN}"
        read -p "是否自动注释所有子配置中的 Port 行? [Y/n]: " fix_include
        if [[ "$fix_include" != "n" && "$fix_include" != "N" ]]; then
            for f in "${conflict_files[@]}"; do
                if ! _reg_backup "$f"; then
                    echo -e "${RED}备份子配置 $f 失败！${PLAIN}"
                    _full_rollback
                    read -p "按回车键返回..."
                    return 1
                fi
                if ! sed -E -i '/^[[:space:]]*Port[[:space:]]+[0-9]+/s/^/# /' "$f"; then
                    echo -e "${RED}修改子配置 $f 失败！${PLAIN}"
                    _full_rollback
                    read -p "按回车键返回..."
                    return 1
                fi
                echo -e "${GREEN}已注释 ${f} 中的 Port 指令。${PLAIN}"
            done
        else
            echo -e "${RED}警告: 子配置冲突未解决，端口修改可能无效！${PLAIN}"
        fi
    fi

    # === 步骤 3: 注释主配置中的旧 Port 行 ===
    if ! sed -E -i '/^[[:space:]]*Port[[:space:]]+[0-9]+/s/^/#/' "$SSH_CONFIG"; then
        echo -e "${RED}修改主配置失败！${PLAIN}"
        _full_rollback
        read -p "按回车键返回..."
        return 1
    fi

    # === 步骤 4: 创建专属子配置文件 ===
    local custom_port_conf="/etc/ssh/sshd_config.d/00-custom-port.conf"
    if [ -d /etc/ssh/sshd_config.d ]; then
        if [ -f "$custom_port_conf" ]; then
            if ! _reg_backup "$custom_port_conf"; then
                _full_rollback
                read -p "按回车键返回..."
                return 1
            fi
        else
            _reg_created "$custom_port_conf"
        fi
        
        if ! cat > "$custom_port_conf" <<PORTEOF
# 由 ufw-utils.sh 自动生成 — 自定义 SSH 端口
# 文件名 00- 前缀确保在 first-match-wins 规则下优先生效
Port ${new_port}
PORTEOF
        then
            echo -e "${RED}创建自定义端口配置文件失败！${PLAIN}"
            _full_rollback
            read -p "按回车键返回..."
            return 1
        fi
        echo -e "${GREEN}已创建子配置: ${custom_port_conf} (Port ${new_port})${PLAIN}"
    else
        # 无 sshd_config.d 目录（旧系统），回退到追加主配置方式
        if ! printf '\n# 修改添加的自定义 SSH 端口\nPort %s\n' "$new_port" >> "$SSH_CONFIG"; then
            echo -e "${RED}追加端口配置到主文件失败！${PLAIN}"
            _full_rollback
            read -p "按回车键返回..."
            return 1
        fi
        echo -e "${GREEN}sshd_config 已更新: Port → ${new_port}${PLAIN}"
    fi

    # === 步骤 5: sshd -t 语法验证 ===
    echo -e "${YELLOW}正在验证 SSH 配置语法...${PLAIN}"
    # 修复: 部分系统 (Debian/Ubuntu) 的 /run/sshd 是 systemd 动态创建的
    # 手动执行 sshd -t 若目录不存在会报 Missing privilege separation directory 导致误判
    if [ ! -d /run/sshd ]; then
        mkdir -p /run/sshd 2>/dev/null || true
    fi
    local sshd_test_output
    if ! sshd_test_output=$(sshd -t 2>&1); then
        echo -e "${RED}SSH 配置验证失败！错误信息:${PLAIN}"
        echo "$sshd_test_output"
        _full_rollback
        read -p "按回车键返回..."
        return 1
    fi
    echo -e "${GREEN}✓ SSH 配置语法验证通过${PLAIN}"

    # === 步骤 6: UFW 放行新端口 ===
    local ufw_rule_added=0
    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        echo -e "${YELLOW}正在为新端口添加 UFW 放行规则...${PLAIN}"
        if ufw allow "${new_port}/tcp" >/dev/null; then
            ufw reload >/dev/null || true
            ufw_rule_added=1
            echo -e "${GREEN}✓ UFW 已放行端口 ${new_port}/tcp 并同步至内核${PLAIN}"
        else
            echo -e "${RED}UFW 放行新端口失败！${PLAIN}"
            _full_rollback
            read -p "按回车键返回..."
            return 1
        fi
    fi

    # === 步骤 7: 重启 SSH 服务 ===
    local use_socket=0
    local socket_unit=""
    for s in ssh.socket sshd.socket; do
        if systemctl list-unit-files --type=socket 2>/dev/null | grep -q "^${s}"; then
            socket_unit="$s"
            use_socket=1
            break
        fi
    done

    local restart_failed=0

    if [[ "$use_socket" -eq 1 ]]; then
        echo -e "${YELLOW}检测到 systemd socket 激活模式 (${socket_unit})，正在更新 socket 监听端口...${PLAIN}"
        local dropin_dir="/etc/systemd/system/${socket_unit}.d"
        local dropin_file="${dropin_dir}/listen.conf"
        
        if ! mkdir -p "$dropin_dir"; then
            echo -e "${RED}创建 socket 配置目录失败！${PLAIN}"
            _full_rollback
            read -p "按回车键返回..."
            return 1
        fi

        if [ -f "$dropin_file" ]; then
            if ! _reg_backup "$dropin_file"; then
                _full_rollback
                read -p "按回车键返回..."
                return 1
            fi
        else
            _reg_created "$dropin_file"
        fi

        if ! cat > "$dropin_file" <<SOCKETEOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:${new_port}
ListenStream=[::]:${new_port}
SOCKETEOF
        then
            echo -e "${RED}创建 socket drop-in 文件失败！${PLAIN}"
            _full_rollback
            read -p "按回车键返回..."
            return 1
        fi
        
        echo -e "${GREEN}已创建 socket drop-in: ${dropin_file}${PLAIN}"
        systemctl daemon-reload 2>/dev/null || true

        echo -e "${YELLOW}正在验证 socket 配置...${PLAIN}"
        local socket_listen
        socket_listen=$(systemctl show "${socket_unit}" -p Listen 2>/dev/null || true)
        if [[ -n "$socket_listen" ]]; then
            echo -e "  Socket 监听配置: ${socket_listen}"
        fi

        echo -e "${YELLOW}正在重启 SSH socket 和服务...${PLAIN}"
        local svc_unit="${socket_unit%.socket}.service"
        systemctl stop "$svc_unit" 2>/dev/null || true
        if ! systemctl restart "$socket_unit" 2>&1; then
            echo -e "${RED}警告: ${socket_unit} 重启失败！${PLAIN}"
            journalctl -u "$socket_unit" --no-pager -n 5
            restart_failed=1
        fi
    else
        echo -e "${YELLOW}传统模式，正在重启 SSH 服务...${PLAIN}"
        local restart_ok=0
        for svc_name in sshd ssh; do
            if systemctl restart "$svc_name" 2>/dev/null; then
                echo -e "${GREEN}SSH 服务 (${svc_name}) 重启成功！${PLAIN}"
                restart_ok=1
                break
            fi
        done
        if [[ "$restart_ok" -eq 0 ]]; then
            echo -e "${RED}SSH 服务重启失败！${PLAIN}"
            restart_failed=1
        fi
    fi

    # === 步骤 8: 验证新端口是否真正开始监听 ===
    local verify_wait=3
    echo -e "${YELLOW}等待 ${verify_wait} 秒后验证端口监听状态...${PLAIN}"
    sleep "$verify_wait"

    if [[ "$restart_failed" -eq 1 ]] || \
       ! ss -tlnp 2>/dev/null | awk 'NR>1 {split($4,a,":"); if(a[length(a)]==port) found=1} END{exit !found}' port="$new_port"; then
        echo -e "${RED}✗ 新端口 ${new_port} 未监听或服务重启失败！${PLAIN}"
        echo -e "${YELLOW}正在执行完整回滚以恢复 SSH 连接...${PLAIN}"

        _full_rollback

        if [[ "$ufw_rule_added" -eq 1 ]]; then
            ufw delete allow "${new_port}/tcp" 2>/dev/null || true
            ufw reload 2>/dev/null || true
            echo -e "  已撤销 UFW 新端口规则"
        fi

        echo -e "${YELLOW}正在重启 SSH 服务以恢复旧端口...${PLAIN}"
        if [[ "$use_socket" -eq 1 ]]; then
            systemctl daemon-reload 2>/dev/null || true
            systemctl restart "$socket_unit" 2>/dev/null || true
        else
            systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
        fi

        sleep 2
        if ss -tlnp 2>/dev/null | awk 'NR>1 {split($4,a,":"); if(a[length(a)]==port) found=1} END{exit !found}' port="$old_port"; then
            echo -e "${GREEN}✓ 旧端口 ${old_port} 已恢复监听。${PLAIN}"
        else
            echo -e "${RED}✗ 警告: 旧端口也未恢复！请通过 VNC/IPMI 等带外通道紧急处理。${PLAIN}"
        fi

        read -p "按回车键返回..."
        return 1
    fi

    echo -e "${GREEN}✓ 确认新端口 ${new_port} 已正常监听！${PLAIN}"

    # === 步骤 9: 同步 Fail2ban 端口配置 ===
    if [ -f "$FAIL2BAN_JAIL" ] && systemctl is-active --quiet fail2ban 2>/dev/null; then
        echo -e "${YELLOW}正在同步 Fail2ban 监控端口...${PLAIN}"
        if grep -A5 '^\[sshd\]' "$FAIL2BAN_JAIL" | grep -qE '^[[:space:]]*port[[:space:]]*='; then
            sed -i "/^\[sshd\]/,/^\[/{s/^[[:space:]]*port[[:space:]]*=.*/port = ${new_port}/}" "$FAIL2BAN_JAIL" || true
        else
            sed -i "/^\[sshd\]/a port = ${new_port}" "$FAIL2BAN_JAIL" || true
        fi
        systemctl restart fail2ban 2>/dev/null || true
        echo -e "${GREEN}✓ Fail2ban 已更新为监控端口 ${new_port}${PLAIN}"
    fi

    # === 步骤 10: 可选清理旧端口 UFW 规则 ===
    # 修复模式下新旧端口相同，跳过此步以防误删刚添加的规则
    if [[ "$is_repair_mode" -eq 0 ]] && command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        read -p "是否从 UFW 中移除旧端口 ($old_port) 的入站规则？[y/N]: " del_old
        if [[ "$del_old" == "y" || "$del_old" == "Y" ]]; then
            ufw delete allow "${old_port}/tcp" 2>/dev/null || true
            ufw delete allow "${old_port}" 2>/dev/null || true
            ufw reload >/dev/null 2>&1 || true
            echo -e "${GREEN}已移除旧端口的放行规则并重载防火墙。${PLAIN}"
        fi
    fi

    # 清理回滚备份文件
    local entry bak
    for entry in "${_rollback_backups[@]}"; do
        bak="${entry%%|*}"
        rm -f "$bak" 2>/dev/null || true
    done

    echo -e ""
    echo -e "${GREEN}操作完成！${PLAIN}"
    echo -e "${YELLOW}⚠ 请先开启新终端用端口 ${new_port} 测试登录，成功后再关闭当前连接！${PLAIN}"
    read -p "按回车键继续..."
}

# ==============================================================================
# 主菜单 (单页设计)
# ==============================================================================

show_menu() {
    check_ufw
    
    while true; do
        clear
        echo -e "========================================"
        echo -e "      UFW & Fail2ban 一键管理 v1.7.3"
        echo -e "========================================" 
        
        # 顶部状态栏
        local ufw_color ufw_text f2b_color f2b_text
        
        # UFW 状态
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            ufw_color="${GREEN}"
            ufw_text="Active"
        else
            ufw_color="${RED}"
            ufw_text="Inactive"
        fi
        
        # Fail2ban 状态
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            f2b_color="${GREEN}"
            f2b_text="Active"
        else
            f2b_color="${RED}"
            f2b_text="Inactive"
        fi
        
        echo -e "UFW: ${ufw_color}${ufw_text}${PLAIN} | Fail2ban: ${f2b_color}${f2b_text}${PLAIN}"
        echo -e "----------------------------------------"
        
        echo -e "${SKYBLUE}[ UFW 防火墙 ]${PLAIN}"
        echo -e " 1. 初始化规则        2. 放行端口"
        echo -e " 3. 删除规则          4. 查看状态"
        echo -e " 5. 启用防火墙        6. 禁用防火墙"
        echo -e " 7. 整理规则          8. 卸载 UFW"
        echo -e "----------------------------------------"
        
        echo -e "${SKYBLUE}[ Fail2ban ]${PLAIN}"
        echo -e " 9. 安装/配置        10. 查看状态"
        echo -e "11. 封禁 IP          12. 解封 IP"
        echo -e "13. 修改策略         14. 卸载"
        echo -e "----------------------------------------"
        echo -e "${SKYBLUE}[ 通用管理 ]${PLAIN}"
        echo -e "15. 更换 SSH 端口"
        echo -e "16. 诊断 iptables 同步"
        echo -e "----------------------------------------"
        echo -e " 0. 退出"
        echo ""
        read -p "请选择 [0-16]: " num
        
        case "$num" in
            1) ufw_basic_setup ;;
            2) ufw_allow_port ;;
            3) ufw_delete_rule ;;
            4) 
                ufw_status_detailed
                ;;
            5) 
                echo "y" | ufw enable
                echo -e "${GREEN}UFW 已启用${PLAIN}"
                # 启用后检查 Docker 兼容性，确保 DOCKER-USER 链不会绕过 UFW
                check_docker_compat
                read -p "按回车继续..." 
                ;;
            6) 
                ufw disable
                echo -e "${YELLOW}UFW 已禁用${PLAIN}"
                read -p "按回车继续..." 
                ;;
            7) ufw_sort_rules ;;
            8) ufw_uninstall ;;
            9) fail2ban_install ;;
            10) 
                fail2ban_status_detailed
                ;;
            11) 
                if ! systemctl is-active --quiet fail2ban; then
                    echo -e "${RED}Fail2ban 未运行${PLAIN}"
                else
                    read -p "输入要封禁的 IP: " ip
                    [ -n "$ip" ] && fail2ban-client set sshd banip "$ip"
                fi
                read -p "按回车继续..." 
                ;;
            12) 
                if ! systemctl is-active --quiet fail2ban; then
                    echo -e "${RED}Fail2ban 未运行${PLAIN}"
                else
                    read -p "输入要解封的 IP: " ip
                    [ -n "$ip" ] && fail2ban-client set sshd unbanip "$ip"
                fi
                read -p "按回车继续..." 
                ;;
            13) fail2ban_config ;;
            14) fail2ban_uninstall ;;
            15) change_ssh_port ;;
            16) check_iptables_sync ;;
            0) exit 0 ;;
            *) echo -e "${RED}无效选择${PLAIN}"; sleep 1 ;;
        esac
    done
}

# ==============================================================================
# 脚本入口
# ==============================================================================
check_root
check_system
show_menu
