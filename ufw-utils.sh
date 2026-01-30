#!/bin/bash
# ==============================================================================
# ufw-utils.sh v1.3.1
# 描述: UFW 防火墙与 Fail2ban 一键管理脚本 (单页菜单版)
# 支持: Ubuntu/Debian (需支持 UFW)
# 作者: Agent (Based on user request)
# ------------------------------------------------------------------------------
# 变更记录:
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

# ==============================================================================
# 基础检查函数
# ==============================================================================

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
check_ufw() {
    if ! command -v ufw &> /dev/null; then
        echo -e "${YELLOW}未检测到 ufw，正在安装...${PLAIN}"
        apt-get update && apt-get install -y ufw
        if [ $? -ne 0 ]; then
            echo -e "${RED}ufw 安装失败，请检查网络或源！${PLAIN}"
            exit 1
        fi
        echo -e "${GREEN}ufw 安装成功！${PLAIN}"
    fi
}

# 检测 SSH 端口
detect_ssh_port() {
    local port=22
    local found_explicit=0
    
    if [ -f "$SSH_CONFIG" ]; then
        local detected_port
        detected_port=$(grep -E "^Port [0-9]+" "$SSH_CONFIG" | head -n 1 | awk '{print $2}')
        if [[ -n "$detected_port" ]]; then
            port=$detected_port
            found_explicit=1
        fi
        
        # 如果未显式检测到端口且存在 Include 指令，提示风险
        if [[ "$found_explicit" -eq 0 ]] && grep -q "^Include" "$SSH_CONFIG"; then
            echo -e "${YELLOW}警告: 检测到 SSH 配置包含 Include 指令，端口可能在子配置中 (回退默认 22)。${PLAIN}" >&2
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
            mem=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
        else
            mem="未知"
        fi
        [ -z "$mem" ] && mem="未知"
        
        # 运行时长
        local start_ts now_ts diff
        start_ts=$(date -d "$(systemctl show -p ActiveEnterTimestamp --value "$svc")" +%s 2>/dev/null)
        now_ts=$(date +%s)
        if [[ -n "$start_ts" ]]; then
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
    if ufw status | grep -q -E "Status: active|To"; then
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
    ufw show added | grep '^ufw ' > "$rule_file"
    
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
            $rule_cmd >/dev/null
            ((count++))
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
             val=$(sed -n '/^\[DEFAULT\]/,/^\[/p' "$f" | grep -E "^[[:space:]]*${k}[[:space:]]*=" | tail -n 1 | cut -d = -f 2- | tr -d '[:space:]')
        else
             val=$(grep -E "^[[:space:]]*${k}[[:space:]]*=" "$f" | tail -n 1 | cut -d = -f 2- | tr -d '[:space:]')
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
    # UFW 是内核模块，没有单一进程，但 systemctl status ufw 可看服务状态
    get_service_info ufw
    echo -e "----------------------------------------"
    ufw status verbose
    
    echo -e "\n${SKYBLUE}>>> 最近拦截记录 (日志摘要)${PLAIN}"
    if [ -f /var/log/ufw.log ]; then
        tail -n 10 /var/log/ufw.log | while read -r line; do
             # 提取时间
            ts=$(echo "$line" | awk '{print $1, $2, $3}')
            # 提取 SRC IP
            src_ip=$(echo "$line" | grep -oP 'SRC=\K[\d\.]+')
            # 提取 DST Port
            dst_port=$(echo "$line" | grep -oP 'DPT=\K\d+')
            proto=$(echo "$line" | grep -oP 'PROTO=\K\w+')
            
            if [[ -n "$src_ip" ]]; then
                 echo -e "${ts} -> ${RED}拦截${PLAIN} 来自 ${src_ip} (目标: ${dst_port}/${proto})"
            fi
        done
    else
        # 尝试 dmesg
        echo "日志文件未找到，尝试系统消息(dmesg)..."
        dmesg | grep '\[UFW BLOCK\]' | tail -n 5 | while read -r line; do
             src_ip=$(echo "$line" | grep -oP 'SRC=\K[\d\.]+')
             [[ -n "$src_ip" ]] && echo -e "${RED}拦截${PLAIN} 来自 ${src_ip}"
        done
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
            ts=$(echo "$line" | awk '{print $1, $2}')
            # 提取 Jail 和 IP
            jail=$(echo "$line" | grep -oP '\[.*?\]' | head -1)
            ip=$(echo "$line" | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            
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
# 主菜单 (单页设计)
# ==============================================================================

show_menu() {
    check_ufw
    
    while true; do
        clear
        echo -e "========================================"
        echo -e "      UFW & Fail2ban 一键管理 v1.3.1"
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
        echo -e " 0. 退出"
        echo ""
        read -p "请选择 [0-14]: " num
        
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
