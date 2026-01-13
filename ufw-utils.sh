#!/bin/bash
# ufw-utils.sh
# 描述: UFW 防火墙与 Fail2ban 一键管理脚本
# 支持: Ubuntu/Debian (需支持 UFW)
# 作者: Agent (Based on user request)

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'

# 全局变量
SSH_CONFIG="/etc/ssh/sshd_config"
FAIL2BAN_JAIL="/etc/fail2ban/jail.local"

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
    # 默认端口
    local port=22
    if [ -f "$SSH_CONFIG" ]; then
        # 查找未被注释的 Port 行
        # grep 匹配行首的 Port, awk 取第二个值
        local detected_port
        detected_port=$(grep -E "^Port [0-9]+" "$SSH_CONFIG" | head -n 1 | awk '{print $2}')
        if [[ -n "$detected_port" ]]; then
            port=$detected_port
        fi
    fi
    echo "$port"
}

# UFW: 基础配置初始化
ufw_basic_setup() {
    echo -e "${YELLOW}>>> 正在初始化 UFW 基础配置...${PLAIN}"
    
    # 检测 SSH 端口，防止自锁
    local ssh_port
    ssh_port=$(detect_ssh_port)
    echo -e "检测到 SSH 端口为: ${GREEN}${ssh_port}${PLAIN}"
    
    # 检查 UFW 是否已有规则
    if ufw status | grep -q -E "Status: active|To"; then
        echo -e "${YELLOW}检测到 UFW 已有配置或处于活动状态。${PLAIN}"
        read -p "是否重置所有规则并重新初始化? (选择 N 将仅确保 SSH/基础策略被应用) [y/N]: " reset_confirm
        if [[ "$reset_confirm" == "y" || "$reset_confirm" == "Y" ]]; then
             echo -e "${RED}正在重置规则...${PLAIN}"
             ufw --force disable
             ufw --force reset
        else
             echo -e "${GREEN}保留现有规则，仅检查基础项...${PLAIN}"
        fi
    fi

    # 默认策略 (如果未重置，这会覆盖策略但不删除规则)
    ufw default deny incoming
    ufw default allow outgoing
    
    # 放行 SSH (ufw 会自动处理重复)
    echo -e "确保放行 SSH 端口: ${ssh_port}"
    ufw allow "${ssh_port}/tcp"
    
    echo -e "${YELLOW}基础配置检查完毕。${PLAIN}"
    if ! ufw status | grep -q "Status: active"; then
        echo -e "提示: UFW 目前处于 ${RED}inactive${PLAIN} 状态。"
        echo -e "若要立即生效，请在菜单中选择 '启用防火墙'。"
    fi
    read -p "按回车键继续..."
}

# UFW: 常用端口放行
ufw_allow_port() {
    echo -e "${SKYBLUE}请输入要放行的端口 (例如 80) 或 端口/协议 (例如 80/tcp)${PLAIN}"
    echo -e "支持输入多个端口 (使用空格或逗号分隔)，例如: 80, 443"
    read -p "端口: " port_input
    if [[ -z "$port_input" ]]; then echo "已取消"; return; fi
    
    # 将逗号替换为空格
    port_input=${port_input//,/ }
    
    # 循环处理每个端口
    for port in $port_input; do
        if [[ -n "$port" ]]; then
            echo -e "正在添加规则: ${GREEN}${port}${PLAIN}"
            ufw allow "$port"
        fi
    done
    
    echo -e "${GREEN}操作完成！${PLAIN}"
    read -p "按回车键继续..."
}

# UFW: 一键放行 Web 端口
ufw_allow_web() {
    echo -e "${YELLOW}正在放行 HTTP(80) 和 HTTPS(443)...${PLAIN}"
    ufw allow 80/tcp
    ufw allow 443/tcp
    echo -e "${GREEN}完成！${PLAIN}"
    read -p "按回车键继续..."
}

# UFW: 删除规则
ufw_delete_rule() {
    # 检查状态
    if ! ufw status | grep -q "Status: active"; then
        echo -e "${RED}错误: UFW 未运行，无法获取规则编号。${PLAIN}"
        echo -e "${YELLOW}请先启用防火墙 (菜单 5 -> Enable) 才能进行删除操作。${PLAIN}"
        read -p "按回车键返回..."
        return
    fi
    
    echo -e "${SKYBLUE}当前规则列表 (带编号):${PLAIN}"
    ufw status numbered
    
    echo -e ""
    echo -e "${YELLOW}请输入要删除的规则【编号】(例如 2)，输入 q 取消${PLAIN}"
    read -p "编号: " num
    
    if [[ "$num" == "q" || -z "$num" ]]; then return; fi
    
    # 确认删除
    ufw delete "$num"
    echo -e "${GREEN}操作结束${PLAIN}"
    read -p "按回车键继续..."
}

# UFW: 规则排序与重载
ufw_sort_rules() {
    echo -e "${YELLOW}>>> 正在整理 UFW 规则...${PLAIN}"
    
    # 1. 检查是否有规则
    if ! ufw status | grep -q "Status: active"; then
        echo -e "${RED}错误: UFW 未运行，无法获取规则。${PLAIN}"
        echo -e "请先启用防火墙。"
        read -p "按回车键返回..."
        return
    fi

    # 2. 提取并排序规则
    # 获取 'ufw allow/deny...' 命令列表
    local rule_file="/tmp/ufw_rules.tmp"
    ufw show added | grep '^ufw ' > "$rule_file"
    
    if [ ! -s "$rule_file" ]; then
        echo -e "${YELLOW}当前没有自定义规则，无需排序。${PLAIN}"
        rm -f "$rule_file"
        read -p "按回车键返回..."
        return
    fi
    
    echo -e "${SKYBLUE}当前发现以下规则 (未排序):${PLAIN}"
    cat "$rule_file"
    echo -e "--------------------------------"
    
    echo -e "${YELLOW}即将执行的操作:${PLAIN}"
    echo -e "1. 备份当前配置"
    echo -e "2. 重置 UFW (清除所有)"
    echo -e "3. 按端口排序、去重并重新添加规则"
    echo -e "${RED}注意: 这将短暂中断连接 (数秒)，但在 SSH 保持连接下通常是安全的。${PLAIN}"
    read -p "是否继续? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        rm -f "$rule_file"
        echo "已取消。"
        return
    fi
    
    # 3. 排序 (按第三列端口号数字排序) 并去重
    # sort -k 3 -V 自然排序 (22 < 80)
    sort -k 3 -V "$rule_file" | uniq > "${rule_file}.sorted"
    
    # 3.1 智能去重: 如果存在宽泛规则 (如 "allow 80")，则移除特定规则 ("allow 80/tcp")
    # 使用 awk 处理: 将所有规则读入数组，检查包含关系
    awk '
    {
        # 去除行首行尾空白 (虽然 grep 处理过，但保险起见)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
        lines[NR] = $0
        seen[$0] = 1
        
        # 提取基础命令，去除可能的 /tcp 或 /udp 后缀
        # 兼容情况: "ufw allow 80/tcp" -> "ufw allow 80"
        # 简单正则: 替换 /tcp 或 /udp 为空，允许结尾有空格
        base = $0
        if (sub(/\/(tcp|udp)([[:space:]]|$)/, "", base)) {
            # 如果发生了替换，且替换后的 base 与原串不同
            if (base != $0) {
                 # 去除 base 可能产生的尾部空格
                 gsub(/[[:space:]]+$/, "", base)
                 has_base[$0] = base
            }
        }
    }
    END {
        for (i = 1; i <= NR; i++) {
            line = lines[i]
            skip = 0
            
            # 如果这行有 base 版本 (例如它是 80/tcp，base是 80)
            if (line in has_base) {
                base_cmd = has_base[line]
                # 并且 base 版本也在文件中
                if (base_cmd in seen) {
                    # 跳过输出 (即删除该冗余规则)
                    print "Debug: Reducing duplicate rule: [" line "] (covered by [" base_cmd "])" > "/dev/tty"
                    skip = 1
                }
            }
            
            if (skip == 0) {
                print line
            }
        }
    }
    ' "${rule_file}.sorted" > "${rule_file}.final"
    
    mv "${rule_file}.final" "${rule_file}.sorted"
    
    echo -e "${GREEN}排序与去重后的规则预览:${PLAIN}"
    cat "${rule_file}.sorted"
    echo -e "Waiting 2 seconds..."
    sleep 2
    
    # 4. 执行真实备份 (Backup)
    echo -e "${YELLOW}正在备份配置 (/etc/ufw/user.rules)...${PLAIN}"
    local bk_ts
    bk_ts=$(date +%Y%m%d_%H%M%S)
    cp /etc/ufw/user.rules "/etc/ufw/user.rules.bak.${bk_ts}" 2>/dev/null
    cp /etc/ufw/user6.rules "/etc/ufw/user6.rules.bak.${bk_ts}" 2>/dev/null
    echo -e "备份已保存至 /etc/ufw/user.rules.bak.${bk_ts}"
    
    # 5. 执行重置与应用
    echo -e "${YELLOW}正在重置 UFW...${PLAIN}"
    ufw --force disable
    ufw --force reset
    
    # 重新应用默认策略
    ufw default deny incoming
    ufw default allow outgoing
    
    echo -e "${YELLOW}正在重新添加规则...${PLAIN}"
    local count=0
    while read -r rule_cmd; do
        if [[ -n "$rule_cmd" ]]; then
            # 执行命令
            echo "Applying: $rule_cmd"
            $rule_cmd >/dev/null
            ((count++))
        fi
    done < "${rule_file}.sorted"
    
    # 5. 确保 UFW 再次启用
    echo -e "${YELLOW}重新启用 UFW...${PLAIN}"
    echo "y" | ufw enable
    
    # 清理
    rm -f "$rule_file" "${rule_file}.sorted"
    
    echo -e "${GREEN}成功! 共重新加载了 $count 条规则。${PLAIN}"
    read -p "按回车键继续..."
}

# UFW: 状态管理
ufw_manage_status() {
    while true; do
        clear
        echo -e "========================="
        echo -e "    UFW 状态管理"
        echo -e "========================="
        echo -e "${SKYBLUE}当前简要状态:${PLAIN}"
        ufw status | head -n 1
        echo -e "-------------------------"
        echo "1. 查看详细状态 (Verbose)"
        echo "2. 查看规则编号 (Numbered)"
        echo "3. 启用防火墙 (Enable)"
        echo "4. 禁用防火墙 (Disable)"
        echo "5. 重载配置 (Reload)"
        echo "6. 🧹 整理规则 (按端口排序重载)"
        echo "-------------------------"
        echo "0. 返回上一级"
        echo ""
        read -p "选择: " choice
        case "$choice" in
            1) ufw status verbose; read -p "按回车键继续..." ;;
            2) ufw status numbered; read -p "按回车键继续..." ;;
            3) 
                echo "y" | ufw enable 
                echo -e "${GREEN}UFW 已启用${PLAIN}"
                read -p "按回车键继续..."
                ;;
            4) 
                ufw disable
                echo -e "${YELLOW}UFW 已禁用${PLAIN}"
                read -p "按回车键继续..."
                ;;
            5) 
                ufw reload
                echo -e "${GREEN}配置已重载${PLAIN}"
                read -p "按回车键继续..."
                ;;
            6)
                ufw_sort_rules
                ;;
            0) break ;;
            *) echo "无效选择"; sleep 1 ;;
        esac
    done
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

# UFW 管理菜单
ufw_menu() {
    while true; do
        clear
        echo -e "========================="
        echo -e "    UFW 防火墙管理"
        echo -e "========================="
        echo -e "1. 🛡️ 初始化/重置基础规则 (SSH+Default)"
        echo -e "2. ➕ 放行指定端口 (Custom Port)"
        echo -e "3. 🌐 一键放行 Web 端口 (80/443)"
        echo -e "4. 🗑️ 删除规则 (Delete Rule)"
        echo -e "5. 👀 状态管理 (Enable/Disable/View)"
        echo -e "6. ❌ 卸载 UFW"
        echo -e "-------------------------"
        echo -e "0. 返回主菜单"
        echo -e ""
        read -p "请选择: " choice
        
        case "$choice" in
            1) ufw_basic_setup ;;
            2) ufw_allow_port ;;
            3) ufw_allow_web ;;
            4) ufw_delete_rule ;;
            5) ufw_manage_status ;;
            6) ufw_uninstall ;;
            0) break ;;
            *) echo "无效选择" ;;
        esac
    done
}

# === Fail2ban 功能区 ===

# 安装 Fail2ban
fail2ban_install() {
    # 检查是否已安装
    if command -v fail2ban-client &> /dev/null; then
        echo -e "${GREEN}检测到 Fail2ban 已安装。${PLAIN}"
        read -p "是否需要强制重新安装/更新? [y/N]: " reinstall
        if [[ "$reinstall" == "y" || "$reinstall" == "Y" ]]; then
            echo -e "${YELLOW}>>> 正在更新/重装 Fail2ban...${PLAIN}"
            apt-get update
            apt-get install -y fail2ban python3-systemd
        else
            echo -e "跳过安装步骤..."
            # 检查服务状态，如果正常则直接返回，避免重复配置和重启
            if systemctl is-active --quiet fail2ban; then
                 echo -e "${GREEN}Fail2ban 服务正在运行。跳过配置与重启。${PLAIN}"
                 read -p "按回车键继续..."
                 return
            fi
            echo -e "${YELLOW}Fail2ban 未运行，正在尝试配置并启动...${PLAIN}"
        fi
    else
        echo -e "${YELLOW}>>> 正在安装 Fail2ban...${PLAIN}"
        apt-get update
        apt-get install -y fail2ban python3-systemd
        
        if ! command -v fail2ban-client &> /dev/null; then
            echo -e "${RED}Fail2ban 安装失败！${PLAIN}"
            return
        fi
    fi
    
    echo -e "${YELLOW}>>> 配置 Jail (使用 UFW 作为动作)...${PLAIN}"
    
    # 智能检测后端 (针对 Debian 12+)
    local backend_mode="auto"
    if [ ! -f /var/log/auth.log ]; then
        echo -e "${YELLOW}提示: 未检测到 /var/log/auth.log，将使用 systemd 后端以避免启动失败。${PLAIN}"
        backend_mode="systemd"
    fi

    # 如果没有 local 配置，直接创建最佳实践配置
    if [ ! -f "$FAIL2BAN_JAIL" ]; then
        echo -e "${GREEN}创建默认 jail.local...${PLAIN}"
        cat > "$FAIL2BAN_JAIL" <<EOF
[DEFAULT]
# Ban action (use UFW)
banaction = ufw

[sshd]
enabled = true
# Auto detect backend (use systemd if auth.log missing)
backend = ${backend_mode}
EOF
        # 确保移除潜在的 Windows 回车符
        sed -i 's/\r//' "$FAIL2BAN_JAIL"
    else
        echo -e "${YELLOW}检测到已有 jail.local，正在通过 sed 更新基础配置...${PLAIN}"
        # 1. 设置 banaction = ufw
        if grep -q "^banaction =" "$FAIL2BAN_JAIL"; then
            sed -i 's/^banaction =.*/banaction = ufw/' "$FAIL2BAN_JAIL"
        else
            if grep -q "^\[DEFAULT\]" "$FAIL2BAN_JAIL"; then
                sed -i '/^\[DEFAULT\]/a banaction = ufw' "$FAIL2BAN_JAIL"
            else
                echo -e "[DEFAULT]\nbanaction = ufw" >> "$FAIL2BAN_JAIL"
            fi
        fi
        
        # 2. 确保 [sshd] 启用
        if ! grep -q "^\[sshd\]" "$FAIL2BAN_JAIL"; then
            echo -e "\n[sshd]\nenabled = true\n" >> "$FAIL2BAN_JAIL"
        else
             if ! grep -q "enabled = true" "$FAIL2BAN_JAIL"; then
                  echo -e "${YELLOW}提示: 现有 [sshd] 配置似乎未启用。${PLAIN}"
                  # sed -i ... (保守策略，暂不强制修改现有块，除非用户明确)
             fi
        fi
        
        # 3. 针对 Debian 12 强制修正 backend (如果不仅是 auto 而是必须 systemd)
        if [[ "$backend_mode" == "systemd" ]]; then
            # 检查是否已经设置了 backend
            if grep -q "backend" "$FAIL2BAN_JAIL"; then
                 # 简单替换 auto -> systemd 如果存在
                 sed -i 's/backend = auto/backend = systemd/' "$FAIL2BAN_JAIL"
            else
                 # 如果 [sshd] 下没有 backend，追加一个
                 if grep -q "^\[sshd\]" "$FAIL2BAN_JAIL"; then
                     sed -i '/^\[sshd\]/a backend = systemd' "$FAIL2BAN_JAIL"
                 fi
            fi
        fi
    fi

    # 尝试启动
    echo -e "${YELLOW}正在启动 Fail2ban...${PLAIN}"
    systemctl restart fail2ban
    systemctl enable fail2ban &>/dev/null
    
    # 检查状态
    sleep 2
    if systemctl is-active --quiet fail2ban; then
        echo -e "${GREEN}Fail2ban 启动成功！${PLAIN}"
    else
        echo -e "${RED}Fail2ban 启动失败！${PLAIN}"
        echo -e "${YELLOW}这可能是因为配置文件 jail.local 存在语法错误或冲突。${PLAIN}"
        echo -e "建议：重置为最小化配置 (仅包含 sshd 和 ufw 设置)。"
        read -p "是否重置 jail.local 为最小可用配置? [y/N]: " reset_conf
        
        if [[ "$reset_conf" == "y" || "$reset_conf" == "Y" ]]; then
            # 备份旧配置
            mv "$FAIL2BAN_JAIL" "${FAIL2BAN_JAIL}.bak.$(date +%s)"
            echo -e "${YELLOW}已备份原配置。写入最小化配置...${PLAIN}"
            
            # 写入最小化配置
            cat > "$FAIL2BAN_JAIL" <<EOF
[DEFAULT]
# Ban action (use UFW)
banaction = ufw

[sshd]
enabled = true
# Auto detect backend (use systemd if auth.log missing)
backend = ${backend_mode}
EOF
            # 确保移除潜在的 Windows 回车符
            sed -i 's/\r//' "$FAIL2BAN_JAIL"
            
            echo -e "${YELLOW}再次尝试启动...${PLAIN}"
            systemctl restart fail2ban
            
            if systemctl is-active --quiet fail2ban; then
                 echo -e "${GREEN}Fail2ban 修复并启动成功！${PLAIN}"
            else
                 echo -e "${RED}启动仍然失败。尝试清理 Fail2ban 数据库并重试...${PLAIN}"
                 systemctl stop fail2ban
                 rm -f /var/lib/fail2ban/fail2ban.sqlite3
                 systemctl restart fail2ban
                 
                 if systemctl is-active --quiet fail2ban; then
                     echo -e "${GREEN}清理数据库后启动成功！${PLAIN}"
                 else
                     echo -e "${RED}最终启动失败。错误日志如下:${PLAIN}"
                     echo -e "--- /var/log/fail2ban.log (Last 20 lines) ---"
                     if [ -f /var/log/fail2ban.log ]; then
                         tail -n 20 /var/log/fail2ban.log
                     else
                         echo "日志文件不存在。"
                     fi
                     echo -e "-----------------------------------------------"
                 fi
            fi
        else
            echo -e "${RED}未进行修复。请手动检查: systemctl status fail2ban${PLAIN}"
        fi
    fi
    read -p "按回车键继续..."
}

# Fail2ban 使用说明
fail2ban_usage() {
    clear
    echo -e "${SKYBLUE}=== Fail2ban 使用说明 ===${PLAIN}"
    echo -e "Fail2ban 通过监控日志文件 (如 /var/log/auth.log) 来检测恶意行为。"
    echo -e "当检测到多次失败尝试时，会临时封禁 offending IP。"
    echo -e "配置模式: 本脚本已配置 [sshd] jail，并使用 UFW 进行封禁。"
    echo -e ""
    echo -e "${YELLOW}核心概念:${PLAIN}"
    echo -e "  - Jail: 监控特定服务规则的定义 (如 sshd)"
    echo -e "  - BanTime: 封禁时长 (默认 10m)"
    echo -e "  - FindTime: 统计时间窗口"
    echo -e "  - MaxRetry: 最大尝试次数"
    echo -e ""
    echo -e "${YELLOW}常用命令:${PLAIN}"
    echo -e "  check status:    fail2ban-client status sshd"
    echo -e "  手动封禁 IP:      fail2ban-client set sshd banip 1.2.3.4"
    echo -e "  手动解封 IP:      fail2ban-client set sshd unbanip 1.2.3.4"
    echo -e "  查看日志:        tail -f /var/log/fail2ban.log"
    echo -e "--------------------------------------------------------"
    read -p "按回车键返回..."
}

# Fail2ban 配置修改
fail2ban_config() {
    if [ ! -f "$FAIL2BAN_JAIL" ]; then
        echo -e "${RED}错误：配置文件 $FAIL2BAN_JAIL 不存在！请先安装。${PLAIN}"
        read -p "按回车键返回..."
        return
    fi

    echo -e "${SKYBLUE}=== 修改 Fail2ban 默认策略 (针对所有 jail) ===${PLAIN}"
    # 辅助函数: 获取当前配置值
    get_conf_value() {
        local k=$1
        local f=$2
        if [ ! -f "$f" ]; then echo ""; return; fi
        
        # 优化策略: 
        # 1. 尝试只读取 [DEFAULT] 区块的内容 (从 [DEFAULT] 开始，到下一个 [...] 结束)
        # 2. 如果文件里没有 [DEFAULT] (如 jail.local 只有 [sshd])，则直接全局 grep (回退)
        
        local val
        if grep -q "^\[DEFAULT\]" "$f"; then
             # 使用 sed 提取 [DEFAULT] 到下一个 section 之间的内容
             # 1. sed -n '/^\[DEFAULT\]/,/^\[/p' : 打印区间
             # 2. grep : 匹配 key = val
             val=$(sed -n '/^\[DEFAULT\]/,/^\[/p' "$f" | grep -E "^[[:space:]]*${k}[[:space:]]*=" | tail -n 1 | cut -d = -f 2- | tr -d '[:space:]')
        else
             # 没有 DEFAULT 块，尝试全局搜索 (主要针对简单配置)
             val=$(grep -E "^[[:space:]]*${k}[[:space:]]*=" "$f" | tail -n 1 | cut -d = -f 2- | tr -d '[:space:]')
        fi
        echo "$val"
    }

    # 读取当前值逻辑优化:
    # 1. 优先读取 jail.local
    # 2. 尝试 fail2ban-client (如果服务运行，这是最准确的)
    # 3. 最后尝试 jail.conf (仅 DEFAULT 区块)
    
    # 辅助: 读取并回退
    read_conf_with_fallback() {
        local key=$1
        local val
        
        # 1. Jail.local
        val=$(get_conf_value "$key" "$FAIL2BAN_JAIL")
        if [ -n "$val" ]; then echo "$val"; return; fi
        
        # 2. Fail2ban-client (Running)
        # 移除: fail2ban-client 无法查询 'DEFAULT' jail，导致报错。
        # 且我们修改的是文件 [DEFAULT] 段，读取文件更准确。
        
        # 3. Jail.conf Default
        val=$(get_conf_value "$key" "/etc/fail2ban/jail.conf")
        if [ -n "$val" ]; then
             echo "${val}(系统默认)"
             return
        fi
        
        echo ""
    }

    current_bantime=$(read_conf_with_fallback "bantime")
    current_findtime=$(read_conf_with_fallback "findtime")
    current_maxretry=$(read_conf_with_fallback "maxretry")
    
    # 设置显示默认值 (如果连 jail.conf 都没有，才显示未知)
    [ -z "$current_bantime" ] && current_bantime="未知(默认10m)"
    [ -z "$current_findtime" ] && current_findtime="未知(默认10m)"
    [ -z "$current_maxretry" ] && current_maxretry="未知(默认5)"

    echo -e "请输入新值覆盖默认设置。"
    echo -e "提示: 输入空值则保留当前值/默认值。"
    
    printf "封禁时长 (bantime) [当前: ${GREEN}${current_bantime}${PLAIN}]: "
    read -r new_bantime
    printf "检测窗口 (findtime) [当前: ${GREEN}${current_findtime}${PLAIN}]: "
    read -r new_findtime
    printf "最大尝试 (maxretry) [当前: ${GREEN}${current_maxretry}${PLAIN}]: "
    read -r new_maxretry
    
    # 检测是否有输入
    if [[ -z "$new_bantime" && -z "$new_findtime" && -z "$new_maxretry" ]]; then
        echo "未输入任何值，取消操作。"
        read -p "按回车键返回..."
        return
    fi

    echo -e "${YELLOW}正在备份原配置文件...${PLAIN}"
    cp "$FAIL2BAN_JAIL" "${FAIL2BAN_JAIL}.bak.$(date +%H%M%S)"
    echo -e "${YELLOW}正在更新配置...${PLAIN}"
    
    # 辅助函数: update_conf_key <key> <value> <file>
    update_conf_key() {
        local k=$1
        local v=$2
        local f=$3
        # 优先替换未注释的
        if grep -q "^${k}[[:space:]]*=" "$f"; then
            sed -i "s/^${k}[[:space:]]*=.*/${k} = ${v}/" "$f"
        # 其次替换注释掉的 (仅第一个)
        elif grep -q "^#[[:space:]]*${k}[[:space:]]*=" "$f"; then
            sed -i "0,/^#[[:space:]]*${k}[[:space:]]*=/s//${k} = ${v}/" "$f"
        else
            # 都不存在，追加到 [DEFAULT] 后
            if grep -q "^\[DEFAULT\]" "$f"; then
                sed -i "/^\[DEFAULT\]/a ${k} = ${v}" "$f"
            else
                # 连 [DEFAULT] 都没有 (罕见)，加文件头
                echo -e "[DEFAULT]\n${k} = ${v}" >> "$f"
            fi
        fi
    }
    
    [ -n "$new_bantime" ] && update_conf_key "bantime" "$new_bantime" "$FAIL2BAN_JAIL"
    [ -n "$new_findtime" ] && update_conf_key "findtime" "$new_findtime" "$FAIL2BAN_JAIL"
    [ -n "$new_maxretry" ] && update_conf_key "maxretry" "$new_maxretry" "$FAIL2BAN_JAIL"
    
    echo -e "${GREEN}配置已更新，重启服务生效中...${PLAIN}"
    systemctl restart fail2ban
    sleep 1
    if systemctl is-active --quiet fail2ban; then
        echo -e "${GREEN}Fail2ban 重启成功！${PLAIN}"
        fail2ban-client status
    else
        echo -e "${RED}Fail2ban 重启失败！${PLAIN}"
        echo -e "${YELLOW}错误日志 (最后 10 行):${PLAIN}"
        journalctl -u fail2ban --no-pager -n 10
        echo -e "${YELLOW}服务状态:${PLAIN}"
        systemctl status fail2ban --no-pager -n 5
        echo -e "${RED}建议: 检查输入的值是否合法，或手动检查 $FAIL2BAN_JAIL${PLAIN}"
    fi
    read -p "按回车键继续..."
}

# Fail2ban 常用操作
fail2ban_ops() {
    while true; do
        clear
        echo -e "========================="
        echo -e "    Fail2ban 操作菜单 (sshd)"
        echo -e "========================="
        
        # 顶部显示简要状态
        if systemctl is-active --quiet fail2ban; then
            echo -e "服务状态: ${GREEN}Active${PLAIN}"
            # 尝试显示 jail 简报
            echo -e "Jail 状态: $(fail2ban-client status sshd 2>/dev/null | grep 'Currently banned' | xargs)"
        else
            echo -e "服务状态: ${RED}Inactive${PLAIN}"
        fi
        echo -e "-------------------------"
    
        echo "1. 查看 Jail 详细状态 (Status)"
        echo "2. 手动封禁 IP (Ban IP)"
        echo "3. 手动解封 IP (Unban IP)"
        echo "4. 查看实时日志 (Tail Log)"
        echo "5. 重启服务 (Restart)"
        echo "-------------------------"
        echo "0. 返回上一级"
        echo ""
        read -p "选择: " op
        
        # 辅助: 检查服务运行状态
        check_f2b_running() {
            if ! systemctl is-active --quiet fail2ban; then
                echo -e "${RED}错误: Fail2ban 服务未运行，无法执行客户端操作。${PLAIN}"
                echo -e "${YELLOW}建议: 请尝试 (5) 重启服务 或 (4) 查看日志排查问题。${PLAIN}"
                read -p "按回车键继续..."
                return 1
            fi
            return 0
        }
        
        case "$op" in
            1) 
                check_f2b_running || continue
                fail2ban-client status sshd
                read -p "按回车键继续..."
                ;;
            2) 
                check_f2b_running || continue
                read -p "请输入要封禁的 IP: " ban_ip
                [ -n "$ban_ip" ] && fail2ban-client set sshd banip "$ban_ip"
                read -p "按回车键继续..."
                ;;
            3) 
                check_f2b_running || continue
                read -p "请输入要解封的 IP: " unban_ip
                [ -n "$unban_ip" ] && fail2ban-client set sshd unbanip "$unban_ip"
                read -p "按回车键继续..."
                ;;
            4)
                echo -e "${YELLOW}按 Ctrl+C 退出日志查看${PLAIN}"
                sleep 1
                # 捕获 SIGINT 避免退出脚本
                trap 'echo -e "\n${GREEN}已退出日志查看${PLAIN}";' SIGINT
                tail -f /var/log/fail2ban.log
                # 恢复默认 trap
                trap - SIGINT
                ;;
            5)
                echo -e "${YELLOW}正在重启 Fail2ban...${PLAIN}"
                systemctl restart fail2ban
                
                if systemctl is-active --quiet fail2ban; then
                     echo -e "${GREEN}服务已重启并运行正常。${PLAIN}"
                else
                     echo -e "${RED}重启失败！${PLAIN}"
                     echo -e "${YELLOW}错误日志:${PLAIN}"
                     journalctl -u fail2ban --no-pager -n 5
                fi
                read -p "按回车键继续..."
                ;;
            0) break ;;
            *) echo "无效选择"; sleep 1 ;;
        esac
    done
}

# Fail2ban 卸载
fail2ban_uninstall() {
    echo -e "${RED}警告：此操作将卸载 Fail2ban 及其配置！${PLAIN}"
    read -p "确认卸载? [y/N]: " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        systemctl stop fail2ban
        systemctl disable fail2ban
        apt-get remove --purge -y fail2ban
        rm -rf /etc/fail2ban
        # 清理 UFW 中的 fail2ban chain (通常 ufw reload 会自动清理无效的 chain reference，但保险起见手动清理一下最好，这里简化处理)
        ufw reload
        echo -e "${GREEN}Fail2ban 已卸载。${PLAIN}"
    else
        echo "已取消。"
    fi
    read -p "按回车键继续..."
}

# Fail2ban 菜单
fail2ban_menu() {
    while true; do
        clear
        echo -e "========================="
        echo -e "    Fail2ban 管理菜单"
        echo -e "========================="
        echo -e "1. 安装 Fail2ban (适配 UFW)"
        echo -e "2. 常用操作 (封禁/解封/状态)"
        echo -e "3. ⚙️ 修改默认策略 (bantime/maxretry)"
        echo -e "4. 📜 详细使用说明 (Help)"
        echo -e "5. 卸载 Fail2ban"
        echo -e "-------------------------"
        echo -e "0. 返回主菜单"
        echo -e ""
        read -p "请选择: " choice
        
        case "$choice" in
            1) fail2ban_install ;;
            2) fail2ban_ops ;;
            3) fail2ban_config ;;
            4) fail2ban_usage ;;
            5) fail2ban_uninstall ;;
            0) break ;;
            *) echo "无效选择" ;;
        esac
    done
}

# 主菜单
show_menu() {
    check_ufw
    
    while true; do
        clear
        echo -e "========================="
        echo -e "   UFW & Fail2ban Manager"
        echo -e "========================="
        echo -e "1. 🛡️ UFW 防火墙管理"
        echo -e "2. 👮 Fail2ban 入侵防护"
        echo -e "-------------------------"
        echo -e "0. 退出脚本"
        echo -e ""
        read -p "请选择 [0-2]: " num
        
        case "$num" in
            1) ufw_menu ;;
            2) fail2ban_menu ;;
            0) exit 0 ;;
            *) echo -e "${RED}请输入正确的数字${PLAIN}"; sleep 1 ;;
        esac
    done
}

# 执行
check_root
check_system
show_menu
