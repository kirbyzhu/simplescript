#!/bin/bash

#================================================
# Rinetd TCP转发 一键安装脚本
# 功能：自动安装配置rinetd，实现TCP端口转发
# 系统：Debian/Ubuntu
# 作者：AI Assistant
# 日期：2026-01-02
#================================================

#================== 全局变量配置 ==================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# 配置文件路径
RINETD_CONF="/etc/rinetd.conf"
RINETD_SERVICE="/etc/systemd/system/rinetd.service"
RINETD_BACKUP="/etc/rinetd.conf.backup"

#================== 日志输出模块 ==================

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_separator() {
    echo -e "${PURPLE}================================================${NC}"
}

#================== 系统检测模块 ==================

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此脚本必须以root权限运行！"
        print_info "请使用：sudo bash $0"
        exit 1
    fi
}

# 检测系统类型
check_system() {
    if ! command -v apt-get >/dev/null 2>&1; then
        print_error "本脚本仅适用于基于apt的Debian/Ubuntu系统"
        exit 1
    fi
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        print_success "系统信息: ${ID} ${VERSION_ID}"
    fi
}

#================== 安装模块 ==================

# 安装rinetd
install_rinetd() {
    print_separator
    print_info "开始安装rinetd..."
    print_separator
    
    check_root
    check_system
    
    # 更新软件源
    print_info "更新软件包列表..."
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get update -y; then
        print_error "apt-get update 失败！"
        return 1
    fi
    
    # 安装rinetd
    print_info "正在安装rinetd..."
    if ! apt-get install -y rinetd; then
        print_error "rinetd安装失败！"
        return 1
    fi
    
    # 停止可能存在的旧服务
    if systemctl list-unit-files | grep -q '^rinetd\.service'; then
        systemctl disable rinetd.service 2>/dev/null || true
        systemctl stop rinetd.service 2>/dev/null || true
    fi
    
    # 创建systemd服务文件
    print_info "正在配置systemd服务..."
    cat > ${RINETD_SERVICE} <<'EOF'
[Unit]
Description=Internet TCP redirection server (rinetd)
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/rinetd -f -c /etc/rinetd.conf
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    # 备份原配置文件
    if [[ -f ${RINETD_CONF} ]]; then
        cp ${RINETD_CONF} ${RINETD_BACKUP}
        print_info "已备份原配置文件到: ${RINETD_BACKUP}"
    fi
    
    # 创建默认配置文件
    if [[ ! -f ${RINETD_CONF} ]] || [[ ! -s ${RINETD_CONF} ]]; then
        print_info "创建默认配置文件..."
        cat > ${RINETD_CONF} <<'EOF'
# rinetd.conf - TCP端口转发配置文件
# 格式: <本地地址> <本地端口> <目标地址> <目标端口>
# 示例: 0.0.0.0 8080 192.168.1.100 80

# 请在下方添加转发规则
# bindaddress bindport connectaddress connectport

EOF
    fi
    
    # 重新加载systemd
    systemctl daemon-reload
    
    # 启动服务
    print_info "正在启动rinetd服务..."
    systemctl enable rinetd.service
    systemctl start rinetd.service
    
    sleep 2
    
    if systemctl is-active --quiet rinetd.service; then
        print_separator
        print_success "✅ rinetd安装完成！"
        print_separator
        print_info "配置文件位置: ${RINETD_CONF}"
        print_info "请编辑配置文件添加转发规则，然后重启服务"
        print_info "重启命令: systemctl restart rinetd"
    else
        print_error "服务启动失败！"
        print_info "查看日志: journalctl -u rinetd -n 50"
    fi
    
    print_separator
}

#================== 卸载模块 ==================

uninstall_rinetd() {
    print_separator
    print_warn "确定要卸载rinetd吗？"
    print_separator
    read -p "输入 yes 确认卸载: " confirm
    
    if [[ "${confirm}" != "yes" ]]; then
        print_info "已取消卸载"
        return
    fi
    
    print_info "正在卸载rinetd..."
    
    # 停止服务
    systemctl stop rinetd.service 2>/dev/null || true
    systemctl disable rinetd.service 2>/dev/null || true
    
    # 删除服务文件
    rm -f ${RINETD_SERVICE}
    systemctl daemon-reload
    
    # 卸载软件包
    print_info "正在卸载rinetd软件包..."
    apt-get remove -y rinetd
    apt-get autoremove -y
    
    # 询问是否删除配置文件
    print_separator
    read -p "是否删除配置文件？(y/n): " del_config
    if [[ "${del_config}" == "y" || "${del_config}" == "Y" ]]; then
        rm -f ${RINETD_CONF}
        rm -f ${RINETD_BACKUP}
        print_info "配置文件已删除"
    else
        print_info "配置文件已保留: ${RINETD_CONF}"
    fi
    
    print_separator
    print_success "✅ rinetd卸载完成！"
    print_separator
}

#================== 状态查看模块 ==================

show_status() {
    print_separator
    print_info "Rinetd 运行状态"
    print_separator
    
    echo -e "\n${CYAN}【服务状态】${NC}"
    if systemctl is-active --quiet rinetd.service; then
        print_success "rinetd服务: 运行中 ✓"
        echo "  进程PID: $(systemctl show rinetd.service -p MainPID --value)"
    else
        print_error "rinetd服务: 未运行 ✗"
        echo "  查看日志: journalctl -u rinetd -n 50"
    fi
    
    echo -e "\n${CYAN}【服务详情】${NC}"
    systemctl status rinetd.service --no-pager -l
    
    print_separator
}

#================== 配置管理模块 ==================

show_config() {
    print_separator
    print_info "Rinetd 配置信息"
    print_separator
    
    if [[ ! -f ${RINETD_CONF} ]]; then
        print_error "配置文件不存在！"
        return
    fi
    
    echo -e "\n${CYAN}【配置文件位置】${NC}"
    echo "  ${RINETD_CONF}"
    
    echo -e "\n${CYAN}【当前配置内容】${NC}"
    cat ${RINETD_CONF}
    
    echo -e "\n${CYAN}【配置格式说明】${NC}"
    echo "  格式: <本地地址> <本地端口> <目标地址> <目标端口>"
    echo "  示例: 0.0.0.0 8080 192.168.1.100 80"
    echo "  说明: 将本机8080端口转发到192.168.1.100的80端口"
    
    print_separator
}

edit_config() {
    print_separator
    print_info "编辑配置文件"
    print_separator
    
    if [[ ! -f ${RINETD_CONF} ]]; then
        print_error "配置文件不存在，请先安装rinetd！"
        return
    fi
    
    # 检测可用的编辑器
    if command -v nano &> /dev/null; then
        EDITOR="nano"
    elif command -v vim &> /dev/null; then
        EDITOR="vim"
    elif command -v vi &> /dev/null; then
        EDITOR="vi"
    else
        print_error "未找到可用的文本编辑器！"
        print_info "请手动编辑: ${RINETD_CONF}"
        return
    fi
    
    print_info "使用${EDITOR}编辑配置文件..."
    print_info "编辑完成后保存退出，然后重启服务使配置生效"
    
    sleep 2
    ${EDITOR} ${RINETD_CONF}
    
    print_separator
    read -p "是否现在重启rinetd服务使配置生效？(y/n): " restart
    if [[ "${restart}" == "y" || "${restart}" == "Y" ]]; then
        systemctl restart rinetd.service
        if systemctl is-active --quiet rinetd.service; then
            print_success "服务重启成功！"
        else
            print_error "服务重启失败，请检查配置文件"
            print_info "查看日志: journalctl -u rinetd -n 50"
        fi
    fi
}

add_forward_rule() {
    print_separator
    print_info "添加端口转发规则"
    print_separator
    
    if [[ ! -f ${RINETD_CONF} ]]; then
        print_error "配置文件不存在，请先安装rinetd！"
        return
    fi
    
    echo "请输入转发规则信息："
    read -p "本地监听地址 (如 0.0.0.0): " bind_addr
    read -p "本地监听端口 (如 8080): " bind_port
    read -p "目标服务器地址 (如 192.168.1.100): " target_addr
    read -p "目标服务器端口 (如 80): " target_port
    
    if [[ -z "${bind_addr}" || -z "${bind_port}" || -z "${target_addr}" || -z "${target_port}" ]]; then
        print_error "输入不完整，操作取消！"
        return
    fi
    
    # 添加规则到配置文件
    echo "${bind_addr} ${bind_port} ${target_addr} ${target_port}" >> ${RINETD_CONF}
    
    print_success "转发规则已添加："
    print_info "${bind_addr}:${bind_port} -> ${target_addr}:${target_port}"
    
    print_separator
    read -p "是否现在重启rinetd服务使配置生效？(y/n): " restart
    if [[ "${restart}" == "y" || "${restart}" == "Y" ]]; then
        systemctl restart rinetd.service
        if systemctl is-active --quiet rinetd.service; then
            print_success "服务重启成功，转发规则已生效！"
        else
            print_error "服务重启失败，请检查配置"
        fi
    fi
}

#================== 主菜单模块 ==================

show_menu() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
╔════════════════════════════════════════════╗
║      Rinetd TCP转发 一键管理脚本          ║
║                                            ║
║            端口转发/流量中转               ║
╚════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    echo -e "${CYAN}请选择操作：${NC}"
    echo ""
    echo -e "  ${GREEN}1.${NC} 安装 rinetd"
    echo -e "  ${GREEN}2.${NC} 卸载 rinetd"
    echo -e "  ${GREEN}3.${NC} 查看运行状态"
    echo -e "  ${GREEN}4.${NC} 查看配置信息"
    echo -e "  ${GREEN}5.${NC} 编辑配置文件"
    echo -e "  ${GREEN}6.${NC} 添加转发规则（快捷方式）"
    echo -e "  ${GREEN}7.${NC} 重启服务"
    echo -e "  ${RED}0.${NC} 退出脚本"
    echo ""
    echo -e "${PURPLE}================================================${NC}"
    echo ""
}

main() {
    check_root
    
    while true; do
        show_menu
        read -p "请输入选项 [0-7]: " choice
        
        case ${choice} in
            1)
                install_rinetd
                read -p "按回车键继续..." 
                ;;
            2)
                uninstall_rinetd
                read -p "按回车键继续..."
                ;;
            3)
                show_status
                read -p "按回车键继续..."
                ;;
            4)
                show_config
                read -p "按回车键继续..."
                ;;
            5)
                edit_config
                read -p "按回车键继续..."
                ;;
            6)
                add_forward_rule
                read -p "按回车键继续..."
                ;;
            7)
                print_info "正在重启rinetd服务..."
                systemctl restart rinetd.service
                if systemctl is-active --quiet rinetd.service; then
                    print_success "服务重启成功！"
                else
                    print_error "服务重启失败！"
                fi
                read -p "按回车键继续..."
                ;;
            0)
                print_info "感谢使用，再见！"
                exit 0
                ;;
            *)
                print_error "无效的选项，请重新选择！"
                sleep 2
                ;;
        esac
    done
}

# 启动主程序
main
