#!/bin/bash

#================== Hysteria2 落地机自动部署脚本 ==================
# 作者: Linux 网络工程师
# 用途: 自动部署基于 Sing-box 的 Hysteria2 接收端节点
# 系统: Ubuntu/Debian
#================================================================

set -e  # 遇到错误立即退出

#================== 全局变量 ==================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置目录
SING_BOX_DIR="/etc/sing-box"
CERT_DIR="/etc/sing-box/certs"
CONFIG_FILE="${SING_BOX_DIR}/config.json"
SERVICE_FILE="/etc/systemd/system/sing-box.service"

# 用户输入变量（稍后交互式获取）
DOMAIN=""
LISTEN_PORT=""
PASSWORD=""
CERT_EMAIL=""
TLS_ENABLED=""  # 是否启用 TLS

#================== 工具函数 ==================

# 打印信息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# 打印成功
print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# 打印警告
print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# 打印错误
print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 打印分隔线
print_separator() {
    echo "================================================"
}

# 检查是否为 root 用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此脚本必须以 root 权限运行！"
        exit 1
    fi
}

# 检查系统类型
check_system() {
    if [[ -f /etc/debian_version ]]; then
        print_success "检测到 Debian/Ubuntu 系统"
    else
        print_error "此脚本仅支持 Debian/Ubuntu 系统！"
        exit 1
    fi
}

#================== 环境准备模块 ==================

# 安装基础依赖
install_dependencies() {
    print_info "正在安装基础依赖..."
    
    # 临时禁用 set -e
    set +e
    
    # 更新包列表
    print_info "更新软件包列表..."
    apt-get update -qq 2>&1 | grep -v "bullseye-backports" | grep -v "^$" || true
    
    # 先尝试修复损坏的依赖
    apt-get install -f -y > /dev/null 2>&1 || true
    
    # 核心依赖（不包含 curl，避免 libzstd1 冲突）
    print_info "安装核心软件包..."
    local core_packages="wget jq openssl socat"
    
    for pkg in $core_packages; do
        apt-get install -y $pkg > /dev/null 2>&1 || {
            print_warn "使用 apt 重试安装 $pkg..."
            apt install -y $pkg > /dev/null 2>&1 || true
        }
    done
    
    # 检查 curl 是否已安装
    if ! command -v curl &> /dev/null; then
        print_info "尝试安装 curl（可选）..."
        # 尝试安装 curl，但不强制要求成功
        apt-get install -y curl > /dev/null 2>&1 || {
            print_warn "curl 安装失败（libzstd1 冲突），将使用 wget 替代"
            print_info "创建 curl 替代函数..."
            # 创建一个简单的 curl 替代脚本
            cat > /usr/local/bin/curl-wrapper.sh << 'EOF'
#!/bin/bash
# curl 替代脚本，使用 wget
if [[ "$1" == "-s" ]]; then
    shift
    wget -qO- "$@"
elif [[ "$1" == "-fsSL" ]]; then
    shift
    wget -qO- "$@"
else
    wget -qO- "$@"
fi
EOF
            chmod +x /usr/local/bin/curl-wrapper.sh
            # 创建 curl 别名
            if ! grep -q "alias curl=" ~/.bashrc 2>/dev/null; then
                echo "alias curl='/usr/local/bin/curl-wrapper.sh'" >> ~/.bashrc
            fi
        }
    else
        print_success "curl 已可用"
    fi
    
    set -e
    print_success "基础依赖安装完成"
}

#================== 证书管理模块 ==================

# 安装 acme.sh
install_acme() {
    print_info "正在安装 acme.sh..."
    
    if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
        print_info "acme.sh 已安装，跳过"
        return 0
    fi
    
    # 使用 wget 或 curl 下载
    if command -v curl &> /dev/null; then
        curl -s https://get.acme.sh | sh -s email=${CERT_EMAIL} > /dev/null 2>&1
    else
        wget -qO- https://get.acme.sh | sh -s email=${CERT_EMAIL} > /dev/null 2>&1
    fi
    
    # 设置环境变量
    source ~/.bashrc 2>/dev/null || true
    
    print_success "acme.sh 安装完成"
}

# 申请 SSL 证书
request_certificate() {
    print_info "正在检查 SSL 证书..."
    
    # 创建证书目录
    mkdir -p ${CERT_DIR}
    
    # 检查是否已有有效证书
    if [[ -f "${CERT_DIR}/private.key" ]] && [[ -f "${CERT_DIR}/cert.pem" ]]; then
        print_info "检测到已存在证书文件"
        
        # 检查证书是否有效
        if openssl x509 -in ${CERT_DIR}/cert.pem -noout -checkend 2592000 2>/dev/null; then
            # 证书在未来 30 天内有效
            local cert_domain=$(openssl x509 -in ${CERT_DIR}/cert.pem -noout -subject 2>/dev/null | grep -oP 'CN\s*=\s*\K[^,]+')
            local expiry_date=$(openssl x509 -in ${CERT_DIR}/cert.pem -noout -enddate 2>/dev/null | cut -d= -f2)
            
            print_success "发现有效证书："
            print_info "  域名: ${cert_domain}"
            print_info "  过期时间: ${expiry_date}"
            
            # 检查域名是否匹配
            if [[ "${cert_domain}" == "${DOMAIN}" ]]; then
                echo ""
                read -p "是否使用现有证书？(Y/n): " use_existing
                use_existing=${use_existing:-y}
                
                if [[ "${use_existing}" == "y" || "${use_existing}" == "Y" ]]; then
                    print_success "使用现有证书"
                    return 0
                else
                    print_info "将申请新证书"
                fi
            else
                print_warn "证书域名不匹配（证书: ${cert_domain}, 需要: ${DOMAIN}）"
                print_info "将申请新证书"
            fi
        else
            print_warn "现有证书即将过期或已过期"
            print_info "将申请新证书"
        fi
    fi
    
    # 申请新证书
    print_info "正在申请 SSL 证书（域名: ${DOMAIN}）..."
    
    # 先停止可能占用 80 端口的服务
    systemctl stop sing-box 2>/dev/null || true
    
    # 申请证书
    ~/.acme.sh/acme.sh --issue \
        --standalone \
        -d ${DOMAIN} \
        --keylength ec-256 \
        --force 2>&1 | grep -E "(Success|error)" || true
    
    # 安装证书到指定目录
    ~/.acme.sh/acme.sh --install-cert \
        -d ${DOMAIN} \
        --ecc \
        --key-file ${CERT_DIR}/private.key \
        --fullchain-file ${CERT_DIR}/cert.pem \
        --reloadcmd "systemctl reload sing-box 2>/dev/null || true" \
        > /dev/null 2>&1
    
    # 设置权限
    chmod 600 ${CERT_DIR}/private.key
    chmod 644 ${CERT_DIR}/cert.pem
    
    # 验证证书文件
    if [[ -f "${CERT_DIR}/private.key" ]] && [[ -f "${CERT_DIR}/cert.pem" ]]; then
        print_success "SSL 证书申请成功"
        print_info "证书路径: ${CERT_DIR}"
    else
        print_error "证书申请失败！"
        print_info "请检查："
        print_info "1. 域名 ${DOMAIN} 是否正确解析到本服务器"
        print_info "2. 80 端口是否被占用"
        print_info "3. 防火墙是否开放 80 端口"
        exit 1
    fi
}

# 设置证书自动续期
setup_cert_renewal() {
    print_info "正在配置证书自动续期..."
    
    # acme.sh 安装时会自动添加 cron，这里只是验证
    if crontab -l 2>/dev/null | grep -q "acme.sh"; then
        print_success "证书自动续期已配置"
    else
        print_warn "未检测到自动续期 cron，请手动检查"
    fi
}

#================== Sing-box 安装模块 ==================

# 安装 Sing-box
install_singbox() {
    print_info "正在安装 Sing-box..."
    
    # 检查是否已安装
    if command -v sing-box &> /dev/null; then
        local version=$(sing-box version 2>&1 | head -1)
        print_info "Sing-box 已安装: ${version}"
        read -p "是否重新安装最新版本？(y/N): " reinstall
        if [[ "${reinstall}" != "y" && "${reinstall}" != "Y" ]]; then
            return 0
        fi
    fi
    
    # 使用官方安装脚本
    bash <(curl -fsSL https://sing-box.app/install.sh) > /dev/null 2>&1
    
    # 验证安装
    if command -v sing-box &> /dev/null; then
        local version=$(sing-box version 2>&1 | head -1)
        print_success "Sing-box 安装成功: ${version}"
    else
        print_error "Sing-box 安装失败！"
        exit 1
    fi
}

#================== 配置生成模块 ==================

# 生成 Sing-box 配置文件
generate_config() {
    print_info "正在生成 Sing-box 配置..."
    
    # 创建配置目录
    mkdir -p ${SING_BOX_DIR}
    
    # 根据是否启用 TLS 生成不同配置
    if [[ "${TLS_ENABLED}" == "true" ]]; then
        # 启用 TLS 的配置
        cat > ${CONFIG_FILE} <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hysteria-in",
      "listen": "::",
      "listen_port": ${LISTEN_PORT},
      "users": [
        {
          "password": "${PASSWORD}"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${DOMAIN}",
        "key_path": "${CERT_DIR}/private.key",
        "certificate_path": "${CERT_DIR}/cert.pem"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]
}
EOF
    else
        # 不启用 TLS 的配置
        cat > ${CONFIG_FILE} <<EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hysteria-in",
      "listen": "::",
      "listen_port": ${LISTEN_PORT},
      "users": [
        {
          "password": "${PASSWORD}"
        }
      ]
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]
}
EOF
    fi
    
    # 设置权限
    chmod 600 ${CONFIG_FILE}
    
    print_success "配置文件生成完成: ${CONFIG_FILE}"
}

# 验证配置文件
validate_config() {
    print_info "正在验证配置文件..."
    
    if sing-box check -c ${CONFIG_FILE} > /dev/null 2>&1; then
        print_success "配置文件验证通过"
    else
        print_error "配置文件验证失败！"
        sing-box check -c ${CONFIG_FILE}
        exit 1
    fi
}

#================== 服务管理模块 ==================

# 创建 systemd 服务
create_service() {
    print_info "正在创建 systemd 服务..."
    
    # 自动检测 sing-box 路径
    local singbox_path=$(command -v sing-box)
    if [[ -z "${singbox_path}" ]]; then
        print_error "无法找到 sing-box 可执行文件！"
        exit 1
    fi
    print_info "检测到 sing-box 路径: ${singbox_path}"
    
    cat > ${SERVICE_FILE} <<EOF
[Unit]
Description=Sing-box Service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
ExecStart=${singbox_path} run -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=5s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    print_success "systemd 服务文件创建完成"
}

# 启动服务
start_service() {
    print_info "正在启动 Sing-box 服务..."
    
    # 重载 systemd
    systemctl daemon-reload
    
    # 启用开机自启
    systemctl enable sing-box > /dev/null 2>&1
    
    # 启动服务
    systemctl restart sing-box
    
    # 等待服务启动
    sleep 2
    
    # 检查服务状态
    if systemctl is-active --quiet sing-box; then
        print_success "Sing-box 服务启动成功"
    else
        print_error "Sing-box 服务启动失败！"
        print_info "查看日志: journalctl -u sing-box -n 50"
        systemctl status sing-box --no-pager
        exit 1
    fi
}

#================== 交互式输入模块 ==================

# 获取用户输入
get_user_input() {
    print_separator
    echo -e "${GREEN}Hysteria2 落地机配置${NC}"
    print_separator
    
    # 询问是否启用 TLS
    echo ""
    echo -e "${YELLOW}TLS 配置说明：${NC}"
    echo "1. 启用 TLS（推荐）："
    echo "   - 需要域名和证书"
    echo "   - 更安全，流量加密"
    echo "   - 适合公网暴露的服务器"
    echo ""
    echo "2. 不启用 TLS（简化部署）："
    echo "   - 不需要域名，只需 IP"
    echo "   - 部署简单快速"
    echo "   - 适合内网或中转场景"
    echo ""
    
    while true; do
        read -p "是否启用 TLS？(y/N): " enable_tls
        enable_tls=${enable_tls:-n}
        
        if [[ "${enable_tls}" == "y" || "${enable_tls}" == "Y" ]]; then
            TLS_ENABLED="true"
            break
        elif [[ "${enable_tls}" == "n" || "${enable_tls}" == "N" ]]; then
            TLS_ENABLED="false"
            break
        else
            print_error "请输入 y 或 n"
        fi
    done
    
    # 如果启用 TLS，需要输入域名
    if [[ "${TLS_ENABLED}" == "true" ]]; then
        while true; do
            read -p "请输入域名（例如: landing.example.com）: " DOMAIN
            if [[ -z "${DOMAIN}" ]]; then
                print_error "域名不能为空！"
                continue
            fi
            
            # 简单验证域名格式
            if [[ ! "${DOMAIN}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
                print_error "域名格式不正确！"
                continue
            fi
            
            break
        done
        
        # 生成随机邮箱
        CERT_EMAIL="admin-$(date +%s)@${DOMAIN}"
        print_info "证书邮箱: ${CERT_EMAIL}"
    else
        print_info "TLS 已禁用，无需域名和证书"
    fi
    
    # 输入监听端口
    while true; do
        read -p "请输入监听端口（默认 50000）: " LISTEN_PORT
        LISTEN_PORT=${LISTEN_PORT:-50000}
        
        if [[ ! "${LISTEN_PORT}" =~ ^[0-9]+$ ]]; then
            print_error "端口必须是数字！"
            continue
        fi
        
        if [[ ${LISTEN_PORT} -lt 1 || ${LISTEN_PORT} -gt 65535 ]]; then
            print_error "端口范围必须在 1-65535 之间！"
            continue
        fi
        
        break
    done
    
    # 输入密码
    echo ""
    read -p "是否自动生成连接密码？(Y/n): " auto_gen_pwd
    auto_gen_pwd=${auto_gen_pwd:-y}
    
    if [[ "${auto_gen_pwd}" == "y" || "${auto_gen_pwd}" == "Y" ]]; then
        # 自动生成 16 位随机密码
        PASSWORD=$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)
        print_success "已自动生成密码: ${PASSWORD}"
    else
        while true; do
            read -p "请输入连接密码（至少 8 个字符）: " PASSWORD
            if [[ ${#PASSWORD} -lt 8 ]]; then
                print_error "密码长度至少 8 个字符！"
                continue
            fi
            break
        done
    fi
    
    # 确认配置
    echo ""
    print_separator
    echo -e "${YELLOW}请确认以下配置：${NC}"
    print_separator
    echo "TLS: ${TLS_ENABLED}"
    if [[ "${TLS_ENABLED}" == "true" ]]; then
        echo "域名: ${DOMAIN}"
        echo "证书邮箱: ${CERT_EMAIL}"
    fi
    echo "监听端口: ${LISTEN_PORT} (UDP)"
    echo "密码: ${PASSWORD}"
    print_separator
    
    read -p "确认无误？(y/N): " confirm
    if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
        print_info "已取消部署"
        exit 0
    fi
}

#================== 信息输出模块 ==================

# 显示连接信息
show_connection_info() {
    print_separator
    echo -e "${GREEN}✅ Hysteria2 落地机部署完成！${NC}"
    print_separator
    
    # 获取服务器 IP
    local server_ip=$(curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null || echo "无法获取")
    
    echo ""
    echo -e "${BLUE}=== 连接信息 ===${NC}"
    echo "服务器 IP: ${server_ip}"
    
    if [[ "${TLS_ENABLED}" == "true" ]]; then
        echo "域名: ${DOMAIN}"
        echo "TLS: 已启用"
    else
        echo "TLS: 未启用"
    fi
    
    echo "端口: ${LISTEN_PORT} (UDP)"
    echo "密码: ${PASSWORD}"
    echo "协议: Hysteria2"
    echo ""
    
    if [[ "${TLS_ENABLED}" == "true" ]]; then
        echo -e "${BLUE}=== 证书信息 ===${NC}"
        echo "证书路径: ${CERT_DIR}/cert.pem"
        echo "私钥路径: ${CERT_DIR}/private.key"
        echo "自动续期: 已启用"
        echo ""
    fi
    
    echo -e "${BLUE}=== 服务管理 ===${NC}"
    echo "查看状态: systemctl status sing-box"
    echo "查看日志: journalctl -u sing-box -f"
    echo "重启服务: systemctl restart sing-box"
    echo "停止服务: systemctl stop sing-box"
    echo ""
    
    echo -e "${BLUE}=== 配置文件 ===${NC}"
    echo "配置文件: ${CONFIG_FILE}"
    echo "服务文件: ${SERVICE_FILE}"
    echo ""
    
    echo -e "${BLUE}=== 客户端配置示例 ===${NC}"
    if [[ "${TLS_ENABLED}" == "true" ]]; then
        echo "服务器: ${DOMAIN}"
    else
        echo "服务器: ${server_ip}"
    fi
    echo "端口: ${LISTEN_PORT}"
    echo "密码: ${PASSWORD}"
    echo "协议: Hysteria2"
    if [[ "${TLS_ENABLED}" == "true" ]]; then
        echo "TLS: 启用"
        echo "SNI: ${DOMAIN}"
    else
        echo "TLS: 禁用"
    fi
    echo ""
    
    print_separator
    print_success "部署完成！请使用以上信息配置客户端"
    print_separator
    
    # 保存连接信息到文件
    cat > ${SING_BOX_DIR}/connection_info.txt <<EOF
Hysteria2 连接信息
================
服务器 IP: ${server_ip}
$(if [[ "${TLS_ENABLED}" == "true" ]]; then echo "域名: ${DOMAIN}"; echo "TLS: 已启用"; else echo "TLS: 未启用"; fi)
端口: ${LISTEN_PORT} (UDP)
密码: ${PASSWORD}
协议: Hysteria2

$(if [[ "${TLS_ENABLED}" == "true" ]]; then echo "证书信息:"; echo "证书路径: ${CERT_DIR}/cert.pem"; echo "私钥路径: ${CERT_DIR}/private.key"; echo "自动续期: 已启用"; fi)

服务管理:
查看状态: systemctl status sing-box
查看日志: journalctl -u sing-box -f
重启服务: systemctl restart sing-box
EOF
    
    chmod 600 ${SING_BOX_DIR}/connection_info.txt
    print_info "连接信息已保存到: ${SING_BOX_DIR}/connection_info.txt"
}

#================== 辅助功能模块 ==================

view_connection_info() {
    if [[ -f ${SING_BOX_DIR}/connection_info.txt ]]; then
        cat ${SING_BOX_DIR}/connection_info.txt
    else
        print_error "未找到连接信息文件"
        print_info "请先完成部署"
    fi
}

restart_services() {
    print_info "正在重启 Sing-box 服务..."
    systemctl restart sing-box
    sleep 2
    
    if systemctl is-active --quiet sing-box; then
        print_success "服务重启成功"
    else
        print_error "服务重启失败，请检查日志"
    fi
}

view_logs() {
    echo -e "${BLUE}=== Sing-box 日志（最后 50 行）===${NC}"
    journalctl -u sing-box -n 50 --no-pager
}

#================== 卸载模块 ==================

uninstall_all() {
    print_separator
    print_warn "⚠️  确定要卸载 Hysteria2 落地机吗？"
    print_warn "这将删除所有配置、证书和服务"
    print_separator
    read -p "输入 yes 确认卸载: " confirm
    
    if [[ "${confirm}" != "yes" ]]; then
        print_info "已取消卸载"
        return
    fi
    
    print_info "正在卸载..."
    
    # 停止并禁用服务
    systemctl stop sing-box 2>/dev/null || true
    systemctl disable sing-box 2>/dev/null || true
    
    # 删除服务文件
    rm -f ${SERVICE_FILE}
    systemctl daemon-reload
    
    # 卸载 Sing-box
    if command -v sing-box &> /dev/null; then
        print_info "卸载 Sing-box..."
        bash <(curl -fsSL https://sing-box.app/install.sh) uninstall 2>/dev/null || true
    fi
    
    # 删除配置目录
    if [[ -d "${SING_BOX_DIR}" ]]; then
        print_info "删除配置目录..."
        rm -rf ${SING_BOX_DIR}
    fi
    
    # 删除证书（如果使用了 acme.sh）
    if [[ -f "$HOME/.acme.sh/acme.sh" ]]; then
        print_info "删除证书..."
        # 尝试读取域名（如果配置文件还存在）
        if [[ -f "${CONFIG_FILE}" ]]; then
            local domain=$(grep -oP '"server_name":\s*"\K[^"]+' ${CONFIG_FILE} 2>/dev/null | head -1)
            if [[ -n "${domain}" ]]; then
                ~/.acme.sh/acme.sh --remove -d ${domain} --ecc 2>/dev/null || true
            fi
        fi
        
        # 删除 cron 任务
        crontab -l 2>/dev/null | grep -v "acme.sh" | crontab - 2>/dev/null || true
    fi
    
    print_separator
    print_success "✅ 卸载完成！"
    print_separator
    
    echo ""
    print_info "已删除："
    print_info "  - Sing-box 程序"
    print_info "  - 配置文件 (${SING_BOX_DIR})"
    print_info "  - Systemd 服务"
    print_info "  - SSL 证书"
    print_info "  - Cron 任务"
    echo ""
}

#================== 主流程 ==================

show_menu() {
    clear
    print_separator
    echo -e "${GREEN}Hysteria2 落地机管理脚本${NC}"
    echo -e "${BLUE}基于 Sing-box${NC}"
    print_separator
    echo "1. 安装 Hysteria2 落地机"
    echo "2. 卸载 Hysteria2 落地机"
    echo "3. 查看连接信息"
    echo "4. 重启服务"
    echo "5. 查看日志"
    echo "0. 退出"
    print_separator
}

main() {
    while true; do
        show_menu
        read -p "请选择操作 [0-5]: " choice
        
        case $choice in
            1)
                install_landing
                read -p "按回车键继续..."
                ;;
            2)
                check_root
                uninstall_all
                read -p "按回车键继续..."
                ;;
            3)
                view_connection_info
                read -p "按回车键继续..."
                ;;
            4)
                check_root
                restart_services
                read -p "按回车键继续..."
                ;;
            5)
                view_logs
                read -p "按回车键继续..."
                ;;
            0)
                print_info "退出脚本"
                exit 0
                ;;
            *)
                print_error "无效选择"
                sleep 2
                ;;
        esac
    done
}

install_landing() {
    clear
    print_separator
    echo -e "${GREEN}开始安装 Hysteria2 落地机${NC}"
    print_separator
    echo ""
    
    # 检查权限和系统
    check_root
    check_system
    
    # 获取用户输入
    get_user_input
    
    echo ""
    print_info "开始部署..."
    echo ""
    
    # 1. 环境准备
    install_dependencies
    
    # 2. 安装 Sing-box
    install_singbox
    
    # 3. 证书管理（仅在启用 TLS 时）
    if [[ "${TLS_ENABLED}" == "true" ]]; then
        install_acme
        request_certificate
        setup_cert_renewal
    else
        print_info "TLS 已禁用，跳过证书申请"
    fi
    
    # 4. 生成配置
    generate_config
    validate_config
    
    # 5. 服务管理
    create_service
    start_service
    
    # 6. 显示连接信息
    echo ""
    show_connection_info
    
    # 提醒配置防火墙
    echo ""
    print_separator
    print_warn "⚠️  请手动配置防火墙开放以下端口："
    if [[ "${TLS_ENABLED}" == "true" ]]; then
        print_info "  - TCP 80 (证书申请/续期)"
    fi
    print_info "  - UDP ${LISTEN_PORT} (Hysteria2)"
    echo ""
    print_info "UFW 示例:"
    if [[ "${TLS_ENABLED}" == "true" ]]; then
        echo "  ufw allow 80/tcp"
    fi
    echo "  ufw allow ${LISTEN_PORT}/udp"
    print_separator
}

# 执行主流程
main
