#!/bin/bash

#================================================
# Sing-box VLESS 一键安装脚本
# 功能：自动安装配置sing-box + caddy，实现vless代理
# 证书：Let's Encrypt自动证书
# 作者：AI Assistant
# 日期：2026-01-04
#================================================

#================== 全局变量配置 ==================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 安装路径配置
CADDY_DIR="/usr/local/caddy"
WEB_DIR="/var/www/singbox"
CONFIG_DIR="/etc/singbox-vless"

# 配置文件路径
SINGBOX_CONFIG="${CONFIG_DIR}/singbox_config.json"
CADDY_CONFIG="${CONFIG_DIR}/Caddyfile"
INFO_FILE="${CONFIG_DIR}/info.conf"

# 服务文件路径
SINGBOX_SERVICE="/etc/systemd/system/singbox-vless.service"
CADDY_SERVICE="/etc/systemd/system/caddy-singbox.service"

# Sing-box配置
SINGBOX_PORT=10000  # sing-box监听的本地端口

#================== 日志输出模块 ==================

# 打印信息日志
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# 打印成功日志
print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# 打印警告日志
print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# 打印错误日志
print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 打印分隔线
print_separator() {
    echo -e "${PURPLE}================================================${NC}"
}

#================== 系统检测模块 ==================

# 检查是否为root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此脚本必须以root权限运行！"
        print_info "请使用：sudo bash $0"
        exit 1
    fi
}

# 检测系统类型和架构
check_system() {
    print_info "正在检测系统信息..."
    
    # 检测操作系统
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        print_error "无法检测操作系统类型！"
        print_info "此脚本仅支持 Debian 10+ 或 Ubuntu 22+ 系统"
        exit 1
    fi
    
    # 验证系统类型和版本
    case ${OS} in
        debian)
            MAJOR_VERSION=$(echo ${OS_VERSION} | cut -d. -f1)
            if [[ ${MAJOR_VERSION} -lt 10 ]]; then
                print_warn "检测到 Debian ${OS_VERSION}，建议使用 Debian 10 或更高版本"
            fi
            ;;
        ubuntu)
            MAJOR_VERSION=$(echo ${OS_VERSION} | cut -d. -f1)
            if [[ ${MAJOR_VERSION} -lt 22 ]]; then
                print_warn "检测到 Ubuntu ${OS_VERSION}，建议使用 Ubuntu 22.04 或更高版本"
            fi
            ;;
        centos|rhel|fedora)
            print_warn "检测到 ${OS} 系统，此脚本主要针对 Debian/Ubuntu 优化"
            ;;
        *)
            print_error "不支持的操作系统: ${OS}"
            print_info "此脚本仅支持 Debian 10+ 或 Ubuntu 22+ 系统"
            exit 1
            ;;
    esac
    
    # 检测系统架构
    ARCH=$(uname -m)
    case ${ARCH} in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="armv7"
            ;;
        *)
            print_error "不支持的系统架构: ${ARCH}"
            exit 1
            ;;
    esac
    
    print_success "系统信息: ${OS} ${OS_VERSION} (${ARCH})"
}

# 安装系统依赖
install_dependencies() {
    print_info "正在安装必要的系统依赖..."
    
    case ${OS} in
        ubuntu|debian)
            print_info "更新软件包列表..."
            apt-get update -y || {
                print_error "apt-get update 失败！"
                print_info "解决方法："
                print_info "1. 检查网络连接"
                print_info "2. 检查 /etc/apt/sources.list 配置"
                return 1
            }
            
            print_info "安装依赖包..."
            apt-get install -y curl wget tar jq net-tools ca-certificates || {
                print_error "依赖包安装失败！"
                return 1
            }
            ;;
        centos|rhel|fedora)
            yum install -y curl wget tar jq net-tools ca-certificates || {
                print_error "依赖包安装失败！"
                return 1
            }
            ;;
    esac
    
    # 验证关键命令
    for cmd in curl wget tar; do
        if ! command -v ${cmd} &> /dev/null; then
            print_error "命令 ${cmd} 不可用！"
            return 1
        fi
    done
    
    print_success "系统依赖安装完成"
}

#================== 配置生成模块 ==================

# 生成UUID
generate_uuid() {
    if command -v uuidgen &> /dev/null; then
        uuidgen | tr 'A-Z' 'a-z'
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

# 生成6位随机路径
generate_random_path() {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 6 | head -n 1
}

# 读取并验证域名
read_domain() {
    print_separator
    print_info "请输入您的域名（必须已解析到本服务器IP）："
    read -p "域名: " DOMAIN
    
    if [[ -z "${DOMAIN}" ]]; then
        print_error "域名不能为空！"
        return 1
    fi
    
    # 获取服务器公网IP
    SERVER_IP=$(curl -s --max-time 10 https://api.ipify.org)
    if [[ -z "${SERVER_IP}" ]]; then
        SERVER_IP=$(curl -s --max-time 10 http://checkip.amazonaws.com)
    fi
    
    if [[ -z "${SERVER_IP}" ]]; then
        print_warn "无法获取服务器公网IP，跳过域名验证"
        print_warn "请确保域名 ${DOMAIN} 已解析到本服务器！"
    else
        print_info "服务器公网IP: ${SERVER_IP}"
        print_info "正在验证域名解析..."
        
        DOMAIN_IP=$(dig +short ${DOMAIN} 2>/dev/null | head -n1)
        if [[ -z "${DOMAIN_IP}" ]]; then
            DOMAIN_IP=$(nslookup ${DOMAIN} 2>/dev/null | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' | head -n1)
        fi
        
        if [[ -z "${DOMAIN_IP}" ]]; then
            print_error "无法解析域名 ${DOMAIN}！"
            print_info "解决方法："
            print_info "1. 确保域名DNS已配置A记录指向 ${SERVER_IP}"
            print_info "2. 等待DNS生效（可能需要几分钟到几小时）"
            return 1
        fi
        
        if [[ "${DOMAIN_IP}" != "${SERVER_IP}" ]]; then
            print_error "域名解析IP (${DOMAIN_IP}) 与服务器IP (${SERVER_IP}) 不匹配！"
            print_info "解决方法："
            print_info "1. 检查域名DNS A记录是否正确指向 ${SERVER_IP}"
            print_info "2. 等待DNS更新生效"
            return 1
        fi
        
        print_success "域名验证通过: ${DOMAIN} -> ${SERVER_IP}"
    fi
    
    return 0
}

# 读取Hysteria2中转配置（可选）
read_hysteria2_outbound() {
    print_separator
    print_info "配置 Hysteria2 中转出站（可选）"
    print_info "流量流向: 客户端 -> VLESS+WS -> Sing-box -> Hysteria2 -> 远程节点"
    print_separator
    
    read -p "是否开启 Hysteria2 中转转发？(y/n, 默认n): " ENABLE_HY2
    if [[ "${ENABLE_HY2}" != "y" ]]; then
        HY2_ENABLED="false"
        print_info "将使用直连模式（不启用中转）"
        return 0
    fi
    
    HY2_ENABLED="true"
    read -p "请输入远程 Hysteria2 服务器地址 (IP/域名): " HY2_ADDR
    while [[ -z "${HY2_ADDR}" ]]; do
        print_error "地址不能为空！"
        read -p "请输入远程 Hysteria2 服务器地址: " HY2_ADDR
    done
    
    read -p "请输入远程 Hysteria2 端口: " HY2_PORT
    while [[ -z "${HY2_PORT}" ]] || [[ ! "${HY2_PORT}" =~ ^[0-9]+$ ]] || [[ "${HY2_PORT}" -lt 1 ]] || [[ "${HY2_PORT}" -gt 65535 ]]; do
        print_error "端口必须为 1-65535 之间的数字！"
        read -p "请输入远程 Hysteria2 端口: " HY2_PORT
    done
    
    read -p "请输入 Hysteria2 密码: " HY2_PASS
    while [[ -z "${HY2_PASS}" ]]; do
        print_error "密码不能为空！"
        read -p "请输入 Hysteria2 密码: " HY2_PASS
    done
    
    read -p "请输入 SNI (可选, 默认为服务器地址): " HY2_SNI
    [[ -z "${HY2_SNI}" ]] && HY2_SNI="${HY2_ADDR}"
    
    # 询问带宽配置（Hysteria2 必需）
    print_separator
    print_info "配置带宽参数（Hysteria2 拥塞控制必需）"
    read -p "请输入上行带宽 (Mbps, 默认100): " HY2_UP_MBPS
    HY2_UP_MBPS=${HY2_UP_MBPS:-100}
    
    read -p "请输入下行带宽 (Mbps, 默认100): " HY2_DOWN_MBPS
    HY2_DOWN_MBPS=${HY2_DOWN_MBPS:-100}
    
    return 0
}

# 生成Sing-box配置文件
generate_singbox_config() {
    local uuid=$1
    local ws_path=$2
    
    print_info "正在生成Sing-box配置文件..."
    
    mkdir -p ${CONFIG_DIR}
    mkdir -p /var/log/singbox
    
    # 准备outbounds配置（根据用户选择）
    local outbounds
    local route_config
    
    if [[ "${HY2_ENABLED}" == "true" ]]; then
        print_info "使用 Hysteria2 作为主出站转发"
        outbounds='[
    {
      "type": "hysteria2",
      "tag": "proxy",
      "server": "'${HY2_ADDR}'",
      "server_port": '${HY2_PORT}',
      "password": "'${HY2_PASS}'",
      "up_mbps": '${HY2_UP_MBPS}',
      "down_mbps": '${HY2_DOWN_MBPS}',
      "tls": {
        "enabled": true,
        "server_name": "'${HY2_SNI}'",
        "insecure": true,
        "alpn": ["h3"]
      }
    },
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]'
        # 添加路由配置（禁回国流量规则）
        route_config=',
  "route": {
    "rules": [
      {
        "protocol": ["bittorrent"],
        "outbound": "block"
      },
      {
        "ip_cidr": [
          "10.0.0.0/8",
          "172.16.0.0/12",
          "192.168.0.0/16",
          "127.0.0.0/8",
          "169.254.0.0/16",
          "224.0.0.0/4",
          "240.0.0.0/4"
        ],
        "outbound": "block"
      },
      {
        "ip_is_private": true,
        "outbound": "block"
      },
      {
        "domain_suffix": [".cn", ".中国"],
        "outbound": "block"
      },
      {
        "inbound": ["vless-in"],
        "outbound": "proxy"
      }
    ],
    "final": "proxy",
    "auto_detect_interface": true
  }'
    else
        print_info "使用直连 (direct) 出站"
        outbounds='[
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]'
        # 直连模式也添加禁回国规则
        route_config=',
  "route": {
    "rules": [
      {
        "protocol": ["bittorrent"],
        "outbound": "block"
      },
      {
        "ip_cidr": [
          "10.0.0.0/8",
          "172.16.0.0/12",
          "192.168.0.0/16",
          "127.0.0.0/8",
          "169.254.0.0/16",
          "224.0.0.0/4",
          "240.0.0.0/4"
        ],
        "outbound": "block"
      },
      {
        "ip_is_private": true,
        "outbound": "block"
      },
      {
        "domain_suffix": [".cn", ".中国"],
        "outbound": "block"
      }
    ],
    "final": "direct",
    "auto_detect_interface": true
  }'
    fi
    
    cat > ${SINGBOX_CONFIG} <<EOF
{
  "log": {
    "level": "warn",
    "timestamp": false,
    "output": "/var/log/singbox/singbox.log"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "127.0.0.1",
      "listen_port": ${SINGBOX_PORT},
      "users": [
        {
          "uuid": "${uuid}"
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/${ws_path}"
      }
    }
  ],
  "outbounds": ${outbounds}${route_config}
}
EOF
    
    chmod 600 ${SINGBOX_CONFIG}
    print_success "Sing-box配置文件生成完成"
}

# 生成Caddy配置文件
generate_caddy_config() {
    local domain=$1
    local ws_path=$2
    
    print_info "正在生成Caddy配置文件..."
    
    mkdir -p ${CONFIG_DIR}
    
    # 检测是否存在全局Caddyfile
    local GLOBAL_CADDYFILE="/etc/caddy/Caddyfile"
    local USE_INCREMENTAL=false
    
    if [[ -f "${GLOBAL_CADDYFILE}" ]] && check_caddy_installed; then
        print_warn "检测到现有Caddyfile: ${GLOBAL_CADDYFILE}"
        read -p "是否追加配置到现有Caddyfile? (y/n, 默认y): " append_choice
        if [[ -z "${append_choice}" ]] || [[ "${append_choice}" == "y" ]]; then
            USE_INCREMENTAL=true
            CADDY_CONFIG="${GLOBAL_CADDYFILE}"
            print_info "将使用增量配置模式"
        fi
    fi
    
    if [[ "${USE_INCREMENTAL}" == "true" ]]; then
        # 增量模式：追加到现有配置
        print_info "追加VLESS配置到: ${CADDY_CONFIG}"
        
        # 检查是否已存在该域名配置
        if grep -q "^${domain} {" "${CADDY_CONFIG}"; then
            print_error "域名 ${domain} 已存在于Caddyfile中！"
            print_info "请手动编辑 ${CADDY_CONFIG} 或使用其他域名"
            return 1
        fi
        
        # 追加新站点配置
        cat >> ${CADDY_CONFIG} <<EOF

# Sing-box VLESS 配置 (由脚本自动添加)
${domain} {
    # TLS配置
    tls {
        protocols tls1.2 tls1.3
    }
    
    # WebSocket代理路径 - 转发到Sing-box
    @websocket {
        path /${ws_path}
        header Connection *Upgrade*
        header Upgrade websocket
    }
    reverse_proxy @websocket localhost:${SINGBOX_PORT}
    
    # 其他所有请求 - 显示伪装网站
    # 根目录 - 显示伪装网站
    root * ${WEB_DIR}
    file_server
}
EOF
        print_success "配置已追加到${CADDY_CONFIG}"
    else
        # 独立模式：创建新配置文件
        cat > ${CADDY_CONFIG} <<EOF
{
    admin off
    email admin@${domain}
}

${domain} {
    # TLS配置
    tls {
        protocols tls1.2 tls1.3
    }
    
    # WebSocket代理路径 - 转发到Sing-box
    @websocket {
        path /${ws_path}
        header Connection *Upgrade*
        header Upgrade websocket
    }
    reverse_proxy @websocket localhost:${SINGBOX_PORT}
    
    # 其他所有请求 - 显示伪装网站
    # 根目录 - 显示伪装网站
    root * ${WEB_DIR}
    file_server
}
EOF
        print_success "Caddy独立配置文件生成完成: ${CADDY_CONFIG}"
    fi
    
    mkdir -p /var/log/caddy
}

# 生成伪装网站模板
generate_website_template() {
    print_info "正在生成伪装网站..."
    
    mkdir -p ${WEB_DIR}
    
    cat > ${WEB_DIR}/index.html <<'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>欢迎访问</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container {
            background: rgba(255, 255, 255, 0.95);
            padding: 3rem;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            text-align: center;
            max-width: 600px;
            animation: fadeIn 1s ease-in;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        h1 {
            color: #667eea;
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }
        p {
            color: #666;
            font-size: 1.1rem;
            line-height: 1.8;
            margin-bottom: 0.8rem;
        }
        .highlight { color: #764ba2; font-weight: 600; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 欢迎访问</h1>
        <p>这是一个<span class="highlight">个人网站</span>，正在建设中。</p>
        <p>感谢您的访问，更多精彩内容即将呈现。</p>
    </div>
</body>
</html>
EOF
    
    print_success "伪装网站生成完成"
}

# 保存配置信息
save_config_info() {
    local uuid=$1
    local ws_path=$2
    local domain=$3
    
    cat > ${INFO_FILE} <<EOF
UUID=${uuid}
WS_PATH=${ws_path}
DOMAIN=${domain}
SINGBOX_PORT=${SINGBOX_PORT}
HY2_ENABLED=${HY2_ENABLED}
HY2_ADDR=${HY2_ADDR:-}
HY2_PORT=${HY2_PORT:-}
HY2_PASS=${HY2_PASS:-}
HY2_SNI=${HY2_SNI:-}
HY2_UP_MBPS=${HY2_UP_MBPS:-}
HY2_DOWN_MBPS=${HY2_DOWN_MBPS:-}
INSTALL_DATE=$(date '+%Y-%m-%d %H:%M:%S')
EOF
    
    chmod 600 ${INFO_FILE}
}

#================== 安装模块 ==================

# 安装Sing-box（使用官方脚本）
install_singbox() {
    # 检测是否已安装
    if command -v sing-box &> /dev/null; then
        local version=$(sing-box version 2>&1 | head -1)
        print_warn "检测到已安装的Sing-box: ${version}"
        print_info "将复用现有安装，只创建新的独立服务"
        
        # 确保日志目录存在
        mkdir -p /var/log/singbox
        chmod 755 /var/log/singbox
        
        return 0
    fi
    
    print_info "准备安装Sing-box..."
    print_info "使用Sing-box官方安装脚本（自动安装最新版本）"
    
    # 使用wget或curl下载安装
    if command -v curl &> /dev/null; then
        if ! bash <(curl -fsSL https://sing-box.app/install.sh); then
            print_error "Sing-box安装失败！"
            print_info "解决方法："
            print_info "1. 检查网络连接"
            print_info "2. 检查GitHub访问是否正常"
            return 1
        fi
    else
        if ! bash <(wget -qO- https://sing-box.app/install.sh); then
            print_error "Sing-box安装失败！"
            return 1
        fi
    fi
    
    # 检测sing-box路径
    local singbox_path=$(command -v sing-box)
    if [[ -z "${singbox_path}" ]]; then
        print_error "Sing-box命令不可用！"
        return 1
    fi
    
    print_info "Sing-box安装路径: ${singbox_path}"
    
    # 创建日志目录
    mkdir -p /var/log/singbox
    chmod 755 /var/log/singbox
    
    local version=$(sing-box version 2>&1 | head -1)
    print_success "Sing-box安装完成: ${version}"
}

# 检测Caddy是否已安装
check_caddy_installed() {
    if command -v caddy &> /dev/null; then
        CADDY_INSTALLED="true"
        CADDY_PATH=$(command -v caddy)
        print_info "检测到已安装的Caddy: ${CADDY_PATH}"
        return 0
    elif [[ -f ${CADDY_DIR}/caddy ]]; then
        CADDY_INSTALLED="true"
        CADDY_PATH="${CADDY_DIR}/caddy"
        print_info "检测到Caddy: ${CADDY_PATH}"
        return 0
    else
        CADDY_INSTALLED="false"
        return 1
    fi
}

# 安装Caddy
install_caddy() {
    # 检测是否已安装
    if check_caddy_installed; then
        print_warn "Caddy已安装，跳过安装步骤"
        print_info "将使用现有Caddy: ${CADDY_PATH}"
        return 0
    fi
    
    print_info "正在安装Caddy..."
    
    local latest_version=$(curl -s --max-time 30 https://api.github.com/repos/caddyserver/caddy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
    
    if [[ -z "${latest_version}" ]]; then
        print_warn "无法获取版本信息，使用latest链接"
        download_url="https://github.com/caddyserver/caddy/releases/latest/download/caddy_linux_${ARCH}.tar.gz"
    else
        print_info "最新版本: v${latest_version}"
        download_url="https://github.com/caddyserver/caddy/releases/download/v${latest_version}/caddy_${latest_version}_linux_${ARCH}.tar.gz"
    fi
    
    local tmp_file="/tmp/caddy.tar.gz"
    
    if ! curl -L --progress-bar --max-time 300 -o ${tmp_file} ${download_url}; then
        print_error "Caddy下载失败！"
        return 1
    fi
    
    mkdir -p ${CADDY_DIR}
    if ! tar -xzf ${tmp_file} -C ${CADDY_DIR}; then
        print_error "Caddy解压失败！"
        return 1
    fi
    
    chmod +x ${CADDY_DIR}/caddy
    rm -f ${tmp_file}
    
    local version=$(${CADDY_DIR}/caddy version 2>/dev/null)
    print_success "Caddy安装完成: ${version}"
}

# 配置Sing-box服务
setup_singbox_service() {
    print_info "正在配置Sing-box服务..."
    
    # 自动检测sing-box路径
    local singbox_path=$(command -v sing-box)
    if [[ -z "${singbox_path}" ]]; then
        print_error "无法找到sing-box可执行文件！"
        return 1
    fi
    
    cat > ${SINGBOX_SERVICE} <<EOF
[Unit]
Description=Sing-box VLESS Service
After=network.target

[Service]
Type=simple
User=root
Restart=on-failure
RestartSec=5s
ExecStart=${singbox_path} run -c ${SINGBOX_CONFIG}

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    print_success "Sing-box服务配置完成"
}

# 配置Caddy服务
setup_caddy_service() {
    print_info "正在配置Caddy服务..."
    
    # 检测是否已有任何Caddy服务（包括caddy.service和caddy-*.service）
    local existing_caddy_service=""
    
    if systemctl list-unit-files | grep -q "^caddy.service"; then
        existing_caddy_service="caddy.service"
    elif systemctl list-units --all | grep -q "caddy-.*\.service"; then
        existing_caddy_service=$(systemctl list-units --all | grep -o "caddy-[a-z]*\.service" | head -1)
    fi
    
    if [[ -n "${existing_caddy_service}" ]]; then
        print_warn "检测到已运行的Caddy服务: ${existing_caddy_service}"
        print_info "将通过reload重新加载配置，而不是创建新服务"
        
        # 重新加载配置
        if [[ -f "${CADDY_CONFIG}" ]]; then
            print_info "重新加载Caddy配置..."
            systemctl reload ${existing_caddy_service} || systemctl restart ${existing_caddy_service}
            print_success "Caddy配置已重新加载"
        fi
        return 0
    fi
    
    # 如果使用的是全局Caddyfile，也检查是否应该reload
    if [[ "${CADDY_CONFIG}" == "/etc/caddy/Caddyfile" ]] && check_caddy_installed; then
        print_info "使用全局配置，reload Caddy服务"
        systemctl reload caddy 2>/dev/null || systemctl restart caddy 2>/dev/null || true
        return 0
    fi
    
    # 创建新的独立服务
    cat > ${CADDY_SERVICE} <<EOF
[Unit]
Description=Caddy Web Server for Sing-box
After=network.target

[Service]
Type=simple
User=root
Restart=on-failure
RestartSec=5s
ExecStart=${CADDY_DIR}/caddy run --config ${CADDY_CONFIG}

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    print_success "Caddy服务配置完成"
}

# 主安装流程
install_all() {
    print_separator
    print_info "开始安装Sing-box VLESS..."
    print_separator
    
    check_root
    check_system
    install_dependencies
    
    if ! read_domain; then
        print_error "域名验证失败，安装中止！"
        return 1
    fi
    
    read_hysteria2_outbound
    
    UUID=$(generate_uuid)
    WS_PATH=$(generate_random_path)
    
    print_info "生成的UUID: ${UUID}"
    print_info "生成的WebSocket路径: /${WS_PATH}"
    
    if ! install_singbox; then
        return 1
    fi
    
    if ! install_caddy; then
        return 1
    fi
    
    generate_singbox_config ${UUID} ${WS_PATH}
    generate_caddy_config ${DOMAIN} ${WS_PATH}
    generate_website_template
    save_config_info ${UUID} ${WS_PATH} ${DOMAIN}
    
    setup_singbox_service
    setup_caddy_service
    
    print_info "正在启动服务..."
    systemctl enable singbox-vless
    systemctl start singbox-vless
    systemctl enable caddy-singbox
    systemctl start caddy-singbox
    
    sleep 3
    
    if systemctl is-active --quiet singbox-vless && systemctl is-active --quiet caddy-singbox; then
        print_separator
        print_success "✅ 安装完成！"
        print_separator
        show_connection_info
    else
        print_error "服务启动失败！请使用菜单选项3查看详细状态"
    fi
}

#================== 升级模块 ==================

# 升级Sing-box
upgrade_singbox() {
    print_separator
    print_info "准备升级Sing-box..."
    print_separator
    
    # 获取当前版本
    if command -v sing-box &> /dev/null; then
        local current_version=$(sing-box version 2>&1 | head -1)
        print_info "当前版本: ${current_version}"
    else
        print_error "Sing-box未安装！"
        return 1
    fi
    
    # 使用官方脚本升级
    print_info "正在使用官方脚本升级Sing-box..."
    if command -v curl &> /dev/null; then
        bash <(curl -fsSL https://sing-box.app/install.sh) || {
            print_error "Sing-box升级失败！"
            return 1
        }
    else
        bash <(wget -qO- https://sing-box.app/install.sh) || {
            print_error "Sing-box升级失败！"
            return 1
        }
    fi
    
    local new_version=$(sing-box version 2>&1 | head -1)
    print_success "Sing-box升级完成: ${new_version}"
    
    # 重启服务
    print_info "正在重启Sing-box服务..."
    systemctl restart singbox-vless
    
    if systemctl is-active --quiet singbox-vless; then
        print_success "Sing-box服务重启成功"
    else
        print_error "Sing-box服务重启失败，请检查配置"
    fi
    
    print_separator
}

# 升级Caddy
upgrade_caddy() {
    print_separator
    print_info "准备升级Caddy..."
    print_separator
    
    # 获取当前版本
    if [[ -f ${CADDY_DIR}/caddy ]]; then
        local current_version=$(${CADDY_DIR}/caddy version 2>/dev/null)
        print_info "当前版本: ${current_version}"
    else
        print_error "Caddy未安装！"
        return 1
    fi
    
    # 重新安装最新版本
    print_info "正在下载最新版本..."
    if ! install_caddy; then
        print_error "Caddy升级失败！"
        return 1
    fi
    
    # 重启服务
    print_info "正在重启Caddy服务..."
    systemctl restart caddy-singbox
    
    if systemctl is-active --quiet caddy-singbox; then
        print_success "Caddy服务重启成功"
    else
        print_error "Caddy服务重启失败，请检查配置"
    fi
    
    print_separator
}

# 升级所有组件
upgrade_all() {
    print_separator
    print_info "开始升级Sing-box和Caddy..."
    print_separator
    
    upgrade_singbox
    echo ""
    upgrade_caddy
    
    print_separator
    print_success "✅ 升级完成！"
    print_separator
}

#================== 卸载模块 ==================

uninstall_all() {
    print_separator
    print_warn "确定要卸载Sing-box VLESS吗？"
    print_separator
    read -p "输入 yes 确认卸载: " confirm
    
    if [[ "${confirm}" != "yes" ]]; then
        print_info "已取消卸载"
        return
    fi
    
    print_info "正在卸载..."
    
    systemctl stop singbox-vless 2>/dev/null || true
    systemctl stop caddy-singbox 2>/dev/null || true
    systemctl disable singbox-vless 2>/dev/null || true
    systemctl disable caddy-singbox 2>/dev/null || true
    
    rm -f ${SINGBOX_SERVICE}
    rm -f ${CADDY_SERVICE}
    systemctl daemon-reload
    
    # 卸载Sing-box
    if command -v sing-box &> /dev/null; then
        bash <(curl -fsSL https://sing-box.app/install.sh) uninstall 2>/dev/null || true
    fi
    
    rm -rf ${CADDY_DIR}
    rm -rf ${CONFIG_DIR}
    rm -rf ${WEB_DIR}
    rm -rf /var/log/caddy
    rm -rf /var/log/singbox
    
    print_separator
    print_success "✅ 卸载完成！"
    print_separator
}

#================== 状态查看模块 ==================

show_status() {
    print_separator
    print_info "Sing-box VLESS 运行状态"
    print_separator
    
    echo -e "\n${CYAN}【Sing-box服务状态】${NC}"
    if systemctl is-active --quiet singbox-vless; then
        print_success "Sing-box服务: 运行中 ✓"
    else
        print_error "Sing-box服务: 未运行 ✗"
        echo "  查看日志: journalctl -u singbox-vless -n 50"
    fi
    
    echo -e "\n${CYAN}【Caddy服务状态】${NC}"
    if systemctl is-active --quiet caddy-singbox; then
        print_success "Caddy服务: 运行中 ✓"
    else
        print_error "Caddy服务: 未运行 ✗"
        echo "  查看日志: journalctl -u caddy-singbox -n 50"
    fi
    
    echo -e "\n${CYAN}【端口监听情况】${NC}"
    netstat -tulpn 2>/dev/null | grep -E ":(80|443|${SINGBOX_PORT}) " || echo "  未检测到监听端口"
    
    print_separator
}

#================== 配置查看模块 ==================

show_connection_info() {
    if [[ ! -f ${INFO_FILE} ]]; then
        print_error "配置文件不存在，请先安装！"
        return
    fi
    
    source ${INFO_FILE}
    
    # 生成VLESS链接
    # 格式: vless://UUID@DOMAIN:443?encryption=none&security=tls&type=ws&host=DOMAIN&path=/WS_PATH#NAME
    local vless_link="vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&type=ws&host=${DOMAIN}&path=%2F${WS_PATH}#Singbox-${DOMAIN}"
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║       Sing-box VLESS 连接信息             ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}服务器地址:${NC} ${DOMAIN}"
    echo -e "${CYAN}端口:${NC} 443"
    echo -e "${CYAN}UUID:${NC} ${UUID}"
    echo -e "${CYAN}传输协议:${NC} WebSocket (ws)"
    echo -e "${CYAN}路径:${NC} /${WS_PATH}"
    echo -e "${CYAN}TLS:${NC} 启用"
    echo -e "${CYAN}加密:${NC} none"
    
    if [[ "${HY2_ENABLED}" == "true" ]]; then
        echo ""
        echo -e "${YELLOW}【Hysteria2 中转信息】${NC}"
        echo -e "${CYAN}转发地址:${NC} ${HY2_ADDR}:${HY2_PORT}"
        echo -e "${CYAN}中转SNI:${NC} ${HY2_SNI}"
    else
        echo ""
        echo -e "${YELLOW}【运行模式】: 直连模式${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}VLESS链接（复制到客户端）:${NC}"
    echo -e "${GREEN}${vless_link}${NC}"
    echo ""
}

show_config() {
    print_separator
    print_info "Sing-box VLESS 配置信息"
    print_separator
    
    if [[ ! -f ${INFO_FILE} ]]; then
        print_error "未找到配置信息，请先安装！"
        return
    fi
    
    show_connection_info
    
    echo -e "${CYAN}【配置文件位置】${NC}"
    echo "  Sing-box配置: ${SINGBOX_CONFIG}"
    echo "  Caddy配置: ${CADDY_CONFIG}"
    echo "  伪装网站: ${WEB_DIR}/index.html"
    echo ""
    
    print_separator
}

#================== 主菜单模块 ==================

show_menu() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
╭──────────────────────────────────────────╮
│    Sing-box VLESS 一键安装脚本 v2.0    │
│                                          │
│   基于 Sing-box + Caddy + Let's Encrypt  │
╰──────────────────────────────────────────╯
EOF
    echo -e "${NC}"
    
    echo -e "${CYAN}请选择操作：${NC}"
    echo ""
    echo -e "  ${GREEN}1.${NC} 安装 Sing-box VLESS"
    echo -e "  ${GREEN}2.${NC} 卸载 Sing-box VLESS"
    echo -e "  ${GREEN}3.${NC} 查看运行状态"
    echo -e "  ${GREEN}4.${NC} 查看配置信息"
    echo -e "  ${GREEN}5.${NC} 升级 Sing-box 和 Caddy"
    echo -e "  ${RED}0.${NC} 退出脚本"
    echo ""
    echo -e "${PURPLE}==========================================${NC}"
    echo ""
}

main() {
    check_root
    
    while true; do
        show_menu
        read -p "请输入选项 [0-5]: " choice
        
        case ${choice} in
            1)
                install_all
                read -p "按回车键继续..." 
                ;;
            2)
                uninstall_all
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
                upgrade_all
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
