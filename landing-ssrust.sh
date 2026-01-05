#!/bin/bash

#================== Shadowsocks Rust 落地机管理脚本 ==================
# 作者: https://1024.day
# 用途: 自动部署和管理 Shadowsocks Rust 服务
# 系统: Debian/Ubuntu
#====================================================================

# 启用严格错误处理
set -euo pipefail

#================== 全局变量 ==================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'  # No Color

# 配置目录和文件
SS_DIR="/etc/shadowsocks"
SS_CONFIG="${SS_DIR}/config.json"
SS_BACKUP_DIR="${SS_DIR}/backups"
SS_LOG_FILE="${SS_DIR}/install.log"
SS_BIN="/usr/local/bin/ssserver"
SS_SERVICE="/etc/systemd/system/shadowsocks.service"
SS_INFO_FILE="${SS_DIR}/connection_info.txt"

# 进程跟踪文件（用于回滚）
INSTALL_STATE_FILE="${SS_DIR}/.install_state"

# 用户输入变量
SS_PORT=""
SS_PASSWORD=""
SS_METHOD="aes-128-gcm"
SS_TIMEOUT="600"

# 系统检测变量（全局）
ARCH=""

#================== 工具函数 ==================

# 日志函数
log_message() {
    local level=$1
    shift
    # 正确处理可能包含空格的消息
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 确保日志目录存在
    local log_dir
    log_dir="$(dirname "${SS_LOG_FILE}")"
    if [[ ! -d "${log_dir}" ]]; then
        mkdir -p "${log_dir}" 2>/dev/null || true
    fi
    
    echo "[${timestamp}] [${level}] ${message}" >> "${SS_LOG_FILE}" 2>/dev/null || true
}

# 打印函数
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    log_message "INFO" "$1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    log_message "SUCCESS" "$1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    log_message "WARN" "$1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    log_message "ERROR" "$1"
}

print_separator() {
    echo "========================================================================"
}

# Root权限检查
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此脚本必须以 root 用户身份运行！"
        exit 1
    fi
}

# 检查系统类型
check_system() {
    if command -v apt-get &>/dev/null; then
        print_success "检测到 Debian/Ubuntu 系统"
    else
        print_error "此脚本仅支持 Debian/Ubuntu 系统！"
        print_info "检测到的系统不支持 apt-get 包管理器"
        exit 1
    fi
}

# 检测系统架构
detect_architecture() {
    print_info "检测系统架构..."
    
    local uname_m=$(uname -m)
    
    case "$uname_m" in
        i386|i686)
            ARCH="i686"
            ;;
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        armv7l|armv7)
            ARCH="arm"
            ;;
        armv8|aarch64)
            ARCH="aarch64"
            ;;
        *)
            print_error "不支持的架构: $uname_m"
            return 1
            ;;
    esac
    
    print_success "系统架构: ${ARCH}"
    return 0
}

#================== 安装状态管理 ==================

# 保存安装步骤
save_install_step() {
    local step=$1
    mkdir -p "${SS_DIR}"
    echo "${step}" >> "${INSTALL_STATE_FILE}"
    log_message "STATE" "安装步骤: ${step}"
}

# 清除安装状态
clear_install_state() {
    rm -f "${INSTALL_STATE_FILE}"
}

# 回滚安装
rollback_installation() {
    print_warn "检测到安装失败，开始回滚..."
    
    if [[ ! -f "${INSTALL_STATE_FILE}" ]]; then
        print_info "没有需要回滚的状态"
        return
    fi
    
    # 读取已完成的步骤
    local steps=$(tac "${INSTALL_STATE_FILE}" 2>/dev/null)
    
    for step in ${steps}; do
        case "${step}" in
            "service_created")
                print_info "回滚: 删除服务..."
                systemctl stop shadowsocks 2>/dev/null || true
                systemctl disable shadowsocks 2>/dev/null || true
                rm -f "${SS_SERVICE}"
                systemctl daemon-reload
                ;;
            "config_created")
                print_info "回滚: 删除配置..."
                rm -f "${SS_CONFIG}"
                ;;
            "binary_installed")
                print_info "回滚: 删除二进制文件..."
                rm -f "${SS_BIN}"
                ;;
            "deps_installed")
                print_info "回滚: 依赖包保留（不删除）"
                ;;
        esac
    done
    
    clear_install_state
    print_success "回滚完成"
}

# 错误处理器
error_handler() {
    local line_no=$1
    print_error "脚本在第 ${line_no} 行发生错误"
    rollback_installation
    exit 1
}

# 设置错误陷阱
trap 'error_handler ${LINENO}' ERR

#================== 端口管理 ==================

# 检查端口是否被占用
check_port_in_use() {
    local port=$1
    
    # 检查 TCP 端口
    if ss -tlnp 2>/dev/null | grep -q ":${port} " || netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
        return 0  # 端口被占用
    fi
    
    # 检查 UDP 端口
    if ss -ulnp 2>/dev/null | grep -q ":${port} " || netstat -ulnp 2>/dev/null | grep -q ":${port} "; then
        return 0  # 端口被占用
    fi
    
    return 1  # 端口未被占用
}

# 查找可用端口
find_available_port() {
    local start_port=$1
    local end_port=${2:-65000}
    
    for ((port=start_port; port<=end_port; port++)); do
        if ! check_port_in_use $port; then
            echo $port
            return 0
        fi
    done
    
    return 1
}

# 获取端口输入（带验证）
get_port_input() {
    while true; do
        echo ""
        read -t 30 -p "请输入监听端口 [1-65535] (默认: 10086): " SS_PORT || {
            print_info "输入超时，使用默认端口"
            SS_PORT=""
        }
        
        # 如果为空，使用默认端口 10086
        if [[ -z "${SS_PORT}" ]]; then
            SS_PORT=10086
            print_info "使用默认端口: ${SS_PORT}"
        fi
        
        # 验证端口格式
        if ! [[ "${SS_PORT}" =~ ^[0-9]+$ ]]; then
            print_error "端口必须是数字！"
            SS_PORT=""
            continue
        fi
        
        # 验证端口范围
        if [[ ${SS_PORT} -lt 1 || ${SS_PORT} -gt 65535 ]]; then
            print_error "端口范围必须在 1-65535 之间！"
            SS_PORT=""
            continue
        fi
        
        # 检查端口是否被占用
        if check_port_in_use ${SS_PORT}; then
            print_warn "端口 ${SS_PORT} 已被占用！"
            read -p "是否自动查找可用端口？(Y/n): " auto_find
            auto_find=${auto_find:-y}
            
            if [[ "${auto_find}" == "y" || "${auto_find}" == "Y" ]]; then
                local new_port=$(find_available_port $((SS_PORT + 1)))
                if [[ -n "${new_port}" ]]; then
                    SS_PORT=${new_port}
                    print_success "找到可用端口: ${SS_PORT}"
                    break
                else
                    print_error "无法找到可用端口，请手动指定"
                    SS_PORT=""
                    continue
                fi
            else
                SS_PORT=""
                continue
            fi
        fi
        
        break
    done
}

#================== IP 地址获取 ==================

# 获取服务器 IP 地址
get_server_ip() {
    print_info "正在获取服务器 IP 地址..."
    
    local ip=""
    
    # 尝试多种方法获取 IPv4（避免使用 eval）
    # 方法1: Cloudflare CDN
    if [[ -z "${ip}" ]]; then
        ip=$(curl -s -4 --max-time 10 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
    fi
    
    # 方法2: ipinfo.io
    if [[ -z "${ip}" ]] || ! [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip=$(curl -s -4 --max-time 10 https://ipinfo.io/ip 2>/dev/null | tr -d '[:space:]')
    fi
    
    # 方法3: ifconfig.me
    if [[ -z "${ip}" ]] || ! [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip=$(curl -s -4 --max-time 10 http://ifconfig.me 2>/dev/null | tr -d '[:space:]')
    fi
    
    # 方法4: 使用 wget
    if [[ -z "${ip}" ]] || ! [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip=$(wget -qO- -4 --timeout=10 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
    fi
    
    # 验证 IPv4 格式
    if [[ -n "${ip}" ]] && [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        print_success "服务器 IP: ${ip}"
        echo "${ip}"
        return 0
    fi
    
    # 如果 IPv4 失败，尝试 IPv6
    ip=$(curl -s -6 --max-time 10 https://api64.ipify.org 2>/dev/null | tr -d '[:space:]')
    
    # 最后检查
    if [[ -z "${ip}" ]]; then
        print_warn "无法自动获取 IP 地址"
        ip="<请手动检查>"
    else
        print_success "服务器 IP: ${ip}"
    fi
    
    echo "${ip}"
}

#================== 依赖管理 ==================

# 安装依赖包
install_dependencies() {
    print_info "安装必要的依赖包..."
    
    # 更新包列表
    print_info "更新软件包列表..."
    apt-get update -qq 2>&1 | grep -v "bullseye-backports" | grep -v "^$" || true
    
    # 定义依赖包
    local deps="gzip wget curl unzip xz-utils jq net-tools"
    
    # 尝试批量安装
    if apt-get install -y -qq ${deps} >/dev/null 2>&1; then
        print_success "依赖包批量安装成功"
    else
        print_warn "批量安装失败，尝试逐个安装..."
        for pkg in ${deps}; do
            if apt-get install -y -qq ${pkg} 2>/dev/null; then
                print_info "✓ ${pkg}"
            else
                print_warn "✗ 无法安装 ${pkg}"
            fi
        done
    fi
    
    save_install_step "deps_installed"
    print_success "依赖包安装完成"
}

#================== Shadowsocks 安装 ==================

# 检查是否已安装
check_installation() {
    if [[ -f "${SS_BIN}" ]] && [[ -f "${SS_CONFIG}" ]] && [[ -f "${SS_SERVICE}" ]]; then
        return 0  # 已安装
    fi
    return 1  # 未安装
}

# 下载并安装 Shadowsocks Rust
install_shadowsocks() {
    print_info "下载 Shadowsocks Rust..."
    
    # 获取最新版本
    local latest_version=$(curl -s https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest | jq -r '.tag_name')
    
    if [[ -z "${latest_version}" || "${latest_version}" == "null" ]]; then
        print_warn "无法获取最新版本，尝试备用方法..."
        latest_version=$(wget -qO- https://api.github.com/repos/shadowsocks/shadowsocks-rust/releases/latest 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    fi
    
    if [[ -z "${latest_version}" || "${latest_version}" == "null" ]]; then
        print_error "无法获取最新版本信息，请检查网络或 GitHub API 限制"
        return 1
    fi
    
    print_success "最新版本: ${latest_version}"
    
    # 构建下载 URL
    local download_url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${latest_version}/shadowsocks-${latest_version}.${ARCH}-unknown-linux-gnu.tar.xz"
    local filename="shadowsocks-${latest_version}.${ARCH}-unknown-linux-gnu.tar.xz"
    
    print_info "下载地址: ${download_url}"
    
    # 下载文件
    if command -v wget &>/dev/null; then
        wget --no-check-certificate -q --show-progress -O "${filename}" "${download_url}" || {
            print_error "wget 下载失败"
            return 1
        }
    elif command -v curl &>/dev/null; then
        curl -L --progress-bar -o "${filename}" "${download_url}" || {
            print_error "curl 下载失败"
            return 1
        }
    else
        print_error "需要 wget 或 curl 来下载文件"
        return 1
    fi
    
    # 验证下载
    if [[ ! -f "${filename}" ]]; then
        print_error "下载文件不存在"
        return 1
    fi
    
    # 解压文件
    print_info "解压文件..."
    tar -xf "${filename}" || {
        print_error "解压失败"
        rm -f "${filename}"
        return 1
    }
    
    # 验证解压结果
    if [[ ! -f "ssserver" ]]; then
        print_error "解压后未找到 ssserver 文件"
        rm -f "${filename}"
        return 1
    fi
    
    # 安装二进制文件
    chmod +x ssserver
    mv -f ssserver "${SS_BIN}" || {
        print_error "无法安装 ssserver 到 ${SS_BIN}"
        return 1
    }
    
    # 清理下载文件
    rm -f "${filename}"
    rm -f sslocal ssmanager ssservice ssurl 2>/dev/null || true
    
    save_install_step "binary_installed"
    print_success "Shadowsocks Rust 安装完成"
    
    # 显示版本
    local version=$(${SS_BIN} --version 2>&1 | head -1)
    print_info "安装版本: ${version}"
    
    return 0
}

#================== 配置管理 ==================

# 备份配置
backup_config() {
    if [[ ! -f "${SS_CONFIG}" ]]; then
        return 0
    fi
    
    print_info "备份现有配置..."
    
    mkdir -p "${SS_BACKUP_DIR}"
    
    local backup_file="${SS_BACKUP_DIR}/config_$(date +%Y%m%d_%H%M%S).json"
    cp "${SS_CONFIG}" "${backup_file}"
    
    print_success "配置已备份到: ${backup_file}"
    
    # 只保留最近 5 个备份
    local backup_count=$(ls -1 "${SS_BACKUP_DIR}"/config_*.json 2>/dev/null | wc -l)
    if [[ ${backup_count} -gt 5 ]]; then
        print_info "清理旧备份..."
        ls -1t "${SS_BACKUP_DIR}"/config_*.json | tail -n +6 | xargs rm -f
    fi
}

# 生成密码
generate_password() {
    if [[ -f /proc/sys/kernel/random/uuid ]]; then
        SS_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
    elif command -v uuidgen &>/dev/null; then
        SS_PASSWORD=$(uuidgen)
    else
        SS_PASSWORD=$(date +%s%N | md5sum | cut -d ' ' -f1)
    fi
}

# 获取用户输入
get_user_input() {
    print_separator
    echo -e "${GREEN}Shadowsocks Rust 配置${NC}"
    print_separator
    
    # 获取端口
    get_port_input
    
    # 选择加密方式（先选择，因为 SS2022 需要特殊密码）
    echo ""
    echo "请选择加密方式："
    echo "1. aes-128-gcm (默认,推荐)"
    echo "2. aes-256-gcm (更安全)"
    echo "3. chacha20-ietf-poly1305 (移动端优选)"
    echo "4. 2022-blake3-aes-128-gcm (SS2022,最新)"
    echo "5. 2022-blake3-aes-256-gcm (SS2022,最安全)"
    echo ""
    print_info "注意: SS2022 (选项4/5) 将自动生成专用 Base64 密码"
    
    read -t 15 -p "请选择 [1-5] (默认: 1): " method_choice || method_choice="1"
    
    local is_ss2022=false
    case "${method_choice}" in
        2)
            SS_METHOD="aes-256-gcm"
            ;;
        3)
            SS_METHOD="chacha20-ietf-poly1305"
            ;;
        4)
            SS_METHOD="2022-blake3-aes-128-gcm"
            is_ss2022=true
            ;;
        5)
            SS_METHOD="2022-blake3-aes-256-gcm"
            is_ss2022=true
            ;;
        *)
            SS_METHOD="aes-128-gcm"
            ;;
    esac
    
    print_success "加密方式: ${SS_METHOD}"
    
    # 获取密码（根据加密方式决定）
    echo ""
    if [[ "${is_ss2022}" == "true" ]]; then
        # SS2022 必须使用 Base64 密码
        print_info "SS2022 加密需要使用 Base64 编码密码，正在自动生成..."
        if [[ "${method_choice}" == "4" ]]; then
            SS_PASSWORD=$(openssl rand -base64 16)
        else
            SS_PASSWORD=$(openssl rand -base64 32)
        fi
        print_success "已生成 SS2022 专用密码: ${SS_PASSWORD}"
    else
        # 传统加密方式，用户可选
        read -p "是否自动生成密码？(Y/n): " auto_pwd
        auto_pwd=${auto_pwd:-y}
        
        if [[ "${auto_pwd}" == "y" || "${auto_pwd}" == "Y" ]]; then
            generate_password
            print_success "自动生成密码: ${SS_PASSWORD}"
        else
            while true; do
                read -p "请输入密码（至少 8 个字符）: " SS_PASSWORD
                if [[ ${#SS_PASSWORD} -lt 8 ]]; then
                    print_error "密码长度至少 8 个字符！"
                    continue
                fi
                break
            done
        fi
    fi
    
    # 确认配置
    echo ""
    print_separator
    echo -e "${YELLOW}请确认以下配置：${NC}"
    print_separator
    echo "端口: ${SS_PORT}"
    echo "密码: ${SS_PASSWORD}"
    echo "加密方式: ${SS_METHOD}"
    echo "模式: TCP + UDP"
    print_separator
    
    read -p "确认无误？(Y/n): " confirm
    confirm=${confirm:-y}
    
    if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
        print_info "已取消安装"
        exit 0
    fi
}

# 生成配置文件
generate_config() {
    print_info "生成配置文件..."
    
    # 如果已有配置，先备份
    backup_config
    
    # 创建配置目录
    mkdir -p "${SS_DIR}"
    
    # 生成配置文件
    cat > "${SS_CONFIG}" <<EOF
{
    "server": "::",
    "server_port": ${SS_PORT},
    "password": "${SS_PASSWORD}",
    "timeout": ${SS_TIMEOUT},
    "method": "${SS_METHOD}",
    "mode": "tcp_and_udp",
    "fast_open": true,
    "nameserver": "8.8.8.8",
    "ipv6_first": false
}
EOF
    
    chmod 600 "${SS_CONFIG}"
    save_install_step "config_created"
    print_success "配置文件已生成: ${SS_CONFIG}"
}

# 验证配置文件
validate_config() {
    print_info "验证配置文件..."
    
    if [[ ! -f "${SS_CONFIG}" ]]; then
        print_error "配置文件不存在"
        return 1
    fi
    
    # 验证 JSON 格式
    if ! jq empty "${SS_CONFIG}" 2>/dev/null; then
        print_error "配置文件 JSON 格式错误"
        return 1
    fi
    
    # 验证必要字段
    local required_fields=("server" "server_port" "password" "method")
    for field in "${required_fields[@]}"; do
        if ! jq -e ".${field}" "${SS_CONFIG}" >/dev/null 2>&1; then
            print_error "配置文件缺少必要字段: ${field}"
            return 1
        fi
    done
    
    print_success "配置文件验证通过"
    return 0
}

#================== 服务管理 ==================

# 创建 systemd 服务
create_service() {
    print_info "创建 systemd 服务..."
    
    cat > "${SS_SERVICE}" <<EOF
[Unit]
Description=Shadowsocks Rust Server
Documentation=https://github.com/shadowsocks/shadowsocks-rust
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${SS_BIN} -c ${SS_CONFIG}
Restart=on-failure
RestartSec=3s
LimitNOFILE=65535
LimitNPROC=512

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    save_install_step "service_created"
    print_success "systemd 服务已创建"
}

# 启动服务
start_service() {
    print_info "启动 Shadowsocks 服务..."
    
    systemctl enable shadowsocks >/dev/null 2>&1
    systemctl restart shadowsocks
    
    # 等待服务启动
    sleep 2
    
    if systemctl is-active --quiet shadowsocks; then
        print_success "Shadowsocks 服务启动成功"
        return 0
    else
        print_error "Shadowsocks 服务启动失败"
        print_info "查看日志: journalctl -u shadowsocks -n 50"
        return 1
    fi
}

#================== 健康检查 ==================

# 健康检查
health_check() {
    print_separator
    echo -e "${CYAN}系统健康检查${NC}"
    print_separator
    
    local health_status=0
    
    # 1. 检查二进制文件
    echo -n "检查二进制文件... "
    if [[ -f "${SS_BIN}" ]] && [[ -x "${SS_BIN}" ]]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        health_status=1
    fi
    
    # 2. 检查配置文件
    echo -n "检查配置文件... "
    if [[ -f "${SS_CONFIG}" ]]; then
        if jq empty "${SS_CONFIG}" 2>/dev/null; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${YELLOW}! (格式错误)${NC}"
            health_status=1
        fi
    else
        echo -e "${RED}✗${NC}"
        health_status=1
    fi
    
    # 3. 检查服务状态
    echo -n "检查服务状态... "
    if systemctl is-active --quiet shadowsocks; then
        echo -e "${GREEN}✓ (运行中)${NC}"
    else
        echo -e "${RED}✗ (未运行)${NC}"
        health_status=1
    fi
    
    # 4. 检查端口监听
    echo -n "检查端口监听... "
    if [[ -f "${SS_CONFIG}" ]]; then
        local port=$(jq -r '.server_port' "${SS_CONFIG}" 2>/dev/null)
        if ss -tlnp 2>/dev/null | grep -q ":${port} " || netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
            echo -e "${GREEN}✓ (TCP:${port})${NC}"
        else
            echo -e "${YELLOW}! (未监听)${NC}"
            health_status=1
        fi
    else
        echo -e "${YELLOW}! (无法检查)${NC}"
    fi
    
    # 5. 检查服务自启动
    echo -n "检查服务自启动... "
    if systemctl is-enabled --quiet shadowsocks 2>/dev/null; then
        echo -e "${GREEN}✓ (已启用)${NC}"
    else
        echo -e "${YELLOW}! (未启用)${NC}"
    fi
    
    echo ""
    if [[ ${health_status} -eq 0 ]]; then
        print_success "健康检查通过"
    else
        print_warn "健康检查发现问题，请检查以上标记"
    fi
    
    print_separator
    
    return ${health_status}
}

#================== 信息显示 ==================

# 保存连接信息
save_connection_info() {
    local server_ip=$(get_server_ip)
    
    # 生成 SS URL
    local ss_link=$(echo -n "${SS_METHOD}:${SS_PASSWORD}@${server_ip}:${SS_PORT}" | base64 -w 0)
    
    cat > "${SS_INFO_FILE}" <<EOF
======================================================================
            Shadowsocks Rust 连接信息
======================================================================

服务器地址: ${server_ip}
端口: ${SS_PORT}
密码: ${SS_PASSWORD}
加密方式: ${SS_METHOD}
传输协议: TCP + UDP

SS URL:
ss://${ss_link}

服务管理:
查看状态: systemctl status shadowsocks
查看日志: journalctl -u shadowsocks -f
重启服务: systemctl restart shadowsocks
停止服务: systemctl stop shadowsocks

配置文件: ${SS_CONFIG}
备份目录: ${SS_BACKUP_DIR}
日志文件: ${SS_LOG_FILE}

安装时间: $(date '+%Y-%m-%d %H:%M:%S')

======================================================================
EOF
    
    chmod 600 "${SS_INFO_FILE}"
}

# 显示连接信息
show_connection_info() {
    if [[ ! -f "${SS_CONFIG}" ]]; then
        print_error "配置文件不存在，请先安装"
        return 1
    fi
    
    # 从配置文件读取信息
    local port=$(jq -r '.server_port' "${SS_CONFIG}" 2>/dev/null)
    local password=$(jq -r '.password' "${SS_CONFIG}" 2>/dev/null)
    local method=$(jq -r '.method' "${SS_CONFIG}" 2>/dev/null)
    local server_ip=$(get_server_ip)
    
    # 生成 SS URL
    local ss_link=$(echo -n "${method}:${password}@${server_ip}:${port}" | base64 -w 0)
    
    # 检查服务状态
    local service_status
    if systemctl is-active --quiet shadowsocks; then
        service_status="${GREEN}运行中${NC}"
    else
        service_status="${RED}未运行${NC}"
    fi
    
    clear
    print_separator
    echo -e "${GREEN}Shadowsocks Rust 连接信息${NC}"
    print_separator
    echo ""
    echo -e "${CYAN}连接参数:${NC}"
    echo "-------------------------------------------"
    echo -e "${YELLOW}服务器地址:${NC} ${server_ip}"
    echo -e "${YELLOW}端口:${NC} ${port}"
    echo -e "${YELLOW}密码:${NC} ${password}"
    echo -e "${YELLOW}加密方式:${NC} ${method}"
    echo -e "${YELLOW}传输协议:${NC} TCP + UDP"
    echo "-------------------------------------------"
    echo -e "${YELLOW}服务状态:${NC} ${service_status}"
    echo ""
    echo -e "${YELLOW}SS URL:${NC}"
    echo ""
    echo -e "ss://${ss_link}"
    echo ""
    echo -e "${GREEN}可使用此 URL 在客户端快速导入配置${NC}"
    echo ""
    print_separator
    echo -e "${CYAN}服务管理:${NC}"
    echo "查看状态: systemctl status shadowsocks"
    echo "查看日志: journalctl -u shadowsocks -f"
    echo "重启服务: systemctl restart shadowsocks"
    echo "停止服务: systemctl stop shadowsocks"
    print_separator
    
    print_info "完整信息已保存到: ${SS_INFO_FILE}"
}

#================== 卸载功能 ==================

# 检测安装组件
detect_components() {
    local components=()
    
    [[ -f "${SS_BIN}" ]] && components+=("二进制文件")
    [[ -f "${SS_CONFIG}" ]] && components+=("配置文件")
    [[ -f "${SS_SERVICE}" ]] && components+=("系统服务")
    [[ -d "${SS_BACKUP_DIR}" ]] && components+=("备份文件")
    [[ -f "${SS_LOG_FILE}" ]] && components+=("日志文件")
    
    echo "${components[@]}"
}

# 卸载功能
uninstall_shadowsocks() {
    print_separator
    print_warn "⚠️  即将卸载 Shadowsocks Rust"
    print_separator
    
    # 检测已安装组件
    local components=($(detect_components))
    
    if [[ ${#components[@]} -eq 0 ]]; then
        print_info "未检测到已安装的 Shadowsocks Rust 组件"
        return 0
    fi
    
    echo ""
    echo -e "${YELLOW}检测到以下组件:${NC}"
    for comp in "${components[@]}"; do
        echo "  - ${comp}"
    done
    echo ""
    
    # 确认卸载
    print_warn "此操作将删除所有 Shadowsocks Rust 相关文件和配置"
    read -p "是否继续？(yes/no): " confirm
    
    if [[ "${confirm}" != "yes" ]]; then
        print_info "已取消卸载"
        return 0
    fi
    
    # 询问是否备份配置
    if [[ -f "${SS_CONFIG}" ]]; then
        echo ""
        read -p "是否在删除前备份配置文件？(Y/n): " backup_choice
        backup_choice=${backup_choice:-y}
        
        if [[ "${backup_choice}" == "y" || "${backup_choice}" == "Y" ]]; then
            backup_config
        fi
    fi
    
    print_info "开始卸载..."
    echo ""
    
    # 1. 停止服务
    if systemctl is-active --quiet shadowsocks 2>/dev/null; then
        print_info "停止 Shadowsocks 服务..."
        systemctl stop shadowsocks
    fi
    
    # 2. 禁用服务
    if systemctl is-enabled --quiet shadowsocks 2>/dev/null; then
        print_info "禁用 Shadowsocks 服务..."
        systemctl disable shadowsocks >/dev/null 2>&1
    fi
    
    # 3. 删除服务文件
    if [[ -f "${SS_SERVICE}" ]]; then
        print_info "删除 systemd 服务文件..."
        rm -f "${SS_SERVICE}"
        systemctl daemon-reload
    fi
    
    # 4. 删除二进制文件
    if [[ -f "${SS_BIN}" ]]; then
        print_info "删除二进制文件..."
        rm -f "${SS_BIN}"
    fi
    
    # 5. 删除配置目录
    if [[ -d "${SS_DIR}" ]]; then
        print_info "删除配置目录..."
        
        # 二次确认删除备份
        if [[ -d "${SS_BACKUP_DIR}" ]]; then
            local backup_count=0
            # 正确统计备份文件
            if compgen -G "${SS_BACKUP_DIR}"/*.json > /dev/null 2>&1; then
                backup_count=$(find "${SS_BACKUP_DIR}" -name "*.json" -type f 2>/dev/null | wc -l)
            fi
            
            if [[ ${backup_count} -gt 0 ]]; then
                echo ""
                read -p "检测到 ${backup_count} 个备份文件，是否保留？(y/N): " keep_backup
                keep_backup=${keep_backup:-n}
                
                if [[ "${keep_backup}" == "y" || "${keep_backup}" == "Y" ]]; then
                    local temp_backup
                    temp_backup="/tmp/shadowsocks_backup_$(date +%s)"
                    print_info "备份文件已移至: ${temp_backup}"
                    mv "${SS_BACKUP_DIR}" "${temp_backup}"
                fi
            fi
        fi
        
        rm -rf "${SS_DIR}"
    fi
    
    # 清理安装状态
    clear_install_state
    
    echo ""
    print_separator
    print_success "✅ Shadowsocks Rust 卸载完成"
    print_separator
    echo ""
    print_info "已删除内容:"
    print_info "  - Shadowsocks 二进制文件"
    print_info "  - 配置文件和目录"
    print_info "  - Systemd 服务"
    echo ""
    
    if [[ -d "/tmp/shadowsocks_backup_"* ]]; then
        print_info "备份文件保留在 /tmp 目录中"
    fi
}

#================== 配置更新 ==================

# 更新配置
update_config() {
    if ! check_installation; then
        print_error "Shadowsocks 未安装，请先安装"
        return 1
    fi
    
    print_separator
    echo -e "${GREEN}更新 Shadowsocks 配置${NC}"
    print_separator
    
    # 显示当前配置
    echo ""
    echo -e "${CYAN}当前配置:${NC}"
    local current_port=$(jq -r '.server_port' "${SS_CONFIG}" 2>/dev/null)
    local current_password=$(jq -r '.password' "${SS_CONFIG}" 2>/dev/null)
    local current_method=$(jq -r '.method' "${SS_CONFIG}" 2>/dev/null)
    
    echo "端口: ${current_port}"
    echo "密码: ${current_password}"
    echo "加密方式: ${current_method}"
    echo ""
    
    # 选择要更新的项目
    echo "请选择要更新的配置:"
    echo "1. 更新端口"
    echo "2. 更新密码"
    echo "3. 更新加密方式"
    echo "4. 全部更新"
    echo "0. 返回"
    
    read -p "请选择 [0-4]: " update_choice
    
    case "${update_choice}" in
        1)
            backup_config  # 添加备份
            get_port_input
            jq ".server_port = ${SS_PORT}" "${SS_CONFIG}" > "${SS_CONFIG}.tmp" && mv "${SS_CONFIG}.tmp" "${SS_CONFIG}"
            ;;
        2)
            backup_config  # 添加备份
            read -p "是否自动生成新密码？(Y/n): " auto_pwd
            auto_pwd=${auto_pwd:-y}
            if [[ "${auto_pwd}" == "y" || "${auto_pwd}" == "Y" ]]; then
                generate_password
            else
                read -p "请输入新密码: " SS_PASSWORD
            fi
            jq ".password = \"${SS_PASSWORD}\"" "${SS_CONFIG}" > "${SS_CONFIG}.tmp" && mv "${SS_CONFIG}.tmp" "${SS_CONFIG}"
            ;;
        3)
            backup_config  # 添加备份
            echo "请选择加密方式："
            echo "1. aes-128-gcm"
            echo "2. aes-256-gcm"
            echo "3. chacha20-ietf-poly1305"
            read -p "请选择 [1-3]: " method_choice
            case "${method_choice}" in
                2) SS_METHOD="aes-256-gcm" ;;
                3) SS_METHOD="chacha20-ietf-poly1305" ;;
                *) SS_METHOD="aes-128-gcm" ;;
            esac
            jq ".method = \"${SS_METHOD}\"" "${SS_CONFIG}" > "${SS_CONFIG}.tmp" && mv "${SS_CONFIG}.tmp" "${SS_CONFIG}"
            ;;
        4)
            backup_config
            get_user_input
            generate_config
            ;;
        0)
            return 0
            ;;
        *)
            print_error "无效选择"
            return 1
            ;;
    esac
    
    # 重启服务应用配置
    print_info "重启服务以应用新配置..."
    systemctl restart shadowsocks
    
    sleep 2
    
    if systemctl is-active --quiet shadowsocks; then
        print_success "配置更新成功，服务已重启"
        save_connection_info
    else
        print_error "服务重启失败，请检查配置"
        return 1
    fi
}

#================== 主菜单 ==================

show_menu() {
    clear
    print_separator
    echo -e "${GREEN}Shadowsocks Rust 管理脚本${NC}"
    echo -e "${BLUE}系统: $(uname -s) $(uname -m)${NC}"
    print_separator
    echo ""
    echo "1. 安装 Shadowsocks Rust"
    echo "2. 卸载 Shadowsocks Rust"
    echo "3. 更新配置"
    echo "4. 查看连接信息"
    echo "5. 查看服务状态"
    echo "6. 重启服务"
    echo "7. 查看日志"
    echo "8. 健康检查"
    echo "0. 退出"
    echo ""
    print_separator
}

# 查看服务状态
view_service_status() {
    print_separator
    echo -e "${CYAN}Shadowsocks 服务状态${NC}"
    print_separator
    systemctl status shadowsocks --no-pager
    print_separator
}

# 查看日志
view_logs() {
    print_separator
    echo -e "${CYAN}Shadowsocks 服务日志（最后 50 行）${NC}"
    print_separator
    journalctl -u shadowsocks -n 50 --no-pager
    print_separator
}

# 重启服务
restart_service() {
    print_info "重启 Shadowsocks 服务..."
    systemctl restart shadowsocks
    sleep 2
    
    if systemctl is-active --quiet shadowsocks; then
        print_success "服务重启成功"
    else
        print_error "服务重启失败"
        print_info "查看日志: journalctl -u shadowsocks -n 50"
    fi
}

#================== 安装流程 ==================

install_process() {
    clear
    print_separator
    echo -e "${GREEN}开始安装 Shadowsocks Rust${NC}"
    print_separator
    echo ""
    
    # 检查是否已安装
    if check_installation; then
        print_warn "检测到已安装 Shadowsocks Rust"
        read -p "是否重新安装？(y/N): " reinstall
        if [[ "${reinstall}" != "y" && "${reinstall}" != "Y" ]]; then
            print_info "已取消安装"
            return 0
        fi
        
        print_info "将重新安装..."
        backup_config
    fi
    
    # 获取用户输入
    get_user_input
    
    echo ""
    print_info "开始安装..."
    echo ""
    
    # 创建日志目录
    mkdir -p "$(dirname ${SS_LOG_FILE})"
    
    # 执行安装步骤
    check_system
    detect_architecture || exit 1
    install_dependencies
    install_shadowsocks || exit 1
    generate_config
    validate_config || exit 1
    create_service
    start_service || exit 1
    
    # 保存连接信息
    save_connection_info
    
    # 健康检查
    echo ""
    health_check
    
    # 显示连接信息
    echo ""
    show_connection_info
    
    # 清除安装状态（成功）
    clear_install_state
    
    # 防火墙提示
    echo ""
    print_separator
    print_warn "⚠️  请确保防火墙开放端口: ${SS_PORT}/tcp 和 ${SS_PORT}/udp"
    echo ""
    print_info "UFW 示例:"
    echo "  ufw allow ${SS_PORT}/tcp"
    echo "  ufw allow ${SS_PORT}/udp"
    echo ""
    print_info "Firewalld 示例:"
    echo "  firewall-cmd --permanent --add-port=${SS_PORT}/tcp"
    echo "  firewall-cmd --permanent --add-port=${SS_PORT}/udp"
    echo "  firewall-cmd --reload"
    print_separator
}

#================== 主流程 ==================

main() {
    # 检查 root 权限
    check_root
    
    # 禁用错误陷阱（菜单模式）
    trap - ERR
    
    # 主循环
    while true; do
        show_menu
        read -p "请选择操作 [0-8]: " choice
        
        case "${choice}" in
            1)
                # 启用错误陷阱（安装模式）
                trap 'error_handler ${LINENO}' ERR
                install_process
                trap - ERR
                read -p "按回车键继续..."
                ;;
            2)
                uninstall_shadowsocks
                read -p "按回车键继续..."
                ;;
            3)
                update_config
                read -p "按回车键继续..."
                ;;
            4)
                show_connection_info
                read -p "按回车键继续..."
                ;;
            5)
                view_service_status
                read -p "按回车键继续..."
                ;;
            6)
                restart_service
                read -p "按回车键继续..."
                ;;
            7)
                view_logs
                read -p "按回车键继续..."
                ;;
            8)
                health_check
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

# 执行主流程
main
