#!/bin/bash

#================== Xray Reality + Caddy 管理脚本 ==================
# 作者: Enhanced by AI
# 用途: 自动部署 VLESS + Vision + Reality + Caddy 后置服务
# 系统: Debian/Ubuntu
# 配置: 偷自己的域名 + PROXY Protocol + HTTP/2
#===================================================================

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

# Xray 相关路径
XRAY_DIR="/usr/local/etc/xray"
XRAY_CONFIG="${XRAY_DIR}/config.json"
XRAY_BIN="/usr/local/bin/xray"
XRAY_SERVICE="/etc/systemd/system/xray.service"
XRAY_LOG_DIR="/var/log/xray"

# Caddy 相关路径
CADDY_DIR="/etc/caddy"
CADDY_CONFIG="${CADDY_DIR}/Caddyfile"
CADDY_LOG_DIR="/var/log/caddy"

# 网站相关路径
WEB_ROOT="/var/www/html"

# 备份和日志
BACKUP_DIR="${XRAY_DIR}/backups"
LOG_FILE="${XRAY_LOG_DIR}/install.log"
INFO_FILE="${XRAY_DIR}/reality_info.txt"
INSTALL_STATE_FILE="${XRAY_DIR}/.install_state"

# 用户输入变量
DOMAIN=""
PORT="443"
UUID=""
PUBLIC_KEY=""
PRIVATE_KEY=""
SHORT_ID=""
EMAIL=""

# 中转模式变量
TRANSIT_MODE=""           # direct/ss
LANDING_SERVER=""         # 落地机地址
LANDING_PORT=""           # 落地机端口
SS_METHOD=""              # SS 加密方法
SS_PASSWORD=""            # SS 密码

#================== 工具函数 ==================

# 日志函数
log_message() {
    local level=$1
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 确保日志目录存在
    local log_dir
    log_dir="$(dirname "${LOG_FILE}")"
    if [[ ! -d "${log_dir}" ]]; then
        mkdir -p "${log_dir}" 2>/dev/null || true
    fi
    
    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}" 2>/dev/null || true
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

# Root 权限检查
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此脚本必须以 root 用户身份运行！"
        exit 1
    fi
}

# 检查系统类型（仅支持 Debian/Ubuntu）
check_system() {
    if command -v apt-get &>/dev/null; then
        print_success "检测到 Debian/Ubuntu 系统"
    else
        print_error "此脚本仅支持 Debian/Ubuntu 系统！"
        print_info "检测到的系统不支持 apt-get 包管理器"
        exit 1
    fi
}

#================== 安装状态管理 ==================

# 保存安装步骤
save_install_step() {
    local step=$1
    mkdir -p "${XRAY_DIR}"
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
    
    # 读取已完成的步骤（倒序）
    local steps
    steps=$(tac "${INSTALL_STATE_FILE}" 2>/dev/null)
    
    for step in ${steps}; do
        case "${step}" in
            "xray_configured")
                print_info "回滚: 删除 Xray 配置..."
                rm -f "${XRAY_CONFIG}"
                ;;
            "caddy_configured")
                print_info "回滚: 删除 Caddy 配置..."
                rm -f "${CADDY_CONFIG}"
                ;;
            "website_created")
                print_info "回滚: 删除网站文件..."
                rm -rf "${WEB_ROOT:?}"/*
                ;;
            "xray_installed")
                print_info "回滚: 停止 Xray..."
                systemctl stop xray 2>/dev/null || true
                systemctl disable xray 2>/dev/null || true
                ;;
            "caddy_installed")
                print_info "回滚: 停止 Caddy..."
                systemctl stop caddy 2>/dev/null || true
                systemctl disable caddy 2>/dev/null || true
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

# 设置错误陷阱（默认禁用，安装时启用）
trap 'error_handler ${LINENO}' ERR

#================== 依赖管理 ==================

# 安装依赖包
install_dependencies() {
    print_info "安装必要的依赖包..."
    
    # 更新包列表
    print_info "更新软件包列表..."
    apt-get update -qq 2>&1 | grep -v "bullseye-backports" | grep -v "^$" || true
    
    # 定义依赖包
    local deps="curl wget unzip jq openssl socat net-tools debian-keyring debian-archive-keyring apt-transport-https"
    
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

#================== Xray 安装与配置 ==================

# 检查 Xray 是否已安装
check_xray_installed() {
    if [[ -f "${XRAY_BIN}" ]] && [[ -x "${XRAY_BIN}" ]]; then
        return 0  # 已安装
    fi
    return 1  # 未安装
}

# 检查 Xray 是否正在运行
check_xray_running() {
    if systemctl is-active --quiet xray; then
        return 0  # 正在运行
    fi
    return 1  # 未运行
}

# 安装 Xray
install_xray() {
    print_info "检查 Xray 状态..."
    
    if check_xray_installed; then
        local current_version
        current_version=$(${XRAY_BIN} version 2>&1 | head -1)
        print_success "检测到 Xray 已安装: ${current_version}"
        
        # 检查是否正在运行
        if check_xray_running; then
            print_success "Xray 服务正在运行"
        else
            print_info "Xray 已安装但未运行"
        fi
        
        # 提供升级选项
        echo ""
        print_info "可以尝试升级到最新版本（如果有）"
        read -p "是否尝试升级 Xray 到最新版本？(Y/n): " upgrade
        upgrade=${upgrade:-y}
        
        if [[ "${upgrade}" == "y" || "${upgrade}" == "Y" ]]; then
            print_info "尝试升级 Xray..."
            # 使用官方脚本升级（如果有新版本）
            bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install
            
            # 检查升级后的版本
            if check_xray_installed; then
                local new_version
                new_version=$(${XRAY_BIN} version 2>&1 | head -1)
                if [[ "${new_version}" != "${current_version}" ]]; then
                    print_success "Xray 已升级: ${new_version}"
                else
                    print_info "Xray 已是最新版本: ${new_version}"
                fi
            fi
        else
            print_info "将使用现有 Xray 版本，仅更新配置"
        fi
        
        return 0
    fi
    
    # 如果没有安装，则进行全新安装
    print_info "开始安装 Xray..."
    
    # 使用官方安装脚本
    print_info "下载并运行 Xray 官方安装脚本..."
    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install
    
    # 验证安装
    if check_xray_installed; then
        local version
        version=$(${XRAY_BIN} version 2>&1 | head -1)
        print_success "Xray 安装成功: ${version}"
        systemctl enable xray 2>/dev/null || true
        save_install_step "xray_installed"
        return 0
    else
        print_error "Xray 安装失败！"
        return 1
    fi
}

#================== 中转模式配置 ==================

# 选择中转模式
get_transit_mode() {
    print_separator
    echo -e "${GREEN}选择中转模式${NC}"
    print_separator
    echo ""
    echo "1. 直连模式 (Direct) - 不使用落地机，直接出站"
    echo "2. SS 中转 - 转发到落地机的 Shadowsocks 服务器"
    echo ""
    
    while true; do
        read -p "请选择模式 [1-2, 默认=1]: " mode_choice
        mode_choice=${mode_choice:-1}
        
        case "${mode_choice}" in
            1)
                TRANSIT_MODE="direct"
                print_success "已选择: 直连模式"
                break
                ;;
            2)
                TRANSIT_MODE="ss"
                print_success "已选择: SS 中转模式"
                get_ss_config
                break
                ;;
            *)
                print_error "无效选择，请输入 1 或 2"
                ;;
        esac
    done
}

# 配置 Shadowsocks 落地机
get_ss_config() {
    echo ""
    print_info "配置 Shadowsocks 落地机"
    print_separator
    
    # 落地机地址
    while true; do
        read -p "落地机地址 (IP或域名): " LANDING_SERVER
        if [[ -n "${LANDING_SERVER}" ]]; then
            break
        fi
        print_error "地址不能为空"
    done
    
    # 落地机端口
    while true; do
        read -p "落地机端口 [1-65535, 默认=10086]: " LANDING_PORT
        LANDING_PORT=${LANDING_PORT:-10086}
        if [[ "${LANDING_PORT}" =~ ^[0-9]+$ ]] && \
           [[ ${LANDING_PORT} -ge 1 ]] && \
           [[ ${LANDING_PORT} -le 65535 ]]; then
            break
        fi
        print_error "端口必须是 1-65535 之间的数字"
    done
    
    # 加密方法
    echo ""
    echo "选择加密方法:"
    echo "1. aes-128-gcm (推荐)"
    echo "2. aes-256-gcm"
    echo "3. chacha20-ietf-poly1305"
    echo "4. 2022-blake3-aes-128-gcm (SS2022)"
    echo "5. 2022-blake3-aes-256-gcm (SS2022)"
    echo ""
    
    while true; do
        read -p "请选择 [1-5, 默认=1]: " method_choice
        method_choice=${method_choice:-1}
        
        case "${method_choice}" in
            1) SS_METHOD="aes-128-gcm"; break ;;
            2) SS_METHOD="aes-256-gcm"; break ;;
            3) SS_METHOD="chacha20-ietf-poly1305"; break ;;
            4) SS_METHOD="2022-blake3-aes-128-gcm"; break ;;
            5) SS_METHOD="2022-blake3-aes-256-gcm"; break ;;
            *) print_error "无效选择，请输入 1-5" ;;
        esac
    done
    
    # 密码
    echo ""
    read -p "SS 密码 (留空自动生成): " SS_PASSWORD
    if [[ -z "${SS_PASSWORD}" ]]; then
        # 根据加密方法生成合适长度的密码
        if [[ "${SS_METHOD}" == "2022-blake3-aes-128-gcm" ]]; then
            # 16字节 Base64
            SS_PASSWORD=$(openssl rand -base64 16)
        elif [[ "${SS_METHOD}" == "2022-blake3-aes-256-gcm" ]]; then
            # 32字节 Base64
            SS_PASSWORD=$(openssl rand -base64 32)
        else
            # 普通密码
            SS_PASSWORD=$(openssl rand -base64 16)
        fi
        print_info "自动生成密码: ${SS_PASSWORD}"
    fi
    
    # 确认配置
    echo ""
    print_separator
    echo -e "${YELLOW}SS 落地机配置:${NC}"
    echo "地址: ${LANDING_SERVER}"
    echo "端口: ${LANDING_PORT}"
    echo "加密: ${SS_METHOD}"
    echo "密码: ${SS_PASSWORD}"
    print_separator
    echo ""
}

# 生成 Reality 密钥
generate_reality_keys() {
    print_info "生成 Reality 密钥..."
    
    # 生成 UUID
    UUID=$(${XRAY_BIN} uuid)
    print_success "UUID: ${UUID}"
    
    # 生成 X25519 密钥对
    local keys
    keys=$(${XRAY_BIN} x25519)
    
    # Xray 25.12.8+ 新格式: PrivateKey / Password / Hash32
    # 旧格式: Private key / Public key
    
    # 尝试新格式 (25.12.8+)
    PRIVATE_KEY=$(echo "${keys}" | grep "^PrivateKey:" | cut -d: -f2- | tr -d ' ')
    PUBLIC_KEY=$(echo "${keys}" | grep "^Password:" | cut -d: -f2- | tr -d ' ')
    
    # 如果新格式失败，尝试旧格式
    if [[ -z "${PRIVATE_KEY}" ]] || [[ -z "${PUBLIC_KEY}" ]]; then
        PRIVATE_KEY=$(echo "${keys}" | grep -i "Private" | awk '{print $NF}')
        PUBLIC_KEY=$(echo "${keys}" | grep -i "Public" | awk '{print $NF}')
    fi
    
    # 如果还是失败，尝试直接按行读取
    if [[ -z "${PRIVATE_KEY}" ]] || [[ -z "${PUBLIC_KEY}" ]]; then
        PRIVATE_KEY=$(echo "${keys}" | sed -n '1p' | awk '{print $NF}')
        PUBLIC_KEY=$(echo "${keys}" | sed -n '2p' | awk '{print $NF}')
    fi
    
    # 如果都失败，显示原始输出用于调试
    if [[ -z "${PRIVATE_KEY}" ]] || [[ -z "${PUBLIC_KEY}" ]]; then
        print_error "无法解析 xray x25519 输出"
        print_info "原始输出："
        echo "${keys}"
        print_info "请手动运行: ${XRAY_BIN} x25519"
        return 1
    fi
    
    print_success "Private Key: ${PRIVATE_KEY}"
    print_success "Public Key: ${PUBLIC_KEY}"
    
    # 生成 Short ID
    SHORT_ID=$(openssl rand -hex 8)
    print_success "Short ID: ${SHORT_ID}"
    
    # 验证生成结果
    if [[ -z "${UUID}" ]] || [[ -z "${PRIVATE_KEY}" ]] || [[ -z "${PUBLIC_KEY}" ]] || [[ -z "${SHORT_ID}" ]]; then
        print_error "密钥生成失败！"
        print_info "UUID 长度: ${#UUID}"
        print_info "Private Key 长度: ${#PRIVATE_KEY}"
        print_info "Public Key 长度: ${#PUBLIC_KEY}"
        print_info "Short ID 长度: ${#SHORT_ID}"
        return 1
    fi
    
    return 0
}

# 配置 Xray
configure_xray() {
    print_info "配置 Xray..."
    
    # 创建配置目录
    mkdir -p "${XRAY_DIR}"
    mkdir -p "${XRAY_LOG_DIR}"
    
    # 设置 Xray 日志目录权限（Xray 以 nobody 用户运行）
    if id -u nobody &>/dev/null; then
        chown -R nobody:nogroup "${XRAY_LOG_DIR}" 2>/dev/null || chown -R nobody:nobody "${XRAY_LOG_DIR}"
        chmod -R 755 "${XRAY_LOG_DIR}"
        print_info "已设置 Xray 日志目录权限"
    fi
    
    # 声明备份文件变量
    local backup_file=""
    
    # 备份现有配置
    if [[ -f "${XRAY_CONFIG}" ]]; then
        backup_file="${XRAY_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "${XRAY_CONFIG}" "${backup_file}"
        print_info "已备份现有配置到: ${backup_file}"
        
        # 检查现有配置类型
        if grep -q "reality" "${XRAY_CONFIG}" 2>/dev/null; then
            print_warn "检测到现有的 Reality 配置"
        fi
        
        print_warn "新配置将覆盖现有配置"
        read -p "是否继续？(Y/n): " overwrite
        overwrite=${overwrite:-y}
        if [[ "${overwrite}" != "y" && "${overwrite}" != "Y" ]]; then
            print_info "保留现有配置，退出配置过程"
            return 1
        fi
    fi
    
    # 根据中转模式生成不同的配置
    if [[ "${TRANSIT_MODE}" == "ss" ]]; then
        # SS 中转模式配置
        cat > "${XRAY_CONFIG}" <<EOF
{
  "log": {
    "access": "${XRAY_LOG_DIR}/access.log",
    "error": "${XRAY_LOG_DIR}/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "127.0.0.1:8443",
          "xver": 1,
          "serverNames": [
            "${DOMAIN}"
          ],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": [
            "${SHORT_ID}"
          ]
        }
      }
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "outboundTag": "ss-out",
        "network": "tcp,udp"
      }
    ]
  },
  "outbounds": [
    {
      "protocol": "shadowsocks",
      "tag": "ss-out",
      "settings": {
        "servers": [
          {
            "address": "${LANDING_SERVER}",
            "port": ${LANDING_PORT},
            "method": "${SS_METHOD}",
            "password": "${SS_PASSWORD}"
          }
        ]
      }
    },
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
EOF
    else
        # 直连模式配置
        cat > "${XRAY_CONFIG}" <<EOF
{
  "log": {
    "access": "${XRAY_LOG_DIR}/access.log",
    "error": "${XRAY_LOG_DIR}/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": ${PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${UUID}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "127.0.0.1:8443",
          "xver": 1,
          "serverNames": [
            "${DOMAIN}"
          ],
          "privateKey": "${PRIVATE_KEY}",
          "shortIds": [
            "${SHORT_ID}"
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
EOF
    fi
    
    # 设置配置文件权限（644 允许 nobody 用户读取）
    chmod 644 "${XRAY_CONFIG}"
    save_install_step "xray_configured"
    print_success "Xray 配置完成: ${XRAY_CONFIG}"
    
    # 如果有备份，提示用户
    if [[ -n "${backup_file}" ]]; then
        print_info "原配置已备份，如需恢复: cp ${backup_file} ${XRAY_CONFIG}"
    fi
}

# 验证 Xray 配置
validate_xray_config() {
    print_info "验证 Xray 配置..."
    
    if [[ ! -f "${XRAY_CONFIG}" ]]; then
        print_error "配置文件不存在"
        return 1
    fi
    
    # Xray 25.12.8+ 移除了 'xray test' 命令
    # 改用 jq 验证 JSON 格式
    if command -v jq &>/dev/null; then
        if jq empty "${XRAY_CONFIG}" 2>/dev/null; then
            print_success "Xray 配置验证通过（JSON 格式正确）"
            return 0
        else
            print_error "Xray 配置验证失败（JSON 格式错误）"
            print_info "请检查配置文件: ${XRAY_CONFIG}"
            return 1
        fi
    else
        # 如果没有 jq，只检查文件是否存在且不为空
        if [[ -s "${XRAY_CONFIG}" ]]; then
            print_warn "跳过配置验证（jq 未安装），但配置文件存在"
            return 0
        else
            print_error "配置文件为空"
            return 1
        fi
    fi
}

#================== Caddy 安装与配置 ==================

# 检查 Caddy 是否已安装
check_caddy_installed() {
    if command -v caddy &>/dev/null; then
        return 0  # 已安装
    fi
    return 1  # 未安装
}

# 检查 Caddy 是否正在运行
check_caddy_running() {
    if systemctl is-active --quiet caddy; then
        return 0  # 正在运行
    fi
    return 1  # 未运行
}

# 检查 Caddy 生成的证书
check_caddy_certificates() {
    print_info "检查现有的 Caddy 证书..."
    
    # Caddy 证书存储位置
    local caddy_data_dir="/var/lib/caddy/.local/share/caddy"
    local caddy_cert_dir="${caddy_data_dir}/certificates"
    
    if [[ -d "${caddy_cert_dir}" ]]; then
        local cert_count
        cert_count=$(find "${caddy_cert_dir}" -name "*.crt" 2>/dev/null | wc -l)
        
        if [[ ${cert_count} -gt 0 ]]; then
            print_success "检测到 ${cert_count} 个现有证书"
            
            # 列出证书域名
            local domains
            domains=$(find "${caddy_cert_dir}" -name "*.crt" -type f 2>/dev/null | xargs -I {} basename {} .crt | head -5)
            if [[ -n "${domains}" ]]; then
                print_info "现有证书域名:"
                echo "${domains}" | while read -r domain; do
                    echo "  - ${domain}"
                done
            fi
            return 0  # 有证书
        fi
    fi
    
    print_info "未检测到现有证书"
    return 1  # 无证书
}

# 安装 Caddy
install_caddy() {
    print_info "检查 Caddy 状态..."
    
    if check_caddy_installed; then
        local version
        version=$(caddy version 2>&1 | head -1)
        print_success "检测到 Caddy 已安装: ${version}"
        
        # 检查是否正在运行
        if check_caddy_running; then
            print_success "Caddy 服务正在运行"
            
            # 检查证书
            check_caddy_certificates
            
            print_info "将保留现有的 Caddy 安装，仅修改配置"
            return 0
        else
            print_info "Caddy 已安装但未运行"
            read -p "是否重新安装 Caddy？(y/N): " reinstall
            if [[ "${reinstall}" != "y" && "${reinstall}" != "Y" ]]; then
                print_info "将使用现有安装，仅修改配置"
                return 0
            fi
        fi
    fi
    
    # 如果没有安装或用户选择重新安装，则进行安装
    print_info "开始安装 Caddy..."
    
    # 添加 Caddy 官方仓库
    print_info "添加 Caddy 官方仓库..."
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    
    # 安装 Caddy
    apt-get update -qq
    apt-get install caddy -y -qq >/dev/null 2>&1
    
    # 验证安装
    if check_caddy_installed; then
        local version
        version=$(caddy version 2>&1 | head -1)
        print_success "Caddy 安装成功: ${version}"
        systemctl enable caddy 2>/dev/null || true
        save_install_step "caddy_installed"
        return 0
    else
        print_error "Caddy 安装失败！"
        return 1
    fi
}

# 配置 Caddy（按用户要求的完整配置）
configure_caddy() {
    print_info "配置 Caddy..."
    
    # 创建日志目录
    mkdir -p "${CADDY_LOG_DIR}"
    mkdir -p "${CADDY_DIR}"
    
    # 设置 Caddy 日志目录权限（Caddy 以 caddy 用户运行）
    if id -u caddy &>/dev/null; then
        chown -R caddy:caddy "${CADDY_LOG_DIR}"
        chmod -R 755 "${CADDY_LOG_DIR}"
        print_info "已设置 Caddy 日志目录权限"
    fi
    
    # 声明备份文件变量
    local backup_file=""
    
    # 备份现有配置
    if [[ -f "${CADDY_CONFIG}" ]]; then
        backup_file="${CADDY_CONFIG}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "${CADDY_CONFIG}" "${backup_file}"
        print_info "已备份现有配置到: ${backup_file}"
        
        # 检查是否有现有域名配置
        if grep -q "^:8443," "${CADDY_CONFIG}" 2>/dev/null; then
            print_warn "检测到现有的 8443 端口配置"
            print_warn "新配置将覆盖现有配置以支持 Reality"
            
            # 给用户选择
            read -p "是否继续覆盖现有配置？(Y/n): " overwrite
            overwrite=${overwrite:-y}
            if [[ "${overwrite}" != "y" && "${overwrite}" != "Y" ]]; then
                print_info "保留现有配置，退出配置过程"
                return 1
            fi
        fi
    fi
    
    # 设置默认邮箱（如果用户没有提供）
    local email_config=""
    if [[ -n "${EMAIL}" ]]; then
        email_config="email ${EMAIL}"
    else
        # 自动生成随机邮箱
        local random_user
        random_user="user$(openssl rand -hex 4)"
        EMAIL="${random_user}@example.com"
        email_config="email ${EMAIL}"
        print_info "自动生成邮箱: ${EMAIL}"
    fi
    
    # 生成新的 Caddyfile
    cat > "${CADDY_CONFIG}" <<EOF
{
    admin off
    persist_config off
    log {
        output file ${CADDY_LOG_DIR}/error.log
        format console
        level ERROR
    }
    log log0 {
        output file ${CADDY_LOG_DIR}/access.log
        format console
        include http.log.access.log0
    }

    ${email_config}

    servers :80 {
        protocols h1
    }

    servers 127.0.0.1:8443 {
        listener_wrappers {
            proxy_protocol {
                allow 127.0.0.1/32
            }
            tls
        }
        protocols h1 h2
    }
}

:80 {
    redir https://{host}{uri} permanent
}

:8443, ${DOMAIN}:8443 {
    bind 127.0.0.1

    tls {
        ciphers TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    }

    log log0

    @host {
        host ${DOMAIN}
    }
    header @host {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    }
    file_server @host {
        root ${WEB_ROOT}
    }
}
EOF
    
    save_install_step "caddy_configured"
    print_success "Caddy 配置完成: ${CADDY_CONFIG}"
    
    # 如果有备份，提示用户
    if [[ -n "${backup_file}" ]]; then
        print_info "原配置已备份，如需恢复: cp ${backup_file} ${CADDY_CONFIG}"
    fi
}

# 验证 Caddy 配置
validate_caddy_config() {
    print_info "验证 Caddy 配置..."
    
    if [[ ! -f "${CADDY_CONFIG}" ]]; then
        print_error "Caddy 配置文件不存在"
        return 1
    fi
    
    # 使用 caddy 验证配置
    if caddy validate --config "${CADDY_CONFIG}" >/dev/null 2>&1; then
        print_success "Caddy 配置验证通过"
        return 0
    else
        print_error "Caddy 配置验证失败"
        caddy validate --config "${CADDY_CONFIG}"
        return 1
    fi
}

#================== 网站设置（多层级丰富内容） ==================

# 生成网站内容
setup_website() {
    print_info "生成伪装网站（多层级内容）..."
    
    # 创建目录结构
    mkdir -p "${WEB_ROOT}"/{css,js,images,assets}
    
    # 生成主页 (index.html)
    cat > "${WEB_ROOT}/index.html" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="专业的企业服务解决方案提供商">
    <title>企业服务解决方案 | 专业技术服务</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div class="logo">TechSolutions</div>
            <ul class="nav-menu">
                <li><a href="/">首页</a></li>
                <li><a href="/about.html">关于我们</a></li>
                <li><a href="/services.html">服务项目</a></li>
                <li><a href="/contact.html">联系方式</a></li>
            </ul>
        </div>
    </nav>

    <header class="hero">
        <div class="container">
            <h1 class="hero-title">专业的企业服务解决方案</h1>
            <p class="hero-subtitle">为您的企业提供全方位的技术支持与咨询服务</p>
            <a href="/services.html" class="btn-primary">了解我们的服务</a>
        </div>
    </header>

    <section class="features">
        <div class="container">
            <h2>我们的优势</h2>
            <div class="feature-grid">
                <div class="feature-item">
                    <h3>专业团队</h3>
                    <p>拥有10年以上行业经验的专业技术团队</p>
                </div>
                <div class="feature-item">
                    <h3>快速响应</h3>
                    <p>7×24小时全天候技术支持服务</p>
                </div>
                <div class="feature-item">
                    <h3>定制方案</h3>
                    <p>根据企业需求量身定制解决方案</p>
                </div>
            </div>
        </div>
    </section>

    <footer class="footer">
        <div class="container">
            <p>&copy; 2024 TechSolutions. All rights reserved.</p>
        </div>
    </footer>

    <script src="/js/main.js"></script>
</body>
</html>
HTMLEOF

    # 生成关于页面 (about.html)
    cat > "${WEB_ROOT}/about.html" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>关于我们 | TechSolutions</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div class="logo">TechSolutions</div>
            <ul class="nav-menu">
                <li><a href="/">首页</a></li>
                <li><a href="/about.html" class="active">关于我们</a></li>
                <li><a href="/services.html">服务项目</a></li>
                <li><a href="/contact.html">联系方式</a></li>
            </ul>
        </div>
    </nav>

    <section class="content">
        <div class="container">
            <h1>关于我们</h1>
            <p>TechSolutions 成立于2014年，是一家专注于为企业提供全方位技术解决方案的专业服务商。</p>
            <p>我们的团队由经验丰富的技术专家组成，致力于帮助企业实现数字化转型，提升运营效率。</p>
            
            <h2>我们的使命</h2>
            <p>通过创新的技术和专业的服务，帮助客户在数字时代保持竞争优势。</p>
            
            <h2>核心价值观</h2>
            <ul>
                <li>客户至上：始终将客户需求放在首位</li>
                <li>专业创新：不断追求技术创新和卓越</li>
                <li>诚信合作：建立长期互信的合作关系</li>
                <li>持续改进：不断优化服务质量</li>
            </ul>
        </div>
    </section>

    <footer class="footer">
        <div class="container">
            <p>&copy; 2024 TechSolutions. All rights reserved.</p>
        </div>
    </footer>

    <script src="/js/main.js"></script>
</body>
</html>
HTMLEOF

    # 生成服务页面 (services.html)
    cat > "${WEB_ROOT}/services.html" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>服务项目 | TechSolutions</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div class="logo">TechSolutions</div>
            <ul class="nav-menu">
                <li><a href="/">首页</a></li>
                <li><a href="/about.html">关于我们</a></li>
                <li><a href="/services.html" class="active">服务项目</a></li>
                <li><a href="/contact.html">联系方式</a></li>
            </ul>
        </div>
    </nav>

    <section class="content">
        <div class="container">
            <h1>服务项目</h1>
            
            <div class="service-item">
                <h2>云计算解决方案</h2>
                <p>提供全面的云基础设施规划、迁移和管理服务，帮助企业实现云端部署。</p>
            </div>
            
            <div class="service-item">
                <h2>网络安全服务</h2>
                <p>专业的安全评估、渗透测试和安全加固服务，保护您的数字资产。</p>
            </div>
            
            <div class="service-item">
                <h2>数据分析与BI</h2>
                <p>通过先进的数据分析工具，帮助企业挖掘数据价值，支持业务决策。</p>
            </div>
            
            <div class="service-item">
                <h2>DevOps咨询</h2>
                <p>协助企业建立高效的DevOps流程，提升软件交付速度和质量。</p>
            </div>
            
            <div class="service-item">
                <h2>技术培训</h2>
                <p>为企业团队提供定制化的技术培训课程，提升技术能力。</p>
            </div>
        </div>
    </section>

    <footer class="footer">
        <div class="container">
            <p>&copy; 2024 TechSolutions. All rights reserved.</p>
        </div>
    </footer>

    <script src="/js/main.js"></script>
</body>
</html>
HTMLEOF

    # 生成联系页面 (contact.html)
    cat > "${WEB_ROOT}/contact.html" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>联系方式 | TechSolutions</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div class="logo">TechSolutions</div>
            <ul class="nav-menu">
                <li><a href="/">首页</a></li>
                <li><a href="/about.html">关于我们</a></li>
                <li><a href="/services.html">服务项目</a></li>
                <li><a href="/contact.html" class="active">联系方式</a></li>
            </ul>
        </div>
    </nav>

    <section class="content">
        <div class="container">
            <h1>联系我们</h1>
            <p>如果您对我们的服务感兴趣，欢迎通过以下方式与我们联系：</p>
            
            <div class="contact-info">
                <h2>公司信息</h2>
                <p><strong>公司名称:</strong> TechSolutions</p>
                <p><strong>电子邮箱:</strong> contact@techsolutions.example.com</p>
                <p><strong>服务时间:</strong> 周一至周五 9:00-18:00</p>
                
                <h2>业务咨询</h2>
                <p>我们的专业团队随时准备为您提供技术咨询和解决方案。</p>
                <p>请通过邮件联系我们，我们将在24小时内回复您的询问。</p>
            </div>
        </div>
    </section>

    <footer class="footer">
        <div class="container">
            <p>&copy; 2024 TechSolutions. All rights reserved.</p>
        </div>
    </footer>

    <script src="/js/main.js"></script>
</body>
</html>
HTMLEOF

    # 生成 CSS 样式
    cat > "${WEB_ROOT}/css/style.css" <<'CSSEOF'
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    line-height: 1.6;
    color: #333;
    background: #f5f5f5;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 20px;
}

/* 导航栏 */
.navbar {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 1rem 0;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    position: sticky;
    top: 0;
    z-index: 1000;
}

.navbar .container {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logo {
    font-size: 1.5rem;
    font-weight: bold;
    color: white;
}

.nav-menu {
    display: flex;
    list-style: none;
    gap: 2rem;
}

.nav-menu a {
    color: white;
    text-decoration: none;
    transition: opacity 0.3s;
}

.nav-menu a:hover,
.nav-menu a.active {
    opacity: 0.8;
    text-decoration: underline;
}

/* 英雄区域 */
.hero {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 6rem 0;
    text-align: center;
}

.hero-title {
    font-size: 3rem;
    margin-bottom: 1rem;
    animation: fadeInUp 1s;
}

.hero-subtitle {
    font-size: 1.3rem;
    margin-bottom: 2rem;
    animation: fadeInUp 1s 0.2s both;
}

.btn-primary {
    display: inline-block;
    padding: 12px 30px;
    background: white;
    color: #667eea;
    text-decoration: none;
    border-radius: 25px;
    font-weight: bold;
    transition: transform 0.3s, box-shadow 0.3s;
    animation: fadeInUp 1s 0.4s both;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 20px rgba(0,0,0,0.2);
}

/* 特性区域 */
.features {
    padding: 4rem 0;
    background: white;
}

.features h2 {
    text-align: center;
    font-size: 2rem;
    margin-bottom: 3rem;
    color: #667eea;
}

.feature-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 2rem;
}

.feature-item {
    padding: 2rem;
    background: #f8f9fa;
    border-radius: 10px;
    text-align: center;
    transition: transform 0.3s, box-shadow 0.3s;
}

.feature-item:hover {
    transform: translateY(-5px);
    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
}

.feature-item h3 {
    color: #667eea;
    margin-bottom: 1rem;
}

/* 内容区域 */
.content {
    padding: 4rem 0;
    background: white;
    min-height: 60vh;
}

.content h1 {
    color: #667eea;
    margin-bottom: 2rem;
    font-size: 2.5rem;
}

.content h2 {
    color: #764ba2;
    margin-top: 2rem;
    margin-bottom: 1rem;
}

.content p {
    margin-bottom: 1rem;
    line-height: 1.8;
}

.content ul {
    margin-left: 2rem;
    margin-bottom: 1rem;
}

.content ul li {
    margin-bottom: 0.5rem;
}

.service-item {
    padding: 2rem;
    background: #f8f9fa;
    border-radius: 10px;
    margin-bottom: 2rem;
    border-left: 4px solid #667eea;
}

.contact-info {
    background: #f8f9fa;
    padding: 2rem;
    border-radius: 10px;
}

.contact-info p {
    margin-bottom: 1rem;
}

/* 页脚 */
.footer {
    background: #2c3e50;
    color: white;
    text-align: center;
    padding: 2rem 0;
    margin-top: 4rem;
}

/* 动画 */
@keyframes fadeInUp {
    from {
        opacity: 0;
        transform: translateY(30px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

/* 响应式设计 */
@media (max-width: 768px) {
    .navbar .container {
        flex-direction: column;
        gap: 1rem;
    }
    
    .hero-title {
        font-size: 2rem;
    }
    
    .hero-subtitle {
        font-size: 1rem;
    }
    
    .nav-menu {
        flex-direction: column;
        gap: 0.5rem;
    }
}
CSSEOF

    # 生成 JavaScript
    cat > "${WEB_ROOT}/js/main.js" <<'JSEOF'
// 平滑滚动
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// 页面加载动画
window.addEventListener('load', () => {
    document.body.classList.add('loaded');
});

// 简单的表单验证（如果有表单）
const forms = document.querySelectorAll('form');
forms.forEach(form => {
    form.addEventListener('submit', (e) => {
        const inputs = form.querySelectorAll('input[required]');
        let isValid = true;
        
        inputs.forEach(input => {
            if (!input.value.trim()) {
                isValid = false;
                input.style.borderColor = 'red';
            } else {
                input.style.borderColor = '';
            }
        });
        
        if (!isValid) {
            e.preventDefault();
            alert('请填写所有必填字段');
        }
    });
});

console.log('TechSolutions Website Loaded Successfully');
JSEOF

    # 生成占位图片 (SVG)
    cat > "${WEB_ROOT}/images/placeholder.svg" <<'SVGEOF'
<svg width="400" height="300" xmlns="http://www.w3.org/2000/svg">
  <rect fill="#667eea" width="400" height="300"/>
  <text fill="#ffffff" font-family="Arial" font-size="24" x="50%" y="50%" text-anchor="middle" dy=".3em">TechSolutions</text>
</svg>
SVGEOF

    # 设置权限
    chown -R www-data:www-data "${WEB_ROOT}" 2>/dev/null || true
    chmod -R 755 "${WEB_ROOT}"
    
    save_install_step "website_created"
    print_success "网站内容生成完成"
    print_info "生成了4个HTML页面、CSS、JavaScript和图片"
}

#================== 服务管理 ==================

# 启动服务
start_services() {
    print_info "启动服务..."
    
    # 启动 Caddy
    print_info "启动 Caddy..."
    systemctl restart caddy
    sleep 2
    
    if systemctl is-active --quiet caddy; then
        print_success "Caddy 服务启动成功"
    else
        print_error "Caddy 服务启动失败"
        print_info "查看日志: journalctl -u caddy -n 50"
        return 1
    fi
    
    # 启动 Xray
    print_info "启动 Xray..."
    systemctl restart xray
    sleep 2
    
    if systemctl is-active --quiet xray; then
        print_success "Xray 服务启动成功"
    else
        print_error "Xray 服务启动失败"
        print_info "查看日志: journalctl -u xray -n 50"
        return 1
    fi
    
    print_success "所有服务启动成功"
    return 0
}

# 重启服务
restart_services() {
    print_info "重启服务..."
    
    systemctl restart caddy xray
    sleep 2
    
    local status=0
    if ! systemctl is-active --quiet caddy; then
        print_error "Caddy 重启失败"
        status=1
    else
        print_success "Caddy 重启成功"
    fi
    
    if ! systemctl is-active --quiet xray; then
        print_error "Xray 重启失败"
        status=1
    else
        print_success "Xray 重启成功"
    fi
    
    return ${status}
}

#================== 健康检查 ==================

# 健康检查
health_check() {
    print_separator
    echo -e "${CYAN}系统健康检查${NC}"
    print_separator
    
    local health_status=0
    
    # 1. 检查 Xray 二进制文件
    echo -n "1. 检查 Xray 二进制文件... "
    if [[ -f "${XRAY_BIN}" ]] && [[ -x "${XRAY_BIN}" ]]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        health_status=1
    fi
    
    # 2. 检查 Xray 配置文件
    echo -n "2. 检查 Xray 配置文件... "
    if [[ -f "${XRAY_CONFIG}" ]]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        health_status=1
    fi
    
    # 3. 检查 Caddy 配置文件
    echo -n "3. 检查 Caddy 配置文件... "
    if [[ -f "${CADDY_CONFIG}" ]]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        health_status=1
    fi
    
    # 4. 检查 Xray 服务状态
    echo -n "4. 检查 Xray 服务状态... "
    if systemctl is-active --quiet xray; then
        echo -e "${GREEN}✓ (运行中)${NC}"
    else
        echo -e "${RED}✗ (未运行)${NC}"
        health_status=1
    fi
    
    # 5. 检查 Caddy 服务状态
    echo -n "5. 检查 Caddy 服务状态... "
    if systemctl is-active --quiet caddy; then
        echo -e "${GREEN}✓ (运行中)${NC}"
    else
        echo -e "${RED}✗ (未运行)${NC}"
        health_status=1
    fi
    
    # 6. 检查端口 443 监听
    echo -n "6. 检查端口 443 监听... "
    if ss -tlnp 2>/dev/null | grep -q ":443 " || netstat -tlnp 2>/dev/null | grep -q ":443 "; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}! (未监听)${NC}"
        health_status=1
    fi
    
    # 7. 检查端口 80 监听
    echo -n "7. 检查端口 80 监听... "
    if ss -tlnp 2>/dev/null | grep -q ":80 " || netstat -tlnp 2>/dev/null | grep -q ":80 "; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}! (未监听)${NC}"
    fi
    
    # 8. 检查端口 8443 监听
    echo -n "8. 检查端口 8443 监听... "
    if ss -tlnp 2>/dev/null | grep -q "127.0.0.1:8443 "; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}! (未监听)${NC}"
    fi
    
    # 9. 检查网站文件
    echo -n "9. 检查网站文件... "
    if [[ -f "${WEB_ROOT}/index.html" ]]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        health_status=1
    fi
    
    # 10. 检查日志文件可写
    echo -n "10. 检查日志目录... "
    if [[ -d "${XRAY_LOG_DIR}" ]] && [[ -d "${CADDY_LOG_DIR}" ]]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}! (部分缺失)${NC}"
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
    local server_ip
    server_ip=$(curl -s -4 --max-time 10 https://api.ipify.org 2>/dev/null || echo "请手动检查")
    
    # 生成 VLESS 链接
    local vless_link="vless://${UUID}@${server_ip}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#Reality-${DOMAIN}"
    
    cat > "${INFO_FILE}" <<EOF
========================================================================
                  Xray Reality 连接信息
========================================================================

服务器地址: ${server_ip}
端口: ${PORT}
UUID: ${UUID}
Public Key: ${PUBLIC_KEY}
Short ID: ${SHORT_ID}
ServerName (SNI): ${DOMAIN}
Flow: xtls-rprx-vision
Network: tcp
Security: reality

VLESS 链接:
${vless_link}

========================================================================
服务管理命令:
========================================================================
查看 Xray 状态: systemctl status xray
查看 Xray 日志: journalctl -u xray -f
重启 Xray: systemctl restart xray

查看 Caddy 状态: systemctl status caddy
查看 Caddy 日志: journalctl -u caddy -f
重启 Caddy: systemctl restart caddy

========================================================================
配置文件位置:
========================================================================
Xray 配置: ${XRAY_CONFIG}
Caddy 配置: ${CADDY_CONFIG}
网站目录: ${WEB_ROOT}
备份目录: ${BACKUP_DIR}

安装时间: $(date '+%Y-%m-%d %H:%M:%S')
========================================================================
EOF
    
    chmod 600 "${INFO_FILE}"
}

# 显示连接信息
show_connection_info() {
    if [[ ! -f "${INFO_FILE}" ]]; then
        print_error "连接信息文件不存在，请先安装"
        return 1
    fi
    
    clear
    cat "${INFO_FILE}"
    echo ""
    print_info "连接信息已保存到: ${INFO_FILE}"
}

#================== 卸载功能 ==================

# 检测已安装组件
detect_components() {
    local components=()
    
    [[ -f "${XRAY_BIN}" ]] && components+=("Xray")
    command -v caddy &>/dev/null && components+=("Caddy")
    [[ -f "${XRAY_CONFIG}" ]] && components+=("Xray配置")
    [[ -f "${CADDY_CONFIG}" ]] && components+=("Caddy配置")
    [[ -d "${WEB_ROOT}" ]] && [[ -f "${WEB_ROOT}/index.html" ]] && components+=("网站文件")
    [[ -d "${BACKUP_DIR}" ]] && components+=("备份文件")
    
    echo "${components[@]}"
}

# 卸载所有组件
uninstall_all() {
    print_separator
    print_warn "⚠️  即将卸载 Xray Reality + Caddy"
    print_separator
    
    # 检测已安装组件
    local components
    components=($(detect_components))
    
    if [[ ${#components[@]} -eq 0 ]]; then
        print_info "未检测到已安装的组件"
        return 0
    fi
    
    echo ""
    echo -e "${YELLOW}检测到以下组件:${NC}"
    for comp in "${components[@]}"; do
        echo "  - ${comp}"
    done
    echo ""
    
    # 确认卸载
    print_warn "此操作将删除所有相关文件和配置"
    read -p "是否继续？(yes/no): " confirm
    
    if [[ "${confirm}" != "yes" ]]; then
        print_info "已取消卸载"
        return 0
    fi
    
    # 询问是否备份配置
    if [[ -f "${XRAY_CONFIG}" ]] || [[ -f "${CADDY_CONFIG}" ]]; then
        echo ""
        read -p "是否在删除前备份配置文件？(Y/n): " backup_choice
        backup_choice=${backup_choice:-y}
        
        if [[ "${backup_choice}" == "y" || "${backup_choice}" == "Y" ]]; then
            local temp_backup
            temp_backup="/tmp/reality_backup_$(date +%s)"
            mkdir -p "${temp_backup}"
            [[ -f "${XRAY_CONFIG}" ]] && cp "${XRAY_CONFIG}" "${temp_backup}/"
            [[ -f "${CADDY_CONFIG}" ]] && cp "${CADDY_CONFIG}" "${temp_backup}/"
            print_info "配置已备份到: ${temp_backup}"
        fi
    fi
    
    print_info "开始卸载..."
    echo ""
    
    # 1. 停止服务
    print_info "停止服务..."
    systemctl stop xray 2>/dev/null || true
    systemctl stop caddy 2>/dev/null || true
    
    # 2. 禁用服务
    print_info "禁用服务..."
    systemctl disable xray 2>/dev/null || true
    systemctl disable caddy 2>/dev/null || true
    
    # 3. 卸载 Xray
    if [[ -f "${XRAY_BIN}" ]]; then
        print_info "卸载 Xray..."
        bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) remove --purge 2>/dev/null || true
        rm -rf "${XRAY_DIR}"
        rm -rf "${XRAY_LOG_DIR}"
        rm -f "${XRAY_SERVICE}"
    fi
    
    # 4. 卸载 Caddy
    if command -v caddy &>/dev/null; then
        print_info "卸载 Caddy..."
        apt-get remove --purge -y caddy 2>/dev/null || true
        rm -rf "${CADDY_DIR}"
        rm -rf "${CADDY_LOG_DIR}"
    fi
    
    # 5. 删除网站文件
    if [[ -d "${WEB_ROOT}" ]]; then
        print_info "删除网站文件..."
        rm -rf "${WEB_ROOT:?}"/*
    fi
    
    # 6. 清理仓库配置
    rm -f /etc/apt/sources.list.d/caddy-stable.list
    rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    
    # 7. 清理状态文件
    clear_install_state
    
    systemctl daemon-reload
    
    echo ""
    print_separator
    print_success "✅ 卸载完成"
    print_separator
    echo ""
    print_info "已删除内容:"
    print_info "  - Xray 和相关配置"
    print_info "  - Caddy 和相关配置"
    print_info "  - 网站文件"
    print_info "  - 服务文件"
    echo ""
}

#================== 用户交互 ==================

# 获取用户输入
get_user_input() {
    print_separator
    echo -e "${GREEN}Xray Reality + Caddy 配置${NC}"
    print_separator
    
    # 获取域名
    while true; do
        echo ""
        read -p "请输入域名（如 example.com）: " DOMAIN
        if [[ -z "${DOMAIN}" ]]; then
            print_error "域名不能为空！"
            continue
        fi
        
        # 简单的域名格式验证
        if [[ ! "${DOMAIN}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            print_error "域名格式不正确！"
            continue
        fi
        
        break
    done
    
    # 获取邮箱（可选,用于 Caddy）
    echo ""
    read -p "请输入邮箱（用于 Caddy，可选，直接回车跳过）: " EMAIL
    if [[ -n "${EMAIL}" ]]; then
        print_info "邮箱: ${EMAIL}"
    else
        print_info "邮箱: 未设置"
    fi
    
    # 确认配置
    echo ""
    print_separator
    echo -e "${YELLOW}请确认以下配置：${NC}"
    print_separator
    echo "域名: ${DOMAIN}"
    echo "端口: ${PORT}"
    if [[ -n "${EMAIL}" ]]; then
        echo "邮箱: ${EMAIL}"
    fi
    echo "协议: VLESS + Vision + Reality"
    echo "后置: Caddy with PROXY Protocol"
    print_separator
    
    read -p "确认无误？(Y/n): " confirm
    confirm=${confirm:-y}
    
    if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
        print_info "已取消安装"
        exit 0
    fi
}

#================== 菜单系统 ==================

# 显示菜单
show_menu() {
    clear
    print_separator
    echo -e "${GREEN}Xray Reality + Caddy 管理脚本${NC}"
    echo -e "${BLUE}系统: $(uname -s) $(uname -m)${NC}"
    print_separator
    echo ""
    echo "1. 安装 Reality"
    echo "2. 卸载 Reality"
    echo "3. 查看连接信息"
    echo "4. 查看服务状态"
    echo "5. 重启服务"
    echo "6. 查看日志"
    echo "7. 健康检查"
    echo "0. 退出"
    echo ""
    print_separator
}

# 查看服务状态
view_service_status() {
    print_separator
    echo -e "${CYAN}服务状态${NC}"
    print_separator
    echo ""
    echo -e "${YELLOW}=== Xray 状态 ===${NC}"
    systemctl status xray --no-pager
    echo ""
    echo -e "${YELLOW}=== Caddy 状态 ===${NC}"
    systemctl status caddy --no-pager
    print_separator
}

# 查看日志
view_logs() {
    print_separator
    echo -e "${CYAN}服务日志（最后 30 行）${NC}"
    print_separator
    echo ""
    echo -e "${YELLOW}=== Xray 日志 ===${NC}"
    journalctl -u xray -n 30 --no-pager
    echo ""
    echo -e "${YELLOW}=== Caddy 日志 ===${NC}"
    journalctl -u caddy -n 30 --no-pager
    print_separator
}

#================== 安装流程 ==================

# 完整安装流程
install_process() {
    clear
    print_separator
    echo -e "${GREEN}开始安装 Xray Reality + Caddy${NC}"
    print_separator
    echo ""
    
    # 获取用户输入
    get_user_input
    
    echo ""
    print_info "开始安装..."
    echo ""
    
    # 执行安装步骤
    check_system
    install_dependencies
    install_xray || exit 1
    install_caddy || exit 1
    generate_reality_keys || exit 1
    configure_xray
    validate_xray_config || exit 1
    configure_caddy
    validate_caddy_config || exit 1
    setup_website
    start_services || exit 1
    
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
    print_warn "⚠️  请确保防火墙开放以下端口:"
    echo "  - TCP 80 (HTTP)"
    echo "  - TCP 443 (Reality)"
    echo ""
    print_info "UFW 示例:"
    echo "  ufw allow 80/tcp"
    echo "  ufw allow 443/tcp"
    echo ""
    print_info "Firewalld 示例:"
    echo "  firewall-cmd --permanent --add-port=80/tcp"
    echo "  firewall-cmd --permanent --add-port=443/tcp"
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
        read -p "请选择操作 [0-7]: " choice
        
        case "${choice}" in
            1)
                # 启用错误陷阱（安装模式）
                trap 'error_handler ${LINENO}' ERR
                install_process
                trap - ERR
                read -p "按回车键继续..."
                ;;
            2)
                uninstall_all
                read -p "按回车键继续..."
                ;;
            3)
                show_connection_info
                read -p "按回车键继续..."
                ;;
            4)
                view_service_status
                read -p "按回车键继续..."
                ;;
            5)
                restart_services
                read -p "按回车键继续..."
                ;;
            6)
                view_logs
                read -p "按回车键继续..."
                ;;
            7)
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
