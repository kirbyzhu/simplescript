#!/bin/bash

#================================================================
# Nginx SNI + Xray 多协议管理系统 (SAN证书版)
# 
# 功能：模块化部署 Nginx (SNI分流) + Xray (多协议)
# 核心特性：
#   - SAN多域名证书：一次性申请包含所有子域名的证书
#   - 简化子域名：使用vlx/vmx/trox/xhx/realx等短格式
#   - "偷自己"架构：Reality dest 指向本地 nginx_web.sock（伪装站）
#   - 协议热插拔：动态添加/删除协议（最多5个）
#   - SNI精确分流：不同域名对应不同协议
#   - 共享证书管理：所有协议使用统一SAN证书
#   - 复杂伪装网站：多页面、响应式、动态生成
#
# 作者：AI Enhanced
# 系统：Debian/Ubuntu
#================================================================

set -euo pipefail

#================== 全局变量 ==================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 路径配置
NGINX_DIR="/etc/nginx"
NGINX_CONF="${NGINX_DIR}/nginx.conf"
NGINX_SSL_DIR="${NGINX_DIR}/ssl"
NGINX_CONF_D="${NGINX_DIR}/conf.d"

XRAY_DIR="/usr/local/etc/xray"
XRAY_CONFIG="${XRAY_DIR}/config.json"
XRAY_BIN="/usr/local/bin/xray"

FAKE_SITE_ROOT="/var/www/fake-site"
ACME_DIR="/var/www/acme"

PROTOCOLS_DB="${XRAY_DIR}/protocols.json"
MAX_PROTOCOLS=5

# Reality 基础端口（监听Unix Socket）
REALITY_PORT=8443
# 注：伪装站使用 /dev/shm/nginx_web.sock，不使用TCP端口

#================== 工具函数 ==================

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
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

print_separator() {
    echo "========================================================================"
}

# 验证域名格式
validate_domain() {
    local domain=$1
    # 检查长度
    if [[ ${#domain} -gt 253 ]]; then
        return 1
    fi
    # 简单的域名正则：字母数字横线组合，点号分隔，至少两级
    if [[ ! "${domain}" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        return 1
    fi
    return 0
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "此脚本必须以 root 权限运行"
        exit 1
    fi
}

check_system() {
    if ! command -v apt-get &>/dev/null; then
        print_error "此脚本仅支持 Debian/Ubuntu 系统"
        exit 1
    fi
    print_success "系统检查通过"
}

#================== 协议数据库管理 ==================

init_protocols_db() {
    if [[ ! -f "${PROTOCOLS_DB}" ]]; then
        mkdir -p "$(dirname "${PROTOCOLS_DB}")"
        cat > "${PROTOCOLS_DB}" <<'EOF'
{
  "protocols": [],
  "max_protocols": 5,
  "next_port": 8001
}
EOF
        print_success "协议数据库已初始化"
    fi
}

get_protocol_count() {
    jq '.protocols | length' "${PROTOCOLS_DB}" 2>/dev/null || echo "0"
}

add_protocol_to_db() {
    local domain=$1
    local type=$2
    local port=$3
    local uuid=$4
    local path=${5:-""}
    
    local tmp_file="/tmp/protocols_db.tmp"
    
    jq --arg domain "${domain}" \
       --arg type "${type}" \
       --arg port "${port}" \
       --arg uuid "${uuid}" \
       --arg path "${path}" \
       '.protocols += [{
           "domain": $domain,
           "type": $type,
           "port": ($port | tonumber),
           "uuid": $uuid,
           "path": $path,
           "enabled": true,
           "created_at": (now | strftime("%Y-%m-%d %H:%M:%S"))
       }]' "${PROTOCOLS_DB}" > "${tmp_file}"
    
    mv "${tmp_file}" "${PROTOCOLS_DB}"
}

remove_protocol_from_db() {
    local domain=$1
    local tmp_file="/tmp/protocols_db.tmp"
    
    jq --arg domain "${domain}" \
       '.protocols = [.protocols[] | select(.domain != $domain)]' \
       "${PROTOCOLS_DB}" > "${tmp_file}"
    
    mv "${tmp_file}" "${PROTOCOLS_DB}"
}

list_protocols() {
    if [[ ! -f "${PROTOCOLS_DB}" ]]; then
        print_info "暂无已安装的协议"
        return
    fi
    
    local count
    count=$(get_protocol_count)
    
    if [[ ${count} -eq 0 ]]; then
        print_info "暂无已安装的协议"
        return
    fi
    
    print_separator
    echo -e "${CYAN}已安装协议列表 (${count}/${MAX_PROTOCOLS})${NC}"
    print_separator
    
    printf "%-25s %-15s %-8s %-22s %-38s\n" "域名" "协议类型" "端口" "多路复用(Mux)" "UUID"
    printf "%-25s %-15s %-8s %-22s %-38s\n" "-------------------------" "---------------" "--------" "----------------------" "--------------------------------------"
    # 读取协议列表
    local protocols
    protocols=$(jq -r '.protocols[] | "\(.domain)|\(.type)|\(.port)|\(.uuid)"' "${PROTOCOLS_DB}" 2>/dev/null) || true
    echo "${protocols}" | while IFS='|' read -r domain type port uuid; do
        local mux_note=""
        case "${type}" in
            "xhttp-vless"|"xhttp-reality")
                mux_note="✅ 原生支持 (H2)"
                ;;
            "reality")
                mux_note="✅ 支持 (需Client开启)"
                ;;
            "ws-vless"|"ws-vmess")
                mux_note="⚠️ 不建议开启"
                ;;
            *)
                mux_note="-"
                ;;
        esac
        printf "%-25s %-15s %-8s %-22s %-38s\n" "${domain}" "${type}" "${port}" "${mux_note}" "${uuid}"
    done
    
    print_separator
}

#================== 安装依赖 ==================

install_dependencies() {
    print_info "安装依赖包..."
    
    apt-get update -qq
    
    local deps="wget curl tar jq socat ca-certificates build-essential libpcre3-dev zlib1g-dev libssl-dev"
    
    for pkg in ${deps}; do
        if ! dpkg -l | grep -q "^ii  ${pkg}"; then
            print_info "安装 ${pkg}..."
            apt-get install -y -qq "${pkg}" >/dev/null 2>&1
        fi
    done
    
    print_success "依赖安装完成"
}

#================== Nginx 安装 ==================

install_nginx() {
    print_info "开始安装 Nginx (含 stream_ssl_preread 模块)..."
    
    # 检查是否已安装
    if command -v nginx &>/dev/null; then
        local version
        version=$(nginx -v 2>&1 | grep -oP 'nginx/\K[0-9.]+')
        print_warn "检测到已安装的 Nginx: ${version}"
        
        # 检查是否有必需模块
        if nginx -V 2>&1 | grep -q "stream_ssl_preread"; then
            print_success "Nginx 已安装且包含所需模块"
            return 0
        else
            print_warn "已安装的 Nginx 缺少 stream_ssl_preread 模块，需要重新安装"
        fi
    fi
    
    # 优先尝试从官方 Nginx 仓库安装预编译包
    print_info "尝试从官方 Nginx 仓库安装 (推荐方式，无需编译)..."
    
    if install_nginx_from_repo; then
        return 0
    fi
    
    # 如果仓库安装失败，回退到单线程编译
    print_warn "仓库安装失败，回退到源码编译 (单线程，内存友好)..."
    install_nginx_from_source_single_thread
}

# 从官方 Nginx 仓库安装
install_nginx_from_repo() {
    # 安装依赖
    apt-get install -y -qq curl gnupg2 ca-certificates lsb-release debian-archive-keyring >/dev/null 2>&1 || true
    
    # 添加 Nginx 官方 GPG 密钥
    if ! curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg 2>/dev/null; then
        print_warn "无法添加 Nginx GPG 密钥"
        return 1
    fi
    
    # 添加 Nginx 官方仓库 (mainline 版本包含所有模块)
    local os_codename
    os_codename=$(lsb_release -cs 2>/dev/null || echo "bookworm")
    
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/mainline/debian ${os_codename} nginx" \
        > /etc/apt/sources.list.d/nginx.list
    
    # 设置仓库优先级
    echo -e "Package: *\nPin: origin nginx.org\nPin-Priority: 900" \
        > /etc/apt/preferences.d/99nginx
    
    # 更新并安装
    apt-get update -qq >/dev/null 2>&1
    
    if ! apt-get install -y nginx >/dev/null 2>&1; then
        print_warn "apt 安装 Nginx 失败"
        return 1
    fi
    
    # 验证安装
    if ! command -v nginx &>/dev/null; then
        print_warn "Nginx 命令不可用"
        return 1
    fi
    
    # 验证模块
    if ! nginx -V 2>&1 | grep -q "stream_ssl_preread"; then
        print_warn "安装的 Nginx 缺少 stream_ssl_preread 模块"
        return 1
    fi
    
    # 确保服务已启用
    systemctl enable nginx >/dev/null 2>&1 || true
    
    print_success "Nginx 从官方仓库安装成功"
    nginx -V 2>&1 | head -1 || true
    return 0
}

# 单线程源码编译 (内存友好)
install_nginx_from_source_single_thread() {
    print_info "开始单线程编译安装 Nginx..."
    
    local nginx_version="1.26.0"
    local workdir="/tmp/nginx-build"
    
    mkdir -p "${workdir}"
    cd "${workdir}" || return 1
    
    # 下载 Nginx
    print_info "下载 Nginx ${nginx_version}..."
    if ! wget -q "https://nginx.org/download/nginx-${nginx_version}.tar.gz"; then
        print_error "Nginx 下载失败"
        return 1
    fi
    
    tar -xzf "nginx-${nginx_version}.tar.gz"
    cd "nginx-${nginx_version}" || return 1
    
    # 配置编译选项
    print_info "配置编译选项..."
    if ! ./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --modules-path=/usr/lib/nginx/modules \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/var/run/nginx.pid \
        --lock-path=/var/run/nginx.lock \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-stream \
        --with-stream_ssl_module \
        --with-stream_ssl_preread_module \
        --with-http_realip_module \
        >/dev/null 2>&1; then
        print_error "Nginx 配置失败"
        cd / && rm -rf "${workdir}"
        return 1
    fi
    
    # 单线程编译 (省内存)
    print_info "单线程编译中（可能需要较长时间）..."
    if ! make -j1 >/dev/null 2>&1; then
        print_error "Nginx 编译失败 (内存不足？建议增加 Swap)"
        cd / && rm -rf "${workdir}"
        return 1
    fi
    
    # 安装
    print_info "安装 Nginx..."
    if ! make install >/dev/null 2>&1; then
        print_error "Nginx 安装失败"
        cd / && rm -rf "${workdir}"
        return 1
    fi
    
    # 创建 systemd 服务
    cat > /etc/systemd/system/nginx.service <<'EOF'
[Unit]
Description=Nginx HTTP and reverse proxy server
After=network.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable nginx
    
    # 清理
    cd /
    rm -rf "${workdir}"
    
    # 验证安装
    if ! command -v nginx &>/dev/null; then
        print_error "Nginx 安装验证失败"
        return 1
    fi
    
    print_success "Nginx 单线程编译安装完成"
    nginx -V 2>&1 | head -1 || true
}

#================== Xray 安装 ==================

install_xray() {
    print_info "安装 Xray..."
    
    if [[ -f "${XRAY_BIN}" ]]; then
        print_warn "检测到已安装的 Xray"
        return 0
    fi
    
    bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) install
    
    systemctl enable xray
    print_success "Xray 安装完成"
}

#================== acme.sh 安装 ==================

install_acme() {
    print_info "安装 acme.sh..."
    
    if [[ -f "${HOME}/.acme.sh/acme.sh" ]]; then
        print_warn "acme.sh 已安装"
        return 0
    fi
    
    # 安装 acme.sh (不指定邮箱，后续注册时也不需要)
    curl -s https://get.acme.sh | sh -s >/dev/null 2>&1
    
    # 配置默认CA
    "${HOME}/.acme.sh/acme.sh" --set-default-ca --server letsencrypt
    
    # 注册账户 (不提供邮箱，避免 example.com 问题)
    "${HOME}/.acme.sh/acme.sh" --register-account >/dev/null 2>&1 || true
    
    print_success "acme.sh 安装完成"
}

#================== SAN 多域名证书申请 ==================

# 申请 SAN 多域名证书（包含所有子域名）
request_cert_san() {
    local base_domain=$1
    
    print_info "申请 SAN 多域名证书（包含所有协议子域名）..."
    
    # 获取所有域名
    local domains=()
    while IFS= read -r domain; do
        domains+=("${domain}")
    done < <(get_all_planned_domains "${base_domain}")
    
    print_info "证书将包含以下 ${#domains[@]} 个域名："
    for domain in "${domains[@]}"; do
        echo "  - ${domain}"
    done
    
    # 创建证书目录
    mkdir -p "${NGINX_SSL_DIR}/${base_domain}"
    chmod 700 "${NGINX_SSL_DIR}/${base_domain}"
    mkdir -p "${ACME_DIR}"
    
    # 检查现有证书
    local need_issue=true
    
    if [[ -f "${NGINX_SSL_DIR}/${base_domain}/fullchain.pem" ]]; then
        # 1. 检查有效期
        if openssl x509 -in "${NGINX_SSL_DIR}/${base_domain}/fullchain.pem" -noout -checkend 2592000 > /dev/null 2>&1; then
            # 2. 检查包含的域名 (SAN匹配)
            local current_sans
            current_sans=$(openssl x509 -in "${NGINX_SSL_DIR}/${base_domain}/fullchain.pem" -noout -text | grep -A1 "Subject Alternative Name" | tail -1)
            
            local all_domains_present=true
            for domain in "${domains[@]}"; do
                if [[ "${current_sans}" != *"DNS:${domain}"* ]]; then
                    print_warn "现有证书缺少域名: ${domain}"
                    all_domains_present=false
                    break
                fi
            done
            
            if [[ "${all_domains_present}" == "true" ]]; then
                print_success "SAN 证书已存在、有效且包含所有计划域名"
                
                print_info "证书当前包含的域名："
                echo "${current_sans}" | sed 's/DNS://g' | tr ',' '\n' | sed 's/^[ \t]*/  - /'
                
                need_issue=false
            else
                print_warn "证书域名不完整，需要重新申请..."
            fi
        else
            print_warn "证书即将过期，重新申请..."
        fi
    fi
    
    if [[ "${need_issue}" == "false" ]]; then
        return 0
    fi
    
    # 构建 acme.sh 参数
    local acme_params=""
    for domain in "${domains[@]}"; do
        acme_params="${acme_params} -d ${domain}"
    done
    
    # 预检 HTTP 可达性
    print_info "预检: 测试主域名 HTTP 连接..."
    local test_file="${ACME_DIR}/.well-known/acme-challenge/test_$(date +%s)"
    mkdir -p "$(dirname "${test_file}")"
    echo "test" > "${test_file}"
    chmod 644 "${test_file}"
    
    local test_url="http://${base_domain}/.well-known/acme-challenge/$(basename "${test_file}")"
    if ! curl -sf --connect-timeout 10 "${test_url}" > /dev/null 2>&1; then
        print_warn "HTTP 预检失败: ${test_url}"
        print_warn "请确保:"
        print_warn "  1) 所有域名的 DNS A 记录已指向本机 IP"
        print_warn "  2) 防火墙已开放 80 端口"
        print_warn "  3) Nginx 正在运行"
        print_info "尝试继续申请证书..."
    else
        print_success "HTTP 预检通过"
    fi
    rm -f "${test_file}"
    
    # 申请证书
    print_info "调用 acme.sh 申请 SAN 证书（这可能需要几分钟）..."
    local acme_log="/tmp/acme_san_${base_domain}.log"
    
    if ! "${HOME}/.acme.sh/acme.sh" --issue \
        ${acme_params} \
        --webroot "${ACME_DIR}" \
        --keylength ec-256 \
        --force \
        > "${acme_log}" 2>&1; then
        print_error "SAN 证书申请失败"
        print_warn "acme.sh 输出:"
        tail -30 "${acme_log}"
        print_info "常见原因:"
        print_info "  1. DNS 记录未正确指向本服务器（检查所有 ${#domains[@]} 个域名）"
        print_info "  2. 防火墙阻止了 80 端口"
        print_info "  3. 域名解析尚未生效（等待 DNS 传播）"
        print_info "  4. Let's Encrypt 速率限制（每周最多 50 个证书）"
        return 1
    fi
    
    # 安装证书
    print_info "安装证书到 ${NGINX_SSL_DIR}/${base_domain}/..."
    if ! "${HOME}/.acme.sh/acme.sh" --install-cert \
        -d "${base_domain}" \
        --key-file "${NGINX_SSL_DIR}/${base_domain}/privkey.pem" \
        --fullchain-file "${NGINX_SSL_DIR}/${base_domain}/fullchain.pem" \
        --reloadcmd "systemctl reload nginx" \
        >> "${acme_log}" 2>&1; then
        print_error "证书安装失败"
        tail -10 "${acme_log}"
        return 1
    fi
    
    print_success "SAN 多域名证书申请成功！"
    print_info "证书路径: ${NGINX_SSL_DIR}/${base_domain}/"
    print_info "证书包含 ${#domains[@]} 个域名，所有协议将共享此证书"
    
    rm -f "${acme_log}"
}


#================== 域名管理辅助函数（新增）==================

# 获取基础域名（从数据库）
get_base_domain() {
    if [[ ! -f "${PROTOCOLS_DB}" ]]; then
        echo ""
        return
    fi
    
    # 尝试从base_domain字段读取
    local base_domain
    base_domain=$(jq -r '.base_domain // empty' "${PROTOCOLS_DB}" 2>/dev/null)
    
    if [[ -n "${base_domain}" && "${base_domain}" != "null" ]]; then
        echo "${base_domain}"
        return
    fi
    
    # 如果没有base_domain字段,从第一个协议的域名提取
    local first_domain
    first_domain=$(jq -r '.protocols[0].domain // empty' "${PROTOCOLS_DB}" 2>/dev/null)
    
    if [[ -z "${first_domain}" || "${first_domain}" == "null" ]]; then
        echo ""
        return
    fi
    
    # 提取基础域名 (reality.example.com -> example.com)
    echo "${first_domain}" | awk -F. '{if (NF>=2) print $(NF-1)"."$NF; else print $0}'
}

# 设置基础域名到数据库
set_base_domain() {
    local base_domain=$1
    local tmp_file="/tmp/protocols_db.tmp"
    
    jq --arg bd "${base_domain}" '.base_domain = $bd' "${PROTOCOLS_DB}" >"${tmp_file}"
    mv "${tmp_file}" "${PROTOCOLS_DB}"
}

# 生成协议专属子域名
generate_subdomain() {
    local protocol_type=$1
    local base_domain=$2
    
    case "${protocol_type}" in
        "reality")
            echo "realx.${base_domain}"
            ;;
        "ws-vless")
            echo "vlx.${base_domain}"
            ;;
        "xhttp-vless")
            echo "xhx.${base_domain}"
            ;;
        "ws-vmess")
            echo "vmx.${base_domain}"
            ;;
        "xhttp-reality")
            echo "vlxrex.${base_domain}"
            ;;
        *)
            echo "proxy.${base_domain}"
            ;;
    esac
}

# 检查域名是否已存在
check_subdomain_exists() {
    local subdomain=$1
    
    if [[ ! -f "${PROTOCOLS_DB}" ]]; then
        echo "false"
        return
    fi
    
    local exists
    exists=$(jq -r --arg d "${subdomain}" '.protocols[] | select(.domain == $d) | .domain' "${PROTOCOLS_DB}" 2>/dev/null | head -1)
    
    [[ -n "${exists}" ]] && echo "true" || echo "false"
}

# 获取所有预定义的子域名列表（用于SAN证书申请）
get_all_planned_domains() {
    local base_domain=$1
    
    echo "${base_domain}"
    echo "realx.${base_domain}"
    echo "vlx.${base_domain}"
    echo "vmx.${base_domain}"
    echo "vlxrex.${base_domain}"
    echo "xhx.${base_domain}"
}



#================== 复杂伪装网站生成 ==================

# 选择网站主题（固定使用咨询主题）
select_theme() {
    echo "consulting"
}

# 生成主题配置（咨询主题）
get_theme_config() {
    echo "专业咨询|企业管理咨询与战略规划|战略咨询,管理优化,数字化转型,培训服务"
}

# 生成网站内容
generate_fake_website() {
    local domain=$1
    
    print_info "生成复杂伪装网站..."
    
    # 选择主题
    local theme
    theme=$(select_theme "${domain}")
    
    # 获取主题配置
    IFS='|' read -r site_title site_desc services <<< "$(get_theme_config "${theme}")"
    
    # 创建目录结构
    mkdir -p "${FAKE_SITE_ROOT}"/{css,js,images}
    
    print_info "生成网站主题: ${theme}"
    
    # 生成HTML页面（后续实现完整内容）
    generate_html_index "${site_title}" "${site_desc}" "${domain}"
    generate_html_about "${site_title}" "${domain}"
    generate_html_services "${services}" "${domain}"
    generate_html_contact "${domain}"
    generate_html_blog "${domain}"
    
    # 生成CSS
    generate_advanced_css
    
    # 生成JavaScript
    generate_interactive_js
    
    # 生成SVG图片
    generate_svg_assets "${theme}"
    
    # 生成sitemap
    generate_sitemap "${domain}"
    
    # 设置权限
    chmod -R 755 "${FAKE_SITE_ROOT}"
    
    print_success "伪装网站生成完成"
}

#================== HTML 页面生成 ==================

# 生成首页
generate_html_index() {
    local site_title=$1
    local site_desc=$2
    local domain=$3
    
    cat > "${FAKE_SITE_ROOT}/index.html" <<EOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="${site_desc}">
    <title>${site_title} - 官方网站</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div class="logo">${site_title}</div>
            <ul class="nav-menu">
                <li><a href="/" class="active">首页</a></li>
                <li><a href="/about.html">关于</a></li>
                <li><a href="/services.html">服务</a></li>
                <li><a href="/blog.html">博客</a></li>
                <li><a href="/contact.html">联系</a></li>
            </ul>
        </div>
    </nav>

    <header class="hero">
        <div class="container">
            <h1 class="hero-title">${site_title}</h1>
            <p class="hero-subtitle">${site_desc}</p>
            <a href="/services.html" class="btn-primary">了解更多</a>
        </div>
    </header>

    <section class="features">
        <div class="container">
            <h2 class="section-title">核心优势</h2>
            <div class="feature-grid">
                <div class="feature-card">
                    <div class="icon">🚀</div>
                    <h3>高效专业</h3>
                    <p>提供快速、高效的专业服务</p>
                </div>
                <div class="feature-card">
                    <div class="icon">🔒</div>
                    <h3>安全可靠</h3>
                    <p>采用业界领先的安全标准</p>
                </div>
                <div class="feature-card">
                    <div class="icon">💡</div>
                    <h3>创新理念</h3>
                    <p>持续创新引领行业发展</p>
                </div>
            </div>
        </div>
    </section>

    <footer class="footer">
        <div class="container">
            <p>&copy; $(date +%Y) ${site_title}. All rights reserved.</p>
            <p class="domain">${domain}</p>
        </div>
    </footer>

    <script src="/js/main.js"></script>
</body>
</html>
EOF
}

# 生成关于页面
generate_html_about() {
    local site_title=$1
    local domain=$2
    
    cat > "${FAKE_SITE_ROOT}/about.html" <<EOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>关于我们 - ${site_title}</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div class="logo">${site_title}</div>
            <ul class="nav-menu">
                <li><a href="/">首页</a></li>
                <li><a href="/about.html" class="active">关于</a></li>
                <li><a href="/services.html">服务</a></li>
                <li><a href="/blog.html">博客</a></li>
                <li><a href="/contact.html">联系</a></li>
            </ul>
        </div>
    </nav>

    <div class="page-header">
        <div class="container">
            <h1>关于${site_title}</h1>
            <p>了解我们的使命与愿景</p>
        </div>
    </div>

    <section class="content">
        <div class="container">
            <div class="about-content">
                <h2>我们的故事</h2>
                <p>${site_title}致力于为客户提供优质的服务与体验。通过不断创新和优化，我们已经成为行业中值得信赖的品牌。</p>
                
                <h2>核心价值观</h2>
                <ul class="values-list">
                    <li><strong>诚信为本</strong> - 以诚信赢得客户信任</li>
                    <li><strong>追求卓越</strong> - 不断提升服务质量</li>
                    <li><strong>客户至上</strong> - 始终将客户需求放在首位</li>
                    <li><strong>创新驱动</strong> - 持续技术创新和服务升级</li>
                </ul>
            </div>
        </div>
    </section>

    <footer class="footer">
        <div class="container">
            <p>&copy; $(date +%Y) ${site_title}. All rights reserved.</p>
            <p class="domain">${domain}</p>
        </div>
    </footer>

    <script src="/js/main.js"></script>
</body>
</html>
EOF
}

# 生成服务页面
generate_html_services() {
    local services=$1
    local domain=$2
    
    # 将服务列表转换为HTML
    local services_html=""
    IFS=',' read -ra service_array <<< "${services}"
    for service in "${service_array[@]}"; do
        services_html+="<div class=\"service-item\"><h3>${service}</h3><p>专业的${service}解决方案</p></div>"
    done
    
    cat > "${FAKE_SITE_ROOT}/services.html" <<EOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>服务项目 - $(basename "${domain}" .com)</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div class="logo">$(basename "${domain}" .com)</div>
            <ul class="nav-menu">
                <li><a href="/">首页</a></li>
                <li><a href="/about.html">关于</a></li>
                <li><a href="/services.html" class="active">服务</a></li>
                <li><a href="/blog.html">博客</a></li>
                <li><a href="/contact.html">联系</a></li>
            </ul>
        </div>
    </nav>

    <div class="page-header">
        <div class="container">
            <h1>我们的服务</h1>
            <p>专业的解决方案</p>
        </div>
    </div>

    <section class="content">
        <div class="container">
            <div class="services-grid">
                ${services_html}
            </div>
        </div>
    </section>

    <footer class="footer">
        <div class="container">
            <p>&copy; $(date +%Y) $(basename "${domain}" .com). All rights reserved.</p>
            <p class="domain">${domain}</p>
        </div>
    </footer>

    <script src="/js/main.js"></script>
</body>
</html>
EOF
}

# 生成联系页面
generate_html_contact() {
    local domain=$1
    
    cat > "${FAKE_SITE_ROOT}/contact.html" <<EOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>联系我们 - $(basename "${domain}" .com)</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div class="logo">$(basename "${domain}" .com)</div>
            <ul class="nav-menu">
                <li><a href="/">首页</a></li>
                <li><a href="/about.html">关于</a></li>
                <li><a href="/services.html">服务</a></li>
                <li><a href="/blog.html">博客</a></li>
                <li><a href="/contact.html" class="active">联系</a></li>
            </ul>
        </div>
    </nav>

    <div class="page-header">
        <div class="container">
            <h1>联系我们</h1>
            <p>期待与您的交流</p>
        </div>
    </div>

    <section class="content">
        <div class="container">
            <div class="contact-info">
                <h2>联系方式</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <h3>📧 电子邮件</h3>
                        <p>contact@${domain}</p>
                        <p>support@${domain}</p>
                    </div>
                    <div class="info-item">
                        <h3>🌐 网站</h3>
                        <p><a href="https://${domain}">${domain}</a></p>
                    </div>
                    <div class="info-item">
                        <h3>⏰ 服务时间</h3>
                        <p>周一至周五: 9:00 - 18:00</p>
                        <p>周末: 休息</p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <footer class="footer">
        <div class="container">
            <p>&copy; $(date +%Y) $(basename "${domain}" .com). All rights reserved.</p>
            <p class="domain">${domain}</p>
        </div>
    </footer>

    <script src="/js/main.js"></script>
</body>
</html>
EOF
}

# 生成博客页面
generate_html_blog() {
    local domain=$1
    
    cat > "${FAKE_SITE_ROOT}/blog.html" <<EOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>博客 - $(basename "${domain}" .com)</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div class="logo">$(basename "${domain}" .com)</div>
            <ul class="nav-menu">
                <li><a href="/">首页</a></li>
                <li><a href="/about.html">关于</a></li>
                <li><a href="/services.html">服务</a></li>
                <li><a href="/blog.html" class="active">博客</a></li>
                <li><a href="/contact.html">联系</a></li>
            </ul>
        </div>
    </nav>

    <div class="page-header">
        <div class="container">
            <h1>博客文章</h1>
            <p>分享我们的见解与经验</p>
        </div>
    </div>

    <section class="content">
        <div class="container">
            <div class="blog-grid">
                <article class="blog-card">
                    <h3>如何选择合适的解决方案</h3>
                    <p class="meta">发布于 $(date -d '7 days ago' '+%Y-%m-%d')</p>
                    <p>在众多选择中，找到最适合自己需求的解决方案至关重要...</p>
                </article>
                <article class="blog-card">
                    <h3>行业趋势分析</h3>
                    <p class="meta">发布于 $(date -d '14 days ago' '+%Y-%m-%d')</p>
                    <p>深入分析当前行业发展趋势和未来展望...</p>
                </article>
                <article class="blog-card">
                    <h3>客户成功案例</h3>
                    <p class="meta">发布于 $(date -d '21 days ago' '+%Y-%m-%d')</p>
                    <p>分享我们帮助客户取得成功的真实案例...</p>
                </article>
            </div>
        </div>
    </section>

    <footer class="footer">
        <div class="container">
            <p>&copy; $(date +%Y) $(basename "${domain}" .com). All rights reserved.</p>
            <p class="domain">${domain}</p>
        </div>
    </footer>

    <script src="/js/main.js"></script>
</body>
</html>
EOF
}

#================== CSS 样式生成 ==================

generate_advanced_css() {
    cat > "${FAKE_SITE_ROOT}/css/style.css" <<'CSSEOF'
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    line-height: 1.6;
    color: #333;
    background: #f8f9fa;
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
    position: sticky;
    top: 0;
    z-index: 1000;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
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
    color: rgba(255,255,255,0.9);
    text-decoration: none;
    transition: color 0.3s;
    font-weight: 500;
}

.nav-menu a:hover, .nav-menu a.active {
    color: white;
}

/* Hero 区域 */
.hero {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 5rem 0;
    text-align: center;
}

.hero-title {
    font-size: 3rem;
    margin-bottom: 1rem;
    font-weight: 700;
    animation: fadeInUp 1s;
}

.hero-subtitle {
    font-size: 1.3rem;
    margin-bottom: 2rem;
    opacity: 0.95;
    animation: fadeInUp 1s 0.2s both;
}

.btn-primary {
    display: inline-block;
    padding: 0.8rem 2rem;
    background: white;
    color: #667eea;
    text-decoration: none;
    border-radius: 50px;
    font-weight: 600;
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

.section-title {
    text-align: center;
    font-size: 2rem;
    margin-bottom: 3rem;
    color: #667eea;
}

.feature-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 2rem;
}

.feature-card {
    padding: 2rem;
    background: #f8f9fa;
    border-radius: 10px;
    text-align: center;
    transition: transform 0.3s, box-shadow 0.3s;
}

.feature-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
}

.icon {
    font-size: 3rem;
    margin-bottom: 1rem;
}

/* 页面头部 */
.page-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 3rem 0;
    text-align: center;
}

/* 内容区域 */
.content {
    padding: 3rem 0;
    min-height: 50vh;
}

.about-content, .contact-info {
    background: white;
    padding: 2rem;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
}

.values-list {
    list-style: none;
    padding-left: 0;
}

.values-list li {
    padding: 0.5rem 0;
    border-bottom: 1px solid #eee;
}

.info-grid, .services-grid, .blog-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 2rem;
    margin: 2rem 0;
}

.info-item, .service-item, .blog-card {
    padding: 1.5rem;
    background: #f8f9fa;
    border-radius: 8px;
}

/* 页脚 */
.footer {
    background: #2d3748;
    color: white;
    text-align: center;
    padding: 2rem 0;
    margin-top: 3rem;
}

.domain {
    margin-top: 0.5rem;
    opacity: 0.7;
    font-size: 0.9rem;
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

/* 响应式 */
@media (max-width: 768px) {
    .hero-title {
        font-size: 2rem;
    }
    .nav-menu {
        gap: 1rem;
    }
}
CSSEOF
}

#================== JavaScript 生成 ==================

generate_interactive_js() {
    cat > "${FAKE_SITE_ROOT}/js/main.js" <<'JSEOF'
// 平滑滚动
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth' });
        }
    });
});

// 页面加载动画
document.body.style.opacity = '0';
setTimeout(() => {
    document.body.style.transition = 'opacity 0.5s';
    document.body.style.opacity = '1';
}, 100);

// 假的分析脚本（增强真实感）
(function() {
    var _gaq = [];
    console.log('Analytics initialized');
})();
JSEOF
}

#================== SVG 资源生成 ==================

generate_svg_assets() {
    local theme=$1
    
    # 生成Logo SVG
    cat > "${FAKE_SITE_ROOT}/images/logo.svg" <<'SVGEOF'
<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="40" fill="#667eea"/>
  <text x="50" y="60" font-size="40" text-anchor="middle" fill="white">S</text>
</svg>
SVGEOF

    # 生成Hero图片
    cat > "${FAKE_SITE_ROOT}/images/hero.svg" <<'SVGEOF'
<svg width="800" height="400" xmlns="http://www.w3.org/2000/svg">
  <rect fill="#667eea" width="800" height="400"/>
  <text fill="#ffffff" font-family="Arial" font-size="48" x="50%" y="50%" text-anchor="middle">企业服务平台</text>
</svg>
SVGEOF
}

#================== Sitemap 生成 ==================

generate_sitemap() {
    local domain=$1
    
    cat > "${FAKE_SITE_ROOT}/sitemap.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://${domain}/</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <priority>1.0</priority>
    </url>
    <url>
        <loc>https://${domain}/about.html</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <priority>0.8</priority>
    </url>
    <url>
        <loc>https://${domain}/services.html</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <priority>0.8</priority>
    </url>
    <url>
        <loc>https://${domain}/blog.html</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <priority>0.7</priority>
    </url>
    <url>
        <loc>https://${domain}/contact.html</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <priority>0.6</priority>
    </url>
</urlset>
EOF
}

#================== Xray Reality 基础配置 ==================

init_reality_protocol() {
    local domain=$1
    
    print_info "初始化 Reality 协议..."
    
    # 检查是否已存在 Reality 配置，如果存在则先清理
    local existing_reality
    existing_reality=$(jq -r '.protocols[] | select(.type == "reality") | .domain' "${PROTOCOLS_DB}" 2>/dev/null | head -1)
    
    if [[ -n "${existing_reality}" ]]; then
        print_warn "发现已有 Reality 配置 (${existing_reality})，将覆盖..."
        # 清理所有旧的 reality 类型配置
        local tmp_file="/tmp/protocols_db.tmp"
        jq '.protocols = [.protocols[] | select(.type != "reality")]' "${PROTOCOLS_DB}" > "${tmp_file}"
        mv "${tmp_file}" "${PROTOCOLS_DB}"
    fi
    
    # 生成Reality密钥
    local keys
    keys=$(${XRAY_BIN} x25519)
    
    local private_key
    local public_key
    
    # 解析密钥（兼容新旧版本）
    private_key=$(echo "${keys}" | grep -i "Private" | awk '{print $NF}')
    public_key=$(echo "${keys}" | grep -i "Public\|Password" | awk '{print $NF}')
    
    # 生成UUID和shortId
    local uuid
    uuid=$(${XRAY_BIN} uuid)
    local short_id
    short_id=$(openssl rand -hex 8)
    
    # 添加到协议数据库
    add_protocol_to_db "${domain}" "reality" "${REALITY_PORT}" "${uuid}"
    
    # 生成Xray配置
    mkdir -p "${XRAY_DIR}"
    cat > "${XRAY_CONFIG}" <<EOF
{
  "log": {
    "loglevel": "error"
  },
  "stats": {},
  "api": {
    "tag": "api",
    "services": [
      "StatsService"
    ]
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink": true,
      "statsOutboundDownlink": true
    }
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
    },
    {
      "tag": "${domain}_reality",
      "listen": "/dev/shm/xray_reality.sock,0666",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "email": "${domain}_reality",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "127.0.0.1:8089",
          "xver": 1,
          "serverNames": ["${domain}"],
          "privateKey": "${private_key}",
          "shortIds": ["${short_id}"]
        },
        "sockopt": {
          "acceptProxyProtocol": true
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
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["api"],
        "outboundTag": "api"
      },
      {
        "type": "field",
        "outboundTag": "block",
        "ip": ["geoip:cn"]
      },
      {
        "type": "field",
        "outboundTag": "block",
        "domain": ["geosite:cn"]
      }
    ]
  }
}
EOF
    
    print_success "Reality协议初始化完成"
    echo "UUID: ${uuid}"
    echo "Short ID: ${short_id}"
    echo "Public Key: ${public_key}"
    
    # 保存公钥和 Short ID 供生成分享链接使用
    mkdir -p "${XRAY_DIR}/.keys"
    chmod 700 "${XRAY_DIR}/.keys"
    echo "${public_key}" > "${XRAY_DIR}/.keys/reality_pubkey"
    echo "${short_id}" > "${XRAY_DIR}/.keys/reality_shortid"
    
    print_info "已添加禁止回国流量路由规则"
}

#================== 分享链接生成 ==================

generate_share_link() {
    local domain=$1
    
    # 从数据库获取协议信息
    local info
    info=$(jq -r --arg domain "${domain}" '.protocols[] | select(.domain == $domain) | "\(.type)|\(.port)|\(.uuid)|\(.path)"' "${PROTOCOLS_DB}" 2>/dev/null)
    
    if [[ -z "${info}" ]]; then
        print_warn "未找到域名 ${domain} 的协议信息"
        return 1
    fi
    
    local type port uuid path
    type=$(echo "${info}" | cut -d'|' -f1)
    port=$(echo "${info}" | cut -d'|' -f2)
    uuid=$(echo "${info}" | cut -d'|' -f3)
    path=$(echo "${info}" | cut -d'|' -f4)
    
    local link=""
    
    case "${type}" in
        "reality")
            # 直接从 Xray 配置中读取，确保一致性
            local config_uuid config_pubkey config_shortid config_privkey
            
            # 从 Xray 配置读取 UUID (过滤 null)
            config_uuid=$(jq -r '.inbounds[] | select(.protocol == "vless") | .settings.clients[0].id // empty' "${XRAY_CONFIG}" 2>/dev/null | head -1)
            
            # 从 Xray 配置读取私钥 (过滤 null)
            config_privkey=$(jq -r '.inbounds[] | select(.protocol == "vless") | .streamSettings.realitySettings.privateKey // empty' "${XRAY_CONFIG}" 2>/dev/null | head -1)
            
            # 从 Xray 配置读取 shortId (过滤 null)
            config_shortid=$(jq -r '.inbounds[] | select(.protocol == "vless") | .streamSettings.realitySettings.shortIds[0] // empty' "${XRAY_CONFIG}" 2>/dev/null | head -1)
            
            # 计算公钥 (xray x25519 -i privatekey 输出中 Password/Public 行就是公钥)
            if [[ -n "${config_privkey}" && "${config_privkey}" != "null" ]]; then
                config_pubkey=$(${XRAY_BIN} x25519 -i "${config_privkey}" 2>/dev/null | grep -i "Password\|Public" | awk '{print $NF}')
            fi
            
            # 如果无法从配置获取，尝试使用保存的文件
            if [[ -z "${config_uuid}" || "${config_uuid}" == "null" ]]; then
                config_uuid="${uuid}"
            fi
            if [[ -z "${config_pubkey}" || "${config_pubkey}" == "null" ]]; then
                config_pubkey=$(cat "${XRAY_DIR}/.keys/reality_pubkey" 2>/dev/null)
            fi
            if [[ -z "${config_shortid}" || "${config_shortid}" == "null" ]]; then
                config_shortid=$(cat "${XRAY_DIR}/.keys/reality_shortid" 2>/dev/null)
            fi
            
            if [[ -z "${config_pubkey}" ]]; then
                print_warn "无法获取 Reality 公钥"
                return 1
            fi
            
            # VLESS Reality 链接格式
            link="vless://${config_uuid}@${domain}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${domain}&fp=chrome&pbk=${config_pubkey}&sid=${config_shortid}&type=tcp#Reality-${domain}"
            ;;
        "ws-vless")
            local encoded_path
            encoded_path=$(echo "${path}" | sed 's/\//%2F/g')
            link="vless://${uuid}@${domain}:443?encryption=none&security=tls&sni=${domain}&type=ws&host=${domain}&path=${encoded_path}#WS-VLESS-${domain}"
            ;;
        "xhttp-vless")
            local encoded_path
            encoded_path=$(echo "${path}" | sed 's/\//%2F/g')
            link="vless://${uuid}@${domain}:443?encryption=none&security=tls&sni=${domain}&type=xhttp&host=${domain}&path=${encoded_path}#XHTTP-${domain}"
            ;;
        "ws-vmess")
            local vmess_json
            vmess_json=$(cat <<VMESS
{
  "v": "2",
  "ps": "VMess-${domain}",
  "add": "${domain}",
  "port": "443",
  "id": "${uuid}",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "${domain}",
  "path": "${path}",
  "tls": "tls",
  "sni": "${domain}"
}
VMESS
)
            link="vmess://$(echo -n "${vmess_json}" | base64 -w 0)"
            ;;
        "xhttp-reality")
            # VLESS + XHTTP + Reality 分享链接格式
            # 读取 Reality 公钥和 ShortID
            local pubkey shortid
            pubkey=$(cat "${XRAY_DIR}/.keys/${domain}_pubkey" 2>/dev/null)
            shortid=$(cat "${XRAY_DIR}/.keys/${domain}_shortid" 2>/dev/null)
            
            if [[ -z "${pubkey}" ]]; then
                print_warn "无法获取 Reality 公钥"
                return 1
            fi
            
            local encoded_path
            encoded_path=$(echo "${path}" | sed 's/\//%2F/g')
            link="vless://${uuid}@${domain}:443?encryption=none&security=reality&sni=${domain}&fp=chrome&pbk=${pubkey}&sid=${shortid}&type=xhttp&host=${domain}&path=${encoded_path}#XHTTP-Reality-${domain}"
            ;;
        *)
            print_warn "未知协议类型: ${type}"
            return 1
            ;;
    esac
    
    if [[ -n "${link}" ]]; then
        echo -e "${GREEN}${link}${NC}"
    else
        print_warn "链接生成失败"
    fi
}

#================== Outbound 配置管理 ==================

# 配置 Outbound（直接出站或中转）
configure_outbound() {
    print_separator
    echo -e "${GREEN}配置出站方式${NC}"
    print_separator
    
    echo "选择出站方式:"
    echo "1) 全局直连 (Direct) - 默认"
    echo "2) 全局中转 (Global Transit)"
    echo "3) 分协议路由 (Policy Routing) - [NEW]"
    echo "0) 返回上级菜单"
    read -p "请选择 [0-3]: " outbound_choice
    
    case "${outbound_choice}" in
        1)
            configure_direct_outbound
            ;;
        2)
            configure_ss_outbound
            ;;
        3)
            configure_policy_routing
            ;;
        0)
            return 0
            ;;
        *)
            print_warn "无效选择，返回上级菜单"
            return 0
            ;;
    esac
}

# 配置直接出站
configure_direct_outbound() {
    print_info "配置直接出站模式..."
    
    local tmp_file="/tmp/xray_config.tmp"
    
    # 1. 移除 ss-transit outbound（如果存在）
    # 2. 重置路由规则（保留API规则和block规则）
    jq '
      # 移除 ss-transit outbound
      .outbounds = [.outbounds[] | select(.tag != "ss-transit")] |
      
      # 重置路由规则
      .routing.rules = [
        # 保留 API 规则
        {
          "type": "field",
          "inboundTag": ["api"],
          "outboundTag": "api"
        },
        # 禁止回国规则  
        {
          "type": "field",
          "outboundTag": "block",
          "ip": ["geoip:cn"]
        },
        {
          "type": "field",
          "outboundTag": "block",
          "domain": ["geosite:cn"]
        }
      ]
    ' "${XRAY_CONFIG}" > "${tmp_file}"
    
    mv "${tmp_file}" "${XRAY_CONFIG}"
    
    # 清理保存的outbound配置
    rm -f "${XRAY_DIR}/.config/outbound.json"
    
    print_success "已配置为直接出站（freedom）"
    print_info "流量将直接从本机发出，禁止回国规则已保留"
}

# 配置 Shadowsocks 中转
input_ss_config_interactive() {
    # Returns global variables (via dynamic scope): ss_server, ss_port, ss_method, ss_password
    # Return 0 on success, 1 on cancel/failure.

    print_separator
    echo -e "${CYAN}配置 Shadowsocks 落地机信息${NC}"
    print_separator

    echo "请输入落地机地址 (支持 IPv4/IPv6 或 域名，例如: 1.2.3.4 或 ss.example.com)"
    read -p "落地机地址: " ss_server
    if [[ -z "${ss_server}" ]]; then
         print_error "地址不能为空"
         return 1
    fi

    echo "请输入端口 (范围: 1-65535，默认: 10086)"
    read -p "落地机端口: " ss_port
    ss_port=${ss_port:-10086}

    echo "请选择加密方式:"
    echo "1) 2022-blake3-aes-128-gcm (推荐)"
    echo "2) 2022-blake3-aes-256-gcm"
    echo "3) aes-128-gcm"
    echo "4) aes-256-gcm"
    echo "5) chacha20-ietf-poly1305"
    echo "6) 手动输入其他"
    read -p "请选择 [1-6] (默认: 1): " method_choice
    
    case "${method_choice}" in
        1|"") ss_method="2022-blake3-aes-128-gcm" ;;
        2) ss_method="2022-blake3-aes-256-gcm" ;;
        3) ss_method="aes-128-gcm" ;;
        4) ss_method="aes-256-gcm" ;;
        5) ss_method="chacha20-ietf-poly1305" ;;
        6) read -p "请输入加密方式: " ss_method ;;
        *) ss_method="2022-blake3-aes-128-gcm" ;;
    esac

    # Password Logic with Retry
    while true; do
        if [[ "${ss_method}" =~ ^2022- ]]; then
            print_info "SS 2022加密需要base64格式的密码"
            echo "1) 自动生成随机密码"
            echo "2) 手动输入"
            read -p "请选择 [1-2]: " pass_choice
            
            if [[ "${pass_choice}" == "1" ]]; then
                # Context-aware length generation
                local key_bytes=16
                if [[ "${ss_method}" =~ aes-256 ]]; then
                    key_bytes=32
                fi
                ss_password=$(openssl rand -base64 ${key_bytes}) 
                echo "生成的密码: ${ss_password}"
                break # Valid by definition
            else
                read -p "请输入base64密码: " ss_password
                # Verification for manual input
                if echo "${ss_password}" | base64 -d &>/dev/null; then
                     break
                else
                     print_warn "密码格式错误：必须为有效的 Base64 字符串"
                fi
            fi
        else
            # Non-2022 methods
            read -p "密码: " ss_password
            if [[ -n "${ss_password}" ]]; then
                break
            else
                print_warn "密码不能为空"
            fi
        fi

        # If we reached here, validation failed.
        echo -e "${YELLOW}验证不通过。${NC}"
        echo "1) 重新输入"
        echo "0) 返回上一级菜单"
        read -p "请选择 [0-1]: " retry_choice
        if [[ "${retry_choice}" == "0" ]]; then
            print_warn "用户取消操作"
            return 1
        fi
        # Loop continues
    done

    return 0
}

configure_ss_outbound() {
    # 1. 获取用户输入
    local ss_server ss_port ss_method ss_password
    if ! input_ss_config_interactive; then
        return 0
    fi
     
    print_info "添加 Shadowsocks 出站配置..."
    
    # 使用 jq 添加 SS outbound
    local tmp_file="/tmp/xray_config.tmp"
    
    jq --arg server "${ss_server}" \
       --arg port "${ss_port}" \
       --arg method "${ss_method}" \
       --arg password "${ss_password}" \
       '
       # 先移除旧的 ss-transit outbound（避免重复）
       .outbounds = [.outbounds[] | select(.tag != "ss-transit")] |
       
       # 添加新的 SS outbound
       .outbounds += [{
         "protocol": "shadowsocks",
         "tag": "ss-transit",
         "settings": {
           "servers": [{
             "address": $server,
             "port": ($port | tonumber),
             "method": $method,
             "password": $password
           }]
         }
       }] | 
       
       # 重置路由规则（保留API规则）
       .routing.rules = [
         # API 规则（必须保留）
         {
           "type": "field",
           "inboundTag": ["api"],
           "outboundTag": "api"
         },
         # 必须：私有IP直连 (解决伪装站回落和本地连接问题)
         {
           "type": "field",
           "ip": ["geoip:private"],
           "outboundTag": "direct"
         },
         # 防止循环：落地机域名直连
         {
           "type": "field",
           "domain": [$server],
           "outboundTag": "direct"
         },
         # 禁止回国规则
         {
           "type": "field",
           "outboundTag": "block",
           "ip": ["geoip:cn"]
         },
         {
           "type": "field",
           "outboundTag": "block",
           "domain": ["geosite:cn"]
         },
         # 其他流量走SS中转
         {
           "type": "field",
           "outboundTag": "ss-transit",
           "network": "tcp,udp"
         }
       ]' "${XRAY_CONFIG}" > "${tmp_file}"
    
    mv "${tmp_file}" "${XRAY_CONFIG}"
    
    # 保存配置信息
    mkdir -p "${XRAY_DIR}/.config"
    cat > "${XRAY_DIR}/.config/outbound.json" <<EOF
{
  "type": "ss-transit",
  "server": "${ss_server}",
  "port": ${ss_port},
  "method": "${ss_method}",
  "configured_at": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF
    
    print_success "Shadowsocks 中转配置完成"
    print_info "落地机: ${ss_server}:${ss_port}"
    print_info "加密: ${ss_method}"
    print_info "流量路由: 本机 → SS落地机 → 目标"
}

ensure_inbound_tags() {
    # 自动修复缺失 tag 的 inbound
    local tmp_file="/tmp/xray_config_tags.tmp"
    jq '
      .inbounds |= map(
        if .tag == null or .tag == "" then
          if .settings.clients[0].email != null then
            .tag = .settings.clients[0].email
          else
            .tag = ("inbound_" + (.port|tostring))
          end
        else
          .
        end
      )
    ' "${XRAY_CONFIG}" > "${tmp_file}"
    if [[ -s "${tmp_file}" ]]; then
        mv "${tmp_file}" "${XRAY_CONFIG}"
    fi
}

configure_policy_routing() {
    print_separator
    echo -e "${CYAN}配置分协议路由策略 (Policy Routing)${NC}"
    print_separator
    
    # 1. 确保 Tag 存在
    ensure_inbound_tags
    
    # 2. SS 配置输入
    local ss_server ss_port ss_method ss_password
    if ! input_ss_config_interactive; then
        return 0
    fi

    # 3. 选择分流协议
    print_separator
    echo "当前可用协议 (Inbound Tags):"
    
    local tags_str
    tags_str=$(jq -r '.inbounds[] | select(.tag != "api" and .tag != null) | .tag' "${XRAY_CONFIG}")
    local avail_tags
    avail_tags=(${tags_str})
    
    if [[ ${#avail_tags[@]} -eq 0 ]]; then
        print_warn "未找到有效的协议 Tag"
        return 1
    fi
    
    local i=1
    for t in "${avail_tags[@]}"; do
        echo "  ${i}) ${t}"
        ((i++))
    done
    
    echo ""
    echo "请选择需要【走中转】的协议序号。"
    echo -e "${YELLOW}**未选中的协议将默认【直连 (Direct)】**${NC}"
    read -p "输入序号 (空格分隔，例如 1 3): " selection
    
    # 解析选择
    local selected_tags_json="[]"
    if [[ -n "${selection}" ]]; then
        local tag_list=()
        for idx in ${selection}; do
            if [[ "$idx" =~ ^[0-9]+$ ]]; then
                local real_idx=$((idx-1))
                if [[ $real_idx -ge 0 && $real_idx -lt ${#avail_tags[@]} ]]; then
                    tag_list+=("${avail_tags[$real_idx]}")
                fi
            fi
        done
        
        if [[ ${#tag_list[@]} -gt 0 ]]; then
            selected_tags_json=$(printf '%s\n' "${tag_list[@]}" | jq -R . | jq -s .)
        fi
    fi
    
    print_info "正在应用路由策略..."
    echo "选中走中转的 Tag: ${selected_tags_json}"
    
    # 4. 应用配置
    local tmp_file="/tmp/xray_config.tmp"
    
     jq --arg server "${ss_server}" \
       --arg port "${ss_port}" \
       --arg method "${ss_method}" \
       --arg password "${ss_password}" \
       --argjson transit_tags "${selected_tags_json}" \
       '
       # 更新 SS Outbound
       .outbounds = [.outbounds[] | select(.tag != "ss-transit")] |
       .outbounds += [{
         "protocol": "shadowsocks",
         "tag": "ss-transit",
         "settings": {
           "servers": [{
             "address": $server,
             "port": ($port | tonumber),
             "method": $method,
             "password": $password
           }]
         }
       }] |
       
       # 更新 Routing
       .routing.rules = [
         {
           "type": "field",
           "inboundTag": ["api"],
           "outboundTag": "api"
         },
         {
           "type": "field",
           "ip": ["geoip:private"],
           "outboundTag": "direct"
         },
         {
           "type": "field",
           "domain": [$server],
           "outboundTag": "direct"
         },
         {
           "type": "field",
           "outboundTag": "block",
           "ip": ["geoip:cn"]
         },
         {
           "type": "field",
           "outboundTag": "block",
           "domain": ["geosite:cn"]
         },
         (if ($transit_tags | length) > 0 then {
            "type": "field",
            "inboundTag": $transit_tags,
            "outboundTag": "ss-transit"
         } else empty end),
         {
            "type": "field",
            "network": "tcp,udp",
            "outboundTag": "direct"
         }
       ]
       ' "${XRAY_CONFIG}" > "${tmp_file}"
       
    mv "${tmp_file}" "${XRAY_CONFIG}"
    
    # 保存配置状态
    mkdir -p "${XRAY_DIR}/.config"
    cat > "${XRAY_DIR}/.config/outbound.json" <<EOF
{
  "type": "policy-routing",
  "server": "${ss_server}",
  "port": ${ss_port},
  "method": "${ss_method}",
  "configured_at": "$(date '+%Y-%m-%d %H:%M:%S')"
}
EOF

    print_success "分协议路由策略已应用！"
}

# 查看当前 Outbound 配置
view_outbound_config() {
    print_separator
    echo -e "${CYAN}当前出站配置详情${NC}"
    print_separator
    
    # 尝试读取真实的 SS 配置 (Source of Truth)
    local ss_config
    ss_config=$(jq -r '.outbounds[] | select(.tag == "ss-transit")' "${XRAY_CONFIG}" 2>/dev/null)
    
    if [[ -n "${ss_config}" ]]; then
        local server=$(echo "${ss_config}" | jq -r '.settings.servers[0].address')
        local port=$(echo "${ss_config}" | jq -r '.settings.servers[0].port')
        local method=$(echo "${ss_config}" | jq -r '.settings.servers[0].method')
        local password=$(echo "${ss_config}" | jq -r '.settings.servers[0].password // .settings.servers[0].settings.password')
        
        echo -e "状态: ${GREEN}已启用中转${NC}"
        echo "--------------------------------"
        echo "落地服务器: ${server}"
        echo "端口:       ${port}"
        echo "加密方式:   ${method}"
        echo "密码:       ${password}"
        echo "--------------------------------"
    else
        echo -e "状态: ${YELLOW}未检测到中转配置 (直连模式)${NC}"
    fi
    
    print_separator
    echo "路由规则摘要:"
    jq -r '.routing.rules[] | 
        .outboundTag as $target |
        if .inboundTag != null then 
             .inboundTag[] | 
                (
                  if endswith("_xhttp_reality") then "VLESS+XHTTP+Reality"
                  elif endswith("_xhttp") then "VLESS+XHTTP+TLS"
                  elif endswith("_reality") then "VLESS+Vision+Reality"
                  elif endswith("_vless") then "VLESS+WS+TLS"
                  elif endswith("_vmess") then "VMess+WS+TLS"
                  else "其他" end
                ) as $type |
                (split(".")[0]) as $prefix |
                "  [协议: " + $prefix + " (" + $type + ")] -> " + $target
        elif .ip != null then
             "  [IP: " + (.ip | join(", ")) + "] -> " + $target
        elif .domain != null then
             "  [域名: " + (.domain | join(", ")) + "] -> " + $target
        else
             "  [" + (.network // "默认") + "] -> " + $target
        end' "${XRAY_CONFIG}" 2>/dev/null || echo "无路由规则"
        
    print_separator
}


#================== 端口复用辅助函数 ==================

# 获取协议固定端口
get_protocol_port() {
    local protocol_type=$1
    
    case "${protocol_type}" in
        "ws-vless")
            echo "8001"
            ;;
        "ws-vmess")
            echo "8002"
            ;;
        "xhttp-vless")
            echo "8003"
            ;;
        "xhttp-reality")
            echo "8004"
            ;;
        *)
            echo "9000"  # 未知类型默认端口
            ;;
    esac
}

# 检查inbound是否已存在 (通过UDS路径)
check_inbound_exists() {
    local port=$1
    
    if [[ ! -f "${XRAY_CONFIG}" ]]; then
        echo "false"
        return
    fi
    
    local exists
    # 匹配 /dev/shm/xray_${port}.sock
    exists=$(jq -r --arg port "${port}" '.inbounds[] | select(.listen | contains("/dev/shm/xray_" + $port + ".sock")) | .listen' "${XRAY_CONFIG}" 2>/dev/null)
    
    if [[ -n "${exists}" ]]; then
        echo "true"
    else
        echo "false"
    fi
}

# 向现有inbound添加client
add_client_to_inbound() {
    local port=$1
    local uuid=$2
    local type=$3
    local email=${4:-""}
    local path=${5:-""} # Add path argument
    
    print_info "向端口 ${port} 添加新客户端 (${type})..."
    
    local tmp_file="/tmp/xray_config.tmp"
    
    # VLESS/VMess/xhttp-reality 使用 id
    # 使用 map 遍历更新，同时更新 Path
    jq --arg port "${port}" \
       --arg uuid "${uuid}" \
       --arg email "${email}" \
       --arg path "${path}" \
       '
         .inbounds |= map(
           if (.listen | contains("/dev/shm/xray_" + $port + ".sock")) then
             # 先移除同名Email的旧客户端 (防止重复)
             (.settings.clients = [.settings.clients[] | select(.email != $email)]) |
             # 添加新客户端
             (.settings.clients += [{"id": $uuid, "email": $email}]) |
             
             # 强制更新 Path (解决重新安装后Path不一致问题)
             (if (.streamSettings.network == "ws") then
                .streamSettings.wsSettings.path = $path
              elif (.streamSettings.network == "xhttp") then
                .streamSettings.xhttpSettings.path = $path
              else
                .
              end) |

             # 清理 Host 头
             if (.streamSettings.network == "ws") then
                del(.streamSettings.wsSettings.headers.Host)
             else
                if (.streamSettings.network == "xhttp") then
                    del(.streamSettings.xhttpSettings.headers.Host)
                else 
                    .
                end
             end
           else
             . 
           end
         )
       ' \
       "${XRAY_CONFIG}" > "${tmp_file}"
    
    mv "${tmp_file}" "${XRAY_CONFIG}"
    print_success "客户端已添加到现有inbound"
}

# 从现有inbound删除client
remove_client_from_inbound() {
    local port=$1
    local uuid=$2
    local type=$3
    
    print_info "从端口 ${port} 删除客户端..."
    
    local tmp_file="/tmp/xray_config.tmp"
    
    # 更可靠的删除逻辑：
    # 1. 先删除指定 UUID 的客户端
    # 2. 然后删除没有客户端的 inbound（保留 API）
    jq --arg port "${port}" \
       --arg uuid "${uuid}" \
       '
       # 找到匹配的 inbound 并删除指定客户端
       .inbounds |= map(
         if (.listen | contains("/dev/shm/xray_" + $port + ".sock")) then
           .settings.clients |= map(select(.id != $uuid))
         else
           .
         end
       ) |
       # 删除没有客户端的 inbound（保留 dokodemo-door API）
       .inbounds |= map(
         select(
           (.protocol == "dokodemo-door") or
           ((.settings.clients // []) | length > 0)
         )
       )
       ' \
       "${XRAY_CONFIG}" > "${tmp_file}"
    
    # 验证生成的配置文件
    if [[ -s "${tmp_file}" ]] && jq . "${tmp_file}" >/dev/null 2>&1; then
        mv "${tmp_file}" "${XRAY_CONFIG}"
    else
        print_error "Xray 配置修改失败: 生成的配置无效"
        rm -f "${tmp_file}"
        return 1
    fi
}


# 删除Nginx相关配置
remove_nginx_config() {
    local domain=$1
    local port=$2
    local path=$3
    
    print_info "清理 Nginx 配置..."
    
    # 1. 删除 SNI 映射 (stream.conf)
    # 不再使用 sed 直接修改 stream.conf，而是通过 regenerate_stream_config 统一重新生成
    # 这样更安全，避免部分匹配误删风险
    
    # 2. 删除 https 配置文件
    # 在新架构中，每个协议（Domain）都有独立的配置文件
    local config_file="${NGINX_CONF_D}/https_${domain}.conf"
    if [[ -f "${config_file}" ]]; then
        rm -f "${config_file}"
        print_info "已删除配置文件: ${config_file}"
    else
        print_warn "配置文件未找到 (可能已手动删除): ${config_file}"
    fi
}



# 添加 WebSocket VLESS
add_ws_vless() {
    local protocol_type="ws-vless"
    
    # 获取基础域名
    local base_domain
    base_domain=$(get_base_domain)
    
    if [[ -z "${base_domain}" ]]; then
        print_error "未找到基础域名，请先运行基础安装"
        return 1
    fi
    
    # 自动生成子域名
    local subdomain
    subdomain=$(generate_subdomain "${protocol_type}" "${base_domain}")
    
    # 检查是否已存在
    if [[ "$(check_subdomain_exists "${subdomain}")" == "true" ]]; then
        print_error "协议 ${protocol_type} (${subdomain}) 已存在"
        return 1
    fi
    
    print_separator
    print_info "添加 VLESS-WebSocket 协议"
    print_separator
    echo "📋 默认配置信息:"
    echo "  协议类型: VLESS + WebSocket + TLS"
    echo "  子域名:   ${subdomain}"
    echo "  证书:     共享 SAN 证书 (${base_domain})"
    print_separator
    
    # 生成配置参数
    local port=$(get_protocol_port "${protocol_type}")
    local uuid=$(${XRAY_BIN} uuid)
    local path="/$(openssl rand -hex 4)"
    
    print_info "生成的配置参数:"
    echo "  端口:     ${port}"
    echo "  UUID:     ${uuid}"
    echo "  路径:     ${path}"
    
    # 添加到数据库
    add_protocol_to_db "${subdomain}" "${protocol_type}" "${port}" "${uuid}" "${path}"
    
    # 使用共享SAN证书（不再单独申请）
    local cert_dir="${NGINX_SSL_DIR}/${base_domain}"
    if [[ ! -f "${cert_dir}/fullchain.pem" ]]; then
        print_error "SAN 证书不存在，请先运行基础安装"
        remove_protocol_from_db "${subdomain}"
        return 1
    fi
    
    # 配置Xray inbound
    local inbound_exists
    inbound_exists=$(check_inbound_exists "${port}")
    if [[ "${inbound_exists}" == "false" ]]; then
        add_xray_inbound "${protocol_type}" "${port}" "${uuid}" "${path}" "${subdomain}_vless" "${base_domain}"
    else
        add_client_to_inbound "${port}" "${uuid}" "${protocol_type}" "${subdomain}_vless" "${path}"
    fi
    
    # 更新Nginx配置
    add_nginx_proto_server "${subdomain}" "${protocol_type}" "${port}" "${path}"
    regenerate_stream_config
    
    # 重载服务
    if nginx -t 2>/dev/null; then
        systemctl reload nginx
    else
        print_error "Nginx配置测试失败"
        return 1
    fi
    if ! systemctl restart xray; then
        print_error "Xray 服务重启失败"
        return 1
    fi
    
    print_success "VLESS-WS 添加成功！"
    print_separator
    echo "📌 连接信息:"
    echo "  子域名: ${subdomain}"
    echo "  UUID:   ${uuid}"
    echo "  路径:   ${path}"
    echo "  端口:   443"
    print_separator
    echo "📋 分享链接:"
    generate_share_link "${subdomain}"
    print_separator
}

# 添加 XHTTP VLESS
add_xhttp_vless() {
    local protocol_type="xhttp-vless"
    
    local base_domain
    base_domain=$(get_base_domain)
    
    if [[ -z "${base_domain}" ]]; then
        print_error "未找到基础域名，请先运行基础安装"
        return 1
    fi
    
    # 自动生成子域名
    local subdomain
    subdomain=$(generate_subdomain "${protocol_type}" "${base_domain}")
    
    if [[ "$(check_subdomain_exists "${subdomain}")" == "true" ]]; then
        print_error "协议 ${protocol_type} (${subdomain}) 已存在"
        return 1
    fi
    
    print_separator
    print_info "添加 XHTTP-VLESS 协议"
    print_separator
    echo "📋 默认配置信息:"
    echo "  协议类型: VLESS + XHTTP + TLS"
    echo "  子域名:   ${subdomain}"
    echo "  证书:     共享 SAN 证书 (${base_domain})"
    print_separator
    
    local port=$(get_protocol_port "${protocol_type}")
    local uuid=$(${XRAY_BIN} uuid)
    local path="/$(openssl rand -hex 4)"
    
    print_info "生成的配置参数:"
    echo "  端口:     ${port}"
    echo "  UUID:     ${uuid}"
    echo "  路径:     ${path}"
    
    add_protocol_to_db "${subdomain}" "${protocol_type}" "${port}" "${uuid}" "${path}"
    
    # 使用共享SAN证书
    local cert_dir="${NGINX_SSL_DIR}/${base_domain}"
    if [[ ! -f "${cert_dir}/fullchain.pem" ]]; then
        print_error "SAN 证书不存在，请先运行基础安装"
        remove_protocol_from_db "${subdomain}"
        return 1
    fi
    
    local inbound_exists
    inbound_exists=$(check_inbound_exists "${port}")
    if [[ "${inbound_exists}" == "false" ]]; then
        add_xray_inbound "${protocol_type}" "${port}" "${uuid}" "${path}" "${subdomain}_xhttp" "${base_domain}"
    else
        add_client_to_inbound "${port}" "${uuid}" "${protocol_type}" "${subdomain}_xhttp" "${path}"
    fi
    
    add_nginx_proto_server "${subdomain}" "${protocol_type}" "${port}" "${path}"
    regenerate_stream_config
    
    if ! nginx -t 2>/dev/null; then
        print_error "Nginx配置测试失败"
        return 1
    fi
    systemctl reload nginx
    
    if ! systemctl restart xray; then
        print_error "Xray 服务重启失败"
        return 1
    fi
    
    print_success "XHTTP-VLESS 添加成功！"
    print_separator
    echo "📌 连接信息:"
    echo "  子域名: ${subdomain}"
    echo "  UUID:   ${uuid}"
    echo "  路径:   ${path}"
    echo "  端口:   443"
    print_separator
    echo "📋 分享链接:"
    generate_share_link "${subdomain}"
    print_separator
}

# 添加 WebSocket VMess
add_ws_vmess() {
    local protocol_type="ws-vmess"
    
    local base_domain
    base_domain=$(get_base_domain)
    
    if [[ -z "${base_domain}" ]]; then
        print_error "未找到基础域名，请先运行基础安装"
        return 1
    fi
    
    # 自动生成子域名
    local subdomain
    subdomain=$(generate_subdomain "${protocol_type}" "${base_domain}")
    
    if [[ "$(check_subdomain_exists "${subdomain}")" == "true" ]]; then
        print_error "协议 ${protocol_type} (${subdomain}) 已存在"
        return 1
    fi
    
    print_separator
    print_info "添加 VMess-WebSocket 协议"
    print_separator
    echo "📋 默认配置信息:"
    echo "  协议类型: VMess + WebSocket + TLS"
    echo "  子域名:   ${subdomain}"
    echo "  证书:     共享 SAN 证书 (${base_domain})"
    print_separator
    
    local port=$(get_protocol_port "${protocol_type}")
    local uuid=$(${XRAY_BIN} uuid)
    local path="/$(openssl rand -hex 4)"
    
    print_info "生成的配置参数:"
    echo "  端口:     ${port}"
    echo "  UUID:     ${uuid}"
    echo "  路径:     ${path}"
    
    add_protocol_to_db "${subdomain}" "${protocol_type}" "${port}" "${uuid}" "${path}"
    
    # 使用共享SAN证书
    local cert_dir="${NGINX_SSL_DIR}/${base_domain}"
    if [[ ! -f "${cert_dir}/fullchain.pem" ]]; then
        print_error "SAN 证书不存在，请先运行基础安装"
        remove_protocol_from_db "${subdomain}"
        return 1
    fi
    
    local inbound_exists
    inbound_exists=$(check_inbound_exists "${port}")
    if [[ "${inbound_exists}" == "false" ]]; then
        add_xray_inbound "${protocol_type}" "${port}" "${uuid}" "${path}" "${subdomain}_vmess" "${base_domain}"
    else
        add_client_to_inbound "${port}" "${uuid}" "${protocol_type}" "${subdomain}_vmess" "${path}"
    fi
    
    add_nginx_proto_server "${subdomain}" "${protocol_type}" "${port}" "${path}"
    regenerate_stream_config
    
    if ! nginx -t 2>/dev/null; then
        print_error "Nginx配置测试失败"
        return 1
    fi
    systemctl reload nginx
    
    if ! systemctl restart xray; then
        print_error "Xray 服务重启失败"
        return 1
    fi
    
    print_success "VMess-WS 添加成功！"
    print_separator
    echo "📌 连接信息:"
    echo "  子域名: ${subdomain}"
    echo "  UUID:   ${uuid}"
    echo "  路径:   ${path}"
    echo "  端口:   443"
    print_separator
    echo "📋 分享链接:"
    generate_share_link "${subdomain}"
    print_separator
}

# 添加 VLESS + XHTTP + Reality
add_xhttp_reality() {
    local protocol_type="xhttp-reality"
    
    local base_domain
    base_domain=$(get_base_domain)
    
    if [[ -z "${base_domain}" ]]; then
        print_error "未找到基础域名，请先运行基础安装"
        return 1
    fi
    
    # 自动生成子域名
    local subdomain
    subdomain=$(generate_subdomain "${protocol_type}" "${base_domain}")
    
    if [[ "$(check_subdomain_exists "${subdomain}")" == "true" ]]; then
        print_error "协议 ${protocol_type} (${subdomain}) 已存在"
        return 1
    fi
    
    print_separator
    print_info "添加 VLESS + XHTTP + Reality 协议"
    print_separator
    echo "📋 默认配置信息:"
    echo "  协议类型: VLESS + XHTTP + Reality"
    echo "  子域名:   ${subdomain}"
    echo "  证书:     共享 SAN 证书 (${base_domain})"
    print_separator
    
    local port=$(get_protocol_port "${protocol_type}")
    local uuid=$(${XRAY_BIN} uuid)
    local path="/$(openssl rand -hex 4)"
    
    # 生成 Reality 密钥对
    print_info "生成 Reality 密钥对..."
    local keys
    keys=$(${XRAY_BIN} x25519)
    local private_key public_key short_id
    private_key=$(echo "${keys}" | grep -i "Private" | awk '{print $NF}')
    public_key=$(echo "${keys}" | grep -i "Public\|Password" | awk '{print $NF}')
    short_id=$(openssl rand -hex 8)
    
    print_info "生成的配置参数:"
    echo "  端口:     ${port}"
    echo "  UUID:     ${uuid}"
    echo "  路径:     ${path}"
    echo "  Short ID: ${short_id}"
    
    add_protocol_to_db "${subdomain}" "${protocol_type}" "${port}" "${uuid}" "${path}"
    
    # 使用共享SAN证书
    local cert_dir="${NGINX_SSL_DIR}/${base_domain}"
    if [[ ! -f "${cert_dir}/fullchain.pem" ]]; then
        print_error "SAN 证书不存在，请先运行基础安装"
        remove_protocol_from_db "${subdomain}"
        return 1
    fi
    
    # 保存 Reality 密钥供分享链接使用
    mkdir -p "${XRAY_DIR}/.keys"
    chmod 700 "${XRAY_DIR}/.keys"
    echo "${public_key}" > "${XRAY_DIR}/.keys/${subdomain}_pubkey"
    echo "${short_id}" > "${XRAY_DIR}/.keys/${subdomain}_shortid"
    echo "${private_key}" > "${XRAY_DIR}/.keys/${subdomain}_privkey"
    
    # 配置 Xray inbound
    local inbound_exists
    inbound_exists=$(check_inbound_exists "${port}")
    if [[ "${inbound_exists}" == "false" ]]; then
        add_xray_inbound "${protocol_type}" "${port}" "${uuid}" "${path}" "${subdomain}_xhttp_reality" "${subdomain}" "${private_key}" "${short_id}"
    else
        add_client_to_inbound "${port}" "${uuid}" "${protocol_type}" "${subdomain}_xhttp_reality" "${path}"
    fi
    
    # xhttp-reality 不需要 Nginx HTTPS server（流量直接到 Xray，Reality 自己处理 TLS）
    # 只需更新 Stream SNI 配置
    regenerate_stream_config
    
    if ! nginx -t 2>/dev/null; then
        print_error "Nginx配置测试失败"
        return 1
    fi
    systemctl reload nginx
    
    if ! systemctl restart xray; then
        print_error "Xray 服务重启失败"
        return 1
    fi
    
    print_success "VLESS + XHTTP + Reality 添加成功！"
    print_separator
    echo "📌 连接信息:"
    echo "  子域名:   ${subdomain}"
    echo "  UUID:     ${uuid}"
    echo "  路径:     ${path}"
    echo "  端口:     443"
    echo "  Public Key: ${public_key}"
    echo "  Short ID:   ${short_id}"
    print_separator
    echo "📋 分享链接:"
    generate_share_link "${subdomain}"
    print_separator
}

#================== Xray 配置更新 ==================

add_xray_inbound() {
    local type=$1
    local port=$2
    local id=$3
    local path=${4:-""}
    local email=${5:-""}
    local domain=${6:-""}  # 域名参数
    local private_key=${7:-""}  # Reality 私钥
    local short_id=${8:-""}  # Reality short ID
    
    local inbound_config=""
    
    case "${type}" in
        "ws-vless")
            inbound_config=$(cat <<EOF
    {
      "tag": "${email}",
      "listen": "/dev/shm/xray_${port}.sock,0666",
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "${id}", "email": "${email}"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${path}"
        },
        "security": "none"
      },
      "sockopt": {"acceptProxyProtocol": false}
    }
EOF
)
            ;;
        "xhttp-vless")
            inbound_config=$(cat <<EOF
    {
      "tag": "${email}",
      "listen": "/dev/shm/xray_${port}.sock,0666",
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "${id}", "email": "${email}"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "path": "${path}"
        },
        "security": "none"
      },
      "sockopt": {"acceptProxyProtocol": false}
    }
EOF
)
            ;;
        "ws-vmess")
            inbound_config=$(cat <<EOF
    {
      "tag": "${email}",
      "listen": "/dev/shm/xray_${port}.sock,0666",
      "protocol": "vmess",
      "settings": {
        "clients": [{"id": "${id}", "email": "${email}"}]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${path}"
        },
        "security": "none"
      },
      "sockopt": {"acceptProxyProtocol": false}
    }
EOF
)
            ;;
        "xhttp-reality")
            # VLESS + XHTTP + Reality 配置
            # 直接从 Nginx stream 接收流量，Xray 处理 Reality TLS
            # 伪装回落到 Nginx HTTPS 伪装站 (8089)
            inbound_config=$(cat <<EOF
    {
      "tag": "${email}",
      "listen": "/dev/shm/xray_${port}.sock,0666",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${id}",
            "email": "${email}"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": "127.0.0.1:8089",
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "path": "${path}"
        },
        "security": "reality",
        "realitySettings": {
          "dest": "127.0.0.1:8089",
          "xver": 1,
          "serverNames": ["${domain}"],
          "privateKey": "${private_key}",
          "shortIds": ["${short_id}"]
        },
        "sockopt": {
          "acceptProxyProtocol": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    }
EOF
)
            ;;
    esac
    
    # 使用jq添加到inbounds数组
    local tmp_file="/tmp/xray_config.tmp"
    jq ".inbounds += [${inbound_config}]" "${XRAY_CONFIG}" > "${tmp_file}"
    mv "${tmp_file}" "${XRAY_CONFIG}"
}

#================== Nginx 配置生成 ==================

# 阶段1: 仅用于ACME证书申请的最小配置
generate_nginx_acme_config() {
    local domain=$1
    
    print_info "生成Nginx ACME配置（用于证书申请）..."
    
    mkdir -p "${NGINX_CONF_D}"
    mkdir -p /var/log/nginx
    mkdir -p "${ACME_DIR}"
    
    # 生成主配置
    cat > "${NGINX_CONF}" <<'EOF'
user www-data;
worker_processes auto;
pid /var/run/nginx.pid;
error_log /var/log/nginx/error.log error;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    access_log off;
    error_log /var/log/nginx/error.log error;
    
    sendfile on;
    keepalive_timeout 65;
    
    # HTTP服务器（用于ACME）
    server {
        listen 80;
        listen [::]:80;
        server_name _;
        
        # ACME 挑战目录 - 使用 alias 直接映射
        location ^~ /.well-known/acme-challenge/ {
            alias /var/www/acme/.well-known/acme-challenge/;
            default_type text/plain;
        }
        
        # 健康检查端点
        location = /health {
            return 200 'OK';
            add_header Content-Type text/plain;
        }
        
        # 其他请求返回空响应
        location / {
            return 444;
        }
    }
}
EOF
    
    # 创建 ACME 目录结构
    mkdir -p "${ACME_DIR}/.well-known/acme-challenge"
    chmod -R 755 "${ACME_DIR}"
    
    # 删除可能存在的旧配置
    rm -f "${NGINX_CONF_D}/stream.conf" "${NGINX_CONF_D}/http.conf"
    
    print_success "Nginx ACME配置生成完成"
}



#================== 主菜单 ==================
# 协议管理菜单
protocol_management_menu() {
    while true; do
        clear
        print_separator
        echo -e "${CYAN}协议管理${NC}"
        print_separator
        echo "1. 添加新协议"
        echo "2. 删除协议"
        echo "3. 查看已安装协议"
        echo "4. 显示分享链接"
        echo "0. 返回主菜单"
        print_separator
        read -p "请选择操作 [0-4]: " choice
        
        case "${choice}" in
            1) add_protocol_interactive || true; read -p "按回车键继续..." ;;
            2) remove_protocol_interactive || true; read -p "按回车键继续..." ;;
            3) list_protocols; read -p "按回车键继续..." ;;
            4) show_all_links; read -p "按回车键继续..." ;;
            0) return 0 ;;
            *) print_warn "无效选择"; sleep 1 ;;
        esac
    done
}

# 中转管理菜单
transit_management_menu() {
    while true; do
        clear
        print_separator
        echo -e "${CYAN}中转管理${NC}"
        print_separator
        echo "1. 配置出站方式 (分流/中转)"
        echo "2. 查看出站配置"
        echo "0. 返回主菜单"
        print_separator
        read -p "请选择操作 [0-2]: " choice
        
        case "${choice}" in
            1) configure_outbound || true; systemctl restart xray || true; read -p "按回车键继续..." ;;
            2) view_outbound_config || true; read -p "按回车键继续..." ;;
            0) return 0 ;;
            *) print_warn "无效选择"; sleep 1 ;;
        esac
    done
}

# 系统管理菜单
system_management_menu() {
    while true; do
        clear
        print_separator
        echo -e "${CYAN}系统管理${NC}"
        print_separator
        echo "1. 重启服务 (Nginx + Xray)"
        echo "2. 查看服务状态"
        echo "3. 强制更新证书"
        echo "4. 重置 Nginx 配置"
        echo "0. 返回主菜单"
        print_separator
        read -p "请选择操作 [0-4]: " choice
        
        case "${choice}" in
            1) 
                print_info "正在重启服务..."
                if systemctl restart nginx; then
                    print_success "Nginx 已重启"
                else
                    print_error "Nginx 重启失败"
                fi
                if systemctl restart xray; then
                    print_success "Xray 已重启"
                else
                    print_error "Xray 重启失败"
                    journalctl -xeu xray --no-pager | tail -n 10
                fi
                read -p "按回车键继续..." 
                ;;
            2) check_service_status || true; read -p "按回车键继续..." ;;
            3) force_update_cert || true; read -p "按回车键继续..." ;;
            4) force_regenerate_conf || true; read -p "按回车键继续..." ;;
            0) return 0 ;;
            *) print_warn "无效选择"; sleep 1 ;;
        esac
    done
}

# 检查服务状态
check_service_status() {
    print_separator
    echo -e "${CYAN}服务运行状态${NC}"
    print_separator
    
    # helper for checking
    check_status() {
        local service=$1
        if systemctl is-active --quiet "${service}"; then
            echo -e "${service}: ${GREEN}运行中 (Running)${NC}"
        else
            echo -e "${service}: ${RED}未运行 (Stopped)${NC}"
        fi
    }
    
    check_status "nginx"
    check_status "xray"
    
    print_separator
    echo -e "${CYAN}端口监听情况${NC}"
    print_separator
    
    if command -v ss &>/dev/null; then
        echo -e "${YELLOW}TCP 端口监听:${NC}"
        # 过滤 nginx 和 xray 进程，格式化输出
        ss -tulpn | grep -E 'nginx|xray' | awk 'BEGIN {printf "%-20s %-10s %s\n", "Address:Port", "PID/Name", "Process"} {printf "%-20s %-10s %s\n", $5, $7, $1}'
    else
        echo "未找到 ss 命令，尝试 netstat..."
        netstat -tulpn | grep -E 'nginx|xray'
    fi
    print_separator
}

show_menu() {
    clear
    print_separator
    echo -e "${CYAN}Nginx SNI + Xray 多协议管理系统${NC}"
    print_separator
    echo "1. 安装基础环境 (仅基础设施)"
    echo "2. 协议管理 (添加/删除/查看)"
    echo "3. 中转管理 (出站/分流)"
    echo "4. 系统管理 (重启/状态/证书)"
    echo "0. 退出"
    print_separator
}

install_base() {
    print_separator
    echo -e "${GREEN}开始安装基础环境${NC}"
    print_separator
    
    # 获取域名
    while true; do
        read -p "请输入主域名（用于Reality）: " main_domain
        if validate_domain "${main_domain}"; then
            break
        else
            print_error "域名格式无效，请重新输入（例如: example.com）"
        fi
    done
    
    # 安装依赖和软件
    check_system
    install_dependencies
    install_nginx || return 1
    install_xray || return 1
    install_acme || return 1
    
    # 初始化数据库
    init_protocols_db
    
    # 保存base_domain到数据库
    set_base_domain "${main_domain}"
    
    # 生成伪装网站
    generate_fake_website "${main_domain}"
    
    # 阶段1: 生成ACME专用配置（无SSL依赖）
    generate_nginx_acme_config "${main_domain}"
    
    # 启动Nginx（HTTP模式，用于ACME验证）
    print_info "启动Nginx（ACME模式）..."
    if ! systemctl start nginx; then
        print_error "Nginx 启动失败"
        print_info "尝试检查配置: nginx -t"
        nginx -t || true
        return 1
    fi
    sleep 2
    
    # 申请 SAN 多域名证书（包含所有预定义子域名）
    print_separator
    print_info "📋 申请 SAN 多域名证书..."
    print_info "这将为以下 6 个域名申请一个统一证书："
    get_all_planned_domains "${main_domain}" | while read -r d; do
        echo "  - ${d}"
    done
    print_separator
    
    if ! request_cert_san "${main_domain}"; then
        print_error "SAN 证书申请失败"
        print_warn "可能原因："
        print_warn "  1. DNS 记录未正确指向本服务器（需要为所有 6 个域名配置 A 记录）"
        print_warn "  2. 防火墙阻止了 80 端口"
        print_warn "  3. 域名解析尚未生效（需等待 DNS 传播）"
        print_separator
        read -p "是否跳过证书申请继续安装？(y/N) " continue_install
        if [[ "${continue_install}" != "y" && "${continue_install}" != "Y" ]]; then
            print_info "已取消安装"
            return 1
        fi
        print_warn "警告: 未申请证书，后续添加协议将失败！"
    else
        print_success "SAN 证书申请成功！所有协议将共享此证书"
    fi
    
    # 初始化Reality（使用realx子域名）- 必须在生成配置前完成，以便写入数据库
    # local reality_domain
    # reality_domain=$(generate_subdomain "reality" "${main_domain}")
    # init_reality_protocol "${reality_domain}"
    
    # 替换为生成初始配置骨架
    generate_initial_xray_config
    
    # 阶段2: 证书申请成功后，生成完整配置 (SNI分流模式)
    generate_nginx_sni_config "${main_domain}"
    
    # 重新加载配置
    print_info "重启服务..."
    systemctl restart nginx
    systemctl restart xray
    
    print_separator
    print_success "基础环境安装完成！(基础设施已就绪)"
    print_separator
    echo "✅ SAN 证书已申请，包含以下域名："
    echo "  - ${main_domain} (主域名)"
    echo "  - reality.${main_domain} (自动预留)"
    echo "  - vlx.${main_domain}"
    echo "  - vmx.${main_domain}"
    echo "  - vlxrex.${main_domain}"
    echo "  - xhx.${main_domain}"
    print_separator
    echo "💡 下一步：请使用 '2. 协议管理' -> '1. 添加新协议' 来安装具体的代理协议。"
    print_separator
}

add_protocol_interactive() {
    print_separator
    echo -e "${GREEN}添加新协议${NC}"
    print_separator
    
    # 检查是否已初始化
    local base_domain
    base_domain=$(get_base_domain)
    if [[ -z "${base_domain}" ]]; then
        print_error "未找到基础域名，请先运行基础安装"
        return 1
    fi
    
    # 检查数量限制
    local count
    count=$(get_protocol_count)
    if [[ ${count} -ge ${MAX_PROTOCOLS} ]]; then
        print_error "已达协议数量上限 (${MAX_PROTOCOLS})"
        return 1
    fi
    
    echo "基础域名: ${base_domain}"
    echo ""
    echo "选择要添加的协议类型（子域名将自动生成）:"
    echo "1) VLESS + Vision + Reality (原默认) → reality.${base_domain}"
    echo "2) VLESS + WebSocket + TLS          → vlx.${base_domain}"
    echo "3) VLESS + XHTTP + TLS              → xhx.${base_domain}"
    echo "4) VMess + WebSocket + TLS          → vmx.${base_domain}"
    echo "5) VLESS + XHTTP + Reality          → vlxrex.${base_domain}"
    echo "0) 返回上级菜单"
    read -p "请选择 [0-5]: " choice
    
    case "${choice}" in
        1) add_vision_reality ;;
        2) add_ws_vless ;;
        3) add_xhttp_vless ;;
        4) add_ws_vmess ;;
        5) add_xhttp_reality ;;
        0) return 0 ;;
        *) print_warn "无效选择，返回上级菜单"; return 0 ;;
    esac
    
    # 注意：服务重启和分享链接显示已在各协议添加函数内完成
}

remove_protocol_interactive() {
    print_separator
    echo -e "${GREEN}删除协议${NC}"
    print_separator
    
    # 检查数据库是否存在
    if [[ ! -f "${PROTOCOLS_DB}" ]]; then
        print_error "协议数据库不存在"
        return 1
    fi

    # 获取所有域名
    local domains
    domains=$(jq -r '.protocols[].domain' "${PROTOCOLS_DB}" 2>/dev/null | sort)
    
    if [[ -z "${domains}" ]]; then
        print_warn "当前没有任何协议"
        return 0
    fi
    
    # 转为数组
    local domain_array=(${domains})
    local total=${#domain_array[@]}
    
    echo "当前已安装协议:"
    local i=1
    for d in "${domain_array[@]}"; do
        echo "  ${i}) ${d}"
        ((i++))
    done
    echo "  0) 取消"
    echo ""
    
    read -p "请输入序号或域名关键词: " input
    
    if [[ "${input}" == "0" ]]; then
        return 0
    fi
    
    local domain=""
    
    # 判断输入是数字还是关键词
    if [[ "${input}" =~ ^[0-9]+$ ]] && [[ ${input} -le ${total} ]] && [[ ${input} -ge 1 ]]; then
        # 输入的是序号
        domain="${domain_array[$((input-1))]}"
    else
        # 输入的是关键词 (模糊匹配)
        local matches=()
        for d in "${domain_array[@]}"; do
            if [[ "${d}" == *"${input}"* ]]; then
                matches+=("${d}")
            fi
        done
        
        local match_count=${#matches[@]}
        
        if [[ ${match_count} -eq 0 ]]; then
            print_error "未找到包含 '${input}' 的协议"
            return 1
        elif [[ ${match_count} -eq 1 ]]; then
            domain="${matches[0]}"
        else
            echo "找到多个匹配项:"
            local j=1
            for m in "${matches[@]}"; do
                echo "  ${j}) ${m}"
                ((j++))
            done
            read -p "请确认删除哪个 (输入序号): " confirm_idx
            if [[ "${confirm_idx}" =~ ^[0-9]+$ ]] && [[ ${confirm_idx} -ge 1 && ${confirm_idx} -le ${match_count} ]]; then
                domain="${matches[$((confirm_idx-1))]}"
            else
                print_error "无效选择"
                return 1
            fi
        fi
    fi
    
    if [[ -z "${domain}" ]]; then
        return 1
    fi
    
    # 获取协议详情
    local info
    info=$(jq -r --arg domain "${domain}" '.protocols[] | select(.domain == $domain) | "\(.type)|\(.port)|\(.uuid)|\(.path)"' "${PROTOCOLS_DB}" 2>/dev/null)
    
    if [[ -z "${info}" ]]; then
        print_error "未找到域名为 ${domain} 的协议"
        return 1
    fi
    
    local type=$(echo "${info}" | cut -d'|' -f1)
    local port=$(echo "${info}" | cut -d'|' -f2)
    local uuid=$(echo "${info}" | cut -d'|' -f3)
    local path=$(echo "${info}" | cut -d'|' -f4)
    
    print_separator
    print_warn "即将删除以下协议:"
    echo "  域名: ${domain}"
    echo "  类型: ${type}"
    echo "  端口: ${port}"
    echo "  UUID: ${uuid}"
    print_separator
    
    read -p "确认删除？(y/N): " confirm
    if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
        print_info "已取消"
        return 0
    fi
    
    # 1. 清理 Nginx
    remove_nginx_config "${domain}" "${port}" "${path}"
    
    # 2. 清理 Xray Client
    remove_client_from_inbound "${port}" "${uuid}" "${type}"
    
    # 3. 从数据库删除
    remove_protocol_from_db "${domain}"
    
    # 3.5 重新生成 Stream 配置 (确保SNI映射被正确移除)
    regenerate_stream_config
    
    # 4. 重载服务
    systemctl reload nginx
    if ! systemctl restart xray; then
        print_warn "Xray 重启失败，请检查日志"
    fi
    
    print_success "协议已完全移除并清理"
}

force_update_cert() {
    print_separator
    echo -e "${GREEN}强制更新/修复证书${NC}"
    print_separator
    
    local base_domain
    base_domain=$(get_base_domain)
    
    if [[ -z "${base_domain}" ]]; then
        print_error "未找到基础域名，请先运行基础安装"
        return 1
    fi
    
    print_info "正在检查并更新域名: ${base_domain}"
    
    # 强制重新申请（通过 request_cert_san 的内部检查逻辑）
    # 如果需要强制覆盖，可以手动删除旧证书，这里我们依赖 request_cert_san 的智能检查
    # 但为了“强制”，我们可以先删除有效期检查标记？
    # 不，request_cert_san 已经很智能了，如果缺少域名会自动更新。
    # 如果用户想完全强制，我们可以在这里删除旧文件。
    
    echo "1) 智能更新 (仅在域名缺失或过期时更新)"
    echo "2) 强制重置 (删除旧证书并重新申请)"
    echo "0) 返回上级菜单"
    read -p "请选择 [0-2]: " cert_choice
    
    if [[ "${cert_choice}" == "0" ]]; then
        return 0
    fi
    
    if [[ "${cert_choice}" == "2" ]]; then
        print_warn "正在删除旧证书..."
        rm -rf "${NGINX_SSL_DIR}/${base_domain}"
    elif [[ "${cert_choice}" != "1" ]]; then
        print_warn "无效选择，返回上级菜单"
        return 0
    fi

    if request_cert_san "${base_domain}"; then
        print_success "证书检查/更新完成"
        systemctl reload nginx
        print_info "Nginx 已重载"
    else
        print_error "证书更新失败"
    fi

}

force_regenerate_conf() {
    print_separator
    echo -e "${GREEN}重置 Nginx 配置文件 & 修复 Xray 配置${NC}"
    print_separator
    
    # 尝试修复可能丢失的 API Inbound
    # 检查 Xray 配置文件状态
    if [[ ! -f "${XRAY_CONFIG}" ]] || ! jq . "${XRAY_CONFIG}" >/dev/null 2>&1; then
        print_warn "Xray 配置文件丢失或损坏，正在重置为默认..."
        mkdir -p "${XRAY_DIR}"
        # 重置为包含 API 的基础配置
        cat > "${XRAY_CONFIG}" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": 10085,
    "protocol": "dokodemo-door",
    "settings": { "address": "127.0.0.1" },
    "tag": "api"
  }],
  "outbounds": [{ "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "block" }],
  "routing": { "domainStrategy": "IPIfNonMatch", "rules": [] }
}
EOF
        print_success "Xray 配置文件已重置"
    else
        # 配置文件存在，检查并修复 API Inbound
        if ! jq -e '.inbounds[]? | select(.tag == "api")' "${XRAY_CONFIG}" >/dev/null 2>&1; then
            print_warn "检测到 Xray API 配置丢失，正在修复..."
            local tmp_fix="/tmp/xray_fix.tmp"
            # 使用更安全的 jq 逻辑 (处理 inbounds 可能为 null 的情况)
            jq '.inbounds = [{
                "listen": "127.0.0.1",
                "port": 10085,
                "protocol": "dokodemo-door",
                "settings": { "address": "127.0.0.1" },
                "tag": "api"
            }] + (.inbounds // [])' "${XRAY_CONFIG}" > "${tmp_fix}"
            
            if [[ -s "${tmp_fix}" ]] && jq . "${tmp_fix}" >/dev/null 2>&1; then
                mv "${tmp_fix}" "${XRAY_CONFIG}"
                print_success "API 配置已恢复"
            else
                print_error "API 修复失败"
                print_error "API 修复失败"
            fi
        fi
        
        # 修复重复用户 (Deduplicate clients by email)
        print_info "检查重复用户配置..."
        local tmp_dedup="/tmp/xray_dedup.tmp"
        # 对每个 inbound 的 clients 数组按 email 去重
        jq '.inbounds |= map(if .settings.clients then .settings.clients |= unique_by(.email) else . end)' "${XRAY_CONFIG}" > "${tmp_dedup}"
        
        if [[ -s "${tmp_dedup}" ]] && jq . "${tmp_dedup}" >/dev/null 2>&1; then
             mv "${tmp_dedup}" "${XRAY_CONFIG}"
             print_success "用户配置去重完成"
        fi
    fi

    local base_domain
    base_domain=$(get_base_domain)
    
    if [[ -z "${base_domain}" ]]; then
        print_error "未找到基础域名"
        return 1
    fi
    
    # 调用生成函数（内部会清理旧文件）
    generate_nginx_sni_config "${base_domain}"
    
    # 还需要重新生成所有已存在协议的 server 块
    print_info "正在重新生成协议 Server 块..."
    if [[ -f "${PROTOCOLS_DB}" ]]; then
        # 遍历数据库重新生成 https_*.conf
        # 格式: domain|type|port|path
        jq -r '.protocols[] | "\(.domain)|\(.type)|\(.port)|\(.path // "")"' "${PROTOCOLS_DB}" | while read -r proto_info; do
            local p_domain=$(echo "${proto_info}" | cut -d'|' -f1)
            local p_type=$(echo "${proto_info}" | cut -d'|' -f2)
            local p_port=$(echo "${proto_info}" | cut -d'|' -f3)
            local p_path=$(echo "${proto_info}" | cut -d'|' -f4)
            
            # Reality 和 xhttp-reality 不需要 https server 块 (它们走内部 socket，自己处理 TLS)
            if [[ "${p_type}" != "reality" && "${p_type}" != "xhttp-reality" ]]; then
                add_nginx_proto_server "${p_domain}" "${p_type}" "${p_port}" "${p_path}"
            fi
        done
    fi

    # 重新加载 Stream
    regenerate_stream_config
    
    if nginx -t; then
        systemctl restart nginx
        print_success "Nginx重启完成"
        
        # 独立的 Xray 检查与重启逻辑
        print_info "正在检查 Xray 配置..."
        if ${XRAY_BIN} -test -config "${XRAY_CONFIG}"; then
            if systemctl restart xray; then
                print_success "Xray 重启完成"
            else
                print_error "Xray 服务启动失败"
                print_warn "正在显示最近的错误日志:"
                journalctl -xeu xray --no-pager | tail -n 20
            fi
        else
            print_error "Xray 配置文件测试未通过"
        fi
    else
        print_error "Nginx 配置有误，请检查日志"
    fi
}

show_all_links() {
    print_separator
    echo -e "${CYAN}所有协议分享链接${NC}"
    print_separator
    
    jq -r '.protocols[].domain' "${PROTOCOLS_DB}" 2>/dev/null | while read -r domain; do
        echo ""
        echo "域名: ${domain}"
        generate_share_link "${domain}"
    done
    
    print_separator
}


#================== Nginx SNI 配置生成（新增）==================

# 动态重新生成 Stream SNI 配置
regenerate_stream_config() {
    print_info "更新Nginx Stream SNI映射..."
    
    # 开始生成 stream.conf
    cat > "${NGINX_CONF_D}/stream.conf" <<'STREAM_START'
stream {
    # 关闭日志防止膨胀
    access_log off;
    
    map $ssl_preread_server_name $backend {
STREAM_START
    
    # 从数据库读取所有协议，生成SNI映射
    if [[ -f "${PROTOCOLS_DB}" ]]; then
        jq -r '.protocols[] | "        \(.domain)  \(.type)_backend;"' "${PROTOCOLS_DB}" >> "${NGINX_CONF_D}/stream.conf"
    fi
    
    # 添加默认backend
    cat >> "${NGINX_CONF_D}/stream.conf" <<'STREAM_MAP_END'
        default  web_backend;
    }
STREAM_MAP_END
    
    # 生成upstream定义（特殊处理Reality协议）
    if [[ -f "${PROTOCOLS_DB}" ]]; then
        # 遍历所有协议类型，生成对应的upstream
        local types
        types=$(jq -r '.protocols[].type' "${PROTOCOLS_DB}" 2>/dev/null | sort -u)
        
        
        for type in ${types}; do
            if [[ "${type}" == "reality" ]]; then
                # Reality 特殊处理：指向 Xray Reality socket
                cat >> "${NGINX_CONF_D}/stream.conf" <<EOF

    upstream reality_backend {
        server unix:/dev/shm/xray_reality.sock;
    }
EOF
            elif [[ "${type}" == "xhttp-reality" ]]; then
                # xhttp-reality 特殊处理：直接路由到 Xray socket（Reality 需要自己处理 TLS）
                local xhttp_reality_port
                xhttp_reality_port=$(jq -r '.protocols[] | select(.type == "xhttp-reality") | .port' "${PROTOCOLS_DB}" | head -n 1)
                
                if [[ -z "${xhttp_reality_port}" || "${xhttp_reality_port}" == "null" ]]; then
                    xhttp_reality_port="8004"
                fi
                
                cat >> "${NGINX_CONF_D}/stream.conf" <<EOF

    upstream xhttp-reality_backend {
        server unix:/dev/shm/xray_${xhttp_reality_port}.sock;
    }
EOF
            else
                # 其他协议：指向 Nginx HTTPS socket
                cat >> "${NGINX_CONF_D}/stream.conf" <<EOF

    upstream ${type}_backend {
        server unix:/dev/shm/nginx_${type}.sock;
    }
EOF
            fi
        done
    fi
    
    # 添加web后端和server块
    cat >> "${NGINX_CONF_D}/stream.conf" <<'STREAM_END'
    
    upstream web_backend {
        server unix:/dev/shm/nginx_web.sock;
    }
    
    server {
        listen 443 reuseport;
        listen [::]:443 reuseport;
        ssl_preread on;
        proxy_protocol on;
        proxy_pass $backend;
    }
}
STREAM_END
    
    print_success "Stream SNI配置已更新"
}

# 为协议添加 Nginx HTTPS server 配置
add_nginx_proto_server() {
    local subdomain=$1
    local protocol_type=$2
    local port=$3
    local path=${4:-""}  # 新增 path 参数
    
    # 获取base_domain用于证书路径
    local base_domain
    base_domain=$(get_base_domain)
    
    local server_file="${NGINX_CONF_D}/https_${subdomain}.conf"
    
    print_info "为 ${subdomain} 生成Nginx HTTPS配置..."
    
    cat > "${server_file}" <<EOF
# ${protocol_type} - ${subdomain}
    server {
        listen unix:/dev/shm/nginx_${protocol_type}.sock ssl proxy_protocol;
        http2 on;
        server_name ${subdomain};
        
        # 使用共享的 SAN 证书
        ssl_certificate ${NGINX_SSL_DIR}/${base_domain}/fullchain.pem;
        ssl_certificate_key ${NGINX_SSL_DIR}/${base_domain}/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        
        set_real_ip_from unix:;
        real_ip_header proxy_protocol;
        
EOF

    if [[ -n "${path}" ]]; then
        # 路径存在：配置分流（Path -> Xray, Root -> Fake Site）
        cat >> "${server_file}" <<EOF
        root ${FAKE_SITE_ROOT};
        index index.html;

        # 默认回落到伪装站
        location / {
            try_files \$uri \$uri/ =404;
        }

        # 代理路径转发给 Xray
        location ${path} {
            proxy_pass http://unix:/dev/shm/xray_${port}.sock;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$proxy_protocol_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
EOF
    else
        # 路径为空：全量转发 (Trojan 等)
        # Trojan 是纯 TCP 协议，不需要 WebSocket 相关头
        cat >> "${server_file}" <<EOF
        location / {
            proxy_pass http://unix:/dev/shm/xray_${port}.sock;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$proxy_protocol_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_buffering off;
        }
EOF
    fi

    cat >> "${server_file}" <<EOF
    }
EOF
    
    print_success "Nginx HTTPS配置已生成: ${server_file}"
}

# 生成伪装站的 HTTP 配置
generate_web_http_config() {
    local domain=$1
    
    # 确保伪装站目录存在
    if [[ ! -d "${FAKE_SITE_ROOT}" ]]; then
        mkdir -p "${FAKE_SITE_ROOT}"
        # 创建默认首页
        cat > "${FAKE_SITE_ROOT}/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
<title>Welcome to Nginx!</title>
<style>
    body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to ${domain}!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.</p>
</body>
</html>
EOF
        chown -R www-data:www-data "${FAKE_SITE_ROOT}"
    fi

    cat > "${NGINX_CONF_D}/http_web.conf" <<EOF
    # 伪装网站（接受所有子域名，用于Reality回落）
    server {
        # Reality 回落专用端口 (TCP)，确保兼容性
        listen 127.0.0.1:8089 ssl proxy_protocol;
        http2 on;
        
        # Trojan/VLESS/VMess 等解密后回落专用端口 (纯文本，无 Proxy Protocol，最稳)
        listen 127.0.0.1:8090;
        
        # 同时也保留 Unix Socket 供 SNI 分流的默认后端使用
        listen unix:/dev/shm/nginx_web.sock ssl proxy_protocol;
        
        # 包含主域名和所有子域名，确保Reality回落能正常显示伪装页面
        server_name ${domain} www.${domain} realx.${domain} vlx.${domain} vmx.${domain} vlxrex.${domain} xhx.${domain} *.${domain};
        
        ssl_certificate ${NGINX_SSL_DIR}/${domain}/fullchain.pem;
        ssl_certificate_key ${NGINX_SSL_DIR}/${domain}/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        
        set_real_ip_from unix:;
        real_ip_header proxy_protocol;
        
        root ${FAKE_SITE_ROOT};
        index index.html;
        
        location / {
            try_files \$uri \$uri/ =404;
        }
    }

    # HTTP重定向 (端口80 -> 443)
    server {
        listen 80;
        listen [::]:80;
        server_name _;
        
        location /.well-known/acme-challenge/ {
            root ${ACME_DIR};
        }
        
        location / {
            return 301 https://\$host\$request_uri;
        }
    }
EOF
}

# 生成完整的 Nginx SNI 配置
generate_nginx_sni_config() {
    local base_domain=$1
    
    print_info "生成Nginx SNI分流配置..."
    
    mkdir -p "${NGINX_CONF_D}"
    mkdir -p /var/log/nginx
    
    # 生成主配置
    cat > "${NGINX_CONF}" <<'EOF'
user www-data;
worker_processes auto;
pid /var/run/nginx.pid;
error_log /var/log/nginx/error.log error;

events {
    worker_connections 1024;
}

# Stream 配置 (TCP/UDP 层)
include /etc/nginx/conf.d/stream.conf;

# HTTP 配置 (应用层)
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    access_log off;
    error_log /var/log/nginx/error.log error;
    
    sendfile on;
    keepalive_timeout 65;
    
    # 包含我们的站点配置
    include /etc/nginx/conf.d/http_web.conf;
    include /etc/nginx/conf.d/https_*.conf;
}
EOF
    
    # 生成Stream配置
    regenerate_stream_config
    
    # 生成伪装站HTTP配置
    generate_web_http_config "${base_domain}"
    
    print_success "Nginx SNI配置生成完成"
}

#================== 主函数 ==================


main() {
    check_root
    
    while true; do
        show_menu
        read -p "请选择操作 [0-4]: " choice
        
        case "${choice}" in
            1)
                if ! install_base; then
                    print_error "基础环境安装失败"
                fi
                read -p "按回车键继续..."
                ;;
            2)
                protocol_management_menu
                ;;
            3)
                transit_management_menu
                ;;
            4)
                system_management_menu
                ;;
            0)
                print_info "退出"
                exit 0
                ;;
            *)
                print_error "无效选择"
                sleep 1
                ;;
        esac
    done
}

# 执行主程序
main
