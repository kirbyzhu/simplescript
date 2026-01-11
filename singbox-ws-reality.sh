#!/bin/bash

#================================================
# Sing-box VLESS (WS/Reality) 一键安装脚本 v2.0
# 系统支持: Debian 10+ (推荐), Ubuntu 22+
# 功能: WS/Reality 双模切换, 完整错误处理, 安全加固
#================================================

set -euo pipefail  # 严格模式

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 路径配置
SINGBOX_BIN="/usr/local/bin/sing-box"
CADDY_BIN="/usr/local/bin/caddy"
CONFIG_DIR="/etc/singbox-vless"
SINGBOX_CONFIG="${CONFIG_DIR}/config.json"
CADDY_CONFIG="${CONFIG_DIR}/Caddyfile"
WEB_DIR="/var/www/singbox"
INFO_FILE="${CONFIG_DIR}/info.conf"

# 日志文件
LOG_SINGBOX="/var/log/singbox.log"
LOG_CADDY="/var/log/caddy.log"

#================== 0. 基础函数 ==================

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_err() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_err "必须以 root 权限运行此脚本！"
        exit 1
    fi
}

check_system() {
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        if [[ "$ID" != "debian" && "$ID" != "ubuntu" ]]; then
            print_err "仅支持 Debian/Ubuntu 系统"
            exit 1
        fi
        print_info "系统: $ID $VERSION_ID"
    else
        print_err "无法检测系统类型"
        exit 1
    fi
}

# 端口检测
check_port() {
    local port=$1
    if ss -tln 2>/dev/null | grep -q ":$port "; then
        print_err "端口 $port 已被占用:"
        ss -tlnp 2>/dev/null | grep ":$port " || true
        return 1
    fi
    return 0
}

# 核心程序查找 (统一逻辑)
REAL_SINGBOX_BIN=""
REAL_CADDY_BIN=""

find_bin_path() {
    local bin_name=$1
    local default_path=$2
    local found_path=""
    
    print_info "正在定位 $bin_name ..." >&2
    
    # 1. 优先检查预设和标准路径
    local paths_to_check=("/usr/bin/$bin_name" "/usr/local/bin/$bin_name" "/usr/sbin/$bin_name" "$default_path")
    
    for p in "${paths_to_check[@]}"; do
        if [ -n "$p" ] && [ -x "$p" ]; then
            found_path="$p"
            break
        fi
    done
    
    # 2. 尝试 command -v
    if [ -z "$found_path" ]; then
        found_path=$(command -v "$bin_name" 2>/dev/null || echo "")
    fi
    
    # 3. 尝试 dpkg 查询 (Debian/Ubuntu)
    if [ -z "$found_path" ] && command -v dpkg &>/dev/null; then
        if dpkg -l "$bin_name" 2>/dev/null | grep -q "^ii"; then
            local dpkg_path
            dpkg_path=$(dpkg -L "$bin_name" 2>/dev/null | grep "bin/$bin_name$" | head -n 1)
            if [ -n "$dpkg_path" ] && [ -x "$dpkg_path" ]; then
                found_path="$dpkg_path"
            fi
        fi
    fi
    
    # 4. 全盘搜索 (最为耗时，作为最后手段)
    if [ -z "$found_path" ]; then
        print_warn "未在标准路径找到 $bin_name，尝试搜索系统..." >&2
        found_path=$(find /usr -type f -name "$bin_name" -executable 2>/dev/null | head -n 1)
    fi
    
    echo "$found_path"
}

detect_core_binaries() {
    # 查找 Sing-box
    REAL_SINGBOX_BIN=$(find_bin_path "sing-box" "$SINGBOX_BIN")
    
    if [ -z "$REAL_SINGBOX_BIN" ]; then
        print_warn "未检测到 Sing-box"
        read -p "请手动输入 Sing-box 路径 (留空取消): " input_sb
        if [ -n "$input_sb" ] && [ -x "$input_sb" ]; then
            REAL_SINGBOX_BIN="$input_sb"
        else
            print_err "无法继续：找不到 Sing-box"
            return 1
        fi
    fi
    print_ok "Sing-box 路径: $REAL_SINGBOX_BIN"
    
    # 查找 Caddy
    REAL_CADDY_BIN=$(find_bin_path "caddy" "$CADDY_BIN")
    
    if [ -z "$REAL_CADDY_BIN" ]; then
        print_warn "未检测到 Caddy"
        read -p "请手动输入 Caddy 路径 (留空取消): " input_caddy
        if [ -n "$input_caddy" ] && [ -x "$input_caddy" ]; then
            REAL_CADDY_BIN="$input_caddy"
        else
            print_err "无法继续：找不到 Caddy"
            return 1
        fi
    fi
    print_ok "Caddy 路径: $REAL_CADDY_BIN"
    
    return 0
}

# 智能下载 (带重试)
download_file() {
    local url=$1
    local dest=$2
    local max_retries=3
    local retry=0
    
    while [ $retry -lt $max_retries ]; do
        if command -v curl &>/dev/null; then
            if curl -L -o "$dest" "$url" --progress-bar --max-time 300 --connect-timeout 30; then
                return 0
            fi
        elif command -v wget &>/dev/null; then
            if wget -qO "$dest" "$url" --timeout=300 --tries=1 --show-progress; then
                return 0
            fi
        else
            print_err "未找到 curl 或 wget"
            return 1
        fi
        
        retry=$((retry + 1))
        if [ $retry -lt $max_retries ]; then
            print_warn "下载失败，重试 $retry/$max_retries..."
            sleep 2
        fi
    done
    
    print_err "下载失败，已重试 $max_retries 次"
    return 1
}

# 域名验证
validate_domain() {
    local domain=$1
    
    # 格式验证
    if ! [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        print_err "域名格式无效"
        return 1
    fi
    
    # DNS 解析验证
    print_info "正在验证域名解析..."
    local server_ip
    server_ip=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null || curl -s --max-time 10 http://checkip.amazonaws.com 2>/dev/null || echo "")
    
    if [ -z "$server_ip" ]; then
        print_warn "无法获取服务器公网IP，跳过DNS验证"
        return 0
    fi
    
    local domain_ip
    domain_ip=$(dig +short "$domain" 2>/dev/null | head -n1 || nslookup "$domain" 2>/dev/null | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' | head -n1 || echo "")
    
    if [ -z "$domain_ip" ]; then
        print_warn "无法解析域名 $domain"
        read -p "是否继续安装? (y/n): " confirm
        [[ "$confirm" != "y" ]] && return 1
        return 0
    fi
    
    if [ "$domain_ip" != "$server_ip" ]; then
        print_warn "域名解析IP ($domain_ip) 与服务器IP ($server_ip) 不匹配"
        read -p "是否继续安装? (y/n): " confirm
        [[ "$confirm" != "y" ]] && return 1
    else
        print_ok "域名验证通过: $domain -> $server_ip"
    fi
    
    return 0
}

#================== 1. 环境准备 ==================

install_dependencies() {
    print_info "正在更新系统并安装依赖..."
    
    export DEBIAN_FRONTEND=noninteractive
    
    if ! apt-get update -y; then
        print_err "apt-get update 失败，请检查网络和源配置"
        return 1
    fi
    
    if ! apt-get install -y curl wget tar jq openssl uuid-runtime qrencode iproute2 dnsutils; then
        print_err "依赖安装失败"
        return 1
    fi
    
    print_ok "系统依赖安装完成"
}

install_singbox() {
    if command -v sing-box &>/dev/null; then
        local version
        version=$(sing-box version 2>/dev/null | head -n1 | awk '{print $3}' || echo "未知")
        print_info "Sing-box 已安装: $version"
        return 0
    fi
    
    print_info "正在安装 Sing-box..."
    
    local arch
    arch=$(uname -m)
    case $arch in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *) print_err "不支持的架构: $arch"; return 1 ;;
    esac
    
    # 直接使用 GitHub latest release 重定向链接（避免 API 限制）
    local base_url="https://github.com/SagerNet/sing-box/releases/latest/download"
    local tmp_file="/tmp/singbox.tar.gz"
    
    print_info "正在下载最新版本..."
    
    # 清理旧文件
    rm -f "$tmp_file"
    
    # 尝试多个可能的文件名格式
    local download_success=false
    local patterns=(
        "sing-box-*-linux-${arch}.tar.gz"
        "sing-box_*_linux_${arch}.tar.gz"
    )
    
    # 先获取实际的最新版本号
    local version
    version=$(curl -sL https://github.com/SagerNet/sing-box/releases/latest | grep -oP 'tag/v\K[0-9.]+' | head -1 || echo "")
    
    if [ -n "$version" ]; then
        print_info "检测到版本: $version"
        local url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-${arch}.tar.gz"
        
        if download_file "$url" "$tmp_file"; then
            download_success=true
        fi
    fi
    
    # 如果上述方法失败，尝试备用格式
    if [ "$download_success" = false ]; then
        print_warn "尝试备用下载方式..."
        local alt_url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box_${version}_linux_${arch}.tar.gz"
        if download_file "$alt_url" "$tmp_file"; then
            download_success=true
        fi
    fi
    
    if [ "$download_success" = false ]; then
        print_err "所有下载方式均失败"
        print_info "请检查网络连接或手动安装 Sing-box"
        return 1
    fi
    
    # 验证文件类型
    if ! file "$tmp_file" | grep -qE "gzip compressed|tar archive"; then
        print_err "下载的文件不是有效的压缩包"
        print_info "文件类型: $(file "$tmp_file")"
        print_info "文件内容预览:"
        head -n 5 "$tmp_file"
        rm -f "$tmp_file"
        return 1
    fi
    
    if ! tar -xzf "$tmp_file" -C /tmp 2>/dev/null; then
        print_err "解压失败"
        rm -f "$tmp_file"
        return 1
    fi
    
    # 查找 sing-box 二进制文件
    local binary_path
    binary_path=$(find /tmp/sing-box* -name "sing-box" -type f -executable 2>/dev/null | head -1)
    
    if [ -z "$binary_path" ]; then
        print_err "未找到 sing-box 可执行文件"
        rm -rf "$tmp_file" /tmp/sing-box*
        return 1
    fi
    
    # 统一安装到 /usr/local/bin
    mv "$binary_path" "$SINGBOX_BIN"
    chmod +x "$SINGBOX_BIN"
    
    # 建立软链接到 /usr/bin 以便直接调用 (兼容性)
    ln -sf "$SINGBOX_BIN" /usr/bin/sing-box
    
    rm -rf "$tmp_file" /tmp/sing-box*
    
    local installed_version
    installed_version=$(sing-box version 2>/dev/null | head -n1 | awk '{print $3}' || echo "未知")
    print_ok "Sing-box 安装完成: $installed_version"
}

install_caddy() {
    # 1. 检查是否存在
    if command -v caddy &>/dev/null; then
        local version
        version=$(caddy version 2>/dev/null | awk '{print $1}' || echo "未知")
        print_info "Caddy 已安装: $version"
        # 确保软链接存在，方便 unify path
        if [ ! -f /usr/bin/caddy ] && [ -f /usr/local/bin/caddy ]; then
             ln -sf /usr/local/bin/caddy /usr/bin/caddy
        fi
        return 0
    fi
    
    print_info "正在安装 Caddy..."
    
    # 2. 优先尝试官方 APT 源安装 (Debian/Ubuntu)
    if command -v apt-get &>/dev/null; then
        print_info "尝试使用 apt 安装官方版本..."
        apt-get install -y debian-keyring debian-archive-keyring apt-transport-https 2>/dev/null
        
        # 导入 Key (带 --yes 防止覆盖时卡住)
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' 2>/dev/null | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null
        
        # 添加源
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' 2>/dev/null | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
        
        apt-get update 2>/dev/null
        if apt-get install -y caddy 2>/dev/null; then
            print_ok "Caddy 通过 apt 安装完成"
            return 0
        fi
        print_warn "apt 安装失败，转为手动下载安装..."
    fi
    
    # 3. 备用方案：直接下载二进制
    local arch
    arch=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
    # 修正架构名称以匹配 Caddy 官方命名 (amd64, arm64, armv7)
    case $arch in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
    esac
    
    local download_url="https://caddyserver.com/api/download?os=linux&arch=${arch}"
    print_info "正在从官网下载 Caddy ($arch)..."
    
    if download_file "$download_url" "/usr/local/bin/caddy"; then
        chmod +x /usr/local/bin/caddy
        # 建立软链接
        ln -sf /usr/local/bin/caddy /usr/bin/caddy
        print_ok "Caddy 手动安装完成"
        return 0
    else
        print_err "Caddy 安装失败"
        return 1
    fi
}

#================== 2. 内容生成 ==================

generate_website() {
    print_info "正在生成高级伪装网站..."
    mkdir -p "$WEB_DIR/css" "$WEB_DIR/js" "$WEB_DIR/blog" "$WEB_DIR/about"
    
    # Enhanced CSS with animations
    cat > "$WEB_DIR/css/style.css" <<'EOF'
:root { 
    --primary: #3b82f6; 
    --secondary: #8b5cf6;
    --text: #1f2937; 
    --bg: #f9fafb;
    --card-bg: #ffffff;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body { 
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.7; 
    color: var(--text); 
    background: var(--bg);
}

header { 
    background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
    padding: 1.5rem 0; 
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    position: sticky;
    top: 0;
    z-index: 100;
}

nav { 
    max-width: 1200px; 
    margin: 0 auto; 
    padding: 0 2rem; 
    display: flex; 
    justify-content: space-between; 
    align-items: center; 
}

.logo { 
    font-weight: 700; 
    font-size: 1.5rem; 
    color: white;
    text-decoration: none;
    text-shadow: 0 2px 4px rgba(0,0,0,0.2);
}

.nav-links { 
    display: flex; 
    gap: 2rem; 
    list-style: none; 
}

.nav-links a { 
    color: white; 
    text-decoration: none; 
    font-weight: 500;
    transition: opacity 0.3s;
}

.nav-links a:hover { opacity: 0.8; }

.container { 
    max-width: 1200px; 
    margin: 3rem auto; 
    padding: 0 2rem; 
}

.hero { 
    background: var(--card-bg);
    padding: 4rem 3rem; 
    border-radius: 1rem; 
    box-shadow: 0 10px 30px rgba(0,0,0,0.08);
    margin-bottom: 3rem;
    text-align: center;
}

.hero h1 { 
    font-size: 3rem; 
    margin-bottom: 1rem; 
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.hero p { 
    font-size: 1.25rem; 
    color: #6b7280; 
    max-width: 600px;
    margin: 0 auto;
}

.posts-grid { 
    display: grid; 
    grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); 
    gap: 2rem; 
}

.post-card { 
    background: var(--card-bg);
    padding: 2rem; 
    border-radius: 0.75rem; 
    box-shadow: 0 4px 12px rgba(0,0,0,0.06);
    transition: transform 0.3s, box-shadow 0.3s;
}

.post-card:hover { 
    transform: translateY(-5px); 
    box-shadow: 0 12px 24px rgba(0,0,0,0.12);
}

.post-card h2 { 
    font-size: 1.5rem; 
    margin-bottom: 0.75rem; 
    color: var(--primary);
}

.post-meta { 
    color: #9ca3af; 
    font-size: 0.875rem; 
    margin-bottom: 1rem; 
}

.post-card p { 
    color: #4b5563; 
    line-height: 1.6; 
}

.btn { 
    display: inline-block; 
    padding: 0.75rem 1.5rem; 
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    color: white; 
    text-decoration: none; 
    border-radius: 0.5rem; 
    font-weight: 600;
    transition: transform 0.2s;
    margin-top: 1rem;
}

.btn:hover { transform: scale(1.05); }

footer { 
    text-align: center; 
    padding: 3rem 2rem; 
    color: #9ca3af; 
    margin-top: 5rem; 
    border-top: 1px solid #e5e7eb;
}

article { 
    background: var(--card-bg);
    padding: 3rem; 
    border-radius: 1rem; 
    box-shadow: 0 10px 30px rgba(0,0,0,0.08);
}

article h1 { 
    font-size: 2.5rem; 
    margin-bottom: 1rem; 
    color: #111827; 
}

article .meta { 
    color: #6b7280; 
    font-size: 0.9rem; 
    margin-bottom: 2rem; 
    padding-bottom: 1rem;
    border-bottom: 2px solid #e5e7eb;
}

article p { margin-bottom: 1.5rem; line-height: 1.8; }
article h2 { margin-top: 2rem; margin-bottom: 1rem; color: var(--primary); }
article code { 
    background: #f3f4f6; 
    padding: 0.2rem 0.5rem; 
    border-radius: 0.25rem; 
    font-family: 'Courier New', monospace;
}
EOF

    # JavaScript for interactivity
    cat > "$WEB_DIR/js/main.js" <<'EOF'
document.addEventListener('DOMContentLoaded', function() {
    // Smooth scroll
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
    
    // Add fade-in animation
    const cards = document.querySelectorAll('.post-card');
    cards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        setTimeout(() => {
            card.style.transition = 'opacity 0.5s, transform 0.5s';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, index * 100);
    });
});
EOF

    # Enhanced Index Page
    cat > "$WEB_DIR/index.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tech Insights - Cloud Native & DevOps</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <header>
        <nav>
            <a href="/" class="logo">⚡ Tech Insights</a>
            <ul class="nav-links">
                <li><a href="/">Home</a></li>
                <li><a href="/blog/kubernetes.html">Blog</a></li>
                <li><a href="/about/">About</a></li>
            </ul>
        </nav>
    </header>
    
    <div class="container">
        <div class="hero">
            <h1>Cloud Native Architecture</h1>
            <p>Exploring modern infrastructure, microservices, and DevOps best practices</p>
        </div>
        
        <div class="posts-grid">
            <div class="post-card">
                <h2>Kubernetes Networking Deep Dive</h2>
                <div class="post-meta">📅 Jan 10, 2026 • ☁️ Cloud Native</div>
                <p>Understanding CNI plugins, service mesh, and eBPF-based networking solutions in modern Kubernetes clusters.</p>
                <a href="/blog/kubernetes.html" class="btn">Read More →</a>
            </div>
            
            <div class="post-card">
                <h2>eBPF: The Future of Observability</h2>
                <div class="post-meta">📅 Jan 8, 2026 • 🔍 Observability</div>
                <p>How eBPF is revolutionizing system monitoring, security, and network performance analysis.</p>
                <a href="/blog/ebpf.html" class="btn">Read More →</a>
            </div>
            
            <div class="post-card">
                <h2>GitOps with ArgoCD</h2>
                <div class="post-meta">📅 Jan 5, 2026 • 🚀 DevOps</div>
                <p>Implementing declarative continuous deployment using GitOps principles and ArgoCD.</p>
                <a href="/blog/gitops.html" class="btn">Read More →</a>
            </div>
        </div>
    </div>
    
    <footer>
        <p>© 2026 Tech Insights. Powered by Cloud Native Technologies.</p>
    </footer>
    
    <script src="/js/main.js"></script>
</body>
</html>
EOF

    # Blog Post 1
    cat > "$WEB_DIR/blog/kubernetes.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kubernetes Networking - Tech Insights</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <header>
        <nav>
            <a href="/" class="logo">⚡ Tech Insights</a>
            <ul class="nav-links">
                <li><a href="/">Home</a></li>
                <li><a href="/blog/kubernetes.html">Blog</a></li>
                <li><a href="/about/">About</a></li>
            </ul>
        </nav>
    </header>
    
    <div class="container">
        <article>
            <h1>Kubernetes Networking Deep Dive</h1>
            <div class="meta">Published on January 10, 2026 by Tech Team</div>
            
            <p>Kubernetes networking is one of the most critical aspects of running containerized workloads at scale. In this comprehensive guide, we'll explore the fundamental concepts and advanced patterns.</p>
            
            <h2>Container Network Interface (CNI)</h2>
            <p>The CNI specification defines how network plugins interact with Kubernetes. Popular implementations include Calico, Cilium, and Flannel, each with unique strengths.</p>
            
            <h2>Service Mesh Integration</h2>
            <p>Service meshes like Istio and Linkerd provide advanced traffic management, security, and observability features. They operate at Layer 7, offering fine-grained control over service-to-service communication.</p>
            
            <h2>eBPF-Based Networking</h2>
            <p>Modern CNI plugins leverage eBPF for high-performance packet processing directly in the kernel, reducing latency and improving throughput significantly.</p>
            
            <p>Understanding these concepts is essential for building resilient, scalable cloud-native applications.</p>
        </article>
    </div>
    
    <footer>
        <p>© 2026 Tech Insights. Powered by Cloud Native Technologies.</p>
    </footer>
</body>
</html>
EOF

    # Blog Post 2
    cat > "$WEB_DIR/blog/ebpf.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>eBPF Observability - Tech Insights</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <header>
        <nav>
            <a href="/" class="logo">⚡ Tech Insights</a>
            <ul class="nav-links">
                <li><a href="/">Home</a></li>
                <li><a href="/blog/kubernetes.html">Blog</a></li>
                <li><a href="/about/">About</a></li>
            </ul>
        </nav>
    </header>
    
    <div class="container">
        <article>
            <h1>eBPF: The Future of Observability</h1>
            <div class="meta">Published on January 8, 2026 by Tech Team</div>
            
            <p>Extended Berkeley Packet Filter (eBPF) has emerged as a game-changing technology for system observability, security, and networking.</p>
            
            <h2>What is eBPF?</h2>
            <p>eBPF allows running sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules. This provides unprecedented visibility into system behavior.</p>
            
            <h2>Use Cases</h2>
            <p>From network monitoring with <code>Cilium</code> to security enforcement with <code>Falco</code>, eBPF powers next-generation cloud-native tools.</p>
            
            <h2>Performance Benefits</h2>
            <p>By processing data directly in the kernel, eBPF eliminates context switches and reduces overhead, making it ideal for high-performance environments.</p>
        </article>
    </div>
    
    <footer>
        <p>© 2026 Tech Insights. Powered by Cloud Native Technologies.</p>
    </footer>
</body>
</html>
EOF

    # Blog Post 3
    cat > "$WEB_DIR/blog/gitops.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitOps with ArgoCD - Tech Insights</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <header>
        <nav>
            <a href="/" class="logo">⚡ Tech Insights</a>
            <ul class="nav-links">
                <li><a href="/">Home</a></li>
                <li><a href="/blog/kubernetes.html">Blog</a></li>
                <li><a href="/about/">About</a></li>
            </ul>
        </nav>
    </header>
    
    <div class="container">
        <article>
            <h1>GitOps with ArgoCD</h1>
            <div class="meta">Published on January 5, 2026 by Tech Team</div>
            
            <p>GitOps represents a paradigm shift in how we manage infrastructure and application deployments, using Git as the single source of truth.</p>
            
            <h2>Core Principles</h2>
            <p>GitOps follows declarative configuration, version control, and automated synchronization to ensure your cluster state matches your Git repository.</p>
            
            <h2>ArgoCD Benefits</h2>
            <p>ArgoCD provides automated deployment, drift detection, and rollback capabilities, making it the de facto standard for Kubernetes GitOps.</p>
            
            <h2>Best Practices</h2>
            <p>Structure your repositories with environment-specific overlays using Kustomize or Helm, and implement proper RBAC policies for security.</p>
        </article>
    </div>
    
    <footer>
        <p>© 2026 Tech Insights. Powered by Cloud Native Technologies.</p>
    </footer>
</body>
</html>
EOF

    # About Page
    cat > "$WEB_DIR/about/index.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>About - Tech Insights</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <header>
        <nav>
            <a href="/" class="logo">⚡ Tech Insights</a>
            <ul class="nav-links">
                <li><a href="/">Home</a></li>
                <li><a href="/blog/kubernetes.html">Blog</a></li>
                <li><a href="/about/">About</a></li>
            </ul>
        </nav>
    </header>
    
    <div class="container">
        <article>
            <h1>About Tech Insights</h1>
            <div class="meta">Our Mission & Vision</div>
            
            <p>Tech Insights is dedicated to exploring and sharing knowledge about cloud-native technologies, DevOps practices, and modern infrastructure patterns.</p>
            
            <h2>What We Cover</h2>
            <p>Our content focuses on Kubernetes, microservices architecture, observability, security, and the latest trends in distributed systems.</p>
            
            <h2>Our Team</h2>
            <p>We are a group of infrastructure engineers and DevOps practitioners passionate about building scalable, reliable systems.</p>
            
            <h2>Contact</h2>
            <p>For inquiries, reach out to us at contact@techinsights.example</p>
        </article>
    </div>
    
    <footer>
        <p>© 2026 Tech Insights. Powered by Cloud Native Technologies.</p>
    </footer>
</body>
</html>
EOF

    # 404 Page
    cat > "$WEB_DIR/404.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <div class="container">
        <div class="hero">
            <h1>404 - Page Not Found</h1>
            <p>The page you're looking for doesn't exist.</p>
            <a href="/" class="btn">← Back to Home</a>
        </div>
    </div>
</body>
</html>
EOF

    chown -R www-data:www-data "$WEB_DIR" 2>/dev/null || chown -R caddy:caddy "$WEB_DIR" 2>/dev/null || chown -R root:root "$WEB_DIR"
    print_ok "增强版伪装网站已准备就绪 (多页面 + JS 动画)"
}

#================== 3. 配置生成 ==================

select_protocol() {
    clear
    echo -e "${CYAN}请选择协议模式:${NC}"
    echo -e "1. ${GREEN}VLESS + WS + TLS${NC} (CDN 友好, Caddy 前置)"
    echo -e "2. ${GREEN}VLESS + Reality (外部)${NC} (偷取 Microsoft 证书, 无需本地证书)"
    echo -e "3. ${GREEN}VLESS + Reality (自己)${NC} (偷取自己域名证书, 需要 80 端口)"
    echo -e "0. ${YELLOW}返回上级菜单${NC}"
    echo ""
    read -p "请输入选项 [0-3] (默认2): " PROTO_CHOICE
    PROTO_CHOICE=${PROTO_CHOICE:-2}
    
    # 返回上级菜单
    if [ "$PROTO_CHOICE" == "0" ]; then
        return 1
    fi
    
    # 验证输入
    if [[ ! "$PROTO_CHOICE" =~ ^[1-3]$ ]]; then
        print_err "无效选项，请输入 1-3"
        sleep 2
        select_protocol
    fi
}

generate_config() {
    mkdir -p "$CONFIG_DIR"
    
    # 停止现有服务（如果存在）以避免端口冲突
    if systemctl is-active --quiet sb-vless 2>/dev/null || systemctl is-active --quiet caddy-vless 2>/dev/null; then
        print_info "检测到现有服务，正在停止..."
        systemctl stop sb-vless caddy-vless 2>/dev/null || true
        sleep 1
    fi
    
    # 配置备份
    if [ -f "$SINGBOX_CONFIG" ]; then
        local backup_dir
        backup_dir="/etc/singbox-vless/backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$backup_dir"
        cp -r "$CONFIG_DIR"/* "$backup_dir/" 2>/dev/null || true
        print_info "已备份配置到 $backup_dir"
    fi
    
    # 域名输入与验证
    local domain
    while true; do
        read -p "请输入解析后的域名: " domain
        # 清理输入
        domain=$(echo "$domain" | tr -cd '[:alnum:].-')
        
        if [ -z "$domain" ]; then
            print_err "域名不能为空"
            continue
        fi
        
        if validate_domain "$domain"; then
            break
        fi
    done
    
    DOMAIN="$domain"
    UUID=$(uuidgen)
    PATH_WS=$(uuidgen | cut -d- -f1)
    
    # Reality 密钥生成
    local keys private_key public_key short_id
    if ! keys=$(sing-box generate reality-keypair 2>&1) || [ -z "$keys" ]; then
        print_err "Reality 密钥生成失败，请检查 sing-box 版本"
        return 1
    fi
    
    private_key=$(echo "$keys" | grep "PrivateKey" | cut -d: -f2 | tr -d ' "')
    public_key=$(echo "$keys" | grep "PublicKey" | cut -d: -f2 | tr -d ' "')
    short_id=$(openssl rand -hex 8)

    # ----------------------------------------------------
    # 模式 A: VLESS + WS + TLS (Caddy 443 -> Singbox 10000)
    # ----------------------------------------------------
    if [ "$PROTO_CHOICE" == "1" ]; then
        MODE="WS"
        PORT_SINGBOX=10000
        
        # 端口检测
        check_port 443 || return 1
        check_port $PORT_SINGBOX || return 1
        
        # Sing-box Config
        cat > "$SINGBOX_CONFIG" <<EOF
{
  "log": { "level": "error", "output": "$LOG_SINGBOX" },
  "dns": {
    "servers": [
      { "tag": "google", "address": "tls://8.8.8.8" },
      { "tag": "local", "address": "https://223.5.5.5/dns-query", "detour": "direct" },
      { "tag": "block", "address": "rcode://success" }
    ],
    "rules": [
      { "rule_set": "geosite-cn", "server": "local" },
      { "rule_set": "geoip-cn", "server": "local" }
    ],
    "final": "google",
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "127.0.0.1",
      "listen_port": $PORT_SINGBOX,
      "users": [{ "uuid": "$UUID" }],
      "transport": { "type": "ws", "path": "/$PATH_WS" }
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "rule_set": ["geosite-cn", "geoip-cn"], "action": "reject" }
    ],
    "rule_set": [
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
        "download_detour": "direct"
      }
    ],
    "final": "direct",
    "auto_detect_interface": true
  }
}
EOF

        # Caddy Config
        cat > "$CADDY_CONFIG" <<EOF
{
    admin off
    log { 
        output file $LOG_CADDY
        level ERROR
    }
}

$DOMAIN {
    tls {
        protocols tls1.2 tls1.3
    }
    
    @ws {
        path /$PATH_WS
        header Connection *Upgrade*
        header Upgrade websocket
    }
    reverse_proxy @ws 127.0.0.1:$PORT_SINGBOX
    
    root * $WEB_DIR
    file_server
}
EOF

    # ----------------------------------------------------
    # 模式 B: VLESS + Reality (外部网站)
    # ----------------------------------------------------
    elif [ "$PROTO_CHOICE" == "2" ]; then
        MODE="Reality-External"
        PORT_CADDY=8443
        
        # 获取目标网站
        read -p "请输入 Reality 目标网站 (默认 www.microsoft.com): " REALITY_DEST
        REALITY_DEST=${REALITY_DEST:-www.microsoft.com}
        
        # 简单验证
        print_info "正在验证 $REALITY_DEST 可达性..."
        if curl -s -I --max-time 5 "https://$REALITY_DEST" >/dev/null; then
            print_ok "目标网站有效"
        else
            print_warn "目标网站无法连接，可能导致 Reality 无法工作"
            read -p "是否继续? (y/n): " confirm
            if [ "$confirm" != "y" ]; then return 1; fi
        fi
        
        # 端口检测
        check_port 443 || return 1
        check_port $PORT_CADDY || return 1
        
        # Sing-box Config (Reality 偷取外部网站证书)
        cat > "$SINGBOX_CONFIG" <<EOF
{
  "log": { "level": "error", "output": "$LOG_SINGBOX" },
  "dns": {
    "servers": [
      { "tag": "google", "address": "tls://8.8.8.8" },
      { "tag": "local", "address": "https://223.5.5.5/dns-query", "detour": "direct" },
      { "tag": "block", "address": "rcode://success" }
    ],
    "rules": [
      { "rule_set": "geosite-cn", "server": "local" },
      { "rule_set": "geoip-cn", "server": "local" }
    ],
    "final": "google",
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 443,
      "users": [{ "uuid": "$UUID", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_DEST",
        "reality": {
          "enabled": true,
          "handshake": { 
              "server": "$REALITY_DEST", 
              "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": ["$short_id"]
        }
      }
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "rule_set": ["geosite-cn", "geoip-cn"], "action": "reject" }
    ],
    "rule_set": [
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
        "download_detour": "direct"
      }
    ],
    "final": "direct",
    "auto_detect_interface": true
  }
}
EOF

        # Caddy Config (HTTP 网站服务器，监听所有 80 端口请求)
        cat > "$CADDY_CONFIG" <<EOF
{
    admin off
    auto_https off
    log { 
        output file $LOG_CADDY
        level ERROR
    }
}

# HTTP 网站 (域名和 IP 都可访问)
:80 {
    root * $WEB_DIR
    file_server
    
    header {
        Server "nginx"
        -X-Powered-By
    }
}
EOF

    # ----------------------------------------------------
    # 模式 C: VLESS + Reality (自己网站)
    # ----------------------------------------------------
    else
        MODE="Reality-Self"
        PORT_CADDY=8443
        
        # 端口检测与自动处理
        check_port 443 || return 1
        check_port $PORT_CADDY || return 1
        
        # 检查 80 端口占用并尝试自动处理
        if ! check_port 80; then
            print_warn "检测到 80 端口被占用，Reality-Self 模式需要此端口用于证书申请"
            
            # 获取占用进程信息
            local port80_info
            port80_info=$(ss -tlnp 2>/dev/null | grep ":80 " | head -1)
            
            if echo "$port80_info" | grep -q "caddy"; then
                print_info "检测到其他 Caddy 进程占用 80 端口"
                read -p "是否停止该 Caddy 服务? (y/n): " stop_caddy
                
                if [ "$stop_caddy" == "y" ]; then
                    systemctl stop caddy 2>/dev/null || pkill -9 caddy
                    sleep 2
                    
                    if check_port 80; then
                        print_ok "80 端口已释放"
                    else
                        print_err "无法释放 80 端口"
                        return 1
                    fi
                else
                    print_err "用户取消，无法继续"
                    return 1
                fi
            else
                print_err "80 端口被其他服务占用，请手动停止后重试"
                echo "$port80_info"
                return 1
            fi
        fi
        
        # Sing-box Config (Reality 偷取本地 Caddy 证书)
        cat > "$SINGBOX_CONFIG" <<EOF
{
  "log": { "level": "error", "output": "$LOG_SINGBOX" },
  "dns": {
    "servers": [
      { "tag": "google", "address": "tls://8.8.8.8" },
      { "tag": "local", "address": "https://223.5.5.5/dns-query", "detour": "direct" },
      { "tag": "block", "address": "rcode://success" }
    ],
    "rules": [
      { "rule_set": "geosite-cn", "server": "local" },
      { "rule_set": "geoip-cn", "server": "local" }
    ],
    "final": "google",
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 443,
      "users": [{ "uuid": "$UUID", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "$DOMAIN",
        "reality": {
          "enabled": true,
          "handshake": { 
              "server": "127.0.0.1", 
              "server_port": $PORT_CADDY 
          },
          "private_key": "$private_key",
          "short_id": ["$short_id"]
        }
      }
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "rule_set": ["geosite-cn", "geoip-cn"], "action": "reject" }
    ],
    "rule_set": [
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
        "download_detour": "direct"
      }
    ],
    "final": "direct",
    "auto_detect_interface": true
  }
}
EOF

        # Caddy Config (监听 80 和 8443, 申请真实证书)
        cat > "$CADDY_CONFIG" <<EOF
{
    admin off
    # 仅禁用自动重定向 (保留自动证书管理功能)
    auto_https disable_redirects
    log { 
        output file $LOG_CADDY
        level ERROR
    }
    email admin@$DOMAIN
}

# HTTP 站点 - 监听 80 用于 HTTP-01 验证
http://$DOMAIN {
    redir https://$DOMAIN{uri}
}

# HTTPS 站点 - Reality 回落目标
$DOMAIN:$PORT_CADDY {
    # 允许外部访问 8443
    # bind 127.0.0.1
    
    tls {
        protocols tls1.2 tls1.3
        # 关键：禁用 TLS-ALPN 验证 (防止 Caddy 尝试绑定 443 端口导致冲突)
        issuer acme {
            disable_tlsalpn_challenge
        }
    }
    
    root * $WEB_DIR
    file_server
}
EOF
    fi

    # 保存信息文件
    cat > "$INFO_FILE" <<EOF
MODE=$MODE
DOMAIN=$DOMAIN
UUID=$UUID
PATH_WS=$PATH_WS
PUBLIC_KEY=$public_key
SHORT_ID=$short_id
REALITY_DEST=${REALITY_DEST:-}
EOF

    chmod 600 "$INFO_FILE"
    chmod 600 "$SINGBOX_CONFIG"
    
    print_ok "配置文件生成完成"
}

#================== 4. 服务配置 ==================

setup_logrotate() {
    print_info "配置日志轮转..."
    cat > /etc/logrotate.d/singbox-vless <<EOF
$LOG_SINGBOX $LOG_CADDY {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0640 root root
}
EOF
}

setup_services() {
    print_info "正在配置 Systemd 服务..."
    
    # 使用全局检测结果 (由 detect_core_binaries 设定)
    # 如果未设定 (例如单独调用)，尝试最后一次兜底检测
    if [ -z "${REAL_SINGBOX_BIN:-}" ] || [ -z "${REAL_CADDY_BIN:-}" ]; then
        print_warn "正在重新检测核心程序..."
        detect_core_binaries || return 1
    fi
    
    local actual_singbox_bin="$REAL_SINGBOX_BIN"
    local actual_caddy_bin="$REAL_CADDY_BIN"
    
    print_info "Sing-box 路径: $actual_singbox_bin"
    print_info "Caddy 路径: $actual_caddy_bin"
    
    # Sing-box Service
    cat > /etc/systemd/system/sb-vless.service <<EOF
[Unit]
Description=Sing-box VLESS
After=network.target

[Service]
Type=simple
User=root
ExecStart=$actual_singbox_bin run -c $SINGBOX_CONFIG
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    # Caddy Service
    cat > /etc/systemd/system/caddy-vless.service <<EOF
[Unit]
Description=Caddy Web Server (VLESS)
After=network.target

[Service]
Type=simple
User=root
ExecStart=$actual_caddy_bin run --config $CADDY_CONFIG --adapter caddyfile
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sb-vless caddy-vless
    
    # 根据模式选择启动顺序
    # shellcheck source=/dev/null
    source "$INFO_FILE"
    
    if [ "$MODE" == "Reality-Self" ]; then
        print_info "Reality-Self 模式: 先启动 Caddy 申请证书，再启动 Sing-box"
        
        # 1. 先启动 Caddy
        systemctl restart caddy-vless
        sleep 2
        
        if ! systemctl is-active --quiet caddy-vless; then
            print_err "Caddy 启动失败"
            journalctl -u caddy-vless -n 20 --no-pager
            return 1
        fi
        
        # 2. 等待证书申请（最多等待 30 秒）
        print_info "等待 Caddy 申请 Let's Encrypt 证书..."
        local wait_count=0
        local cert_obtained=false
        
        # 检查多个可能的证书位置
        local cert_paths=(
            "/var/lib/caddy/certificates"
            "$HOME/.local/share/caddy/certificates"
            "/root/.local/share/caddy/certificates"
        )
        
        while [ $wait_count -lt 30 ]; do
            for cert_path in "${cert_paths[@]}"; do
                if [ -d "$cert_path" ] && find "$cert_path" -name "*.crt" -o -name "*.pem" 2>/dev/null | grep -q .; then
                    cert_obtained=true
                    print_ok "证书申请成功 (位置: $cert_path)"
                    break 2
                fi
            done
            sleep 1
            wait_count=$((wait_count + 1))
            echo -n "."
        done
        echo ""
        
        if [ "$cert_obtained" = false ]; then
            print_warn "未在常见位置检测到证书文件"
            print_info "检查 Caddy 日志以确认证书申请状态..."
            
            # 检查 Caddy 日志中的证书申请信息
            if journalctl -u caddy-vless -n 50 --no-pager | grep -q "certificate obtained successfully"; then
                print_ok "Caddy 日志显示证书已成功申请"
            elif journalctl -u caddy-vless -n 50 --no-pager | grep -qi "acme"; then
                print_warn "检测到 ACME 活动，证书可能仍在申请中"
            fi
            
            print_info "继续启动 Sing-box..."
        fi
        
        # 3. 启动 Sing-box
        systemctl restart sb-vless
        sleep 2
        
    else
        # WS 或 Reality-External 模式：同时启动
        print_info "同时启动 Sing-box 和 Caddy..."
        systemctl restart sb-vless caddy-vless
        sleep 3
    fi
    
    # 验证服务启动
    local sb_status caddy_status
    sb_status=$(systemctl is-active sb-vless 2>/dev/null || echo "inactive")
    caddy_status=$(systemctl is-active caddy-vless 2>/dev/null || echo "inactive")
    
    if [ "$sb_status" == "active" ] && [ "$caddy_status" == "active" ]; then
        print_ok "所有服务启动成功"
    else
        print_err "服务启动失败，查看日志:"
        if [ "$sb_status" != "active" ]; then
            echo -e "${YELLOW}=== Sing-box 日志 ===${NC}"
            journalctl -u sb-vless -n 20 --no-pager
        fi
        if [ "$caddy_status" != "active" ]; then
            echo -e "${YELLOW}=== Caddy 日志 ===${NC}"
            journalctl -u caddy-vless -n 20 --no-pager
        fi
        return 1
    fi
}

show_links() {
    # shellcheck source=/dev/null
    source "$INFO_FILE"
    print_ok "安装完成！以下是您的配置信息："
    echo ""
    echo -e "${CYAN}=== VLESS Link (复制使用) ===${NC}"
    
    local link
    if [ "$MODE" == "WS" ]; then
        link="vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&type=ws&host=${DOMAIN}&path=%2F${PATH_WS}&sni=${DOMAIN}#${DOMAIN}-WS"
    elif [ "$MODE" == "Reality-External" ]; then
        link="vless://${UUID}@${DOMAIN}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_DEST}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${DOMAIN}-Reality-Ext"
    else
        link="vless://${UUID}@${DOMAIN}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&headerType=none#${DOMAIN}-Reality-Self"
    fi
    
    echo -e "${GREEN}${link}${NC}"
    echo ""
}

#================== 5. 主流程 ==================

uninstall() {
    echo ""
    print_warn "正在进行彻底卸载..."
    echo "  - 此操作将停止服务、删除所有配置、日志以及核心程序"
    echo ""
    read -p "确认彻底卸载? 请输入 'yes' 确认: " REMOVE_CONFIRM
    
    if [ "$REMOVE_CONFIRM" != "yes" ]; then
        print_info "已取消"
        return 0
    fi
    
    print_info "正在停止服务..."
    systemctl stop sb-vless caddy-vless 2>/dev/null || true
    systemctl disable sb-vless caddy-vless 2>/dev/null || true
    
    print_info "正在删除服务文件..."
    rm -f /etc/systemd/system/sb-vless.service
    rm -f /etc/systemd/system/caddy-vless.service
    systemctl daemon-reload
    
    print_info "正在删除配置文件与日志..."
    rm -rf "$CONFIG_DIR"
    rm -rf "$WEB_DIR"
    rm -f "$LOG_SINGBOX" "$LOG_CADDY"
    rm -f /etc/logrotate.d/singbox-vless
    
    # 彻底删除核心程序
    print_info "正在删除核心程序..."
    
    # 1. 尝试卸载 APT 包
    if dpkg -l caddy &>/dev/null; then
        print_info "检测到 Caddy APT 包，正在卸载..."
        apt-get remove --purge -y caddy 2>/dev/null || true
        apt-get autoremove -y 2>/dev/null || true
    fi
    
    # 2. 手动删除二进制文件 (涵盖所有可能路径)
    local bins_to_remove=(
        "/usr/local/bin/sing-box"
        "/usr/bin/sing-box"
        "/usr/sbin/sing-box"
        "/usr/local/bin/caddy"
        "/usr/bin/caddy"
        "/usr/sbin/caddy"
    )
    
    for bin in "${bins_to_remove[@]}"; do
        if [ -f "$bin" ]; then
            rm -f "$bin"
            print_info "已删除: $bin"
        fi
    done
    
    # 3. 清理残留的 Caddy 数据 (证书等)
    rm -rf /var/lib/caddy
    rm -rf /root/.local/share/caddy
    rm -rf /etc/caddy
    
    print_ok "彻底卸载完成！系统已恢复干净状态。"
}

show_status() {
    while true; do
        clear
        echo -e "${CYAN}====================================================${NC}"
        echo -e "${CYAN}               系统运行状态看板                    ${NC}"
        echo -e "${CYAN}====================================================${NC}"
        
        # Sing-box Status
        local sb_pid sb_ver
        sb_pid=$(pgrep -x sing-box | head -n 1 || true)
        sb_ver=$(sing-box version 2>/dev/null | head -n 1 | awk '{print $3}' || echo "未知")
        
        if [ -n "$sb_pid" ]; then
            local sb_stats sb_cpu sb_rss sb_mem_mb sb_time
            sb_stats=$(ps -o %cpu,rss,etime -p "$sb_pid" --no-headers 2>/dev/null || echo "0 0 0")
            sb_cpu=$(echo "$sb_stats" | awk '{print $1}')
            sb_rss=$(echo "$sb_stats" | awk '{print $2}')
            sb_mem_mb=$(awk "BEGIN {printf \"%.1f\", $sb_rss/1024}")
            sb_time=$(echo "$sb_stats" | awk '{print $3}')
            
            echo -e "Sing-box: ${GREEN}运行中${NC} (Ver: $sb_ver)"
            echo -e "  - PID: $sb_pid"
            echo -e "  - CPU: ${sb_cpu}%  |  内存: ${sb_mem_mb} MB"
            echo -e "  - 时长: ${sb_time}"
        else
            echo -e "Sing-box: ${RED}未运行${NC}"
        fi
        
        echo -e "${CYAN}----------------------------------------------------${NC}"
        
        # Caddy Status
        local caddy_pid caddy_ver
        caddy_pid=$(pgrep -x caddy | head -n 1 || true)
        caddy_ver=$(caddy version 2>/dev/null | awk '{print $1}' || echo "未知")
        
        if [ -n "$caddy_pid" ]; then
            local caddy_stats caddy_cpu caddy_rss caddy_mem_mb caddy_time
            caddy_stats=$(ps -o %cpu,rss,etime -p "$caddy_pid" --no-headers 2>/dev/null || echo "0 0 0")
            caddy_cpu=$(echo "$caddy_stats" | awk '{print $1}')
            caddy_rss=$(echo "$caddy_stats" | awk '{print $2}')
            caddy_mem_mb=$(awk "BEGIN {printf \"%.1f\", $caddy_rss/1024}")
            caddy_time=$(echo "$caddy_stats" | awk '{print $3}')
            
            echo -e "Caddy   : ${GREEN}运行中${NC} (Ver: $caddy_ver)"
            echo -e "  - PID: $caddy_pid"
            echo -e "  - CPU: ${caddy_cpu}%  |  内存: ${caddy_mem_mb} MB"
            echo -e "  - 时长: ${caddy_time}"
        else
            echo -e "Caddy   : ${RED}未运行${NC}"
        fi
        
        echo -e "${CYAN}----------------------------------------------------${NC}"
        
        if [ -f "$INFO_FILE" ]; then
            # shellcheck source=/dev/null
            source "$INFO_FILE"
            echo -e "当前模式: ${YELLOW}$MODE${NC}"
            echo -e "域名    : $DOMAIN"
        fi
        
        echo -e "${CYAN}====================================================${NC}"
        echo -e "按 ${GREEN}r${NC} 重启服务  |  按 ${GREEN}m${NC} 返回菜单"
        read -n 1 -s key
        case "$key" in
            r|R) 
                systemctl restart sb-vless caddy-vless
                print_ok "服务已重启"
                sleep 1
                ;;
            *) return ;;
        esac
    done
}

view_config() {
    if [ ! -f "$INFO_FILE" ]; then
        print_err "未找到配置文件，请先配置协议"
        return 1
    fi
    
    clear
    echo -e "${CYAN}====================================================${NC}"
    echo -e "${CYAN}               当前配置信息                        ${NC}"
    echo -e "${CYAN}====================================================${NC}"
    
    # shellcheck source=/dev/null
    source "$INFO_FILE" 2>/dev/null || {
        print_err "配置文件损坏，请重新配置"
        return 1
    }
    
    echo -e "${YELLOW}协议模式:${NC} $MODE"
    echo -e "${YELLOW}域名:${NC} $DOMAIN"
    echo -e "${YELLOW}UUID:${NC} $UUID"
    
    if [ "$MODE" == "WS" ]; then
        echo -e "${YELLOW}WS 路径:${NC} /$PATH_WS"
    else
        echo -e "${YELLOW}Public Key:${NC} $PUBLIC_KEY"
        echo -e "${YELLOW}Short ID:${NC} $SHORT_ID"
        if [ "$MODE" == "Reality-External" ]; then
            echo -e "${YELLOW}SNI:${NC} $REALITY_DEST"
        else
            echo -e "${YELLOW}SNI:${NC} $DOMAIN"
        fi
    fi
    
    echo -e "${CYAN}----------------------------------------------------${NC}"
    echo -e "${YELLOW}配置文件:${NC}"
    echo -e "  - Sing-box: $SINGBOX_CONFIG"
    echo -e "  - Caddy: $CADDY_CONFIG"
    echo -e "  - 信息: $INFO_FILE"
    echo -e "${CYAN}====================================================${NC}"
    return 0
}

delete_config() {
    if [ ! -f "$INFO_FILE" ]; then
        print_err "未找到配置文件，无需删除"
        return 1
    fi
    
    view_config || return 1
    echo ""
    print_warn "此操作将删除当前协议配置并停止服务"
    print_warn "核心程序 (Sing-box/Caddy) 不会被删除"
    echo ""
    read -p "确认删除? 请输入 'yes' 确认: " confirm
    
    if [ "$confirm" != "yes" ]; then
        print_info "已取消"
        return 0
    fi
    
    print_info "正在删除配置..."
    
    # 停止服务
    systemctl stop sb-vless caddy-vless 2>/dev/null || true
    systemctl disable sb-vless caddy-vless 2>/dev/null || true
    
    # 删除服务文件
    rm -f /etc/systemd/system/sb-vless.service
    rm -f /etc/systemd/system/caddy-vless.service
    systemctl daemon-reload
    
    # 删除配置文件
    rm -f "$SINGBOX_CONFIG"
    rm -f "$CADDY_CONFIG"
    rm -f "$INFO_FILE"
    
    # 删除日志
    rm -f "$LOG_SINGBOX"
    rm -f "$LOG_CADDY"
    
    # 删除日志轮转配置
    rm -f /etc/logrotate.d/singbox-vless
    
    print_ok "配置已删除，核心程序保留"
    return 0
}

menu() {
    while true; do
        clear
        echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║  Sing-box VLESS 脚本 v2.0 (增强版)   ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}=== 核心程序管理 ===${NC}"
        echo -e "1. 安装/更新核心程序 (Sing-box + Caddy)"
        echo ""
        echo -e "${YELLOW}=== 协议配置管理 ===${NC}"
        echo -e "2. 新建/重置配置"
        echo -e "3. 查看当前配置"
        echo -e "4. 删除当前配置"
        echo ""
        echo -e "${YELLOW}=== 信息查看 ===${NC}"
        echo -e "5. 查看连接链接"
        echo -e "6. 运行状态"
        echo ""
        echo -e "${YELLOW}=== 系统管理 ===${NC}"
        echo -e "7. 完全卸载"
        echo -e "0. 退出"
        echo ""
        read -p "请选择 [0-7]: " OPT
        
        # 输入验证
        if [[ ! "$OPT" =~ ^[0-7]$ ]]; then
            print_err "无效选项，请输入 0-7"
            sleep 1
            continue
        fi
        
        case $OPT in
            1)
                # 仅安装核心程序
                check_root
                check_system
                install_dependencies || { print_err "依赖安装失败"; read -p "按回车继续..."; continue; }
                install_singbox || { print_err "Sing-box 安装失败"; read -p "按回车继续..."; continue; }
                install_caddy || { print_err "Caddy 安装失败"; read -p "按回车继续..."; continue; }
                print_ok "核心程序安装完成"
                read -p "按回车继续..."
                ;;
            2)
                # 新建/重置配置
                check_root
                
                # 统一检测核心程序
                if ! detect_core_binaries; then
                    echo ""
                    print_err "核心程序检测失败，无法继续配置。"
                    print_info "请先选择 [1] 安装/更新核心程序，或手动安装并确保可被检测到。"
                    read -p "按回车返回..."
                    continue
                fi
                
                generate_website
                select_protocol || continue  # 如果返回 1（用户选择返回），则继续主循环
                generate_config || { print_err "配置生成失败"; read -p "按回车继续..."; continue; }
                setup_logrotate
                setup_services || { print_err "服务启动失败"; read -p "按回车继续..."; continue; }
                show_links
                read -p "按回车继续..."
                ;;
            3)
                view_config || true
                read -p "按回车继续..."
                ;;
            4)
                delete_config || true
                read -p "按回车继续..."
                ;;
            5) 
                if [ -f "$INFO_FILE" ]; then
                    show_links
                else
                    print_err "未找到配置，请先配置协议"
                fi
                read -p "按回车继续..."
                ;;
            6) show_status ;;
            7) 
                uninstall
                read -p "按回车继续..."
                ;;
            0) 
                print_info "感谢使用！"
                exit 0 
                ;;
        esac
    done
}

# Entry
if [ "${1:-}" == "uninstall" ]; then
    check_root
    uninstall
else
    menu
fi

