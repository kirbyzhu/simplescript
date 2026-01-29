#!/bin/bash

# ==============================================================================
# Xray-Nginx-5in1.sh -  多协议切换与流量中转管理脚本 v5.3 (Complete)
#
# 【 核心架构 】
#  - Protocol Switcher:  单一时刻只运行一种协议，自动切换 443 端口归属。
#  - 443 Owner:          [Xray] (Reality模式)  vs.  [Nginx] (TLS模式)

# Author: Antigravity
# ==============================================================================

set -euo pipefail

# --- 全局变量 ---
VERSION="v5.3"
BASE_DIR="/usr/local/etc/xray"
CONFIG_FILE="${BASE_DIR}/user_config.json"
NGINX_CONF_DIR="/etc/nginx/conf.d"
WEB_ROOT="/var/www/tech-blog"
CERT_DIR="${BASE_DIR}/certs"
LOG_DIR="${BASE_DIR}/logs"

# 端口定义 (仅外部端口)
PORT_NGINX_FRONT=443
PORT_XRAY_FRONT=443

# UDS 路径定义 (内部通信)
SOCK_DIR="/run/xray"
SOCK_XRAY_WS="${SOCK_DIR}/ws.sock"
SOCK_XRAY_XHTTP="${SOCK_DIR}/xhttp.sock"

# Xray Service User
# 关键: XRAY_GROUP 设为 www-data 使 Xray 和 Nginx 共享同一组
# 这样 UDS Socket 文件可被双方访问 (组写权限)
XRAY_USER="nobody"
XRAY_GROUP="www-data"

# 颜色定义
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[0;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'

# --- 0. 基础设置与辅助 ---

# 设置 umask 以确保新文件默认安全
umask 077

check_root() {
    echo "DEBUG: Inside check_root. Checking $(id -u)"
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}必须以 root 用户运行此脚本!${NC}"
        echo "当前用户 ID: $(id -u)"
        exit 1
    fi
}

# 域名校验
check_domain_valid() {
    local domain=$1
    # 简单正则校验域名格式 (支持子域名)
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$ ]]; then
        print_err "域名格式无效: $domain"
        return 1
    fi
    return 0
}

# 目标网站连通性检查 (用于 Reality)
check_target_reachable() {
    local target=$1
    print_info "正在检查目标网站连通性: $target:443 ..."
    
    # 尝试连接 443 端口 (超时 3秒)
    if timeout 3 bash -c "</dev/tcp/$target/443" >/dev/null 2>&1; then
        print_ok "目标网站 $target 可达"
        return 0
    else
        echo ""
        print_warn "无法连接到目标网站 ($target)"
        print_warn "可能是以下原因:"
        echo "  1. 目标网站屏蔽了您的服务器 IP"
        echo "  2. 服务器防火墙限制了出站流量"
        echo "  3. IPv6 配置问题 (如果目标解析为 IPv6)"
        echo ""
        echo -e "是否仍要使用此目标? (不推荐)"
        read -p "强制继续? [y/N]: " force
        if [[ "$force" == "y" || "$force" == "Y" ]]; then
            print_warn "用户强制继续，Reality 可能会失效"
            return 0
        fi
        return 1
    fi
}

# 端口占用检测
check_port_usage() {
    local port=$1
    if ss -tulpn | grep -q ":$port "; then
        print_warn "端口 $port 已被占用"
        return 1
    fi
    return 0
}

# 自动放行防火墙端口
func_open_ports() {
    local ports=("80" "443")
    print_info "正在检查并放行防火墙端口 (80, 443)..."
    
    # Check UFW (Ubuntu/Debian usually)
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -q "Status: active"; then
            print_info "检测到 UFW 防火墙开启，正在放行..."
            for port in "${ports[@]}"; do
                ufw allow "${port}/tcp" >/dev/null 2>&1
            done
            ufw reload >/dev/null 2>&1
            print_ok "UFW: 端口已放行"
            return 0
        else
            print_warn "UFW 已安装但未启用 (Status: inactive)"
        fi
    fi
    
    # Check FirewallD (CentOS/Fedora)
    if command -v firewall-cmd >/dev/null 2>&1; then
        if systemctl is-active --quiet firewalld; then
            print_info "检测到 FirewallD 开启，正在放行..."
            for port in "${ports[@]}"; do
                firewall-cmd --zone=public --add-port="${port}/tcp" --permanent >/dev/null 2>&1
            done
            firewall-cmd --reload >/dev/null 2>&1
            print_ok "FirewallD: 端口已放行"
            return 0
        fi
    fi
    
    # Check IPTables (Fallback)
    if command -v iptables >/dev/null 2>&1; then
        # Check if rule exists before adding to avoid duplicates
        for port in "${ports[@]}"; do
            if ! iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
                iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
                print_info "IPTables: 已添加规则允许端口 $port"
            fi
        done
        # Try to save (persist) if possible
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1
        elif command -v service >/dev/null 2>&1; then
             service iptables save >/dev/null 2>&1
        fi
        return 0
    fi
    print_info "未检测到活跃的防火墙，跳过设置"
}


# 端口范围校验
func_is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# IP 严格验证函数（检查八位组 0-255）
func_is_valid_ip() {
    local ip="$1"
    local a b c d
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    a=${BASH_REMATCH[1]} b=${BASH_REMATCH[2]} c=${BASH_REMATCH[3]} d=${BASH_REMATCH[4]}
    (( a <= 255 && b <= 255 && c <= 255 && d <= 255 && a >= 0 ))
}


print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_err() { echo -e "${RED}[ERROR]${NC} $1"; }

ensure_dirs() {
    mkdir -p "$BASE_DIR" "$CERT_DIR" "$LOG_DIR" "$WEB_ROOT" "$NGINX_CONF_DIR" "$SOCK_DIR"
    # [Sec] 强制目录安全权限 & 修正 Xray Service User 权限
    chown -R "$XRAY_USER:$XRAY_GROUP" "$BASE_DIR"
    chmod 700 "$BASE_DIR"
    chmod 700 "$CERT_DIR"
    
    # [Critical] UDS Socket 目录权限设置
    # 目录所属 www-data:www-data，权限 775
    # Xray (nobody:www-data) 和 Nginx (www-data:www-data) 都能创建/访问 Socket
    chown www-data:www-data "$SOCK_DIR"
    chmod 775 "$SOCK_DIR"
}

# 临时文件自动清理机制
TEMP_FILES=()
cleanup() {
    # [Fix] 防止空数组时 for 循环在 strict mode 下报错
    [[ ${#TEMP_FILES[@]} -eq 0 ]] && return
    for f in "${TEMP_FILES[@]}"; do
        [[ -f "$f" ]] && rm -f "$f"
    done
}
trap cleanup EXIT

# 安全的 mktemp 包装器
# 参数: [可选] 文件后缀 (如 .json)
# 用法: secure_mktemp .json
secure_mktemp() {
    local suffix="${1:-}"
    local tmp
    # [Fix] 添加后缀支持，解决 Xray 无法识别无扩展名配置文件的问题
    tmp=$(mktemp --suffix="$suffix")
    TEMP_FILES+=("$tmp")
    echo "$tmp"
}

# --- 1. 基础环境安装 ---

func_install_base() {
    print_info "开始安装基础环境 (Nginx, Xray, acme.sh)..."
    echo ""
    
    if ! command -v apt-get &>/dev/null; then
        print_err "仅支持 Debian/Ubuntu"
        return 1
    fi
    
    export DEBIAN_FRONTEND=noninteractive
    
    # ========== [1/6] 安装系统依赖 ==========
    echo -e "${CYAN}[1/6] 安装系统依赖包...${NC}"
    apt-get update -qq
    # 显示安装进度（不使用 -qq 和 >/dev/null）
    apt-get install -y curl wget tar jq socat ca-certificates libcap2-bin qrencode uuid-runtime openssl iproute2
    print_ok "依赖包安装完成"
    echo ""
    
    # ========== [2/6] Nginx ==========
    echo -e "${CYAN}[2/6] 检查/安装 Nginx...${NC}"
    # [Refactor] 清理可能存在的 Nginx 官方源配置，改用更稳定的 OS 默认源
    rm -f /etc/apt/sources.list.d/nginx.list \
          /etc/apt/preferences.d/99nginx \
          /usr/share/keyrings/nginx-archive-keyring.gpg

    if ! command -v nginx &>/dev/null; then
        print_info "Nginx 未安装，正在从 OS 默认源安装..."
        apt-get update -qq
        apt-get install -y nginx
        systemctl enable nginx >/dev/null
        print_ok "Nginx 安装完成"
    else
        print_ok "Nginx 已安装 ($(nginx -v 2>&1 | cut -d'/' -f2))"
        systemctl enable nginx >/dev/null
    fi
    
    # 检查端口占用
    if check_port_usage 80 || check_port_usage 443; then
        print_warn "检测到 80/443 端口被占用，后续可能导致 Nginx 启动失败"
    fi
    echo ""

    # ========== [3/6] Xray ==========
    echo -e "${CYAN}[3/6] 检查/安装 Xray...${NC}"
    if ! command -v xray &>/dev/null; then
        print_info "Xray 未安装，正在从官方脚本安装..."
        # 不抑制输出，让用户看到安装进度
        bash <(curl -L https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh) install
        setcap cap_net_bind_service=+ep /usr/local/bin/xray
        systemctl enable xray >/dev/null
        print_ok "Xray 安装完成"
    else
        print_ok "Xray 已安装 ($(xray version 2>&1 | head -n1 | awk '{print $2}'))"
    fi
    echo ""

    # ========== [4/6] acme.sh ==========
    echo -e "${CYAN}[4/6] 检查/安装 acme.sh...${NC}"
    if [ ! -f "$HOME/.acme.sh/acme.sh" ]; then
        print_info "acme.sh 未安装，正在安装..."
        # 显示安装输出
        curl https://get.acme.sh | sh -s
        "$HOME/.acme.sh/acme.sh" --upgrade --auto-upgrade
        print_ok "acme.sh 安装完成"
    else
        print_ok "acme.sh 已安装"
    fi
    echo ""
    
    # ========== [5/6] GeoData ==========
    echo -e "${CYAN}[5/6] 更新 GeoData 数据库...${NC}"
    mkdir -p /usr/local/share/xray
    print_info "下载 geoip.dat..."
    curl -L --progress-bar -o /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
    print_info "下载 geosite.dat..."
    curl -L --progress-bar -o /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
    print_ok "GeoData 更新完成"
    echo ""

    # ========== [6/6] 日志轮转 ==========
    echo -e "${CYAN}[6/6] 配置日志轮转...${NC}"
    cat > /etc/logrotate.d/xray << 'LOGROTATE'
/var/log/xray/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 nobody www-data
    postrotate
        systemctl kill -s USR1 xray 2>/dev/null || true
    endscript
}
LOGROTATE
    mkdir -p /var/log/xray
    chown nobody:www-data /var/log/xray
    chmod 750 /var/log/xray
    print_ok "日志轮转配置完成 (每日, 保留 7 天)"
    echo ""

    func_generate_website

    echo ""
    echo -e "${GREEN}========================================${NC}"
    print_ok "基础环境安装完成！"
    echo -e "${GREEN}========================================${NC}"
    read -n 1 -s -p "按任意键返回..."
}

func_generate_website() {
    local css_dir="$WEB_ROOT/assets/css"
    local articles_dir="$WEB_ROOT/articles"
    
    rm -rf "$WEB_ROOT"
    mkdir -p "$css_dir" "$articles_dir"
    
    # --- 1. 生成 CSS 样式表 ---
    cat > "$css_dir/style.css" <<'EOFCSS'
:root {
    --primary: #667eea;
    --secondary: #764ba2;
    --dark: #1a1a2e;
    --light: #f8f9fa;
    --accent: #00d4ff;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: var(--light);
    color: #333;
    line-height: 1.7;
}
a { color: var(--primary); text-decoration: none; transition: all 0.3s; }
a:hover { color: var(--secondary); }

/* Header & Navigation */
header {
    background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
    color: white;
    padding: 1rem 0;
    position: sticky;
    top: 0;
    z-index: 100;
    box-shadow: 0 2px 20px rgba(0,0,0,0.1);
}
nav { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; padding: 0 2rem; }
.logo { font-size: 1.5rem; font-weight: 700; letter-spacing: -1px; }
.nav-links { display: flex; gap: 2rem; }
.nav-links a { color: white; font-weight: 500; opacity: 0.9; }
.nav-links a:hover { opacity: 1; transform: translateY(-2px); }

/* Hero Section */
.hero {
    background: linear-gradient(135deg, var(--dark) 0%, #16213e 100%);
    color: white;
    padding: 6rem 2rem;
    text-align: center;
}
.hero h1 { font-size: 3.5rem; margin-bottom: 1rem; animation: fadeInUp 0.8s ease; }
.hero p { font-size: 1.3rem; opacity: 0.8; max-width: 600px; margin: 0 auto 2rem; }
.btn {
    display: inline-block;
    background: var(--accent);
    color: var(--dark);
    padding: 1rem 2.5rem;
    border-radius: 50px;
    font-weight: 600;
    transition: all 0.3s;
}
.btn:hover { transform: translateY(-3px); box-shadow: 0 10px 30px rgba(0,212,255,0.3); color: var(--dark); }

/* Main Content */
.container { max-width: 1200px; margin: 0 auto; padding: 4rem 2rem; }
.section-title { font-size: 2.5rem; text-align: center; margin-bottom: 3rem; color: var(--dark); }

/* Article Cards */
.articles-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 2rem; }
.article-card {
    background: white;
    border-radius: 16px;
    overflow: hidden;
    box-shadow: 0 4px 20px rgba(0,0,0,0.08);
    transition: all 0.3s;
}
.article-card:hover { transform: translateY(-8px); box-shadow: 0 12px 40px rgba(0,0,0,0.15); }
.card-image { height: 200px; background: linear-gradient(135deg, var(--primary), var(--secondary)); display: flex; align-items: center; justify-content: center; }
.card-image span { font-size: 4rem; }
.card-content { padding: 1.5rem; }
.card-content h3 { font-size: 1.3rem; margin-bottom: 0.5rem; color: var(--dark); }
.card-content p { color: #666; font-size: 0.95rem; margin-bottom: 1rem; }
.card-meta { font-size: 0.85rem; color: #999; display: flex; justify-content: space-between; }

/* About Page */
.about-section { display: grid; grid-template-columns: 1fr 1fr; gap: 4rem; align-items: center; }
.about-text h2 { font-size: 2.5rem; margin-bottom: 1.5rem; }
.about-text p { margin-bottom: 1rem; color: #555; }
.stats { display: flex; gap: 3rem; margin-top: 2rem; }
.stat h3 { font-size: 2.5rem; color: var(--primary); }
.stat p { color: #666; }

/* Footer */
footer {
    background: var(--dark);
    color: white;
    padding: 3rem 2rem;
    text-align: center;
}
footer p { opacity: 0.7; }

/* Animations */
@keyframes fadeInUp {
    from { opacity: 0; transform: translateY(30px); }
    to { opacity: 1; transform: translateY(0); }
}
.animate { animation: fadeInUp 0.6s ease forwards; }

/* Responsive */
@media (max-width: 768px) {
    .hero h1 { font-size: 2.5rem; }
    .about-section { grid-template-columns: 1fr; }
    .nav-links { display: none; }
}
EOFCSS

    # --- 2. 生成首页 ---
    cat > "$WEB_ROOT/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Future Tech Insights - Exploring cloud computing, AI, and distributed systems">
    <title>Future Tech Insights | Cloud & AI Blog</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <header>
        <nav>
            <div class="logo">🚀 FutureTech</div>
            <div class="nav-links">
                <a href="index.html">Home</a>
                <a href="about.html">About</a>
                <a href="articles/">Articles</a>
            </div>
        </nav>
    </header>

    <section class="hero">
        <h1>Future Tech Insights</h1>
        <p>Deep dives into cloud computing, artificial intelligence, and the future of distributed systems.</p>
        <a href="articles/" class="btn">Explore Articles</a>
    </section>

    <section class="container">
        <h2 class="section-title">Latest Articles</h2>
        <div class="articles-grid">
            <article class="article-card animate">
                <div class="card-image"><span>☁️</span></div>
                <div class="card-content">
                    <h3>Kubernetes at Scale: Lessons from Production</h3>
                    <p>Managing 10,000+ pods across multiple regions taught us invaluable lessons about orchestration...</p>
                    <div class="card-meta"><span>Jan 15, 2026</span><span>8 min read</span></div>
                </div>
            </article>
            <article class="article-card animate">
                <div class="card-image"><span>🤖</span></div>
                <div class="card-content">
                    <h3>LLM Inference Optimization Techniques</h3>
                    <p>How we reduced latency by 60% using quantization, batching, and custom CUDA kernels...</p>
                    <div class="card-meta"><span>Jan 12, 2026</span><span>12 min read</span></div>
                </div>
            </article>
            <article class="article-card animate">
                <div class="card-image"><span>🔒</span></div>
                <div class="card-content">
                    <h3>Zero Trust Architecture in Practice</h3>
                    <p>Implementing service mesh security with mTLS, RBAC, and continuous verification...</p>
                    <div class="card-meta"><span>Jan 8, 2026</span><span>10 min read</span></div>
                </div>
            </article>
        </div>
    </section>

    <footer>
        <p>&copy; $(date +%Y) Future Tech Insights. All rights reserved.</p>
    </footer>
</body>
</html>
EOF

    # --- 3. 生成关于页面 ---
    cat > "$WEB_ROOT/about.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>About - Future Tech Insights</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <header>
        <nav>
            <div class="logo">🚀 FutureTech</div>
            <div class="nav-links">
                <a href="index.html">Home</a>
                <a href="about.html">About</a>
                <a href="articles/">Articles</a>
            </div>
        </nav>
    </header>

    <section class="container">
        <div class="about-section">
            <div class="about-text">
                <h2>About Our Mission</h2>
                <p>We are a team of engineers, researchers, and technology enthusiasts dedicated to sharing deep technical knowledge with the community.</p>
                <p>Our focus areas include cloud-native technologies, machine learning infrastructure, distributed systems, and security engineering.</p>
                <div class="stats">
                    <div class="stat"><h3>150+</h3><p>Articles</p></div>
                    <div class="stat"><h3>50K+</h3><p>Readers</p></div>
                    <div class="stat"><h3>12</h3><p>Contributors</p></div>
                </div>
            </div>
            <div class="about-visual" style="background: linear-gradient(135deg, var(--primary), var(--secondary)); border-radius: 20px; height: 400px; display: flex; align-items: center; justify-content: center;">
                <span style="font-size: 8rem;">💡</span>
            </div>
        </div>
    </section>

    <footer>
        <p>&copy; $(date +%Y) Future Tech Insights. All rights reserved.</p>
    </footer>
</body>
</html>
EOF

    # --- 4. 生成文章列表页 ---
    cat > "$articles_dir/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Articles - Future Tech Insights</title>
    <link rel="stylesheet" href="../assets/css/style.css">
</head>
<body>
    <header>
        <nav>
            <div class="logo">🚀 FutureTech</div>
            <div class="nav-links">
                <a href="../index.html">Home</a>
                <a href="../about.html">About</a>
                <a href="./">Articles</a>
            </div>
        </nav>
    </header>

    <section class="container">
        <h2 class="section-title">All Articles</h2>
        <div class="articles-grid">
            <article class="article-card">
                <div class="card-image" style="background: linear-gradient(135deg, #11998e, #38ef7d);"><span>📊</span></div>
                <div class="card-content">
                    <h3>Building Real-time Data Pipelines with Apache Kafka</h3>
                    <p>A comprehensive guide to event streaming architecture and exactly-once semantics...</p>
                    <div class="card-meta"><span>Jan 20, 2026</span><span>15 min read</span></div>
                </div>
            </article>
            <article class="article-card">
                <div class="card-image" style="background: linear-gradient(135deg, #ee0979, #ff6a00);"><span>⚡</span></div>
                <div class="card-content">
                    <h3>Rust for Systems Programming: Beyond the Hype</h3>
                    <p>Memory safety without garbage collection - a practical deep dive...</p>
                    <div class="card-meta"><span>Jan 18, 2026</span><span>11 min read</span></div>
                </div>
            </article>
            <article class="article-card">
                <div class="card-image" style="background: linear-gradient(135deg, #4776E6, #8E54E9);"><span>🌐</span></div>
                <div class="card-content">
                    <h3>WebAssembly: The Future of Edge Computing</h3>
                    <p>Running sandboxed code at the edge with Wasm and Cloudflare Workers...</p>
                    <div class="card-meta"><span>Jan 14, 2026</span><span>9 min read</span></div>
                </div>
            </article>
            <article class="article-card">
                <div class="card-image" style="background: linear-gradient(135deg, #654ea3, #eaafc8);"><span>🔬</span></div>
                <div class="card-content">
                    <h3>Observability Stack: From Metrics to Traces</h3>
                    <p>Building a complete observability platform with Prometheus, Grafana, and Jaeger...</p>
                    <div class="card-meta"><span>Jan 10, 2026</span><span>14 min read</span></div>
                </div>
            </article>
        </div>
    </section>

    <footer>
        <p>&copy; $(date +%Y) Future Tech Insights. All rights reserved.</p>
    </footer>
</body>
</html>
EOF

    # 设置权限
    chmod -R 755 "$WEB_ROOT"
    chown -R www-data:www-data "$WEB_ROOT" 2>/dev/null || true
    print_ok "伪装网站生成完成 (4 页面, 含 CSS 动画)"
}

# 根据目标网站生成主题伪装站 (Mode 1 专用)
# 参数: $1 = 目标域名 (如 www.microsoft.com)
func_generate_themed_website() {
    local target=$1
    local theme_root="$WEB_ROOT"
    
    mkdir -p "$theme_root"
    
    # 根据目标域名选择主题
    local brand_name brand_color brand_bg brand_icon tagline
    case "$target" in
        *microsoft*)
            brand_name="Microsoft"
            brand_color="#0078d4"
            brand_bg="#f3f2f1"
            brand_icon="🪟"
            tagline="Empowering Every Person and Organization"
            ;;
        *apple*)
            brand_name="Apple"
            brand_color="#000000"
            brand_bg="#fbfbfd"
            brand_icon="🍎"
            tagline="Think Different"
            ;;
        *amazon*)
            brand_name="Amazon"
            brand_color="#ff9900"
            brand_bg="#232f3e"
            brand_icon="📦"
            tagline="Work Hard. Have Fun. Make History."
            ;;
        *cloudflare*)
            brand_name="Cloudflare"
            brand_color="#f38020"
            brand_bg="#1a1a2e"
            brand_icon="☁️"
            tagline="Helping Build a Better Internet"
            ;;
        *google*)
            brand_name="Google"
            brand_color="#4285f4"
            brand_bg="#ffffff"
            brand_icon="🔍"
            tagline="Organizing the World's Information"
            ;;
        *edu*|*university*|*college*|*school*|*academic*)
            # 大学/学院风格
            brand_name="University Portal"
            brand_color="#1e3a5f"
            brand_bg="#f5f5f5"
            brand_icon="🎓"
            tagline="Excellence in Education and Research"
            ;;
        *gov*|*government*|*ministry*|*public*)
            # 政府网站风格
            brand_name="Government Services"
            brand_color="#003366"
            brand_bg="#f0f4f8"
            brand_icon="🏛️"
            tagline="Serving Citizens with Integrity"
            ;;
        *)
            # 默认企业风格
            brand_name="Enterprise Portal"
            brand_color="#2c3e50"
            brand_bg="#ecf0f1"
            brand_icon="🏢"
            tagline="Secure Business Solutions"
            ;;
    esac
    
    print_info "正在生成 $brand_name 风格伪装站..."
    
    cat > "$theme_root/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$brand_name - $tagline</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: $brand_bg;
            min-height: 100vh;
        }
        header {
            background: ${brand_color};
            padding: 1rem 2rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        header .logo { font-size: 1.5rem; color: white; font-weight: 600; }
        header nav { margin-left: auto; display: flex; gap: 1.5rem; }
        header nav a { color: rgba(255,255,255,0.9); text-decoration: none; font-size: 0.9rem; }
        header nav a:hover { color: white; }
        .hero {
            text-align: center;
            padding: 6rem 2rem;
            background: linear-gradient(135deg, ${brand_color}22, ${brand_color}11);
        }
        .hero-icon { font-size: 5rem; margin-bottom: 1rem; }
        .hero h1 { font-size: 2.5rem; color: #1a1a1a; margin-bottom: 1rem; font-weight: 300; }
        .hero p { font-size: 1.2rem; color: #666; max-width: 600px; margin: 0 auto 2rem; }
        .btn {
            display: inline-block;
            padding: 0.8rem 2rem;
            background: ${brand_color};
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-weight: 500;
        }
        .btn:hover { opacity: 0.9; }
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 2rem;
            padding: 4rem 2rem;
            max-width: 1200px;
            margin: 0 auto;
        }
        .feature {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        .feature h3 { color: ${brand_color}; margin-bottom: 0.5rem; }
        .feature p { color: #666; line-height: 1.6; }
        footer {
            text-align: center;
            padding: 2rem;
            background: #1a1a1a;
            color: rgba(255,255,255,0.6);
            font-size: 0.85rem;
        }
    </style>
</head>
<body>
    <header>
        <span class="logo">${brand_icon} ${brand_name}</span>
        <nav>
            <a href="#">Products</a>
            <a href="#">Solutions</a>
            <a href="#">Resources</a>
            <a href="#">Support</a>
        </nav>
    </header>
    
    <section class="hero">
        <div class="hero-icon">${brand_icon}</div>
        <h1>${tagline}</h1>
        <p>Discover powerful tools and services designed to help you achieve more in work and life.</p>
        <a href="#" class="btn">Get Started</a>
    </section>
    
    <section class="features">
        <div class="feature">
            <h3>🔒 Security First</h3>
            <p>Enterprise-grade security protecting your data with advanced encryption and compliance tools.</p>
        </div>
        <div class="feature">
            <h3>⚡ High Performance</h3>
            <p>Lightning-fast infrastructure delivering exceptional speed and reliability worldwide.</p>
        </div>
        <div class="feature">
            <h3>🌍 Global Scale</h3>
            <p>Deploy anywhere with our worldwide network of data centers and edge locations.</p>
        </div>
    </section>
    
    <footer>
        <p>&copy; $(date +%Y) ${brand_name}. All rights reserved. | Privacy | Terms | Contact</p>
    </footer>
</body>
</html>
EOF
    
    chmod -R 755 "$theme_root"
    chown -R www-data:www-data "$theme_root" 2>/dev/null || true
    print_ok "$brand_name 风格伪装站生成完成"
}

func_uninstall_menu() {
    clear
    echo -e "${RED}=== 卸载管理 ===${NC}"
    echo "1. 仅删除配置与日志 (保留核心程序和证书)"
    echo "2. 仅删除伪装网站文件"
    echo "3. 仅删除核心程序 (保留证书)"
    echo "4. 彻底卸载所有"
    echo "0. 返回"
    read -p "警告：操作不可逆。请选择: " ch
    
    case "$ch" in
        1)
            # 删除配置与日志
            rm -rf "$BASE_DIR" "$LOG_DIR" "${NGINX_CONF_DIR}/xray_*.conf" "${NGINX_CONF_DIR}/acme.conf"
            # 重启服务以应用配置变更
            systemctl restart xray nginx 2>/dev/null || true
            echo -e "${GREEN}[OK] 配置与日志已清除 (核心程序与证书已保留)${NC}"
            ;;
        2)
            rm -rf "$WEB_ROOT"
            echo -e "${GREEN}[OK] 伪装网站文件已清除${NC}"
            ;;
        3)
            # 停止服务
            systemctl stop xray nginx 2>/dev/null || true
            systemctl disable xray 2>/dev/null || true
            
            # 删除 Xray 二进制
            rm -f /usr/local/bin/xray
            # 删除 Systemd
            rm -f /etc/systemd/system/xray.service
            rm -rf /etc/systemd/system/xray.service.d
            
            # 卸载 Nginx
            echo -e "${YELLOW}正在尝试移除 Nginx...${NC}"
            apt-get remove --purge -y nginx nginx-common nginx-full 2>/dev/null || true
            apt-get autoremove -y 2>/dev/null || true
            
            systemctl daemon-reload
            echo -e "${GREEN}[OK] 核心程序已清除 (证书已保留在 $CERT_DIR)${NC}"
            ;;
        4)
            echo ""
            echo -e "${YELLOW}是否保留 SSL 证书？${NC}"
            echo "证书位置: $CERT_DIR"
            read -p "保留证书? [Y/n]: " keep_cert
            
            # 停止所有相关服务
            systemctl stop xray nginx 2>/dev/null || true
            systemctl disable xray nginx 2>/dev/null || true
            
            # 删除服务文件
            rm -f /etc/systemd/system/xray.service
            rm -rf /etc/systemd/system/xray.service.d
            systemctl daemon-reload
            
            # 删除数据目录
            rm -rf "$BASE_DIR" "$LOG_DIR" "$WEB_ROOT"
            
            # 删除 Nginx 配置目录
            rm -rf /etc/nginx
            
            # 处理证书
            if [[ "$keep_cert" == "n" || "$keep_cert" == "N" ]]; then
                rm -rf "$CERT_DIR"
                rmdir /etc/xray 2>/dev/null || true
                echo -e "${YELLOW}证书已删除${NC}"
            else
                echo -e "${GREEN}证书已保留在 $CERT_DIR${NC}"
            fi
            
            # 删除二进制与包
            rm -f /usr/local/bin/xray
            apt-get remove --purge -y nginx nginx-common nginx-full 2>/dev/null || true
            apt-get autoremove -y 2>/dev/null || true
            
            # 卸载 acme.sh
            if [ -d "$HOME/.acme.sh" ]; then
                "$HOME/.acme.sh/acme.sh" --uninstall 2>/dev/null || true
                rm -rf "$HOME/.acme.sh"
            fi
            
            echo -e "${GREEN}[OK] 彻底卸载完成${NC}"
            ;;
        *) return ;;
    esac
    read -n 1 -s -p "按任意键继续..."
}

# --- 2. 配置管理 (Persistence) ---

func_get_config() {
    local key=$1
    if [ -f "$CONFIG_FILE" ]; then
        # 仅读取者需要权限
        jq -r ".$key // empty" "$CONFIG_FILE" 2>/dev/null
    fi
}

func_set_config() {
    local key=$1
    local val=$2
    local tmp
    tmp=$(secure_mktemp)
    
    if [ ! -f "$CONFIG_FILE" ]; then echo "{}" > "$CONFIG_FILE"; chmod 600 "$CONFIG_FILE"; fi
    
    jq --arg k "$key" --arg v "$val" '.[$k] = $v' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
    chown "$XRAY_USER:$XRAY_GROUP" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
}

func_set_config_json() {
    local key=$1
    local json_val=$2
    local tmp
    tmp=$(secure_mktemp)
    
    if [ ! -f "$CONFIG_FILE" ]; then echo "{}" > "$CONFIG_FILE"; chmod 600 "$CONFIG_FILE"; fi
    
    jq --arg k "$key" --argjson v "$json_val" '.[$k] = $v' "$CONFIG_FILE" > "$tmp" && mv "$tmp" "$CONFIG_FILE"
    chown "$XRAY_USER:$XRAY_GROUP" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
}

func_configure_base_settings() {
    echo -e "${CYAN}=== 基础配置 ===${NC}"
    
    # 读取现有配置
    local existing_domain=""
    local existing_uuid=""
    local existing_ws_path=""
    local existing_block_cn=""
    
    if [ -f "$CONFIG_FILE" ]; then
        existing_domain=$(func_get_config "domain")
        existing_uuid=$(func_get_config "uuid")
        existing_ws_path=$(func_get_config "ws_path")
        existing_block_cn=$(func_get_config "block_cn")
        
        # 检测是否有有效配置
        if [[ -n "$existing_domain" && "$existing_domain" != "null" ]]; then
            echo -e "${YELLOW}[WARN] 检测到已有配置文件！${NC}"
            echo ""
            echo -e "当前配置:"
            echo -e "  域名: ${GREEN}${existing_domain}${NC}"
            echo -e "  UUID: ${GREEN}${existing_uuid}${NC}"
            echo -e "  WS路径: ${GREEN}${existing_ws_path:-/ws}${NC}"
            echo -e "  屏蔽回国: ${GREEN}$([ "$existing_block_cn" == "true" ] && echo "是" || echo "否")${NC}"
            echo ""
            echo -e "继续配置将覆盖现有设置 (中转节点会保留)"
            echo "y: 继续配置 (留空可保持现有值)"
            echo "n: 返回主菜单"
            read -p "请选择 [y/n]: " choice
            if [[ "$choice" != "y" && "$choice" != "Y" ]]; then
                return
            fi
        fi
    fi
    
    # --- 域名配置 ---
    local domain
    while true; do
        if [[ -n "$existing_domain" && "$existing_domain" != "null" ]]; then
            read -p "输入域名 (当前: $existing_domain, 留空保持不变): " domain
            [ -z "$domain" ] && domain="$existing_domain"
        else
            read -p "输入域名: " domain
        fi
        
        if check_domain_valid "$domain"; then
            break
        fi
    done
    func_set_config "domain" "$domain"
    
    # --- UUID 配置 ---
    local uuid
    local auto_uuid
    auto_uuid=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)
    
    if [[ -n "$existing_uuid" && "$existing_uuid" != "null" ]]; then
        read -p "UUID (当前: $existing_uuid, 留空保持不变): " uuid
        [ -z "$uuid" ] && uuid="$existing_uuid"
    else
        read -p "UUID (留空自动生成): " uuid
        [ -z "$uuid" ] && uuid="$auto_uuid"
    fi
    func_set_config "uuid" "$uuid"
    echo -e "UUID: ${GREEN}$uuid${NC}"
    
    # --- WS 路径配置 ---
    local ws_path
    if [[ -n "$existing_ws_path" && "$existing_ws_path" != "null" ]]; then
        read -p "WS 路径 (当前: $existing_ws_path, 留空保持不变): " ws_path
        [ -z "$ws_path" ] && ws_path="$existing_ws_path"
    else
        read -p "WS 路径 (默认 /ws): " ws_path
        [ -z "$ws_path" ] && ws_path="/ws"
    fi
    [[ ! "$ws_path" =~ ^/ ]] && ws_path="/$ws_path"
    func_set_config "ws_path" "$ws_path"
    
    # --- Block CN 配置 ---
    local block_cn
    if [[ -n "$existing_block_cn" && "$existing_block_cn" != "null" ]]; then
        local current_cn_status
        local default_prompt
        current_cn_status=$([ "$existing_block_cn" == "true" ] && echo "是" || echo "否")
        default_prompt=$([ "$existing_block_cn" == "true" ] && echo "[Y/n]" || echo "[y/N]")
        read -p "是否屏蔽回国流量 (当前: $current_cn_status, 留空保持不变)? $default_prompt: " block_cn_input
        
        if [ "$existing_block_cn" == "true" ]; then
            block_cn="true"
            [[ "$block_cn_input" == "n" || "$block_cn_input" == "N" ]] && block_cn="false"
        else
            block_cn="false"
            [[ "$block_cn_input" == "y" || "$block_cn_input" == "Y" ]] && block_cn="true"
        fi
    else
        read -p "是否屏蔽回国流量 (Block CN)? [Y/n]: " block_cn_input
        block_cn="true"
        [[ "$block_cn_input" == "n" || "$block_cn_input" == "N" ]] && block_cn="false"
    fi
    func_set_config "block_cn" "$block_cn"
    
    print_ok "配置已保存"
    
    # 询问是否立即应用配置
    local cur_mode
    cur_mode=$(func_get_config "current_mode")
    
    if [[ -n "$cur_mode" && "$cur_mode" != "null" ]]; then
        echo ""
        echo -e "${YELLOW}是否立即应用新配置？${NC}"
        echo "  y: 重新生成配置并重启服务 (推荐)"
        echo "  n: 仅保存，稍后手动应用 (菜单3切换模式)"
        read -p "请选择 [Y/n]: " apply_now
        
        if [[ "$apply_now" != "n" && "$apply_now" != "N" ]]; then
            echo ""
            print_info "正在应用配置..."
            if func_gen_config "$cur_mode"; then
                print_ok "配置已应用并生效"
            else
                print_err "配置应用失败，请检查错误信息"
            fi
        else
            print_warn "配置已保存但未应用，请通过菜单3切换模式以生效"
        fi
    else
        print_warn "请先选择协议模式 (菜单 3) 以应用配置"
    fi
    
    read -n 1 -s -p "按任意键返回..."
}

# --- 3. 证书管理 ---

func_ensure_cert() {
    local domain=$1
    local cert_crt="${CERT_DIR}/${domain}.crt"
    local cert_key="${CERT_DIR}/${domain}.key"
    local acme_cert_dir="$HOME/.acme.sh/${domain}_ecc"  # ECC 证书目录 (acme.sh 默认)
    local acme_cert_dir_rsa="$HOME/.acme.sh/${domain}"  # RSA 证书目录
    
    ensure_dirs # 确保证书目录权限
    
    # --- 证书复用逻辑 ---
    # 1. 检查本地证书是否有效
    if [[ -f "$cert_crt" && -f "$cert_key" ]]; then
        if openssl x509 -checkend 86400 -noout -in "$cert_crt" > /dev/null 2>&1; then
            local expiry_date
            expiry_date=$(openssl x509 -enddate -noout -in "$cert_crt" | cut -d= -f2)
            
            # [Fix] 非交互模式下自动复用证书
            if [[ "${NO_PROMPT:-}" == "true" ]]; then
                print_ok "证书有效: $domain (到期: $expiry_date) - 自动复用"
                return 0
            fi
            
            print_ok "证书有效: $domain (到期: $expiry_date)"
            
            read -p "使用现有证书? [Y/n]: " use_existing
            if [[ "$use_existing" != "n" && "$use_existing" != "N" ]]; then
                return 0
            fi
            print_info "用户选择重新申请..."
        else
            print_warn "证书已过期或即将过期，需要续签..."
        fi
    # 2. 检查 acme.sh 缓存是否有有效证书 (可能本地被删但 acme.sh 还有)
    elif [[ -d "$acme_cert_dir" || -d "$acme_cert_dir_rsa" ]]; then
        local acme_dir="$acme_cert_dir"
        [[ ! -d "$acme_dir" ]] && acme_dir="$acme_cert_dir_rsa"
        
        if [[ -f "$acme_dir/fullchain.cer" ]]; then
            print_info "发现 acme.sh 缓存证书，尝试导入..."
            if "$HOME/.acme.sh/acme.sh" --install-cert -d "$domain" \
                --key-file "$cert_key" \
                --fullchain-file "$cert_crt" \
                --reloadcmd "systemctl restart xray nginx" 2>/dev/null; then
                
                # 设置正确权限
                chown root:www-data "$cert_key" "$cert_crt"
                chmod 640 "$cert_key"
                chmod 644 "$cert_crt"
                print_ok "从 acme.sh 缓存导入证书成功"
                return 0
            fi
            print_warn "缓存导入失败，重新申请..."
        fi
    fi
    
    # [Fix] 非交互模式下如果证书不存在/过期则报错退出
    if [[ "${NO_PROMPT:-}" == "true" ]]; then
        print_err "证书不存在或已过期，但当前为非交互模式，无法自动申请"
        print_warn "请手动运行菜单3切换模式以交互式申请证书"
        return 1
    fi
    
    # --- CA 提供商选择 ---
    echo -e "\n${CYAN}选择证书颁发机构 (CA):${NC}"
    echo "  1) Let's Encrypt (默认, 推荐)"
    echo "  2) ZeroSSL (Let's Encrypt 被限制时备选)"
    echo "  3) Buypass (欧洲备选)"
    echo "  4) 自动尝试 (失败自动切换)"
    read -p "选择 [1-4]: " ca_choice
    [ -z "$ca_choice" ] && ca_choice="1"
    
    local ca_servers=()
    case "$ca_choice" in
        1) ca_servers=("letsencrypt") ;;
        2) ca_servers=("zerossl") ;;
        3) ca_servers=("buypass") ;;
        *) ca_servers=("letsencrypt" "zerossl" "buypass") ;;
    esac
    
    print_info "正在申请证书 (使用 Nginx 80 端口验证)..."
    
    mkdir -p "$NGINX_CONF_DIR"
    cat > "$NGINX_CONF_DIR/acme.conf" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $domain;
    location /.well-known/acme-challenge/ {
        root /var/www/acme;
        allow all;
    }
}
EOF
    mkdir -p /var/www/acme
    chown www-data:www-data /var/www/acme
    chmod 755 /var/www/acme
    systemctl restart nginx
    
    # --- 带超时和回退的证书申请 ---
    local cert_success=0
    local timeout_seconds=120
    
    for ca in "${ca_servers[@]}"; do
        print_info "尝试 $ca (超时: ${timeout_seconds}s)..."
        
        local server_arg=""
        case "$ca" in
            "letsencrypt") server_arg="--server letsencrypt" ;;
            "zerossl") server_arg="--server zerossl" ;;
            "buypass") server_arg="--server https://api.buypass.com/acme/directory" ;;
        esac
        
        # 使用 timeout 命令限制申请时间
        if timeout "$timeout_seconds" "$HOME/.acme.sh/acme.sh" --issue -d "$domain" \
            --webroot /var/www/acme $server_arg --force 2>&1; then
            
            "$HOME/.acme.sh/acme.sh" --install-cert -d "$domain" \
                --key-file "$cert_key" \
                --fullchain-file "$cert_crt" \
                --reloadcmd "systemctl restart xray nginx"
            
            # [Critical] 证书权限修复
            chown root:www-data "$cert_key" "$cert_crt"
            chmod 640 "$cert_key"
            chmod 644 "$cert_crt"
            
            print_ok "证书申请成功 (CA: $ca)"
            rm -f "$NGINX_CONF_DIR/acme.conf"
            cert_success=1
            break
        else
            print_warn "$ca 申请失败或超时，尝试下一个..."
        fi
    done
    
    if [ "$cert_success" -eq 0 ]; then
        print_err "所有 CA 都申请失败! 请检查:"
        echo "  1. 80 端口是否开放"
        echo "  2. 域名 DNS 是否正确解析到本机"
        echo "  3. 防火墙是否允许入站 HTTP"
        rm -f "$NGINX_CONF_DIR/acme.conf"
        return 1
    fi
    return 0
}

# 生成自签名证书 (用于 Reality Steal Self)
func_generate_self_signed() {
    local domain=$1
    local cert_crt="${CERT_DIR}/${domain}_self.crt"
    local cert_key="${CERT_DIR}/${domain}_self.key"
    
    ensure_dirs
    
    if [[ -f "$cert_crt" && -f "$cert_key" ]]; then
        print_info "使用现有自签名证书..."
        return 0
    fi
    
    print_info "生成自签名证书 (用于 Reality 本地回落)..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$cert_key" \
        -out "$cert_crt" \
        -days 3650 \
        -subj "/CN=${domain}" >/dev/null 2>&1
        
    chown root:www-data "$cert_key" "$cert_crt"
    chmod 640 "$cert_key"
    chmod 644 "$cert_crt"
}

# --- 4. 核心生成逻辑 ---

# 获取或生成 Reality 密钥对 (复用逻辑)
func_get_or_gen_reality_keys() {
    local existing_pk existing_pub existing_short
    existing_pk=$(func_get_config "reality_pk")
    existing_pub=$(func_get_config "reality_pub")
    existing_short=$(func_get_config "reality_short")
    
    local reuse="n"
    if [[ -n "$existing_pk" && -n "$existing_pub" && "$existing_pk" != "null" ]]; then
        # [Fix] 非交互模式下自动复用密钥
        if [[ "${NO_PROMPT:-}" == "true" ]]; then
            reuse="y"
            print_ok "检测到现有 Reality 密钥对 - 自动复用"
        else
            echo -e "${GREEN}[Info] 检测到现有 Reality 密钥对${NC}"
            echo -e "  Public Key: ${CYAN}${existing_pub:0:20}...${NC}"
            read -p "是否复用现有密钥? [Y/n]: " reuse_input
            if [[ "$reuse_input" != "n" && "$reuse_input" != "N" ]]; then
                reuse="y"
            fi
        fi
    fi
    
    if [[ "$reuse" == "y" ]]; then
        # 全局变量赋值返回
        pk="$existing_pk"
        pub="$existing_pub"
        short="$existing_short"
        # 补全 shortId
        [[ -z "$short" || "$short" == "null" ]] && short=$(openssl rand -hex 4)
        [[ "${NO_PROMPT:-}" != "true" ]] && print_ok "已复用现有 Reality 密钥"
        return 0
    fi
    
    # 生成新密钥
    print_info "正在生成新 Reality 密钥对..."
    local keys xray_exit_code
    
    set +euo pipefail
    keys=$(xray x25519 2>&1)
    xray_exit_code=$?
    set -euo pipefail
    
    if [[ $xray_exit_code -ne 0 || -z "$keys" ]]; then
        print_err "Reality 密钥对生成失败！"
        echo "详情: $keys"
        return 1
    fi
    
    set +o pipefail
    pk=$(echo "$keys" | grep -i "private" | awk -F': ' '{print $2}' | tr -d ' ')
    pub=$(echo "$keys" | grep -i "public" | awk -F': ' '{print $2}' | tr -d ' ')
    if [[ -z "$pub" ]]; then
        pub=$(echo "$keys" | grep -i "password" | awk -F': ' '{print $2}' | tr -d ' ')
    fi
    set -o pipefail
    
    if [[ -z "$pk" || -z "$pub" ]]; then
        print_err "无法提取密钥对"
        return 1
    fi
    
    short=$(openssl rand -hex 4)
    print_ok "新密钥生成成功"
    return 0
}

func_gen_config() {
    local mode=$1
    local domain uuid block_cn
    domain=$(func_get_config "domain")
    uuid=$(func_get_config "uuid")
    block_cn=$(func_get_config "block_cn")
    
    if [[ -z "$domain" || -z "$uuid" ]]; then
        print_err "请先完成基础配置 (菜单 2)"
        read -n 1 -s -p "..."
        return 1
    fi
    
    systemctl stop nginx xray 2>/dev/null || true
    
    local xray_inbound=""
    local nginx_server=""
    local reality_sni=""
    
    case "$mode" in
        "reality_steal_others")
            local default_target="www.microsoft.com"
            echo -e "${CYAN}[Reality Steal Others] 请输入被偷的目标网站${NC}"
            echo "常用选项: www.microsoft.com, www.apple.com, www.amazon.com, www.cloudflare.com"
            echo "注意: 请确保服务器能访问该网站 (无防火墙拦截)"
            
            # 循环直到用户输入有效目标或放弃
            while true; do
                read -p "目标网站 (留空使用默认: $default_target): " custom_target
                [[ -z "$custom_target" ]] && custom_target="$default_target"
                
                if check_target_reachable "$custom_target"; then
                    break
                else
                    echo -e "${YELLOW}请重新输入目标网站...${NC}"
                fi
            done
            
            # [UX] 调用密钥复用/生成 Helper
            local keys pk pub short
            if ! func_get_or_gen_reality_keys; then return 1; fi
            
            reality_sni="$custom_target"
            
            func_set_config "reality_pk" "$pk"
            func_set_config "reality_pub" "$pub"
            func_set_config "reality_short" "$short"
            func_set_config "reality_sni" "$reality_sni"
            
            xray_inbound=$(jq -n \
                --argjson port "$PORT_XRAY_FRONT" \
                --arg uuid "$uuid" \
                --arg pk "$pk" \
                --arg short "$short" \
                --arg sni "$reality_sni" \
                '{
                  port: $port,
                  protocol: "vless",
                  settings: {
                    clients: [{id: $uuid, flow: "xtls-rprx-vision"}],
                    decryption: "none"
                  },
                  streamSettings: {
                    network: "tcp",
                    security: "reality",
                    realitySettings: {
                      show: false,
                      dest: ($sni + ":443"),
                      xver: 0,
                      serverNames: [$sni],
                      privateKey: $pk,
                      shortIds: [$short]
                    }
                  }
                }')
            
            # [Mode 1 v3.10] 生成与被偷目标风格一致的伪装站
            func_generate_themed_website "$reality_sni"
            
            # [Mode 1 v3.10] Nginx HTTP 80 回落 - 显示主题伪装站
            nginx_server="server {
    listen 80;
    listen [::]:80;
    server_name _;
    
    root $WEB_ROOT;
    index index.html;
    
    # 防止目录浏览
    autoindex off;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}"
            
            # [Mode 1 v3.10] 启用 Nginx 后端 (HTTP 80)
            print_info "正在配置 HTTP 回落伪装站 (风格: $reality_sni)..."
            rm -f /etc/nginx/sites-enabled/default
            ;;

        "reality_steal_self")
            # [Fix] 确保非 Mode 1 模式下使用默认企业风格 (重置网站)
            func_generate_website

            # [UX] 调用密钥复用/生成 Helper
            local keys pk pub short
            if ! func_get_or_gen_reality_keys; then return 1; fi
            
            reality_sni="$domain"
            
            func_set_config "reality_pk" "$pk"
            func_set_config "reality_pub" "$pub"
            func_set_config "reality_short" "$short"
            func_set_config "reality_sni" "$reality_sni"
            
            func_ensure_cert "$domain" || return 1
            local self_port=8100
            
            xray_inbound=$(jq -n \
                --argjson port "$PORT_XRAY_FRONT" \
                --argjson self_port "$self_port" \
                --arg uuid "$uuid" \
                --arg pk "$pk" \
                --arg short "$short" \
                --arg sni "$reality_sni" \
                '{
                  port: $port,
                  protocol: "vless",
                  settings: {
                    clients: [{id: $uuid, flow: "xtls-rprx-vision"}],
                    decryption: "none",
                    fallbacks: []
                  },
                  streamSettings: {
                    network: "tcp",
                    security: "reality",
                    realitySettings: {
                      dest: ("127.0.0.1:" + ($self_port|tostring)),
                      xver: 0,
                      serverNames: [$sni],
                      privateKey: $pk,
                      shortIds: [$short]
                    }
                  }
                }')
            
            nginx_server="server {
    listen 127.0.0.1:$self_port ssl http2;
    server_name $domain;
    ssl_certificate ${CERT_DIR}/${domain}.crt;
    ssl_certificate_key ${CERT_DIR}/${domain}.key;
    root $WEB_ROOT;
    index index.html;
}"
            ;;

        "xhttp_reality_steal_self")
            # [Fix] 确保非 Mode 1 模式下使用默认企业风格 (重置网站)
            func_generate_website

            # [UX] 调用密钥复用/生成 Helper
            local keys pk pub short
            if ! func_get_or_gen_reality_keys; then return 1; fi
            
            reality_sni="$domain"
            
            func_set_config "reality_pk" "$pk"
            func_set_config "reality_pub" "$pub"
            func_set_config "reality_short" "$short"
            func_set_config "reality_sni" "$reality_sni"
            
            func_ensure_cert "$domain" || return 1
            local self_port=8101
            
            xray_inbound=$(jq -n \
                --argjson port "$PORT_XRAY_FRONT" \
                --argjson self_port "$self_port" \
                --arg uuid "$uuid" \
                --arg pk "$pk" \
                --arg short "$short" \
                --arg sni "$reality_sni" \
                '{
                  port: $port,
                  protocol: "vless",
                  settings: {
                    clients: [{id: $uuid}],
                    decryption: "none",
                    fallbacks: []
                  },
                  streamSettings: {
                    network: "xhttp",
                    xhttpSettings: {path: "/xr"},
                    security: "reality",
                    realitySettings: {
                      dest: ("127.0.0.1:" + ($self_port|tostring)),
                      xver: 0,
                      serverNames: [$sni],
                      privateKey: $pk,
                      shortIds: [$short]
                    }
                  }
                }')
            
            nginx_server="server {
    listen 127.0.0.1:$self_port ssl http2;
    server_name $domain;
    ssl_certificate ${CERT_DIR}/${domain}.crt;
    ssl_certificate_key ${CERT_DIR}/${domain}.key;
    root $WEB_ROOT;
    index index.html;
}"
            ;;

        "ws_tls")
            # [Fix] 确保非 Mode 1 模式下使用默认企业风格 (重置网站)
            func_generate_website

            func_ensure_cert "$domain" || return 1
            local ws_path="/ws"
            func_set_config "ws_path" "$ws_path"
            
            xray_inbound=$(jq -n \
                --arg sock "$SOCK_XRAY_WS" \
                --arg uuid "$uuid" \
                --arg path "$ws_path" \
                '{
                  listen: $sock,
                  protocol: "vless",
                  settings: {clients: [{id: $uuid}], decryption: "none"},
                  streamSettings: {network: "ws", wsSettings: {path: $path}}
                }')
            
            nginx_server="server {
    listen $PORT_NGINX_FRONT ssl http2;
    server_name $domain;
    ssl_certificate ${CERT_DIR}/${domain}.crt;
    ssl_certificate_key ${CERT_DIR}/${domain}.key;
    
    root $WEB_ROOT;
    index index.html;
    
    location $ws_path {
        proxy_pass http://unix:${SOCK_XRAY_WS};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
    }
}"
            ;;

        "xhttp_tls")
            # [Fix] 确保非 Mode 1 模式下使用默认企业风格 (重置网站)
            func_generate_website

            func_ensure_cert "$domain" || return 1
            local xhttp_path="/xh"
            func_set_config "xhttp_path" "$xhttp_path"
            
            xray_inbound=$(jq -n \
                --arg sock "$SOCK_XRAY_XHTTP" \
                --arg uuid "$uuid" \
                --arg path "$xhttp_path" \
                '{
                  listen: $sock,
                  protocol: "vless",
                  settings: {clients: [{id: $uuid}], decryption: "none"},
                  streamSettings: {network: "xhttp", xhttpSettings: {path: $path}}
                }')
            
            nginx_server="server {
    listen $PORT_NGINX_FRONT ssl http2;
    server_name $domain;
    ssl_certificate ${CERT_DIR}/${domain}.crt;
    ssl_certificate_key ${CERT_DIR}/${domain}.key;
    
    root $WEB_ROOT;
    index index.html;
    
    location $xhttp_path {
        proxy_pass http://unix:${SOCK_XRAY_XHTTP};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
    }
}"
            ;;
    esac

    # --- 构建完整配置 ---
    local outbounds='[{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"}]'
    
    local transits
    transits=$(func_get_config "transit_enabled")
    local rules='[]'
    
    # 规则优先级策略：
    # - Transit 关闭: Google Direct > Block CN (避免误杀 Google)
    # - Transit 开启: Block CN > Relay catch-all (Google 走 Relay)
    
    if [[ "$transits" != "true" ]]; then
        # Transit 关闭: Google 直连优先（避免 Block CN 误杀）
        rules='[{"type":"field","outboundTag":"direct","domain":["geosite:google"]}]'
    fi
    
    # Block CN 规则
    if [[ "$block_cn" == "true" ]]; then
        rules=$(echo "$rules" | jq '. + [
            {"type":"field","outboundTag":"block","domain":["geosite:cn"]},
            {"type":"field","outboundTag":"block","ip":["geoip:cn"]}
        ]')
    fi
    
    # Transit Relay 规则将在稍后添加（作为 catch-all，捕获包括 Google 在内的所有流量）
    
    
    local inbounds="[$xray_inbound]"
    
    # [Global Relay] 如果启用了落地转发，配置 Shadowsocks 出站
    if [[ "$transits" == "true" ]]; then
        local t_ss
        t_ss=$(func_get_config "transit_ss")
        if [[ -n "$t_ss" && "$t_ss" != "null" ]]; then
            local ss_srv ss_port ss_meth ss_pass
            ss_srv=$(echo "$t_ss" | jq -r '.server')
            ss_port=$(echo "$t_ss" | jq -r '.port')
            ss_meth=$(echo "$t_ss" | jq -r '.method')
            ss_pass=$(echo "$t_ss" | jq -r '.password')
            
            # 1. 添加 Shadowsocks Outbound (tag: transit_relay)
            local t_outbound
            t_outbound=$(jq -n \
                --arg addr "$ss_srv" \
                --argjson port "$ss_port" \
                --arg method "$ss_meth" \
                --arg pass "$ss_pass" \
                '{
                  tag: "transit_relay",
                  protocol: "shadowsocks",
                  settings: {servers: [{address: $addr, port: $port, method: $method, password: $pass}]}
                }')
            outbounds=$(echo "$outbounds" | jq ". + [$t_outbound]")
            
            # 2. 添加 Relay 规则 (作为 catch-all，最低优先级)
            # 注意：此规则追加到 rules 数组末尾，确保 Block CN 规则先匹配
            rules=$(echo "$rules" | jq '. + [{"type":"field","network":"tcp,udp","outboundTag":"transit_relay"}]')
            
            print_info "已启用全局落地转发 (Relay -> $ss_srv:$ss_port)"
        fi
    fi

    local final_config
    final_config=$(jq -n \
        --argjson inbounds "$inbounds" \
        --argjson outbounds "$outbounds" \
        --argjson rules "$rules" \
        '{
          log: {loglevel: "debug"},
          inbounds: $inbounds,
          outbounds: $outbounds,
          routing: {
            domainStrategy: "IPIfNonMatch",
            rules: $rules
          }
        }')
    
    # 写入配置前进行 JSON 语法和 Xray 配置校验
    rm -f "$NGINX_CONF_DIR/xray_*.conf" "$NGINX_CONF_DIR/acme.conf"
    if [ -n "$nginx_server" ]; then
        echo "$nginx_server" > "$NGINX_CONF_DIR/xray_main.conf"
    fi
    
    # 先写入临时文件进行校验
    # [Critical] 必须使用 .json 后缀，否则 Xray 无法识别配置格式
    local tmp_config
    tmp_config=$(secure_mktemp ".json")
    echo "$final_config" > "$tmp_config"
    
    # JSON 语法校验
    if ! jq empty "$tmp_config" 2>/dev/null; then
        print_err "生成的配置文件 JSON 语法错误！"
        cat "$tmp_config"
        read -n 1 -s -p "按任意键返回..."
        return 1
    fi
    
    # Xray 配置校验
    print_info "正在验证 Xray 配置..."
    if ! xray -test -config "$tmp_config" 2>&1; then
        print_err "Xray 配置校验失败！请检查上方错误信息。"
        read -n 1 -s -p "按任意键返回..."
        return 1
    fi
    print_ok "配置校验通过"
    
    # 校验通过后写入正式配置
    mv "$tmp_config" "$BASE_DIR/config.json"
    chown "$XRAY_USER:$XRAY_GROUP" "$BASE_DIR/config.json"
    chmod 600 "$BASE_DIR/config.json"
    
    # Systemd override for UDS permissions and capabilities
    # 关键修复: 解决 Xray 与 Nginx 的 UDS 跨用户通信权限问题
    local override_file="/etc/systemd/system/xray.service.d/override.conf"
    local override_needed=0
    
    # 检查是否需要更新 override (比较关键配置行)
    # [v3.0.7] 增加对 ExecStartPre=+ 的检查，旧版用不带 + 的命令会导致权限失败
    if [ ! -f "$override_file" ]; then
        override_needed=1
    elif ! grep -q "Group=www-data" "$override_file" 2>/dev/null; then
        override_needed=1
    elif ! grep -q "ExecStartPre=+" "$override_file" 2>/dev/null; then
        override_needed=1
    fi
    
    if [ "$override_needed" -eq 1 ]; then
        mkdir -p /etc/systemd/system/xray.service.d
        cat > "$override_file" << 'XRAY_OVERRIDE'
[Service]
# UDS 权限修复: Xray 加入 www-data 组，使其创建的 Socket 可被 Nginx 访问
Group=www-data
# UMask 0002 使新创建文件权限为 775/664，组可写
UMask=0002
# 端口绑定能力 (443)
AmbientCapabilities=CAP_NET_BIND_SERVICE
# 启动前确保 Socket 目录存在且权限正确 (/run 是 tmpfs，重启后消失)
# [Critical] + 前缀表示以 root 权限运行，否则 chown 会因权限不足失败
ExecStartPre=+/bin/mkdir -p /run/xray
ExecStartPre=+/bin/chown www-data:www-data /run/xray
ExecStartPre=+/bin/chmod 775 /run/xray
XRAY_OVERRIDE
        systemctl daemon-reload
        print_ok "Systemd override 已更新 (UDS 权限修复)"
    fi
    
    # 启动顺序与错误检查: 使用 return 代替 exit 以优雅返回菜单
    if [[ "$mode" == "ws_tls" || "$mode" == "xhttp_tls" ]]; then
        if ! systemctl restart xray; then
            print_err "Xray 启动失败"
            read -n 1 -s -p "按任意键返回..."
            return 1
        fi
        if ! systemctl restart nginx; then
            print_err "Nginx 启动失败，请检查配置"
            read -n 1 -s -p "按任意键返回..."
            return 1
        fi
    else
        systemctl stop nginx 2>/dev/null || true
        if ! systemctl restart xray; then
            print_err "Xray (Frontend) 启动失败"
            read -n 1 -s -p "按任意键返回..."
            return 1
        fi
        # [v3.0.8] 只有当生成了 Nginx 配置时才启动 Nginx 后端
        # Reality Steal Others 模式不生成 Nginx 配置，无需启动 Nginx
        if [ -n "$nginx_server" ]; then
            systemctl start nginx 2>/dev/null || print_warn "Nginx (Backend) 启动失败，伪装站可能不可用"
        fi
    fi
    
    print_ok "服务已重启，模式切换完成: $mode"
    func_set_config "current_mode" "$mode"
    
    # [UX] 自动显示连接信息
    read -n 1 -s -p "按任意键查看连接信息..."
    func_show_links_only
}

# --- 5/6/7 菜单函数 ---

func_menu_switch() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                切换协议模式 (Mode Switch)            ║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} ${YELLOW}A组: Xray 前置 (443占用)${NC}                            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   1. VLESS-Vision-Reality [Steal Others] (无需域名) ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   2. VLESS-Vision-Reality [Steal Self]   (本地伪装) ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   3. VLESS-XHTTP-Reality  [Steal Self]   (本地伪装) ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC} ${YELLOW}B组: Nginx 前置 (443占用)${NC}                            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   4. VLESS-WS-TLS         [Standard]     (CDN首选)  ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}   5. VLESS-XHTTP-TLS      [Standard]     (CDN备选)  ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo "0. 返回主菜单"
    read -p "选择模式 [1-5]: " c
    
    case "$c" in
        1) func_gen_config "reality_steal_others" ;;
        2) func_gen_config "reality_steal_self" ;;
        3) func_gen_config "xhttp_reality_steal_self" ;;
        4) func_gen_config "ws_tls" ;;
        5) func_gen_config "xhttp_tls" ;;
        *) return ;;
    esac
}

func_transit_mgr() {
    while true; do
        clear
        echo -e "${CYAN}=== 落地转发 (Global Relay) 管理 ===${NC}"
        
        local t_enabled t_ss
        t_enabled=$(func_get_config "transit_enabled")
        t_ss=$(func_get_config "transit_ss")
        
        local s_status="${RED}Disabled${NC}"
        local s_target="-"
        
        if [ "$t_enabled" == "true" ]; then
            s_status="${GREEN}Enabled${NC}"
            if [[ -n "$t_ss" && "$t_ss" != "null" ]]; then
                local ip port method
                ip=$(echo "$t_ss" | jq -r '.server')
                port=$(echo "$t_ss" | jq -r '.port')
                method=$(echo "$t_ss" | jq -r '.method')
                s_target="${ip}:${port} ($method)"
            fi
        fi
        
        echo -e "当前状态: $s_status"
        echo -e "目标 SS : $s_target"
        echo "--------------------------------"
        echo "1. 启用并配置转发 (Enable & Config)"
        echo "2. 关闭转发 (Disable)"
        echo "0. 返回"
        read -p "选择: " c
        
        case "$c" in
            1)
                echo -e "\n${BLUE}[配置 Shadowsocks 落地转发]${NC}"
                echo "此功能将所有出站流量(除回国/Direct外)转发至指定 SS 节点。"
                
                # --- 手动输入 SS 配置 ---
                local ss_ip ss_port ss_method ss_pass
                
                # IP/域名 输入 + 域名解析
                while true; do
                    read -p "  目标 SS 地址 (IP或域名): " ss_input
                    
                    # 检查是否为IP
                    if func_is_valid_ip "$ss_input"; then
                        ss_ip="$ss_input"
                        break
                    else
                        # 尝试域名解析
                        print_info "检测到域名，正在解析 IP 地址..."
                        local resolved_ip
                        resolved_ip=$(dig +short "$ss_input" A | grep -E '^[0-9.]+$' | head -n 1)
                        
                        if [ -z "$resolved_ip" ]; then
                            # dig 失败，尝试 nslookup
                            resolved_ip=$(nslookup "$ss_input" 2>/dev/null | awk '/^Address: / { print $2 }' | grep -E '^[0-9.]+$' | head -n 1)
                        fi
                        
                        if [ -n "$resolved_ip" ]; then
                            ss_ip="$resolved_ip"
                            print_ok "域名解析成功: $ss_input -> $ss_ip"
                            break
                        else
                            print_err "域名解析失败且非有效 IP，请重新输入"
                        fi
                    fi
                done
                
                # 端口输入 + 默认值 10086
                while true; do
                    read -p "  目标 SS 端口 (默认 10086): " ss_port
                    [ -z "$ss_port" ] && ss_port="10086"
                    if func_is_valid_port "$ss_port"; then break; else print_err "端口无效"; fi
                done
                
                # 加密方法 (默认改为选项1)
                echo -e "\n  加密协议选择:"
                echo "    1) 2022-blake3-aes-128-gcm (默认, 推荐)"
                echo "    2) 2022-blake3-aes-256-gcm"
                echo "    3) aes-256-gcm"
                echo "    4) aes-128-gcm"
                echo "    5) chacha20-ietf-poly1305"
                read -p "  选择 [1-5, 默认1]: " m_choice
                case "$m_choice" in
                    2) ss_method="2022-blake3-aes-256-gcm" ;;
                    3) ss_method="aes-256-gcm" ;;
                    4) ss_method="aes-128-gcm" ;;
                    5) ss_method="chacha20-ietf-poly1305" ;;
                    *) ss_method="2022-blake3-aes-128-gcm" ;;
                esac
                
                read -p "  密码 (留空自动生成): " ss_pass
                [ -z "$ss_pass" ] && ss_pass=$(openssl rand -base64 16)
                
                # 保存配置
                local ss_obj
                ss_obj=$(jq -n \
                    --arg s "$ss_ip" --argjson p "$ss_port" \
                    --arg m "$ss_method" --arg pwd "$ss_pass" \
                    '{server:$s, port:$p, method:$m, password:$pwd}')
                    
                func_set_config_json "transit_ss" "$ss_obj"
                func_set_config "transit_enabled" "true"
                
                print_ok "落地转发已启用 -> $ss_ip:$ss_port"
                
                # 应用配置（非交互模式）
                local cur_mode
                cur_mode=$(func_get_config "current_mode")
                if [[ -n "$cur_mode" && "$cur_mode" != "null" ]]; then
                    NO_PROMPT=true func_gen_config "$cur_mode"
                else
                    print_warn "请先选择协议模式 (菜单 3) 以应用中转配置"
                    read -n 1 -s -p "按任意键继续..."
                fi
                sleep 1
                ;;
            2)
                func_set_config "transit_enabled" "false"
                print_ok "落地转发已关闭 (直连模式)"
                # 应用配置（非交互模式）
                local cur_mode
                cur_mode=$(func_get_config "current_mode")
                if [[ -n "$cur_mode" && "$cur_mode" != "null" ]]; then
                    NO_PROMPT=true func_gen_config "$cur_mode"
                else
                    print_warn "请先选择协议模式 (菜单 3) 以应用中转配置"
                    read -n 1 -s -p "按任意键继续..."
                fi
                sleep 1
                ;;
            0) return ;;
        esac
    done
}



func_show_links_only() {
    clear
    local mode domain uuid
    mode=$(func_get_config "current_mode")
    domain=$(func_get_config "domain")
    uuid=$(func_get_config "uuid")
    
    echo -e "${CYAN}=== 连接配置信息 ===${NC}"
    echo -e "当前模式: ${GREEN}${mode:-未配置}${NC}"
    echo "Domain:   $domain"
    echo "UUID:     $uuid"
    
    local link=""
    case "$mode" in
        "reality_steal_others")
           local pb sid sni public_ip
           pb=$(func_get_config "reality_pub")
           sid=$(func_get_config "reality_short")
           sni=$(func_get_config "reality_sni")
           
           # [Critical Fix] Mode 1 连接地址: 优先使用了配置的 Domain (或 IP)
           # 用户明确要求使用配置的域名/IP，而非自动获取的公网 IP
           link="vless://$uuid@$domain:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=$pb&sid=$sid&type=tcp#Reality-Others"
           ;;
        "reality_steal_self")
           local pb sid
           pb=$(func_get_config "reality_pub")
           sid=$(func_get_config "reality_short")
           link="vless://$uuid@$domain:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$domain&fp=chrome&pbk=$pb&sid=$sid&type=tcp#Reality-Self"
           ;;
        "xhttp_reality_steal_self")
           local pb sid
           pb=$(func_get_config "reality_pub")
           sid=$(func_get_config "reality_short")
           link="vless://$uuid@$domain:443?encryption=none&security=reality&sni=$domain&fp=chrome&pbk=$pb&sid=$sid&type=xhttp&path=%2Fxr&host=$domain#XHTTP-Reality"
           ;;
        "ws_tls")
           local ws_path
           ws_path=$(func_get_config "ws_path")
           link="vless://$uuid@$domain:443?encryption=none&security=tls&type=ws&host=$domain&path=$(echo "$ws_path" | sed 's|/|%2F|g')&sni=$domain#WS-TLS"
           ;;
        "xhttp_tls")
           local xhttp_path
           xhttp_path=$(func_get_config "xhttp_path")
           link="vless://$uuid@$domain:443?encryption=none&security=tls&type=xhttp&host=$domain&path=$(echo "$xhttp_path" | sed 's|/|%2F|g')&sni=$domain#XHTTP-TLS"
           ;;
    esac
    
    if [ -n "$link" ]; then
        echo ""
        echo -e "${YELLOW}分享链接 (VLESS):${NC}"
        echo "$link"
        echo ""
        echo -e "${YELLOW}二维码:${NC}"
        if command -v qrencode &>/dev/null; then
            # -t UTF8 使用半块字符，比 ANSI 更小
            qrencode -t UTF8 "$link"
        else
            echo "未安装 qrencode，无法显示二维码"
        fi
    else
        print_warn "当前未生成有效配置链接"
    fi
    
    echo ""
    read -n 1 -s -p "按任意键返回..."
}

func_show_service_status() {
    clear
    echo -e "${CYAN}=== 系统与服务状态 ===${NC}"
    echo ""
    
    # 1. 基础信息
    echo -e "${BLUE}【 基础信息 】${NC}"
    echo "Hostname:  $(hostname)"
    echo "OS:        $(grep -oP 'PRETTY_NAME="\K[^"]+' /etc/os-release)"
    echo "Kernel:    $(uname -r)"
    echo "Time:      $(date)"
    echo "Uptime:    $(uptime -p)"
    echo ""
    
    # 2. 资源使用
    echo -e "${BLUE}【 资源使用 】${NC}"
    free -h | awk 'NR==2{printf "Memory:    %s / %s (Used: %s)\n", $3, $2, $3}'
    df -h / | awk 'NR==2{printf "Disk:      %s / %s (Used: %s)\n", $3, $2, $5}'
    echo ""
    
    # 3. 服务状态
    echo -e "${BLUE}【 服务状态 】${NC}"
    
    local x_status x_ver
    if systemctl is-active --quiet xray; then 
        x_status="${GREEN}Running${NC}"
        x_ver=$(xray version 2>/dev/null | head -n1 | awk '{print $2}')
    else 
        x_status="${RED}Stopped${NC}"
        x_ver="Unknown"
    fi
    printf "%-10s %-20b (Ver: %s)\n" "Xray:" "$x_status" "$x_ver"
    
    local n_status n_ver
    if systemctl is-active --quiet nginx; then 
        n_status="${GREEN}Running${NC}"
        n_ver=$(nginx -v 2>&1 | cut -d'/' -f2)
    else 
        n_status="${RED}Stopped${NC}"
        n_ver="Unknown"
    fi
    printf "%-10s %-20b (Ver: %s)\n" "Nginx:" "$n_status" "$n_ver"
    
    local t_enabled t_ss t_status_str
    t_enabled=$(func_get_config "transit_enabled")
    if [ "$t_enabled" == "true" ]; then
        t_ss=$(func_get_config "transit_ss")
        local tip tport
        tip=$(echo "$t_ss" | jq -r '.server')
        tport=$(echo "$t_ss" | jq -r '.port')
        t_status_str="${GREEN}Enabled${NC} (via $tip:$tport)"
    else
        t_status_str="${RED}Disabled${NC} (Direct)"
    fi
    printf "%-10s %-20b\n" "Relay:" "$t_status_str"
    
    echo ""
    # 4. 端口监听
    echo -e "${BLUE}【 端口监听 】${NC}"
    # 过滤显示 xray/nginx 相关的监听端口
    ss -tulpn | grep -E 'xray|nginx' | awk '{print $1, $5, $7}' | while read proto addr pidinfo; do
        # 简单格式化输出
        printf "%-5s %-20s %s\n" "$proto" "$addr" "$pidinfo"
    done
    
    echo ""
    read -n 1 -s -p "按任意键返回..."
}

main() {
    check_root
    ensure_dirs
    func_open_ports
    while true; do
        clear
        echo -e "${CYAN}Xray-Nginx-5in1 管理脚本 ${VERSION}${NC}"
        echo "1. 安装基础环境"
        echo "2. 基础配置 (域名/UUID)"
        echo "3. 切换协议模式 (Mode Switch)"
        echo "4. 落地转发管理 (Global Relay)"
        echo "--------------------------------"
        echo "5. 查看连接信息 (Links & QR)"
        echo "6. 服务运行状态 (Status & Stats)"
        echo "7. 卸载 (Uninstall)"
        echo "0. 退出"
        
        read -p "选择: " choice
        case "$choice" in
            1) func_install_base ;;
            2) func_configure_base_settings ;;
            3) func_menu_switch ;;
            4) func_transit_mgr ;;
            5) func_show_links_only ;;
            6) func_show_service_status ;;
            7) func_uninstall_menu ;;
            0) exit 0 ;;
            *) echo "无效选择" ;;
        esac
    done
}

main
