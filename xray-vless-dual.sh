#!/bin/bash

# ====================================================
# Xray VLESS 一键部署脚本 (Integrated Edition)
# Author: Antigravity
# Description: VLESS over TCP with TLS + Caddy Fallback + Dual-path WS
# ====================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# 工作目录
BASE_DIR="/opt/xray-vless-deploy"
CONFIG_DIR="${BASE_DIR}/config"
LOG_DIR="${BASE_DIR}/logs"
USER_CONFIG="${CONFIG_DIR}/user_config.json"

# 初始化目录
mkdir -p "$BASE_DIR" "$CONFIG_DIR" "$LOG_DIR"

# ====================================================
# 0. 基础函数与验证
# ====================================================

# 验证域名格式
func_is_valid_domain() {
    local domain=$1
    # 简单正则：包含点，且仅含字母数字连字符
    if [[ "$domain" =~ ^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$ ]]; then
        return 0
    else
        return 1
    fi
}

# 验证IP格式
func_is_valid_ip() {
    local ip=$1
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# 验证端口范围
func_is_valid_port() {
    local port=$1
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

# ====================================================
# 1. 系统检测与环境准备
# ====================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
       echo -e "${RED}[ERROR]${NC} 请使用 root 用户运行此脚本。"
       exit 1
    fi
}

func_check_system() {
    echo -e "${BLUE}[INFO]${NC} 正在检测系统环境..."
    if [ -f /etc/debian_version ]; then
        OS_VER=$(cat /etc/debian_version | cut -d'.' -f1)
        if [ "$OS_VER" -lt 10 ]; then
            echo -e "${RED}[ERROR]${NC} 仅支持 Debian 11 及以上版本。"
            exit 1
        fi
        echo -e "${GREEN}[OK]${NC} 系统版本: Debian $OS_VER"
    else
        echo -e "${RED}[ERROR]${NC} 此脚本仅支持 Debian 系统。"
        exit 1
    fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) echo -e "${RED}[ERROR]${NC} 不支持的架构: $ARCH"; exit 1 ;;
    esac
    echo -e "${GREEN}[OK]${NC} 系统架构: $ARCH"
}

func_install_dependencies() {
    # 简单检测关键依赖是否已存在，跳过冗余安装
    if command -v curl >/dev/null && command -v jq >/dev/null && command -v openssl >/dev/null && command -v xray >/dev/null; then
        echo -e "${GREEN}[INFO]${NC} 依赖貌似已齐全，快速跳过 apt 安装（如遇报错请手动运行 apt install）。"
        return
    fi

    echo -e "${BLUE}[INFO]${NC} 正在安装必要的依赖包..."
    apt-get update
    apt-get install -y curl wget unzip tar socat jq uuid-runtime openssl git qrencode iproute2 net-tools libcap2-bin
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} 依赖安装失败，请检查网络连接。"
        exit 1
    fi
    echo -e "${GREEN}[OK]${NC} 依赖安装完成。"
}

func_check_ports() {
    local ports=("443" "8001" "10001" "10002")
    echo -e "${BLUE}[INFO]${NC} 正在检测端口占用情况..."
    for port in "${ports[@]}"; do
        if ss -tln | awk '{print $4}' | grep -q ":$port$"; then
            echo -e "${YELLOW}[WARNING]${NC} 端口 $port 已被占用，请确保安装前已释放该端口。"
        fi
    done
}

# ====================================================
# 2. SSL 证书管理
# ====================================================

func_apply_cert() {
    local domain=$1
    
    # 智能检测：如果证书已存在且域名匹配，跳过申请
    if [ -f /etc/xray/certs/fullchain.pem ] && [ -f /etc/xray/certs/private.key ]; then
        local current_cn=$(openssl x509 -noout -subject -in /etc/xray/certs/fullchain.pem | sed -n 's/^subject=.*CN = //p')
        if [ "$current_cn" == "$domain" ]; then
            echo -e "${GREEN}[INFO]${NC} 域名 $domain 的证书已存在，跳过重新申请。"
            return
        fi
    fi

    echo -e "${BLUE}[INFO]${NC} 正在通过 acme.sh 申请 SSL 证书 ($domain)..."
    if [ ! -f ~/.acme.sh/acme.sh ]; then
        curl https://get.acme.sh | sh -s email=admin@${domain}
    fi
    mkdir -p /usr/local/etc/xray/certs/
    systemctl stop caddy >/dev/null 2>&1
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    ~/.acme.sh/acme.sh --issue -d "$domain" --standalone
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} SSL 证书申请失败，请确保域名解析正确且 80 端口开放。"
        exit 1
    fi
    # 安装证书并配置自动续期
    ~/.acme.sh/acme.sh --install-cert -d "$domain" \
        --fullchain-file /usr/local/etc/xray/certs/fullchain.pem \
        --key-file /usr/local/etc/xray/certs/private.key \
        --reloadcmd "systemctl restart xray"
    echo -e "${GREEN}[OK]${NC} SSL 证书申请并安装成功，已配置自动续期。"
}

# ====================================================
# 3. Xray 安装与配置
# ====================================================

func_install_xray() {
    if command -v xray >/dev/null; then
        echo -e "${GREEN}[INFO]${NC} Xray 已安装，跳过。"
        return
    fi
    echo -e "${BLUE}[INFO]${NC} 正在安装 Xray-core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    # 赋予绑定特权端口的能力
    setcap cap_net_bind_service=+ep /usr/local/bin/xray
    echo -e "${GREEN}[OK]${NC} Xray 处理完成。"
}

func_generate_xray_config() {
    local domain=$1 uuid=$2 ws_direct=$3 ws_transit=$4 ss_ip=$5 ss_port=$6 ss_pass=$7 ss_method=$8
    echo -e "${BLUE}[INFO]${NC} 正在生成 Xray 配置文件 (双路径+中转)..."
    mkdir -p /usr/local/etc/xray/
    cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$uuid" }],
        "decryption": "none",
        "fallbacks": [
          { "dest": "127.0.0.1:8001" },
          { "path": "$ws_direct", "dest": "127.0.0.1:10001" },
          { "path": "$ws_transit", "dest": "127.0.0.1:10002" }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [{
            "certificateFile": "/usr/local/etc/xray/certs/fullchain.pem",
            "keyFile": "/usr/local/etc/xray/certs/private.key"
          }]
        }
      }
    },
    {
      "port": 10001,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "$uuid"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "$ws_direct" }
      },
      "tag": "ws-direct-in"
    },
    {
      "port": 10002,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [{"id": "$uuid"}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "$ws_transit" }
      },
      "tag": "ws-transit-in"
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    {
      "protocol": "shadowsocks",
      "settings": {
        "servers": [{
          "address": "$ss_ip",
          "port": $ss_port,
          "method": "$ss_method",
          "password": "$ss_pass"
        }]
      },
      "tag": "transit"
    },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "inboundTag": ["ws-direct-in"], "outboundTag": "direct" },
      { "type": "field", "inboundTag": ["ws-transit-in"], "outboundTag": "transit" }
    ]
  }
}
EOF
    echo -e "${GREEN}[OK]${NC} Xray 配置生成完成。"
}

# ====================================================
# 4. Caddy 与 伪装网站
# ====================================================

func_install_caddy() {
    if command -v caddy >/dev/null; then
        echo -e "${GREEN}[INFO]${NC} Caddy 已安装，跳过。"
        return
    fi
    echo -e "${BLUE}[INFO]${NC} 正在安装 Caddy..."
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt-get update && apt-get install -y caddy
    echo -e "${GREEN}[OK]${NC} Caddy 处理完成。"
}

func_generate_caddy_config() {
    echo -e "${BLUE}[INFO]${NC} 正在生成 Caddy 配置文件..."
    cat > /etc/caddy/Caddyfile <<EOF
:8001 {
    bind 127.0.0.1
    root * /var/www/tech-blog
    file_server
    header {
        Strict-Transport-Security "max-age=31536000;"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy no-referrer-when-downgrade
    }
}
EOF
}

func_generate_website() {
    local site_path="/var/www/tech-blog"
    echo -e "${BLUE}[INFO]${NC} 正在生成增强版科技博客伪装网站..."
    mkdir -p "$site_path/css" "$site_path/about" "$site_path/posts"
    
    # 主CSS样式
    cat > "$site_path/css/main.css" <<'CSS'
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; line-height: 1.6; color: #2c3e50; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
a { color: #3498db; text-decoration: none; transition: all 0.3s ease; }
a:hover { color: #2980b9; }
header { background: rgba(255, 255, 255, 0.98); backdrop-filter: blur(10px); box-shadow: 0 2px 20px rgba(0,0,0,0.1); position: sticky; top: 0; z-index: 100; animation: slideDown 0.5s ease; }
@keyframes slideDown { from { transform: translateY(-100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
nav { max-width: 1200px; margin: 0 auto; padding: 1.2rem 2rem; display: flex; justify-content: space-between; align-items: center; }
.logo { font-size: 1.6rem; font-weight: 700; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.nav-links { display: flex; gap: 2.5rem; list-style: none; }
.nav-links a { color: #2c3e50; font-weight: 500; }
.nav-links a:hover { color: #667eea; }
.container { max-width: 1200px; margin: 2.5rem auto; padding: 0 2rem; }
.hero { background: white; border-radius: 20px; padding: 4rem 3rem; margin-bottom: 3rem; box-shadow: 0 15px 60px rgba(0,0,0,0.15); animation: fadeInUp 0.6s ease; }
@keyframes fadeInUp { from { opacity: 0; transform: translateY(30px); } to { opacity: 1; transform: translateY(0); } }
.hero h1 { font-size: 3.5rem; margin-bottom: 1rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 800; }
.hero p { font-size: 1.2rem; color: #7f8c8d; }
.posts-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 2rem; }
.post-card { background: white; border-radius: 16px; padding: 2.5rem; box-shadow: 0 5px 25px rgba(0,0,0,0.08); transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1); animation: fadeInUp 0.6s ease; animation-fill-mode: both; cursor: pointer; }
.post-card:nth-child(1) { animation-delay: 0.1s; }
.post-card:nth-child(2) { animation-delay: 0.2s; }
.post-card:nth-child(3) { animation-delay: 0.3s; }
.post-card:nth-child(4) { animation-delay: 0.4s; }
.post-card:hover { transform: translateY(-10px); box-shadow: 0 15px 50px rgba(102, 126, 234, 0.3); }
.post-title { font-size: 1.6rem; margin-bottom: 0.8rem; color: #2c3e50; font-weight: 700; }
.post-meta { color: #95a5a6; font-size: 0.9rem; margin-bottom: 1.2rem; display: flex; gap: 1rem; align-items: center; }
.post-meta::before { content: "📅"; }
.post-excerpt { color: #555; line-height: 1.8; margin-bottom: 1.5rem; }
.btn { display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 0.9rem 2rem; border-radius: 10px; font-weight: 600; transition: all 0.3s ease; border: none; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4); }
.btn:hover { transform: translateY(-2px); box-shadow: 0 6px 25px rgba(102, 126, 234, 0.5); color: white; }
footer { text-align: center; padding: 3rem; color: rgba(255,255,255,0.9); margin-top: 4rem; font-size: 0.95rem; }
CSS

    # 首页
    cat > "$site_path/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>极客技术洞察 | 云原生与分布式架构博客</title>
    <meta name="description" content="专注云原生、分布式系统、微服务架构的技术博客">
    <link rel="stylesheet" href="/css/main.css">
</head>
<body>
    <header>
        <nav>
            <div class="logo">🚀 极客洞察</div>
            <ul class="nav-links">
                <li><a href="/">首页</a></li>
                <li><a href="/about">关于</a></li>
                <li><a href="#">归档</a></li>
                <li><a href="#">标签</a></li>
            </ul>
        </nav>
    </header>
    
    <div class="container">
        <div class="hero">
            <h1>探索云原生与分布式架构</h1>
            <p>深入解析 Kubernetes、微服务、分布式系统等前沿技术，助力工程师成长</p>
        </div>
        
        <div class="posts-grid">
            <article class="post-card">
                <h2 class="post-title">Kubernetes 网络模型深度解析</h2>
                <div class="post-meta">2026-01-10 · 云原生</div>
                <p class="post-excerpt">从 CNI 插件到 Service 网络，全面剖析 K8s 网络架构的内部实现机制。理解 Pod 网络、Service 抽象以及 Ingress 控制器的工作原理...</p>
                <a href="/posts/k8s-network" class="btn">阅读全文 →</a>
            </article>
            
            <article class="post-card">
                <h2 class="post-title">eBPF 在可观测性领域的应用</h2>
                <div class="post-meta">2026-01-08 · Linux 内核</div>
                <p class="post-excerpt">利用 eBPF 技术实现高性能的网络监控和分析，深入了解内核态追踪。探索 Cilium、Falco 等现代云原生工具的底层实现...</p>
                <a href="/posts/ebpf" class="btn">阅读全文 →</a>
            </article>
            
            <article class="post-card">
                <h2 class="post-title">Raft 共识算法实战指南</h2>
                <div class="post-meta">2026-01-05 · 分布式系统</div>
                <p class="post-excerpt">从理论到实践，探讨 Raft 在 etcd 和 TiKV 中的工程化实现。深入分析 Leader 选举、日志复制和成员变更机制...</p>
                <a href="/posts/raft" class="btn">阅读全文 →</a>
            </article>
            
            <article class="post-card">
                <h2 class="post-title">Golang 高并发模式最佳实践</h2>
                <div class="post-meta">2026-01-03 · 编程语言</div>
                <p class="post-excerpt">深入分析 Goroutine 调度、Channel 设计模式以及常见的并发陷阱。构建高性能、可扩展的并发系统...</p>
                <a href="/posts/golang" class="btn">阅读全文 →</a>
            </article>
        </div>
    </div>
    
    <footer>
        <p>&copy; 2026 极客技术洞察. All Rights Reserved. | 专注技术分享，探索前沿架构</p>
    </footer>
</body>
</html>
HTML

    # 关于页面
    cat > "$site_path/about/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>关于我们 - 极客技术洞察</title>
    <link rel="stylesheet" href="/css/main.css">
</head>
<body>
    <header>
        <nav>
            <div class="logo">🚀 极客洞察</div>
            <ul class="nav-links">
                <li><a href="/">首页</a></li>
                <li><a href="/about">关于</a></li>
                <li><a href="#">归档</a></li>
            </ul>
        </nav>
    </header>
    
    <div class="container">
        <div class="hero">
            <h1>关于我们</h1>
            <p>专注于云原生技术和分布式系统研究的技术团队</p>
        </div>
        
        <div class="posts-grid">
            <div class="post-card">
                <h2 class="post-title">我们的使命</h2>
                <p class="post-excerpt">通过深度技术文章和实战经验分享，帮助工程师更好地理解和应用云原生技术栈，推动技术社区的发展。</p>
            </div>
            
            <div class="post-card">
                <h2 class="post-title">技术栈</h2>
                <p class="post-excerpt">Kubernetes • Docker • Golang • gRPC • Prometheus • Envoy • eBPF • Service Mesh</p>
            </div>
        </div>
    </div>
    
    <footer>
        <p>&copy; 2026 极客技术洞察</p>
    </footer>
</body>
</html>
HTML

    # 生成文章页面 (填充空链接)
    local posts=("k8s-network" "ebpf" "raft" "golang")
    local titles=("Kubernetes 网络模型深度解析" "eBPF 在可观测性领域的应用" "Raft 共识算法实战指南" "Golang 高并发模式最佳实践")
    local dates=("2026-01-10" "2026-01-08" "2026-01-05" "2026-01-03")
    
    for i in "${!posts[@]}"; do
        local post_dir="$site_path/posts/${posts[$i]}"
        mkdir -p "$post_dir"
        cat > "$post_dir/index.html" <<EOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${titles[$i]} - 极客技术洞察</title>
    <link rel="stylesheet" href="/css/main.css">
    <style>
        .article-content { background: white; padding: 3rem; border-radius: 20px; box-shadow: 0 10px 40px rgba(0,0,0,0.1); }
        .article-header { margin-bottom: 2rem; border-bottom: 1px solid #eee; padding-bottom: 1rem; }
        .article-title { font-size: 2.2rem; color: #2c3e50; margin-bottom: 0.5rem; }
        .article-meta { color: #7f8c8d; font-size: 0.9rem; }
        .article-body p { margin-bottom: 1.2rem; font-size: 1.1rem; color: #34495e; }
        .back-link { display: inline-block; margin-top: 2rem; color: #3498db; font-weight: 600; }
    </style>
</head>
<body>
    <header>
        <nav>
            <div class="logo">🚀 极客洞察</div>
            <ul class="nav-links">
                <li><a href="/">首页</a></li>
                <li><a href="/about">关于</a></li>
            </ul>
        </nav>
    </header>
    
    <div class="container">
        <article class="article-content">
            <div class="article-header">
                <h1 class="article-title">${titles[$i]}</h1>
                <div class="article-meta">发布于 ${dates[$i]} · 阅读 3.2k+</div>
            </div>
            <div class="article-body">
                <p><strong>摘要：</strong>本文深入探讨了 ${titles[$i]} 的核心原理与工程实践...</p>
                <p>（此处为技术文章正文占位符。在实际部署中，这里将包含详细的技术解析、代码示例和架构图表。）</p>
                <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
                <p>总结来说，掌握这项技术对于构建现代化、高可用的分布式系统至关重要。</p>
            </div>
            <a href="/" class="back-link">← 返回首页</a>
        </article>
    </div>
    
    <footer>
        <p>&copy; 2026 极客技术洞察</p>
    </footer>
</body>
</html>
EOF
    done


    # 智能判断 Web 用户权限
    local web_user="www-data"
    if id -u caddy >/dev/null 2>&1; then
        web_user="caddy"
    elif id -u nginx >/dev/null 2>&1; then
        web_user="nginx"
    fi
    
    echo -e "${BLUE}[INFO]${NC} 设置网站目录权限 (用户: $web_user)..."
    chown -R "$web_user:$web_user" "$site_path" 2>/dev/null || chown -R root:root "$site_path"
    echo -e "${GREEN}[OK]${NC} 增强版伪装网站生成完成（含CSS动画、多页面结构）。"
}

# ====================================================
# 5. 管理、状态与分享
# ====================================================

func_show_status() {
    while true; do
        clear
        echo -e "${CYAN}====================================================${NC}"
        echo -e "${CYAN}               系统运行状态看板                    ${NC}"
        echo -e "${CYAN}====================================================${NC}"
        
        # --- Xray Status ---
        local xray_pid=$(pgrep -x xray | head -n 1)
        local xray_ver=$(xray version 2>/dev/null | head -n 1 | awk '{print $2}')
        [ -z "$xray_ver" ] && xray_ver="未知"
        
        if [ -n "$xray_pid" ]; then
            # rss 单位为 kB
            local xray_stats=$(ps -o %cpu,rss,etime -p "$xray_pid" --no-headers)
            local xray_cpu=$(echo "$xray_stats" | awk '{print $1}')
            local xray_rss=$(echo "$xray_stats" | awk '{print $2}')
            # 转换为 MB
            local xray_mem_mb=$(awk "BEGIN {printf \"%.1f\", $xray_rss/1024}")
            local xray_time=$(echo "$xray_stats" | awk '{print $3}')
            
            echo -e "Xray 服务: ${GREEN}运行中${NC} (Ver: $xray_ver)"
            echo -e "  - PID: $xray_pid"
            echo -e "  - CPU: ${xray_cpu}%  |  内存: ${xray_mem_mb} MB"
            echo -e "  - 运行时长: ${xray_time}"
        else
            echo -e "Xray 服务: ${RED}未运行${NC} (Ver: $xray_ver)"
            if systemctl is-active --quiet xray; then
                echo -e "  ${YELLOW}警告: systemd 报告运行中但 PID 未找到${NC}"
            fi
        fi
        
        echo -e "${CYAN}----------------------------------------------------${NC}"
        
        # --- Caddy Status ---
        local caddy_pid=$(pgrep -x caddy | head -n 1)
        local caddy_ver=$(caddy version 2>/dev/null | awk '{print $1}')
        [ -z "$caddy_ver" ] && caddy_ver="未知"
        
        if [ -n "$caddy_pid" ]; then
            local caddy_stats=$(ps -o %cpu,rss,etime -p "$caddy_pid" --no-headers)
            local caddy_cpu=$(echo "$caddy_stats" | awk '{print $1}')
            local caddy_rss=$(echo "$caddy_stats" | awk '{print $2}')
            local caddy_mem_mb=$(awk "BEGIN {printf \"%.1f\", $caddy_rss/1024}")
            local caddy_time=$(echo "$caddy_stats" | awk '{print $3}')
            
            echo -e "Caddy 服务: ${GREEN}运行中${NC} (Ver: $caddy_ver)"
            echo -e "  - PID: $caddy_pid"
            echo -e "  - CPU: ${caddy_cpu}%  |  内存: ${caddy_mem_mb} MB"
            echo -e "  - 运行时长: ${caddy_time}"
        else
            echo -e "Caddy 服务: ${RED}未运行${NC} (Ver: $caddy_ver)"
        fi
        
        echo -e "${CYAN}----------------------------------------------------${NC}"
        echo -e "${BLUE}端口监听状态:${NC}"
        for port in 443 8001 10001 10002; do
            if ss -tln | awk '{print $4}' | grep -q ":$port$"; then
                echo -e "  - 端口 $port: ${GREEN}监听中${NC}"
            else
                echo -e "  - 端口 $port: ${RED}未监听${NC}"
            fi
        done
        
        echo -e "${CYAN}====================================================${NC}"
        echo -e "按 ${GREEN}r${NC} 重启所有服务"
        echo -e "按 ${GREEN}q${NC} 返回主菜单"
        read -n 1 -s key
        case "$key" in
            r|R)
                echo -e "\n${BLUE}[INFO]${NC} 正在重启服务..."
                systemctl restart xray caddy
                echo -e "${GREEN}[OK]${NC} 服务已重启，正在刷新状态..."
                sleep 2
                ;;
            q|Q) break ;;
            *) break ;;
        esac
    done
}

func_generate_links() {
    if [ ! -f "/usr/local/etc/xray/config.json" ]; then 
        echo -e "${RED}未找到 Xray 配置文件${NC}"
        return
    fi
    
    # 优先从保存的配置读取
    local domain uuid path_direct path_transit
    if [ -f "$USER_CONFIG" ]; then
        domain=$(jq -r '.domain' "$USER_CONFIG")
        uuid=$(jq -r '.uuid' "$USER_CONFIG")
        path_direct=$(jq -r '.ws_direct_path' "$USER_CONFIG")
        path_transit=$(jq -r '.ws_transit_path' "$USER_CONFIG")
    else
        # 备用方案：从 Xray 配置提取
        uuid=$(jq -r '.inbounds[0].settings.clients[0].id' /usr/local/etc/xray/config.json)
        path_direct=$(jq -r '.inbounds[1].streamSettings.wsSettings.path' /usr/local/etc/xray/config.json)
        path_transit=$(jq -r '.inbounds[2].streamSettings.wsSettings.path' /usr/local/etc/xray/config.json)
        
        # 尝试从证书文件中提取域名
        if [ -f "/usr/local/etc/xray/certs/fullchain.pem" ]; then
            domain=$(openssl x509 -noout -subject -in /usr/local/etc/xray/certs/fullchain.pem | sed -n 's/^subject=.*CN = //p')
        fi
        [ -z "$domain" ] && domain="YOUR_DOMAIN"
    fi

    local link_d="vless://${uuid}@${domain}:443?encryption=none&security=tls&type=ws&host=${domain}&path=${path_direct}&sni=${domain}#VLESS-WS-Direct"
    local link_t="vless://${uuid}@${domain}:443?encryption=none&security=tls&type=ws&host=${domain}&path=${path_transit}&sni=${domain}#VLESS-WS-Transit"

    echo -e "\n${CYAN}====================================================${NC}"
    echo -e "${GREEN}直连链接 (VLESS+WS+TLS):${NC}"
    echo -e "${BLUE}${link_d}${NC}"
    echo -e "\n${GREEN}直连二维码:${NC}"
    qrencode -t UTF8 "$link_d"
    
    echo -e "\n${CYAN}----------------------------------------------------${NC}"
    echo -e "${GREEN}中转链接 (VLESS+WS+TLS -> Transit):${NC}"
    echo -e "${BLUE}${link_t}${NC}"
    echo -e "\n${GREEN}中转二维码:${NC}"
    qrencode -t UTF8 "$link_t"
    echo -e "${CYAN}====================================================${NC}"
}

# 修正权限 (关键步骤: 确保 nobody 用户能读取证书和配置)
func_fix_permissions() {
    echo -e "${BLUE}[INFO]${NC} 正在修正文件权限..."
    # 确保证书目录可被读取 (Xray 默认以 nobody 运行)
    if [ -d "/usr/local/etc/xray/certs" ]; then
        chown -R root:root /usr/local/etc/xray/certs
        chmod 755 /usr/local/etc/xray/certs
        chmod 644 /usr/local/etc/xray/certs/fullchain.pem
        chmod 600 /usr/local/etc/xray/certs/private.key
    fi
    # 确保配置文件可读取
    # 确保配置文件可读取
    chown root:root /usr/local/etc/xray/config.json
    chmod 644 /usr/local/etc/xray/config.json
    
    # 确保日志文件(如果有)可写，修正为 root:root 以匹配 Xray 进程
    mkdir -p /var/log/xray
    chown -R root:root /var/log/xray
}

# 强制 Xray 以 root 运行 (解决 LXC/部分VPS 环境下 capabilities 失效问题)
func_force_xray_root() {
    echo -e "${BLUE}[INFO]${NC} 正在配置 Xray 服务权限..."
    local service_file="/etc/systemd/system/xray.service"
    if [ -f "$service_file" ]; then
        # 如果存在 User=nobody，替换为 User=root
        sed -i 's/^User=.*/User=root/' "$service_file"
        sed -i 's/^Group=.*/Group=root/' "$service_file"
        # 如果没有 User 字段，可以考虑添加，但默认 root 通常不需要显式指定
        
        # 移除可能导致问题的 Capability 限制 (如果有)
        sed -i '/^CapabilityBoundingSet=/d' "$service_file"
        sed -i '/^AmbientCapabilities=/d' "$service_file"
        
        systemctl daemon-reload
        echo -e "${GREEN}[OK]${NC} 已配置 Xray 为 root 用户运行。"
    fi
}

# 更新 GeoData 文件
func_update_geodata() {
    echo -e "${BLUE}[INFO]${NC} 正在更新 GeoData 文件..."
    mkdir -p /usr/local/share/xray
    
    # 下载 geoip.dat
    echo -e "${BLUE}[INFO]${NC} 下载 geoip.dat..."
    curl -L -o /usr/local/share/xray/geoip.dat.new \
        https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
    
    # 下载 geosite.dat
    echo -e "${BLUE}[INFO]${NC} 下载 geosite.dat..."
    curl -L -o /usr/local/share/xray/geosite.dat.new \
        https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
    
    # 原子替换
    if [ -f /usr/local/share/xray/geoip.dat.new ] && [ -f /usr/local/share/xray/geosite.dat.new ]; then
        mv -f /usr/local/share/xray/geoip.dat.new /usr/local/share/xray/geoip.dat
        mv -f /usr/local/share/xray/geosite.dat.new /usr/local/share/xray/geosite.dat
        echo -e "${GREEN}[OK]${NC} GeoData 更新完成。"
        
        # 重载 Xray 配置
        if systemctl is-active --quiet xray; then
            systemctl reload xray 2>/dev/null || systemctl restart xray
            echo -e "${GREEN}[OK]${NC} Xray 已重载配置。"
        fi
    else
        echo -e "${YELLOW}[WARNING]${NC} GeoData 下载失败，保持原有数据。"
        rm -f /usr/local/share/xray/*.new
    fi
}

# 设置 GeoData 自动更新 (每周日凌晨3点)
func_setup_geodata_autoupdate() {
    echo -e "${BLUE}[INFO]${NC} 正在配置 GeoData 自动更新..."
    
    # 创建更新脚本
    cat > /usr/local/bin/update-geodata.sh <<'SCRIPT'
#!/bin/bash
# GeoData 自动更新脚本
LOG_FILE="/var/log/xray/geodata-update.log"
mkdir -p /var/log/xray

{
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 开始更新 GeoData..."
    
    cd /usr/local/share/xray || exit 1
    
    # 下载新文件
    curl -L -o geoip.dat.new https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
    curl -L -o geosite.dat.new https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
    
    # 检查并替换
    if [ -f geoip.dat.new ] && [ -f geosite.dat.new ]; then
        mv -f geoip.dat.new geoip.dat
        mv -f geosite.dat.new geosite.dat
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓ GeoData 更新成功"
        
        # 重载 Xray
        systemctl reload xray 2>/dev/null || systemctl restart xray
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓ Xray 已重载"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✗ 下载失败"
        rm -f *.new
    fi
} >> "$LOG_FILE" 2>&1
SCRIPT
    
    chmod +x /usr/local/bin/update-geodata.sh
    
    # 添加 cron 任务（每周日凌晨3点）
    local cron_job="0 3 * * 0 /usr/local/bin/update-geodata.sh"
    
    # 检查是否已存在
    if ! crontab -l 2>/dev/null | grep -q "update-geodata.sh"; then
        (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
        echo -e "${GREEN}[OK]${NC} GeoData 自动更新已配置（每周日 03:00）"
    else
        echo -e "${GREEN}[INFO]${NC} GeoData 自动更新已存在，跳过。"
    fi
    
    # 显示下次更新时间
    echo -e "${BLUE}[INFO]${NC} 查看更新日志: tail -f /var/log/xray/geodata-update.log"
}

# 诊断 Xray 运行问题
func_diagnose_xray() {
    echo -e "${CYAN}=== Xray 诊断信息 ===${NC}"
    
    # 检查二进制文件
    if ! command -v xray >/dev/null; then
        echo -e "${RED}[ERROR]${NC} Xray 二进制文件不存在！"
        return 1
    fi
    echo -e "${GREEN}[OK]${NC} Xray 二进制: $(which xray)"
    
    # 检查配置文件
    if [ ! -f "/usr/local/etc/xray/config.json" ]; then
        echo -e "${RED}[ERROR]${NC} 配置文件不存在！"
        return 1
    fi
    echo -e "${GREEN}[OK]${NC} 配置文件存在"
    
    # 测试配置
    echo -e "${BLUE}[INFO]${NC} 测试配置文件..."
    if ! xray -test -config /usr/local/etc/xray/config.json; then
        echo -e "${RED}[ERROR]${NC} 配置文件测试失败！"
        return 1
    fi
    
    # 检查证书
    if [ ! -f "/usr/local/etc/xray/certs/fullchain.pem" ] || [ ! -f "/usr/local/etc/xray/certs/private.key" ]; then
        echo -e "${RED}[ERROR]${NC} SSL 证书文件不存在！"
        return 1
    fi
    echo -e "${GREEN}[OK]${NC} SSL 证书文件存在"
    
    # 检查服务状态
    echo -e "${BLUE}[INFO]${NC} 服务状态:"
    systemctl status xray --no-pager -l
    
    # 显示最近日志
    echo -e "\n${BLUE}[INFO]${NC} 最近 20 行日志:"
    journalctl -u xray -n 20 --no-pager
}

# 手动测试 Xray (前台运行，查看实时错误)
func_manual_test_xray() {
    echo -e "${CYAN}=== 手动测试 Xray (前台模式) ===${NC}"
    echo -e "${YELLOW}提示: 按 Ctrl+C 停止测试，服务将自动重启。${NC}\n"
    
    if [ ! -f "/usr/local/etc/xray/config.json" ]; then
        echo -e "${RED}[ERROR]${NC} 配置文件不存在！"
        return 1
    fi
    
    # 先测试配置
    echo -e "${BLUE}[INFO]${NC} 正在验证配置文件..."
    if ! xray -test -config /usr/local/etc/xray/config.json; then
        echo -e "${RED}[ERROR]${NC} 配置验证失败！请检查 /etc/xray/config.json"
        return 1
    fi
    
    echo -e "${GREEN}[OK]${NC} 配置验证通过\n"
    echo -e "${BLUE}[INFO]${NC} 正在前台启动 Xray（查看实时输出）...\n"
    echo -e "${CYAN}========================================${NC}"
    
    # 停止后台服务避免端口冲突
    systemctl stop xray >/dev/null 2>&1
    
    # 注册退出信号捕获，确保恢复服务
    trap 'echo -e "\n${BLUE}[INFO]${NC} 测试结束，正在自动重启后台服务..."; systemctl restart xray; echo -e "${GREEN}[OK]${NC} 服务已恢复。"; return' EXIT INT TERM
    
    # 前台运行
    xray -config /usr/local/etc/xray/config.json
    
    # 解除 trap (如果正常退出)
    trap - EXIT INT TERM
    echo -e "\n${BLUE}[INFO]${NC} 测试结束，正在自动重启后台服务..."
    systemctl restart xray
    echo -e "${GREEN}[OK]${NC} 服务已恢复。"
}

# 更新 GeoData 文件
func_update_geodata() {
    echo -e "${BLUE}[INFO]${NC} 正在更新 GeoData 文件..."
    mkdir -p /usr/local/share/xray
    curl -L -o /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
    curl -L -o /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[OK]${NC} GeoData 更新完成。"
    else
        echo -e "${YELLOW}[WARNING]${NC} GeoData 更新失败，将使用系统默认数据。"
    fi
}

# 保存配置
func_save_config() {
    local domain=$1 uuid=$2 ws_direct=$3 ws_transit=$4
    cat > "$USER_CONFIG" <<EOF
{
  "domain": "$domain",
  "uuid": "$uuid",
  "ws_direct_path": "$ws_direct",
  "ws_transit_path": "$ws_transit",
  "install_date": "$(date +%Y-%m-%d_%H:%M:%S)"
}
EOF
    echo -e "${GREEN}[OK]${NC} 配置已保存到 $USER_CONFIG"
}

# 读取配置 (Unused function removed)


func_uninstall_all() {
    echo -e "${RED}警告：此操作将删除所有配置和数据！${NC}"
    echo -en "请输入 ${YELLOW}delete${NC} 以确认卸载: "
    read -r confirm
    [[ "$confirm" != "delete" ]] && echo -e "${BLUE}已取消操作。${NC}" && return
    
    echo -e "${BLUE}[INFO]${NC} 正在停止服务..."
    systemctl stop xray caddy && systemctl disable xray caddy
    
    echo -e "${BLUE}[INFO]${NC} 正在清理文件..."
    rm -rf /usr/local/bin/xray /etc/xray /var/www/tech-blog /etc/caddy /opt/xray-vless-deploy
    apt-get purge -y caddy >/dev/null 2>&1
    
    # 清理 acme.sh
    if [ -f ~/.acme.sh/acme.sh ]; then
        echo -e "${BLUE}[INFO]${NC} 正在卸载 acme.sh..."
        ~/.acme.sh/acme.sh --uninstall >/dev/null 2>&1
        rm -rf ~/.acme.sh
    fi
    
    echo -e "${GREEN}[OK]${NC} 卸载完成。"
}

# ====================================================
# 6. 安装向导与主循环
# ====================================================

func_install_complete() {
    # 停止现有服务，防止端口误判
    echo -e "${BLUE}[INFO]${NC} 正在停止潜在的冲突服务..."
    systemctl stop xray caddy >/dev/null 2>&1
    
    func_check_system; func_check_ports
    func_check_system; func_check_ports
    
    # 域名输入与验证
    while true; do
        echo -en "\n${CYAN}请输入您的解析域名 (例如: example.com): ${NC}"
        read -r domain
        if [ -z "$domain" ]; then
            echo -e "${RED}域名不能为空，请重试。${NC}"
        elif ! func_is_valid_domain "$domain"; then
             echo -e "${RED}域名格式错误，请检查输入。${NC}"
        else
             break
        fi
    done
    
    local auto_uuid=$(uuidgen)
    echo -en "请输入 UUID (留空自动生成: ${YELLOW}$auto_uuid${NC}): "
    read -r uuid
    if [ -z "$uuid" ]; then
        uuid="$auto_uuid"
        echo -e "${GREEN}[已生成]${NC} UUID: ${CYAN}$uuid${NC}"
    fi
    
    
    echo -en "直连路径 (默认 wwd): "
    read -r ws_direct_path
    [ -z "$ws_direct_path" ] && ws_direct_path="wwd"
    [[ ! "$ws_direct_path" =~ ^/ ]] && ws_direct_path="/$ws_direct_path"
    
    echo -en "中转路径 (默认 wwt): "
    read -r ws_transit_path
    [ -z "$ws_transit_path" ] && ws_transit_path="wwt"
    [[ ! "$ws_transit_path" =~ ^/ ]] && ws_transit_path="/$ws_transit_path"
    
    echo -en "配置中转机? (y/n): "
    read -r tc
    ss_ip="127.0.0.1"; ss_port=10086; ss_method="2022-blake3-aes-128-gcm"; ss_pass=""
    if [[ "$tc" == "y" ]]; then
        # IP 验证
        while true; do
            echo -en "${CYAN}请输入落地机 IP: ${NC}"
            read -r ss_ip
            if func_is_valid_ip "$ss_ip"; then
                break
            else
                echo -e "${RED}IP 格式无效，请重试。${NC}"
            fi
        done
        
        # 端口验证
        while true; do
            echo -en "${CYAN}请输入落地机 SS 端口 (默认 10086): ${NC}"
            read -r ss_port
            [ -z "$ss_port" ] && ss_port=10086
            if func_is_valid_port "$ss_port"; then
                break
            else
                echo -e "${RED}端口必须在 1-65535 之间，请重试。${NC}"
            fi
        done
        echo -e "请选择落地机协议:"
        echo -e "  1. SS2022-128 (默认)"
        echo -e "  2. SS2022-256"
        echo -e "  3. AES-256-GCM"
        echo -e "  4. AES-128-GCM"
        echo -e "  5. Chacha20-Poly1305"
        echo -e "  6. XChacha20-Poly1305"
        read -p "选项 [1-6]: " method_choice
        case "$method_choice" in
            2) ss_method="2022-blake3-aes-256-gcm" ;;
            3) ss_method="aes-256-gcm" ;;
            4) ss_method="aes-128-gcm" ;;
            5) ss_method="chacha20-ietf-poly1305" ;;
            6) ss_method="xchacha20-ietf-poly1305" ;;
            *) ss_method="2022-blake3-aes-128-gcm" ;;
        esac
        
        # 根据协议生成建议密钥
        local auto_pass=""
        if [[ "$ss_method" == *"2022-blake3-aes-256-gcm"* ]]; then
            auto_pass=$(openssl rand -base64 32)
        else
            auto_pass=$(openssl rand -base64 16)
        fi
        
        echo -en "落地机 SS 密码 (留空随机生成: ${YELLOW}$auto_pass${NC}): "
        read -r ss_pass
        if [ -z "$ss_pass" ]; then
            ss_pass="$auto_pass"
            echo -e "${GREEN}[已生成]${NC} 密码: ${CYAN}$ss_pass${NC}"
        fi
    fi
    
    func_install_dependencies; func_apply_cert "$domain"
    func_install_xray; func_generate_xray_config "$domain" "$uuid" "$ws_direct_path" "$ws_transit_path" "$ss_ip" "$ss_port" "$ss_pass" "$ss_method"
    
    # 配置文件校验
    echo -e "${BLUE}[INFO]${NC} 正在校验 Xray 配置..."
    if ! xray -test -config /usr/local/etc/xray/config.json; then
        echo -e "${RED}[ERROR]${NC} Xray 配置文件错误，请检查日志。"
        exit 1
    fi
    
    
    func_install_caddy; func_generate_caddy_config; func_generate_website
    
    # 下载 GeoData
    func_update_geodata
    
    # 配置 GeoData 自动更新
    func_setup_geodata_autoupdate
    
    # 保存配置
    func_save_config "$domain" "$uuid" "$ws_direct_path" "$ws_transit_path"
    
    # 修复权限
    func_fix_permissions
    func_force_xray_root
    
    # 启动服务
    echo -e "${BLUE}[INFO]${NC} 正在启动服务..."
    systemctl enable xray caddy
    if ! systemctl restart xray caddy; then
        echo -e "${RED}[ERROR]${NC} 服务启动失败！正在进行诊断..."
        func_diagnose_xray
        exit 1
    fi
    
    echo -e "${BLUE}[INFO]${NC} 等待服务启动 (3秒)..."
    sleep 3
    
    echo -e "${GREEN}====================================================${NC}"
    echo -e "${GREEN}              安装成功！服务已运行                   ${NC}"
    echo -e "${GREEN}====================================================${NC}"
    func_show_status; func_generate_links
}

show_menu() {
    clear
    echo -e "${CYAN}====================================================${NC}"
    echo -e "${GREEN}         Xray VLESS 一键集成脚本 v1.1              ${NC}"
    echo -e "${CYAN}====================================================${NC}"
    echo -e "  ${PURPLE}1.${NC} 安装 Xray VLESS (完整部署)"
    echo -e "  ${PURPLE}2.${NC} 查看运行状态"
    echo -e "  ${PURPLE}3.${NC} 生成分享链接"
    echo -e "  ${PURPLE}4.${NC} ${RED}一键卸载${NC}"
    echo -e "  ${PURPLE}5.${NC} ${YELLOW}诊断 Xray 问题 (查看详细日志)${NC}"
    echo -e "  ${PURPLE}0.${NC} 退出"
    echo -e "${CYAN}====================================================${NC}"
    read -p "请选择 [0-5]: " choice
}

main() {
    check_root
    while true; do
        show_menu
        case "$choice" in
            1) func_install_complete ;;
            2) func_show_status ;;
            3) func_generate_links ;;
            4) func_uninstall_all ;;
            5) func_manual_test_xray ;;
            0) echo -e "${GREEN}感谢使用！${NC}"; exit 0 ;;
            *) echo -e "${RED}无效选项${NC}"; sleep 1 ;;
        esac
        read -p "按回车返回..."
    done
}

main "$@"

