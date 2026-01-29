#!/bin/bash

# ====================================================
# Xray Vision 一键部署脚本 v3.0
# Author: Antigravity
# Description: Pure VLESS-TCP-XTLS-Vision with Multi-User Routing
# ====================================================
# 更新日志 (v3.0 - 2026-01-21)
# - [Default] Block CN 默认开启
# - [Web] 高级伪装站点 (CSS/HTML5)
# - [Cert] 支持 Let's Encrypt / ZeroSSL 切换与复用
# - [Status] 详细服务状态显示
# - [Uninstall] 完整卸载 (支持保留证书)
# ====================================================

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# 工作目录
BASE_DIR="/opt/xray-vision"
CONFIG_DIR="${BASE_DIR}/config"
LOG_DIR="${BASE_DIR}/logs"
USER_CONFIG="${CONFIG_DIR}/user_config.json"

# 初始化目录
mkdir -p "$BASE_DIR" "$CONFIG_DIR" "$LOG_DIR"

# ====================================================
# 0. 基础函数与验证
# ====================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
       echo -e "${RED}[ERROR]${NC} 请使用 root 用户运行此脚本。"
       exit 1
    fi
}

func_is_valid_domain() {
    [[ "$1" =~ ^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$ ]]
}

func_is_valid_ip() {
    [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
}

func_is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

parse_ss_link() {
    local link="$1"
    link=${link#ss://}
    
    local server port method password
    
    # --- Strategy A: Standard SIP002 (userinfo@host:port) ---
    if [[ "$link" =~ @ ]]; then
        local userinfo hostport
        userinfo=$(echo "$link" | awk -F'@' '{print $1}')
        hostport=$(echo "$link" | awk -F'@' '{print $2}')
        
        # Decode userinfo
        local mod=$((${#userinfo} % 4))
        if [ $mod -eq 2 ]; then userinfo="${userinfo}=="; elif [ $mod -eq 3 ]; then userinfo="${userinfo}="; fi
        local decoded
        decoded=$(echo "$userinfo" | base64 -d 2>/dev/null)
        
        if [ -n "$decoded" ] && [[ "$hostport" =~ : ]]; then
             # Clean up HostPort (remove garbage if any)
             # Try standard match first
             server=$(echo "$hostport" | cut -d':' -f1)
             port=$(echo "$hostport" | cut -d':' -f2 | grep -oE '^[0-9]+')
             
             if [ -n "$server" ] && [ -n "$port" ]; then
                 method=$(echo "$decoded" | cut -d':' -f1)
                 password=$(echo "$decoded" | cut -d':' -f2-)
                 echo "$server|$port|$method|$password"
                 return 0
             fi
        fi
    fi
    
    # --- Strategy B: Legacy Base64(method:password@host:port) ---
    # (Simplified check)
    local decoded_full
    decoded_full=$(echo "$link" | base64 -d 2>/dev/null)
    if [[ "$decoded_full" =~ :.*@.*: ]]; then
         # Extract info from decoded
         local info=$(echo "$decoded_full" | cut -d'@' -f1)
         local hp=$(echo "$decoded_full" | cut -d'@' -f2)
         method=$(echo "$info" | cut -d':' -f1)
         password=$(echo "$info" | cut -d':' -f2-)
         server=$(echo "$hp" | cut -d':' -f1)
         port=$(echo "$hp" | cut -d':' -f2)
         echo "$server|$port|$method|$password"
         return 0
    fi
    
    # --- Strategy C: Heuristic for "Messy" Links (Terminal Copy) ---
    # 1. Regex find last valid IP:PORT or Domain:PORT
    local found_ip_port
    # Grep IP:PORT (last occurrence)
    found_ip_port=$(echo "$link" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}' | tail -n 1)
    
    if [ -n "$found_ip_port" ]; then
         server=$(echo "$found_ip_port" | cut -d':' -f1)
         port=$(echo "$found_ip_port" | cut -d':' -f2)
         
         # 2. Try to decode the START of the link as UserInfo
         # Take everything up to the first '==' or just the first chunk of base64 chars
         local candidate_b64
         candidate_b64=$(echo "$link" | grep -oE '^[A-Za-z0-9+/]+={0,2}' | head -n 1)
         
         local decoded_info
         decoded_info=$(echo "$candidate_b64" | base64 -d 2>/dev/null)
         
         if [[ "$decoded_info" =~ : ]]; then
             method=$(echo "$decoded_info" | cut -d':' -f1)
             password=$(echo "$decoded_info" | cut -d':' -f2-)
             
             # Validation: Method should look like a method
             if [[ "$method" =~ (aes|chacha|2022|gcm) ]]; then
                 echo "$server|$port|$method|$password"
                 return 0
             fi
         fi
    fi
    
    return 1
}

generate_uuid() {
    if command -v uuidgen &>/dev/null; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "$(date +%s%N | md5sum | head -c 36)"
    fi
}

func_pause() {
    echo ""
    read -n 1 -s -p "按任意键继续..."
    echo ""
}

# ====================================================
# 1. 核心安装与环境
# ====================================================

func_install_core() {
    clear
    echo -e "${CYAN}====================================================${NC}"
    echo -e "${CYAN}           核心程序安装 (Xray + Caddy)             ${NC}"
    echo -e "${CYAN}====================================================${NC}"
    
    check_root
    apt-get update
    apt-get install -y curl wget unzip tar socat jq uuid-runtime openssl qrencode iproute2 libcap2-bin
    
    # Xray
    if ! command -v xray >/dev/null; then
        echo -e "${BLUE}[INFO]${NC} 安装 Xray..."
        # 忽略安装脚本的启动错误 (可能是端口冲突或配置未生成)
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install || echo -e "${YELLOW}[WARN] Xray 初次启动失败 (预期内，后续将重新配置)${NC}"
        setcap cap_net_bind_service=+ep /usr/local/bin/xray
    else
        echo -e "${GREEN}[OK]${NC} Xray 已安装"
    fi
    
    # Caddy
    if ! command -v caddy >/dev/null; then
        echo -e "${BLUE}[INFO]${NC} 安装 Caddy..."
        local arch
        arch=$(uname -m)
        [ "$arch" == "x86_64" ] && arch="amd64"
        [ "$arch" == "aarch64" ] && arch="arm64"
        curl -L -o "/usr/local/bin/caddy" "https://caddyserver.com/api/download?os=linux&arch=${arch}" --progress-bar
        chmod +x /usr/local/bin/caddy
        ln -sf /usr/local/bin/caddy /usr/bin/caddy
    else
        echo -e "${GREEN}[OK]${NC} Caddy 已安装"
    fi

    # Caddy User & Service
    if ! id -u caddy >/dev/null 2>&1; then
        useradd --system --home /var/lib/caddy --shell /usr/sbin/nologin caddy
        mkdir -p /var/lib/caddy && chown caddy:caddy /var/lib/caddy
    fi

    if [ ! -f /etc/systemd/system/caddy.service ] && [ ! -f /lib/systemd/system/caddy.service ]; then
        cat > /etc/systemd/system/caddy.service <<EOF
[Unit]
Description=Caddy
After=network.target network-online.target
Requires=network-online.target
[Service]
User=caddy
Group=caddy
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile
TimeoutStopSec=5s
LimitNOFILE=1048576
LimitNPROC=512
PrivateTmp=true
ProtectSystem=full
AmbientCapabilities=CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    fi
    
    # GeoData
    mkdir -p /usr/local/share/xray
    echo -e "${BLUE}[INFO]${NC} 更新 GeoData..."
    curl -L -o /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat 2>/dev/null
    curl -L -o /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat 2>/dev/null
    
    echo -e "${GREEN}[OK]${NC} 核心环境安装完成"
    func_pause
}

# ====================================================
# 2. 配置生成
# ====================================================

func_generate_caddy_config() {
    local site_path="/var/www/vision-site"
    mkdir -p /etc/caddy "$site_path/assets/css" "$site_path/assets/js"
    
    # 1. Stylesheet (style.css)
    cat > "$site_path/assets/css/style.css" <<EOF
:root { --primary: #0ea5e9; --bg: #0f172a; --card: #1e293b; --text: #e2e8f0; --muted: #94a3b8; }
body { font-family: 'Inter', system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; line-height: 1.6; }
.navbar { background: rgba(15, 23, 42, 0.9); backdrop-filter: blur(10px); border-bottom: 1px solid #334155; padding: 1rem 0; position: fixed; width: 100%; top: 0; z-index: 100; }
.container { max-width: 1200px; margin: 0 auto; padding: 0 2rem; }
.nav-content { display: flex; justify-content: space-between; align-items: center; }
.brand { font-weight: 700; font-size: 1.25rem; color: var(--primary); text-decoration: none; }
.nav-links a { color: var(--muted); text-decoration: none; margin-left: 2rem; transition: color 0.2s; }
.nav-links a:hover { color: var(--primary); }
.hero { padding: 8rem 0 4rem; text-align: center; }
h1 { font-size: 3.5rem; margin-bottom: 1.5rem; background: linear-gradient(to right, #38bdf8, #818cf8); -webkit-background-clip: text; color: transparent; }
.btn { display: inline-block; background: var(--primary); color: white; padding: 0.75rem 1.5rem; border-radius: 9999px; text-decoration: none; font-weight: 500; margin-top: 2rem; transition: opacity 0.2s; }
.features { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; padding: 4rem 0; }
.card { background: var(--card); padding: 2rem; border-radius: 1rem; border: 1px solid #334155; }
.footer { border-top: 1px solid #334155; padding: 4rem 0; margin-top: 4rem; text-align: center; color: var(--muted); }
EOF

    # 2. Main Page (index.html)
    cat > "$site_path/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantum Edge | Next-Gen Cloud Infrastructure</title>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container nav-content">
            <a href="/" class="brand">Quantum Edge</a>
            <div class="nav-links">
                <a href="/">Platform</a>
                <a href="/products.html">Products</a>
                <a href="/about.html">Company</a>
            </div>
        </div>
    </nav>
    <section class="hero">
        <div class="container">
            <h1>Accelerate Your Digital Future</h1>
            <p>Deploy globally distributed applications with sub-millisecond latency.</p>
            <a href="/products.html" class="btn">Explore Network</a>
        </div>
    </section>
    <section class="container">
        <div class="features">
            <div class="card">
                <h3>Global CDN</h3>
                <p>200+ PoPs worldwide ensuring content delivery at the speed of light.</p>
            </div>
            <div class="card">
                <h3>Edge Compute</h3>
                <p>Serverless functions running closer to your users than ever before.</p>
            </div>
            <div class="card">
                <h3>Cyber Security</h3>
                <p>Enterprise-grade DDoS protection and WAF built into every node.</p>
            </div>
        </div>
    </section>
    <footer class="footer">
        <div class="container">
            <p>&copy; $(date +%Y) Quantum Edge Networks Inc. All rights reserved.</p>
        </div>
    </footer>
</body>
</html>
EOF

    # 3. Products Page (products.html)
    cat > "$site_path/products.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Products - Quantum Edge</title>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container nav-content">
            <a href="/" class="brand">Quantum Edge</a>
            <div class="nav-links">
                <a href="/">Platform</a>
                <a href="/products.html" style="color:var(--primary)">Products</a>
                <a href="/about.html">Company</a>
            </div>
        </div>
    </nav>
    <section class="container" style="padding-top: 8rem;">
        <h2>Core Solutions</h2>
        <div class="features">
            <div class="card">
                <h3>Quantum Storage</h3>
                <p>S3-compatible object storage with 99.999999999% durability.</p>
            </div>
            <div class="card">
                <h3>Virtual Private Cloud</h3>
                <p>Isolated network environments with custom routing policies.</p>
            </div>
        </div>
    </section>
</body>
</html>
EOF

    # 4. About Page (about.html)
    cat > "$site_path/about.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>About Us - Quantum Edge</title>
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container nav-content">
            <a href="/" class="brand">Quantum Edge</a>
            <div class="nav-links">
                <a href="/">Platform</a>
                <a href="/products.html">Products</a>
                <a href="/about.html" style="color:var(--primary)">Company</a>
            </div>
        </div>
    </nav>
    <section class="container" style="padding-top: 8rem; max-width: 800px;">
        <h2>Our Mission</h2>
        <p>To build the internet's most reliable and performant infrastructure layer.</p>
        <div class="card" style="margin-top: 2rem;">
            <h3>System Status</h3>
            <p>All Global Regions: <span style="color:#22c55e">● Operational</span></p>
            <p>Last Incident: None in last 90 days.</p>
        </div>
    </section>
</body>
</html>
EOF

    chown -R caddy:caddy "$site_path"

    cat > /etc/caddy/Caddyfile <<EOF
:8001 {
    root * $site_path
    file_server
    header {
        Strict-Transport-Security "max-age=31536000;"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
    }
    handle_errors {
        rewrite * /index.html
        file_server
    }
}
EOF
}

func_generate_xray_config() {
    if [ ! -f "$USER_CONFIG" ]; then return; fi
    
    local uuid_main domain block_cn
    uuid_main=$(jq -r '.uuid' "$USER_CONFIG")
    domain=$(jq -r '.domain' "$USER_CONFIG")
    block_cn=$(jq -r '.block_cn_traffic' "$USER_CONFIG")
    
    # 构建 Clients 列表
    local clients="{\"id\": \"$uuid_main\", \"flow\": \"xtls-rprx-vision\", \"email\": \"main\"}"
    
    # 构建 Outbounds
    local transit_outbounds=""
    
    local count
    count=$(jq '.transit_nodes | length' "$USER_CONFIG")
    if [ "$count" -gt 0 ]; then
        for ((i=0; i<count; i++)); do
            local t_uuid t_tag t_email ss_server ss_port ss_method ss_pass
            t_uuid=$(jq -r ".transit_nodes[$i].uuid" "$USER_CONFIG")
            t_tag="transit-$i"
            t_email="user-$t_tag"
            ss_server=$(jq -r ".transit_nodes[$i].ss.server" "$USER_CONFIG")
            ss_port=$(jq -r ".transit_nodes[$i].ss.port" "$USER_CONFIG")
            ss_method=$(jq -r ".transit_nodes[$i].ss.method" "$USER_CONFIG")
            ss_pass=$(jq -r ".transit_nodes[$i].ss.password" "$USER_CONFIG")
            
            clients="$clients, {\"id\": \"$t_uuid\", \"flow\": \"xtls-rprx-vision\", \"email\": \"$t_email\"}"
            
            transit_outbounds="$transit_outbounds, {
                \"protocol\": \"shadowsocks\", \"tag\": \"out-$t_tag\",
                \"settings\": {
                    \"servers\": [{ \"address\": \"$ss_server\", \"port\": $ss_port, \"method\": \"$ss_method\", \"password\": \"$ss_pass\" }]
                }
            }"
        done
    fi
    
    # ============================================================
    # 路由规则构建 (按优先级顺序)
    # 
    # 【问题】geosite:cn 可能包含 google.cn 等域名，会导致中转用户访问
    #        谷歌中国时被误杀。需要在 Block CN 之前放行 Google 域名。
    # 
    # 【规则顺序】
    # 1. main 用户 Google → direct
    # 2. 中转用户 Google → 对应落地 SS (防止被 Block CN 误杀)
    # 3. Block CN (全局)
    # 4. 中转用户兜底 → 对应落地 SS
    # 5. 默认 → direct
    # ============================================================
    local routing_rules_arr=()
    
    if [ "$block_cn" == "true" ]; then
        # --- 1. main 用户 Google 直连 ---
        routing_rules_arr+=("{ \"type\": \"field\", \"outboundTag\": \"direct\", \"user\": [\"main\"], \"domain\": [\"geosite:google\", \"geosite:google-cn\"] }")
        
        # --- 2. 中转用户 Google 走落地 (防止 geosite:cn 误杀 google.cn) ---
        if [ "$count" -gt 0 ]; then
            for ((i=0; i<count; i++)); do
                local t_email="user-transit-$i"
                local t_tag="transit-$i"
                routing_rules_arr+=("{ \"type\": \"field\", \"user\": [\"$t_email\"], \"outboundTag\": \"out-$t_tag\", \"domain\": [\"geosite:google\", \"geosite:google-cn\"] }")
            done
        fi
        
        # --- 3. Block CN (全局) ---
        routing_rules_arr+=("{ \"type\": \"field\", \"outboundTag\": \"block\", \"domain\": [\"geosite:cn\"] }")
        routing_rules_arr+=("{ \"type\": \"field\", \"outboundTag\": \"block\", \"ip\": [\"geoip:cn\"] }")
    fi
    
    # --- 4. 中转用户兜底 (非 Google、非 CN 的其他流量) ---
    if [ "$count" -gt 0 ]; then
        for ((i=0; i<count; i++)); do
            local t_email="user-transit-$i"
            local t_tag="transit-$i"
            routing_rules_arr+=("{ \"type\": \"field\", \"user\": [\"$t_email\"], \"outboundTag\": \"out-$t_tag\" }")
        done
    fi
    
    # 拼接路由规则 (正确处理逗号)
    local routing_rules=""
    if [ ${#routing_rules_arr[@]} -gt 0 ]; then
        routing_rules=$(IFS=','; echo "${routing_rules_arr[*]}")
    fi
    
    mkdir -p /usr/local/etc/xray
    cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": 443, "listen": "0.0.0.0", "protocol": "vless",
      "settings": {
        "clients": [ $clients ],
        "decryption": "none",
        "fallbacks": [{ "dest": 8001 }]
      },
      "streamSettings": {
        "network": "tcp", "security": "tls",
        "sockopt": { "tcpFastOpen": true },
        "tlsSettings": {
          "alpn": ["http/1.1", "h2"],
          "certificates": [{ "certificateFile": "/usr/local/etc/xray/certs/fullchain.pem", "keyFile": "/usr/local/etc/xray/certs/private.key" }]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"],
        "routeOnly": true
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
    $transit_outbounds
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [ $routing_rules ]
  }
}
EOF
}

func_restart_services() {
    echo -e "${BLUE}[INFO]${NC} 验证配置..."
    chown -R nobody:nogroup /usr/local/etc/xray
    
    if ! xray -test -config /usr/local/etc/xray/config.json; then
        echo -e "${RED}[ERROR]${NC} 配置验证失败"
        return 1
    fi
    
    echo -e "${BLUE}[INFO]${NC} 重启服务..."
    systemctl daemon-reload
    systemctl enable xray caddy >/dev/null 2>&1
    systemctl restart xray caddy
    
    if systemctl is-active --quiet xray && systemctl is-active --quiet caddy; then
        echo -e "${GREEN}[OK]${NC} 服务启动成功"
    else
        echo -e "${RED}[ERROR]${NC} 服务启动异常，请检查日志"
    fi
}

# ====================================================
# 3. 证书与配置向导
# ====================================================

func_apply_cert() {
    local domain=$1
    local cert_file="/usr/local/etc/xray/certs/fullchain.pem"
    local key_file="/usr/local/etc/xray/certs/private.key"
    
    mkdir -p /usr/local/etc/xray/certs
    
    # 1. Reuse Check
    if [ -f "$cert_file" ]; then
        echo -e "${YELLOW}检测到已有证书:${NC} $cert_file"
        openssl x509 -noout -dates -in "$cert_file" 2>/dev/null | grep "notAfter"
        read -p "是否直接复用该证书? [Y/n]: " reuse
        if [[ "$reuse" != "n" && "$reuse" != "N" ]]; then
            echo -e "${GREEN}[INFO]${NC} 已复用旧证书"
            return
        fi
    fi
    
    # 2. CA Selection
    echo -e "${BLUE}[INFO]${NC} 准备申请证书..."
    if [ ! -f ~/.acme.sh/acme.sh ]; then
        curl https://get.acme.sh | sh -s email=admin@"$domain"
    fi
    local acme=~/.acme.sh/acme.sh
    
    echo -e "选择证书颁发机构 (Default: Let's Encrypt):"
    echo "  1) Let's Encrypt"
    echo "  2) ZeroSSL"
    read -p "Select [1-2]: " ca_choice
    
    local ca_server="letsencrypt"
    if [ "$ca_choice" == "2" ]; then
        ca_server="zerossl"
        echo -e "${BLUE}[INFO]${NC} 注册 ZeroSSL 账户..."
        $acme --register-account -m "admin$((RANDOM%10000))@gmail.com" --server zerossl
    fi
    
    # 3. Stop Web Server
    systemctl stop caddy nginx >/dev/null 2>&1 || true
    
    # 4. Issue Cert
    if $acme --issue -d "$domain" --standalone --server "$ca_server" --force; then
        echo -e "${GREEN}[OK]${NC} 证书申请成功"
        $acme --install-cert -d "$domain" \
            --fullchain-file "$cert_file" \
            --key-file "$key_file"
            
        chmod 644 "$cert_file" "$key_file"
        chown -R nobody:nogroup /usr/local/etc/xray/certs
    else
        echo -e "${RED}[ERROR]${NC} 证书申请失败，请检查域名解析或防火墙 (80/443端口)"
        return 1
    fi
}

func_configure_base() {
    clear
    echo -e "${CYAN}=== Vision 基础配置向导 ===${NC}"
    
    local d_domain d_uuid
    d_domain=$(jq -r '.domain // ""' "$USER_CONFIG" 2>/dev/null) || d_domain=""
    d_uuid=$(jq -r '.uuid // ""' "$USER_CONFIG" 2>/dev/null) || d_uuid=""
    local d_block
    d_block=$(jq -r '.block_cn_traffic // "true"' "$USER_CONFIG" 2>/dev/null) || d_block="true"
    
    if [ -n "$d_domain" ]; then
        echo -e "${YELLOW}检测到已有配置:${NC}"
        echo -e "  Domain: $d_domain"
        echo -e "  UUID:   $d_uuid"
        echo -e "  BlockCN: $d_block"
        echo ""
        read -p "是否重新配置? [y/N] (y=修改/重置, n=仅重启服务): " reconf
        if [[ "$reconf" != "y" && "$reconf" != "Y" ]]; then
            echo -e "${GREEN}保持现有配置，正在应用...${NC}"
            func_generate_caddy_config
            func_generate_xray_config
            func_restart_services
            func_pause
            return
        fi
    fi

    # 1. 域名 (带验证)
    local domain=""
    while true; do
        read -p "域名 [${d_domain:-必填}]: " domain
        [ -z "$domain" ] && domain="$d_domain"
        
        if [ -z "$domain" ]; then
            echo -e "${RED}域名不能为空${NC}"
        elif func_is_valid_domain "$domain"; then
            break
        else
            echo -e "${RED}域名格式无效${NC}"
        fi
    done
    
    # 2. UUID
    local uuid new_uuid
    new_uuid=$(generate_uuid)
    read -p "主UUID [${d_uuid:-$new_uuid}]: " uuid
    [ -z "$uuid" ] && uuid="${d_uuid:-$new_uuid}"
    
    # 3. Block CN
    local block_in block_cn
    read -p "屏蔽回国流量? [Y/n] (当前:${d_block}): " block_in
    if [[ "$block_in" == "n" || "$block_in" == "N" ]]; then
        block_cn="false"
    else
        block_cn="true"
    fi
    
    # 保留中转
    local transits="[]"
    [ -f "$USER_CONFIG" ] && transits=$(jq -r '.transit_nodes // []' "$USER_CONFIG")
    
    func_apply_cert "$domain"
    
    cat > "$USER_CONFIG" <<EOF
{
  "domain": "$domain",
  "uuid": "$uuid",
  "block_cn_traffic": $block_cn,
  "transit_nodes": $transits,
  "updated_at": "$(date)"
}
EOF
    func_generate_caddy_config
    func_generate_xray_config
    func_restart_services
    func_pause
}

# ====================================================
# 4. 中转管理
# ====================================================

func_list_transits() {
    if [ ! -f "$USER_CONFIG" ]; then
        echo -e "${YELLOW}未配置${NC}"
        return
    fi
    
    local count
    count=$(jq '.transit_nodes | length' "$USER_CONFIG")
    
    if [ "$count" -eq 0 ]; then
        echo -e "${YELLOW}暂无中转节点${NC}"
        return
    fi
    
    echo -e "${CYAN}当前中转节点列表:${NC}"
    for ((i=0; i<count; i++)); do
        local note uuid server
        note=$(jq -r ".transit_nodes[$i].note // \"Transit-$i\"" "$USER_CONFIG")
        uuid=$(jq -r ".transit_nodes[$i].uuid" "$USER_CONFIG")
        server=$(jq -r ".transit_nodes[$i].ss.server" "$USER_CONFIG")
        echo -e "  [${GREEN}$i${NC}] $note (UUID: ${uuid:0:8}... -> $server)"
    done
}

func_manage_transits() {
    while true; do
        clear
        echo -e "${CYAN}=== 多用户中转管理 ===${NC}"
        func_list_transits
        echo ""
        echo "1. 添加中转节点"
        echo "2. 删除节点"
        echo "0. 返回"
        read -p "选择: " op
        
        case "$op" in
            1)
                read -p "中转 UUID (留空自动生成): " in_uuid
                local t_uuid="$in_uuid"
                if [ -z "$t_uuid" ]; then
                    t_uuid=$(generate_uuid)
                    echo -e "自动分配: ${GREEN}$t_uuid${NC}"
                fi
                
                read -p "备注 (如 HK-Relay): " note
                [ -z "$note" ] && note="Transit"
                
                # Input Mode Selection
                echo -e "\n配置落地机 SS 信息:"
                echo "   1) 手动输入参数 (支持域名解析)"
                echo "   2) 使用 SS 链接粘贴"
                read -p "   选择 [1-2, 默认1]: " ss_mode
                [ -z "$ss_mode" ] && ss_mode="1"

                local ss_ip ss_port ss_pass ss_method="2022-blake3-aes-128-gcm"
                
                if [ "$ss_mode" == "2" ]; then
                    read -p "   粘贴 SS 链接: " link
                    local res
                    if res=$(parse_ss_link "$link"); then
                        IFS='|' read -r ss_ip ss_port ss_method ss_pass <<< "$res"
                        echo -e "${GREEN}链接解析成功${NC}"
                        echo -e "Server: $ss_ip, Port: $ss_port, Method: $ss_method"
                        
                        # Domain Resolution Check
                        if ! func_is_valid_ip "$ss_ip"; then
                            echo -e "${YELLOW}检测到域名，正在解析: $ss_ip ...${NC}"
                            local resolved_ip
                            resolved_ip=$(getent hosts "$ss_ip" | awk '{print $1}' | head -n 1)
                            if [ -n "$resolved_ip" ]; then
                                echo -e "解析结果: ${GREEN}$resolved_ip${NC}"
                                ss_ip="$resolved_ip"
                            else
                                echo -e "${RED}无法解析域名，保留原值${NC}"
                            fi
                        fi
                    else
                        echo -e "${RED}[ERROR] 链接解析失败${NC}"
                        ss_mode="1" # Fallback to manual
                    fi
                fi
                
                if [ "$ss_mode" == "1" ]; then
                    # Manual Input with Domain Resolution
                    while true; do
                        read -p "落地地址 (IP 或 域名): " input_addr
                        if func_is_valid_ip "$input_addr"; then
                            ss_ip="$input_addr"
                            break
                        else
                            # Try resolve
                            echo -e "${YELLOW}正在解析域名: $input_addr ...${NC}"
                            local resolved_ip
                            resolved_ip=$(getent hosts "$input_addr" | awk '{print $1}' | head -n 1)
                            if [ -n "$resolved_ip" ]; then
                                echo -e "解析成功: ${GREEN}$resolved_ip${NC}"
                                read -p "确认使用此 IP? [Y/n]: " use_res
                                if [[ "$use_res" != "n" && "$use_res" != "N" ]]; then
                                    ss_ip="$resolved_ip"
                                    break
                                fi
                            else
                                echo -e "${RED}解析失败，请检查拼写或 DNS${NC}"
                            fi
                        fi
                    done
                
                    while true; do
                        read -p "落地 SS 端口 (默认 10086): " ss_port
                        [ -z "$ss_port" ] && ss_port=10086
                        if func_is_valid_port "$ss_port"; then
                            break
                        else
                            echo -e "${RED}端口无效 (1-65535)${NC}"
                        fi
                    done
                    
                    echo -e "\n加密协议选择:"
                    echo "   1) aes-256-gcm"
                    echo "   2) aes-128-gcm"
                    echo "   3) chacha20-ietf-poly1305"
                    echo "   4) 2022-blake3-aes-128-gcm (默认)"
                    echo "   5) 2022-blake3-aes-256-gcm"
                    read -p "   选择 [1-5]: " m_choice
                    case "$m_choice" in
                        1) ss_method="aes-256-gcm" ;;
                        2) ss_method="aes-128-gcm" ;;
                        3) ss_method="chacha20-ietf-poly1305" ;;
                        5) ss_method="2022-blake3-aes-256-gcm" ;;
                        *) ss_method="2022-blake3-aes-128-gcm" ;;
                    esac

                    read -p "密码: " ss_pass
                    [ -z "$ss_pass" ] && ss_pass=$(uuidgen) && echo -e "生成的随机密码: ${GREEN}$ss_pass${NC}"
                fi
                
                local json
                json=$(jq -n --arg id "$t_uuid" --arg n "$note" \
                    --arg si "$ss_ip" --argjson sp "$ss_port" --arg sm "$ss_method" --arg spa "$ss_pass" \
                    '{uuid:$id, note:$n, ss:{server:$si, port:$sp, method:$sm, password:$spa}}')
                
                local tmp
                tmp=$(mktemp)
                jq ".transit_nodes += [$json]" "$USER_CONFIG" > "$tmp" && mv "$tmp" "$USER_CONFIG"
                func_generate_xray_config
                func_restart_services
                echo -e "${GREEN}添加成功${NC}"
                func_pause
                ;;
            2)
                local count
                count=$(jq '.transit_nodes | length' "$USER_CONFIG" 2>/dev/null) || count=0
                if [ "$count" -eq 0 ]; then
                    echo -e "${YELLOW}无可删除的节点${NC}"
                    func_pause
                    continue
                fi
                
                read -p "输入要删除的索引号: " idx
                if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -lt "$count" ]; then
                    local tmp
                    tmp=$(mktemp)
                    jq "del(.transit_nodes[$idx])" "$USER_CONFIG" > "$tmp" && mv "$tmp" "$USER_CONFIG"
                    func_generate_xray_config
                    func_restart_services
                    echo -e "${GREEN}删除成功${NC}"
                else
                    echo -e "${RED}索引无效${NC}"
                fi
                func_pause
                ;;
            0) return ;;
            *) echo -e "${RED}无效选项${NC}"; sleep 1 ;;
        esac
    done
}

# ====================================================
# 5. 链接展示
# ====================================================

func_show_links() {
    clear
    if [ ! -f "$USER_CONFIG" ]; then
        echo -e "${RED}未找到配置，请先完成基础配置${NC}"
        func_pause
        return
    fi
    
    local domain uuid
    domain=$(jq -r '.domain' "$USER_CONFIG")
    uuid=$(jq -r '.uuid' "$USER_CONFIG")
    
    echo -e "${CYAN}=== 节点链接 (VLESS-Vision XTLS) ===${NC}"
    
    # helper for showing details
    show_details() {
        echo -e "---------------------------------------------------"
        echo -e "别名 (Alias):   ${GREEN}$1${NC}"
        echo -e "地址 (Address): ${YELLOW}$2${NC}"
        echo -e "端口 (Port):    ${YELLOW}443${NC}"
        echo -e "用户ID (UUID):  ${PURPLE}$3${NC}"
        echo -e "流控 (Flow):    xtls-rprx-vision"
        echo -e "传输 (Network): tcp"
        echo -e "安全 (TLS):     tls (SNI: $2)"
        echo -e "---------------------------------------------------"
        echo -e "分享链接 (Link):"
        echo "$4"
        echo ""
    }

    echo -e "\n${GREEN}[1. 直连节点 (Main)]${NC}"
    local main_link="vless://${uuid}@${domain}:443?encryption=none&security=tls&type=tcp&flow=xtls-rprx-vision&headerType=none&sni=${domain}#${domain}-Main"
    show_details "${domain}-Main" "$domain" "$uuid" "$main_link"
    
    local count
    count=$(jq '.transit_nodes | length' "$USER_CONFIG")
    if [ "$count" -gt 0 ]; then
        for ((i=0; i<count; i++)); do
            local t_uuid note link ss_server ss_port ss_method ss_pass
            t_uuid=$(jq -r ".transit_nodes[$i].uuid" "$USER_CONFIG")
            note=$(jq -r ".transit_nodes[$i].note // \"Transit-$i\"" "$USER_CONFIG")
            
            # Read Transit SS Info
            ss_server=$(jq -r ".transit_nodes[$i].ss.server" "$USER_CONFIG")
            ss_port=$(jq -r ".transit_nodes[$i].ss.port" "$USER_CONFIG")
            ss_method=$(jq -r ".transit_nodes[$i].ss.method" "$USER_CONFIG")
            ss_pass=$(jq -r ".transit_nodes[$i].ss.password" "$USER_CONFIG")

            link="vless://${t_uuid}@${domain}:443?encryption=none&security=tls&type=tcp&flow=xtls-rprx-vision&headerType=none&sni=${domain}#${domain}-${note}"
            
            echo -e "\n${YELLOW}[$((i+2)). 中转: $note]${NC}"
            show_details "${domain}-${note}" "$domain" "$t_uuid" "$link"
            
            echo -e "${CYAN}--- 落地配置 (Transit Config) ---${NC}"
            echo -e "Server:   ${GREEN}$ss_server${NC}"
            echo -e "Port:     ${GREEN}$ss_port${NC}"
            echo -e "Method:   ${GREEN}$ss_method${NC}"
            echo -e "Password: ${GREEN}$ss_pass${NC}"
            echo ""
        done
    fi
    
    func_pause
}

# ====================================================
# 6. 服务状态
# ====================================================

func_show_status() {
    clear
    echo -e "${CYAN}=== 服务运行状态 ===${NC}"
    
    # Xray Status
    local x_pid
    x_pid=$(pgrep -x xray | head -n 1)
    if [ -n "$x_pid" ]; then
        local x_ver x_uptime x_mem
        x_ver=$(xray version | head -n 1 | awk '{print $2}')
        x_uptime=$(ps -o etime= -p "$x_pid" | xargs)
        x_mem=$(ps -o rss= -p "$x_pid" | awk '{print int($1/1024)}')
        echo -e "Xray Core: ${GREEN}Running${NC} v$x_ver (PID: $x_pid, Mem: ${x_mem}MB, Up: $x_uptime)"
    else
        echo -e "Xray Core: ${RED}Stopped${NC}"
    fi

    # Caddy Status
    local c_pid
    c_pid=$(pgrep -x caddy | head -n 1)
    if [ -n "$c_pid" ]; then
        local c_ver c_uptime c_mem
        c_ver=$(caddy version | awk '{print $1}')
        c_uptime=$(ps -o etime= -p "$c_pid" | xargs)
        c_mem=$(ps -o rss= -p "$c_pid" | awk '{print int($1/1024)}')
        echo -e "Caddy Web: ${GREEN}Running${NC} $c_ver (PID: $c_pid, Mem: ${c_mem}MB, Up: $c_uptime)"
    else
        echo -e "Caddy Web: ${RED}Stopped${NC}"
    fi
    
    echo -e "\n${BLUE}[System Log Tail]${NC}"
    if [ -n "$x_pid" ]; then
        echo "--- Xray Last 3 Logs ---"
        journalctl -u xray -n 3 --no-pager
    fi
    
    func_pause
}

# ====================================================
# 7. 卸载管理
# ====================================================

func_uninstall() {
    clear
    echo -e "${RED}=== 卸载管理 ===${NC}"
    echo "1. 仅删除配置与日志 (保留核心与证书)"
    echo "2. 仅删除伪装网站"
    echo "3. 彻底卸载 (可选保留证书)"
    echo "0. 返回"
    read -p "选择: " ch
    
    case "$ch" in
        1)
            rm -rf "$CONFIG_DIR" "$LOG_DIR" /usr/local/etc/xray/config.json /etc/caddy/Caddyfile
            systemctl restart xray caddy 2>/dev/null
            echo "配置已清除"
            func_pause
            ;;
        2)
            rm -rf /var/www/vision-site
            echo "网站文件已清除"
            func_pause
            ;;
        3)
            echo -e "${YELLOW}警告: 此操作将删除所有相关文件与服务${NC}"
            echo "证书位置: /usr/local/etc/xray/certs/"
            read -p "是否保留 SSL 证书? [Y/n]: " keep_cert
            
            echo -e "${BLUE}[INFO]${NC} 停止服务..."
            systemctl stop xray caddy 2>/dev/null || true
            systemctl disable xray caddy 2>/dev/null || true
            rm -f /etc/systemd/system/xray.service /etc/systemd/system/caddy.service
            systemctl daemon-reload
            
            # 删除文件
            rm -f /usr/local/bin/xray /usr/local/bin/caddy /usr/bin/caddy
            rm -rf "$BASE_DIR" /etc/caddy /var/www/vision-site
            
            # 证书处理
            if [[ "$keep_cert" == "n" || "$keep_cert" == "N" ]]; then
                rm -rf /usr/local/etc/xray
                echo "证书已删除"
            else
                # 保留 certs 目录，删除其他
                find /usr/local/etc/xray -mindepth 1 -maxdepth 1 ! -name 'certs' -exec rm -rf {} +
                echo -e "${GREEN}证书已保留${NC}"
            fi
            
            # 删除用户
            userdel caddy 2>/dev/null || true
            
            echo -e "${GREEN}[OK]${NC} 卸载完成"
            func_pause
            ;;
        *) return ;;
    esac
}

# ====================================================
# 7. 主菜单
# ====================================================

func_menu() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║    Xray Vision Manager v3.0            ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo "  1. 安装/更新环境"
    echo "  2. 基础配置 (Domain/UUID)"
    echo "  3. 中转管理 (Multi-User)"
    echo "  4. 获取链接"
    echo "  5. 服务状态"
    echo "  6. 卸载管理"
    echo "  0. 退出"
    echo ""
    read -p "请选择: " choice
    
    case "$choice" in
        1) func_install_core ;;
        2) func_configure_base ;;
        3) func_manage_transits ;;
        4) func_show_links ;;
        5) func_show_status ;;
        6) func_uninstall ;;
        0) echo "Bye!"; exit 0 ;;
        *) echo -e "${RED}无效选项${NC}"; sleep 1 ;;
    esac
}

# ====================================================
# Entry
# ====================================================

check_root
[[ "${1:-}" == "install" ]] && { func_install_core; exit; }
while true; do func_menu; done
