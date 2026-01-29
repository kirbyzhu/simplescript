#!/bin/bash

# ====================================================
# Xray VLESS 一键部署脚本 v6.0 (Modular Edition)
# Author: Antigravity
# Description: Modular VLESS setup with Multi-Path Transit Support
# ====================================================
#
# 版本更新日志 (v6.0 - 2026-01-20)
# --------------------------------------------------
# 1. 配置复用优化
#    - 统一所有配置项的交互提示格式
#    - 明确标注"留空保持不变",提升用户体验
#    - 涵盖域名、UUID、WS路径、Block CN等配置项
#
# 2. Caddy 配置目录修复 (P0)
#    - 修复二进制安装 Caddy 后配置目录不存在的问题
#    - 在生成配置文件前自动创建 /etc/caddy 目录
#    - 避免服务启动失败: "no such file or directory"
#
# 3. SS 配置模式默认值修复 (P1)
#    - 修复中转节点 SS 配置模式选择留空时无默认值的问题
#    - 确保留空回车时正确使用默认选项1(手动输入参数)
#    - 保持与其他配置项的一致性
#
# 4. 路由规则确认
#    - 确认谷歌回国直连路由规则位于 Block CN 规则之前
#    - 路由顺序: Google直连 > 屏蔽CN域名 > 屏蔽CN IP
#    - 确保启用 Block CN 时谷歌服务仍可正常访问
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
CORE_INFO_FILE="${BASE_DIR}/core_info.json"

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
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

func_is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

generate_uuid() {
    if command -v uuidgen &>/dev/null; then
        uuidgen
    else
        cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "$(date +%s%N | md5sum | head -c 36)"
    fi
}

# 解析 SS 链接 (Enhanced v2)
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
    local decoded_full
    decoded_full=$(echo "$link" | base64 -d 2>/dev/null)
    if [[ "$decoded_full" =~ :.*@.*: ]]; then
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
    local found_ip_port
    found_ip_port=$(echo "$link" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}' | tail -n 1)
    
    if [ -n "$found_ip_port" ]; then
         server=$(echo "$found_ip_port" | cut -d':' -f1)
         port=$(echo "$found_ip_port" | cut -d':' -f2)
         
         local candidate_b64
         candidate_b64=$(echo "$link" | grep -oE '^[A-Za-z0-9+/]+={0,2}' | head -n 1)
         local decoded_info
         decoded_info=$(echo "$candidate_b64" | base64 -d 2>/dev/null)
         
         if [[ "$decoded_info" =~ : ]]; then
             method=$(echo "$decoded_info" | cut -d':' -f1)
             password=$(echo "$decoded_info" | cut -d':' -f2-)
             if [[ "$method" =~ (aes|chacha|2022|gcm) ]]; then
                 echo "$server|$port|$method|$password"
                 return 0
             fi
         fi
    fi
    
    return 1
}

# 验证核心依赖是否就绪
check_dependencies_ready() {
    local missing=0
    if ! command -v jq >/dev/null; then missing=1; fi
    if [ ! -f /usr/local/bin/xray ]; then missing=1; fi
    
    if [ $missing -eq 1 ]; then
        echo -e "${RED}[ERROR]${NC} 核心组件缺失 (jq 或 /usr/local/bin/xray)"
        echo -e "${YELLOW}请先运行 Option 1 初始化运行环境!${NC}"
        read -n 1 -s -p "按任意键返回..."
        return 1
    fi
    return 0
}

# ====================================================
# 1. 核心安装与环境
# ====================================================

func_install_core() {
    echo -e "${CYAN}====================================================${NC}"
    echo -e "${CYAN}           核心程序安装 (Xray + Caddy)             ${NC}"
    echo -e "${CYAN}====================================================${NC}"
    
    check_root
    
    # 检测系统
    if [ -f /etc/debian_version ]; then
        echo -e "${GREEN}[OK]${NC} 系统检测通过: Debian/Ubuntu"
    else
        echo -e "${RED}[ERROR]${NC} 仅支持 Debian/Ubuntu 系统。"
        exit 1
    fi

    # 安装依赖
    echo -e "${BLUE}[INFO]${NC} 正在安装依赖..."
    apt-get update
    apt-get install -y curl wget unzip tar socat jq uuid-runtime openssl qrencode iproute2 libcap2-bin
    
    # 安装 Xray
    if ! command -v xray >/dev/null; then
        echo -e "${BLUE}[INFO]${NC} 正在安装 Xray..."
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
        setcap cap_net_bind_service=+ep /usr/local/bin/xray
    else
        echo -e "${GREEN}[INFO]${NC} Xray 已安装"
    fi
    
    # 安装 Caddy (二进制方式)
    if ! command -v caddy >/dev/null; then
        echo -e "${BLUE}[INFO]${NC} 正在安装 Caddy..."
        
        # 检测系统架构
        local arch=$(uname -m)
        case $arch in
            x86_64) arch="amd64" ;;
            aarch64) arch="arm64" ;;
            armv7l) arch="armv7" ;;
            *) 
                echo -e "${RED}[ERROR]${NC} 不支持的架构: $arch"
                return 1
                ;;
        esac
        
        # 下载 Caddy 二进制文件
        local url="https://caddyserver.com/api/download?os=linux&arch=${arch}"
        local tmp_file="/tmp/caddy_${arch}"
        
        echo -e "${BLUE}[INFO]${NC} 正在下载 Caddy ($arch)..."
        if curl -L -o "$tmp_file" "$url" --progress-bar --max-time 300; then
            mv "$tmp_file" /usr/local/bin/caddy
            chmod +x /usr/local/bin/caddy
            ln -sf /usr/local/bin/caddy /usr/bin/caddy
            
            local version=$(caddy version 2>/dev/null | awk '{print $1}' || echo "installed")
            echo -e "${GREEN}[OK]${NC} Caddy 安装成功: $version"
        else
            echo -e "${RED}[ERROR]${NC} Caddy 下载失败"
            rm -f "$tmp_file"
            return 1
        fi
    else
        echo -e "${GREEN}[INFO]${NC} Caddy 已安装"
    fi

    # 确保 Caddy 用户存在
    if ! id -u caddy >/dev/null 2>&1; then
        echo -e "${BLUE}[INFO]${NC} 创建 Caddy 用户..."
        useradd --system --home /var/lib/caddy --shell /usr/sbin/nologin caddy
        mkdir -p /var/lib/caddy
        chown caddy:caddy /var/lib/caddy
    fi

    # 创建 Caddy Service 文件 (如果是二进制安装或缺失)
    if [ ! -f /etc/systemd/system/caddy.service ] && [ ! -f /lib/systemd/system/caddy.service ]; then
        echo -e "${BLUE}[INFO]${NC} 创建 Caddy Service 文件..."
        cat > /etc/systemd/system/caddy.service <<EOF
[Unit]
Description=Caddy
Documentation=https://caddyserver.com/docs/
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
        echo -e "${GREEN}[OK]${NC} Caddy Service 创建完成"
    fi
    
    # 更新 GeoData
    echo -e "${BLUE}[INFO]${NC} 更新 GeoData..."
    mkdir -p /usr/local/share/xray
    curl -L -o /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
    curl -L -o /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
    
    # 保存核心信息
    cat > "$CORE_INFO_FILE" <<EOF
{
  "install_date": "$(date +%Y-%m-%d_%H:%M:%S)",
  "xray_version": "$(xray version 2>/dev/null | head -n1 | awk '{print $2}')",
  "caddy_version": "$(caddy version 2>/dev/null | awk '{print $1}')"
}
EOF
    echo -e "${GREEN}[OK]${NC} 核心环境安装完成！请继续配置服务。"
    echo -e "${BLUE}任意键返回主菜单...${NC}"
    read -n 1 -s
}

# ====================================================
# 2. 配置逻辑生成
# ====================================================

func_generate_caddy_config() {
    local site_path="/var/www/tech-blog"
    
    # 确保 Caddy 配置目录存在
    mkdir -p /etc/caddy
    
    cat > /etc/caddy/Caddyfile <<EOF
:8001 {
    bind 127.0.0.1
    root * $site_path
    file_server
    header {
        Strict-Transport-Security "max-age=31536000;"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
    }
}
EOF
}

func_generate_website() {
    local site_path="/var/www/tech-blog"
    local css_path="$site_path/assets/css"
    
    # 始终重新生成以确保存度
    rm -rf "$site_path"
    mkdir -p "$css_path"
    
    # 1. Generate CSS
    cat > "$css_path/style.css" <<EOF
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background: #f4f4f9; color: #333; }
header { background: #333; color: #fff; padding: 1rem 0; text-align: center; }
nav ul { list-style: none; padding: 0; }
nav ul li { display: inline; margin: 0 15px; }
nav a { color: #fff; text-decoration: none; font-weight: bold; }
.container { width: 80%; margin: 2rem auto; display: flex; flex-wrap: wrap; gap: 2rem; }
.card { background: #fff; padding: 1.5rem; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); flex: 1 1 300px; }
.card h2 { color: #444; }
.hero { background: #007bff; color: white; padding: 3rem 1rem; text-align: center; }
footer { background: #222; color: #aaa; text-align: center; padding: 1rem 0; margin-top: 2rem; }
EOF

    # 2. Generate Index
    cat > "$site_path/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Future Tech Insights</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <header>
        <h1>Future Tech Insights</h1>
        <nav>
            <ul>
                <li><a href="index.html">Home</a></li>
                <li><a href="about.html">About</a></li>
                <li><a href="#">Categories</a></li>
            </ul>
        </nav>
    </header>
    
    <div class="hero">
        <h2>Exploring the Boundaries of Technology</h2>
        <p>Deep dives into AI, Cloud Computing, and Decentralized Networks.</p>
    </div>

    <div class="container">
        <article class="card">
            <h2>The Rise of Edge Computing</h2>
            <p>Edge computing is transforming how data is processed, reducing latency and bandwidth use by bringing computation closer to the source...</p>
            <a href="#">Read more</a>
        </article>
        <article class="card">
            <h2>Kubernetes Patterns</h2>
            <p>Understanding the essential patterns for deploying scalable applications in a containerized environment is crucial for modern DevOps...</p>
            <a href="#">Read more</a>
        </article>
        <article class="card">
            <h2>Rust vs. Go</h2>
            <p>A comparative analysis of two of the most popular modern systems programming languages. When to use which?</p>
            <a href="#">Read more</a>
        </article>
    </div>

    <footer>
        <p>&copy; $(date +%Y) Future Tech Insights. All reserved.</p>
    </footer>
</body>
</html>
EOF

    # 3. Generate About Page
    cat > "$site_path/about.html" <<EOF
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
        <h1>Future Tech Insights</h1>
        <nav>
            <ul>
                <li><a href="index.html">Home</a></li>
                <li><a href="about.html">About</a></li>
            </ul>
        </nav>
    </header>

    <div class="container">
        <div class="card" style="flex: 100%;">
            <h2>About Us</h2>
            <p>Welcome to Future Tech Insights. We are a community of developers, engineers, and tech enthusiasts passionate about the latest developments in the software industry.</p>
            <p>Our mission is to provide high-quality, in-depth articles that help you stay ahead of the curve.</p>
        </div>
    </div>

    <footer>
        <p>&copy; $(date +%Y) Future Tech Insights. All reserved.</p>
    </footer>
</body>
</html>
EOF

    # Fix permissions
    chown -R caddy:caddy "$site_path" 2>/dev/null || chown -R www-data:www-data "$site_path" 2>/dev/null
}

func_generate_xray_config() {
    if [ ! -f "$USER_CONFIG" ]; then echo "No config found"; return; fi
    
    local uuid=$(jq -r '.uuid' "$USER_CONFIG")
    local ws_direct=$(jq -r '.ws_direct_path' "$USER_CONFIG")
    local block_cn=$(jq -r '.block_cn_traffic' "$USER_CONFIG")
    
    # 动态生成 inbounds 和 outbounds
    local transit_inbounds=""
    local transit_outbounds=""
    local routing_rules=""
    local fallback_entries="{ \"path\": \"$ws_direct\", \"dest\": 10001 }"
    
    # 读取中转节点数量
    local count=$(jq '.transit_nodes | length' "$USER_CONFIG")
    
    if [ "$count" -gt 0 ]; then
        for ((i=0; i<count; i++)); do
            local path=$(jq -r ".transit_nodes[$i].path" "$USER_CONFIG")
            local port=$(jq -r ".transit_nodes[$i].port" "$USER_CONFIG")
            local tag="transit-$i"
            local ss_server=$(jq -r ".transit_nodes[$i].ss.server" "$USER_CONFIG")
            local ss_port=$(jq -r ".transit_nodes[$i].ss.port" "$USER_CONFIG")
            local ss_method=$(jq -r ".transit_nodes[$i].ss.method" "$USER_CONFIG")
            local ss_pass=$(jq -r ".transit_nodes[$i].ss.password" "$USER_CONFIG")
            
            # Fallback entry
            fallback_entries="$fallback_entries, { \"path\": \"$path\", \"dest\": $port }"
            
            # Inbound entry
            transit_inbounds="$transit_inbounds,
    {
      \"port\": $port,
      \"listen\": \"127.0.0.1\",
      \"protocol\": \"vless\",
      \"settings\": { \"clients\": [{\"id\": \"$uuid\"}], \"decryption\": \"none\" },
      \"streamSettings\": { \"network\": \"ws\", \"wsSettings\": { \"path\": \"$path\" } },
      \"tag\": \"in-$tag\"
    }"
            
            # Outbound entry
            transit_outbounds="$transit_outbounds,
    {
      \"protocol\": \"shadowsocks\",
      \"tag\": \"out-$tag\",
      \"settings\": {
        \"servers\": [{ \"address\": \"$ss_server\", \"port\": $ss_port, \"method\": \"$ss_method\", \"password\": \"$ss_pass\" }]
      }
    }"
            
            # Routing rule
            routing_rules="$routing_rules, { \"type\": \"field\", \"inboundTag\": [\"in-$tag\"], \"outboundTag\": \"out-$tag\" }"
        done
    fi
    
    # ==============================================================================
    # 路由规则生成逻辑 (v5.1 重构)
    # 
    # 【设计目标】
    # - 直连模式 (in-direct)：Google 直连，CN 域名/IP 屏蔽
    # - 中转模式 (in-transit-*)：所有流量走落地 SS，CN 域名/IP 屏蔽（不送往落地）
    # 
    # 【规则执行顺序】(Xray 按顺序匹配，首条命中即停止)
    # 1. CN 屏蔽规则（全局生效，无论直连还是中转）
    # 2. 直连入站的 Google 流量 → direct（仅对 in-direct 生效）
    # 3. 直连入站的其他流量 → direct
    # 4. 中转入站的流量 → 对应 SS outbound
    # ==============================================================================
    
    local block_cn_rules=""
    local google_direct_rule=""
    
    if [ "$block_cn" == "true" ]; then
        # Block CN 规则 (全局生效，优先级最高)
        block_cn_rules="{ \"type\": \"field\", \"outboundTag\": \"block\", \"domain\": [\"geosite:cn\"] },
      { \"type\": \"field\", \"outboundTag\": \"block\", \"ip\": [\"geoip:cn\"] },"
        
        # Google 直连规则 (仅对直连入站生效，避免 geosite:cn 误杀 google-cn 子域)
        google_direct_rule="{ \"type\": \"field\", \"inboundTag\": [\"in-direct\"], \"outboundTag\": \"direct\", \"domain\": [\"geosite:google\", \"geosite:google-cn\"] },"
    fi
    
    mkdir -p /usr/local/etc/xray
    cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "error" },
  "inbounds": [
    {
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [{ "id": "$uuid" }],
        "decryption": "none",
        "fallbacks": [ $fallback_entries, { "dest": 8001 } ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1"],
          "certificates": [{ "certificateFile": "/usr/local/etc/xray/certs/fullchain.pem", "keyFile": "/usr/local/etc/xray/certs/private.key" }]
        }
      }
    },
    {
      "port": 10001,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": { "clients": [{"id": "$uuid"}], "decryption": "none" },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "$ws_direct" } },
      "tag": "in-direct"
    }
    $transit_inbounds
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
    $transit_outbounds
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      $google_direct_rule
      $block_cn_rules
      { "type": "field", "inboundTag": ["in-direct"], "outboundTag": "direct" }
      $routing_rules
    ]
  }
}
EOF
}



func_safe_restart_services() {
    echo -e "${BLUE}[INFO]${NC} 正在验证 Xray 配置文件..."
    if ! xray -test -config /usr/local/etc/xray/config.json; then
        echo -e "${RED}[ERROR]${NC} 配置文件验证失败！服务未重启。"
        echo -e "${YELLOW}请检查配置参数或查看上方错误信息。${NC}"
        read -n 1 -s -p "按任意键继续..."
        return 1
    fi
    
    echo -e "${GREEN}[PASS]${NC} 配置验证通过。"
    
    # 修正权限 (安全优化: 运行用户为 nobody)
    # 确保证书和配置对 nobody 可读
    chown -R nobody:nogroup /usr/local/etc/xray
    chmod 755 /usr/local/etc/xray
    chmod 644 /usr/local/etc/xray/config.json
    
    # 假如存在 service 文件，确保 User 是 nobody (官方默认 usually is nobody, but we check)
    local service_file="/etc/systemd/system/xray.service"
    # 如果是 apt 安装或者官方脚本，通常在 /etc/systemd/system/xray.service 或 /lib/systemd/system/xray.service
    # 我们只尝试修改 /etc 下的覆盖文件
    if [ -f "$service_file" ]; then
        # 如果之前被改为 root，改回 nobody
        if grep -q "User=root" "$service_file"; then
             sed -i 's/^User=root/User=nobody/' "$service_file"
             systemctl daemon-reload
        fi
    fi
    
    echo -e "${BLUE}[INFO]${NC} 正在重启服务..."
    systemctl enable xray caddy >/dev/null 2>&1
    systemctl restart xray caddy
    
    if systemctl is-active --quiet xray; then
        echo -e "${GREEN}[OK]${NC} 服务启动成功。"
    else
        echo -e "${RED}[ERROR]${NC} 服务启动失败，请查看日志 (Option 6 -> 7)。"
    fi
}

func_apply_changes() {
    func_generate_caddy_config
    func_generate_website
    func_generate_xray_config
    func_safe_restart_services
}

# ====================================================
# 3. 基础配置 Wizard (Option 2)
# ====================================================

func_apply_cert() {
    local domain=$1
    
    # 检查证书是否已存在且有效
    if [ -f /usr/local/etc/xray/certs/fullchain.pem ] && [ -f /usr/local/etc/xray/certs/private.key ]; then
        echo -e "${GREEN}[INFO]${NC} 检测到已有证书"
        
        # 检查证书有效期
        local expiry_date
        expiry_date=$(openssl x509 -enddate -noout -in /usr/local/etc/xray/certs/fullchain.pem 2>/dev/null | cut -d= -f2)
        
        if [ -n "$expiry_date" ]; then
            local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry_date" +%s 2>/dev/null)
            local now_epoch=$(date +%s)
            local days_left=$(( ($expiry_epoch - $now_epoch) / 86400 ))
            
            if [ $days_left -gt 30 ]; then
                echo -e "${GREEN}证书有效期剩余: ${days_left} 天${NC}"
                read -p "是否复用现有证书? [Y/n]: " reuse_cert
                if [[ "$reuse_cert" != "n" && "$reuse_cert" != "N" ]]; then
                    echo -e "${GREEN}[OK]${NC} 复用现有证书"
                    return 0
                fi
            else
                echo -e "${YELLOW}证书即将过期 (剩余 ${days_left} 天)，建议重新申请${NC}"
            fi
        fi
    fi
    
    # 选择 CA 服务商
    echo -e "\n${CYAN}选择证书颁发机构 (CA):${NC}"
    echo "1. Let's Encrypt (推荐，速度快)"
    echo "2. ZeroSSL (备选)"
    read -p "请选择 [1-2, 默认1]: " ca_choice
    
    local ca_server=""
    case "$ca_choice" in
        2)
            ca_server="--server zerossl"
            echo -e "${BLUE}[INFO]${NC} 使用 ZeroSSL"
            ;;
        *)
            ca_server="--server letsencrypt"
            echo -e "${BLUE}[INFO]${NC} 使用 Let's Encrypt"
            ;;
    esac
    
    echo -e "${BLUE}[INFO]${NC} 正在通过 acme.sh 申请证书..."
    
    # 安装 acme.sh (如果未安装)
    if [ ! -f ~/.acme.sh/acme.sh ]; then 
        curl https://get.acme.sh | sh -s email=admin@${domain}
        # 重新加载环境
        source ~/.bashrc 2>/dev/null || source ~/.profile 2>/dev/null || true
    fi
    
    # 检查端口 80
    local port80_pid
    port80_pid=$(lsof -t -i:80 2>/dev/null)
    if [ -n "$port80_pid" ]; then
        local p_name=$(ps -p $port80_pid -o comm= 2>/dev/null)
        if [[ "$p_name" == "caddy" ]]; then
             systemctl stop caddy >/dev/null 2>&1
        else
             echo -e "${RED}[WARN] 端口 80 被进程 $p_name (PID: $port80_pid) 占用！${NC}"
             echo -e "acme.sh standalone 模式需要 80 端口。"
             read -p "是否尝试停止该进程? [y/N]: " stop_p
             if [[ "$stop_p" == "y" ]]; then
                 kill -9 $port80_pid 2>/dev/null || true
             else
                 echo -e "${RED}[ERROR] 端口 80 被占用，无法申请证书。${NC}"
                 return 1
             fi
        fi
    fi
    
    # 创建证书目录
    mkdir -p /usr/local/etc/xray/certs
    
    # 申请证书 (添加超时和重试机制)
    echo -e "${BLUE}[INFO]${NC} 开始申请证书 (最多等待 120 秒)..."
    
    # 使用 timeout 命令限制执行时间
    if timeout 120 ~/.acme.sh/acme.sh --issue -d "$domain" --standalone $ca_server --force; then
        echo -e "${GREEN}[OK]${NC} 证书申请成功"
    else
        local exit_code=$?
        echo -e "${RED}[ERROR] 证书申请失败 (退出码: $exit_code)${NC}"
        
        if [ $exit_code -eq 124 ]; then
            echo -e "${YELLOW}原因: 申请超时 (超过120秒)${NC}"
        fi
        
        echo -e "${YELLOW}请检查:${NC}"
        echo -e "  1. 域名 $domain 是否正确解析到本机 IP"
        echo -e "  2. 防火墙是否放行 80 端口"
        echo -e "  3. 网络连接是否正常"
        
        # 恢复 Caddy
        systemctl start caddy >/dev/null 2>&1
        return 1
    fi

    # 安装证书
    ~/.acme.sh/acme.sh --install-cert -d "$domain" \
        --fullchain-file /usr/local/etc/xray/certs/fullchain.pem \
        --key-file /usr/local/etc/xray/certs/private.key \
        --reloadcmd "systemctl restart xray"
        
    # 设置权限
    chmod 644 /usr/local/etc/xray/certs/fullchain.pem
    chmod 644 /usr/local/etc/xray/certs/private.key
    chown -R nobody:nogroup /usr/local/etc/xray/certs
    
    echo -e "${GREEN}[OK]${NC} 证书配置完成"
    echo -e "${YELLOW}[提示] Caddy 将在配置完成后自动启动${NC}"
}

func_configure_base() {
    echo -e "${CYAN}=== 配置基础直连服务 ===${NC}"
    
    # 读取现有配置（如果存在）
    local existing_domain=""
    local existing_uuid=""
    local existing_path=""
    local existing_block_cn="false"
    
    if [ -f "$USER_CONFIG" ]; then
        echo -e "${YELLOW}[WARN] 检测到已有配置文件！${NC}"
        
        # 读取现有配置
        existing_domain=$(jq -r '.domain' "$USER_CONFIG" 2>/dev/null)
        existing_uuid=$(jq -r '.uuid' "$USER_CONFIG" 2>/dev/null)
        existing_path=$(jq -r '.ws_direct_path' "$USER_CONFIG" 2>/dev/null)
        existing_block_cn=$(jq -r '.block_cn_traffic' "$USER_CONFIG" 2>/dev/null)
        
        echo -e "当前配置:"
        echo -e "  域名: ${GREEN}${existing_domain}${NC}"
        echo -e "  UUID: ${GREEN}${existing_uuid}${NC}"
        echo -e "  WS路径: ${GREEN}${existing_path}${NC}"
        echo -e "  屏蔽回国: ${GREEN}$([ "$existing_block_cn" == "true" ] && echo "是" || echo "否")${NC}"
        echo ""
        echo -e "若继续配置将覆盖现有设置 (中转节点列表会尝试保留)"
        echo "y: 继续配置 (可使用现有值作为默认)"
        echo "n: 返回主菜单"
        read -p "请选择 [y/n]: " choice
        if [[ "$choice" != "y" ]]; then return; fi
    fi
    
    # 域名配置
    while true; do
        if [ -n "$existing_domain" ]; then
            read -p "请输入解析域名 (当前: $existing_domain, 留空保持不变): " domain
            [ -z "$domain" ] && domain="$existing_domain"
        else
            read -p "请输入解析域名: " domain
        fi
        
        if func_is_valid_domain "$domain"; then 
            break
        else 
            echo -e "${RED}格式错误，请重新输入${NC}"
        fi
    done
    
    # UUID配置
    local auto_uuid=$(generate_uuid)
    if [ -n "$existing_uuid" ]; then
        read -p "UUID (当前: $existing_uuid, 留空保持不变): " uuid
        [ -z "$uuid" ] && uuid="$existing_uuid"
    else
        read -p "UUID (默认 $auto_uuid): " uuid
        [ -z "$uuid" ] && uuid="$auto_uuid"
    fi
    
    # 路径配置
    if [ -n "$existing_path" ]; then
        read -p "直连 WS 路径 (当前: $existing_path, 留空保持不变): " ws_path
        [ -z "$ws_path" ] && ws_path="$existing_path"
    else
        read -p "直连 WS 路径 (默认 /wwd): " ws_path
        [ -z "$ws_path" ] && ws_path="/wwd"
    fi
    [[ ! "$ws_path" =~ ^/ ]] && ws_path="/$ws_path"
    
    # Block CN配置
    if [ -n "$existing_block_cn" ]; then
        local current_cn_status=$([ "$existing_block_cn" == "true" ] && echo "是" || echo "否")
        local default_prompt=$([ "$existing_block_cn" == "true" ] && echo "[Y/n]" || echo "[y/N]")
        read -p "是否屏蔽回国流量 (当前: $current_cn_status, 留空保持不变)? $default_prompt: " block_cn_input
        
        # 根据现有配置设置默认值
        if [ "$existing_block_cn" == "true" ]; then
            local block_cn="true"
            [[ "$block_cn_input" == "n" || "$block_cn_input" == "N" ]] && block_cn="false"
        else
            local block_cn="false"
            [[ "$block_cn_input" == "y" || "$block_cn_input" == "Y" ]] && block_cn="true"
        fi
    else
        read -p "是否屏蔽回国流量 (Block CN)? [Y/n]: " block_cn_input
        local block_cn="true"
        [[ "$block_cn_input" == "n" || "$block_cn_input" == "N" ]] && block_cn="false"
    fi
    
    # 申请证书
    func_apply_cert "$domain"
    
    # 保存配置（保留中转节点）
    local transits="[]"
    if [ -f "$USER_CONFIG" ]; then
        transits=$(jq -r '.transit_nodes // []' "$USER_CONFIG")
    fi
    
    cat > "$USER_CONFIG" <<EOF
{
  "domain": "$domain",
  "uuid": "$uuid",
  "ws_direct_path": "$ws_path",
  "block_cn_traffic": $block_cn,
  "transit_nodes": $transits,
  "updated_at": "$(date)"
}
EOF
    func_apply_changes
    echo -e "\n${BLUE}请按任意键继续...${NC}"
    read -n 1 -s
}

# ====================================================
# 4. 中转管理 (Option 3)
# ====================================================

func_manage_transits() {
    while true; do
        clear
        echo -e "${CYAN}=== 中转落地节点管理 ===${NC}"
        
        if [ ! -f "$USER_CONFIG" ]; then
            echo -e "${RED}[ERROR]${NC} 请先完成基础配置 (Option 2)"
            read -n 1 -s; return
        fi
        
        # List Nodes
        echo -e "${BLUE}当前节点列表:${NC}"
        local count=$(jq '.transit_nodes | length' "$USER_CONFIG")
        if [ "$count" -eq 0 ]; then
            echo "  (无中转节点)"
        else
            printf "%-5s %-15s %-20s %-10s %-15s\n" "ID" "LocalPath" "Target IP" "L-Port" "Method"
            echo "------------------------------------------------------------------------"
            for ((i=0; i<count; i++)); do
                local p=$(jq -r ".transit_nodes[$i].path" "$USER_CONFIG")
                local pt=$(jq -r ".transit_nodes[$i].port" "$USER_CONFIG")
                local sip=$(jq -r ".transit_nodes[$i].ss.server" "$USER_CONFIG")
                local m=$(jq -r ".transit_nodes[$i].ss.method" "$USER_CONFIG")
                printf "%-5s %-15s %-20s %-10s %-15s\n" "$i" "$p" "$sip" "$pt" "$m"
            done
        fi
        echo "------------------------------------------------------------------------"
        echo "1. 添加节点 (Add)"
        echo "2. 删除节点 (Delete)"
        echo "0. 返回主菜单"
        echo "------------------------------------------------------------------------"
        read -p "选择: " choice
        
        case "$choice" in
            1)
                echo -e "\n${BLUE}[添加节点向导]${NC}"
                read -p "1. 设置 WS 路径 (默认 /transit$count): " new_path
                [ -z "$new_path" ] && new_path="/transit$count"
                [[ ! "$new_path" =~ ^/ ]] && new_path="/$new_path"
                
                # Check collision with direct
                local dir_path=$(jq -r '.ws_direct_path' "$USER_CONFIG")
                if [ "$new_path" == "$dir_path" ]; then echo -e "${RED}路径与直连冲突${NC}"; sleep 1; continue; fi
                
                # SS Config
                local ss_ip ss_port ss_method ss_pass
                echo -e "\n2. 配置落地机 SS 信息:"
                echo "   1) 手动输入参数 (默认)"
                echo "   2) 使用 SS 链接粘贴"
                read -p "   选择 [1-2]: " ss_mode
                
                # 设置默认值
                [ -z "$ss_mode" ] && ss_mode="1"
                
                if [ "$ss_mode" == "2" ]; then
                    read -p "   粘贴 SS 链接: " link
                    local res
                    if ! res=$(parse_ss_link "$link"); then
                        echo -e "${RED}[ERROR] 链接解析失败,请检查格式。${NC}"
                        echo -e "是否切换到手动输入模式? [y/N]"
                        read -r switch_manual
                        if [[ "$switch_manual" == "y" || "$switch_manual" == "Y" ]]; then
                             ss_mode="1"
                             # Fall through to manual mode logic below (we need to restructure slightly)
                        else
                             continue
                        fi
                    else
                        IFS='|' read -r ss_ip ss_port ss_method ss_pass <<< "$res"
                    fi
                fi
                
                # Manual Input Block (Execute if mode 1 OR fallback from mode 2)
                if [ "$ss_mode" == "1" ]; then
                    while true; do
                        read -p "   目标 IP: " ss_ip
                        if func_is_valid_ip "$ss_ip"; then break; else echo -e "${RED}IP 格式错误${NC}"; fi
                    done
                    
                    read -p "   目标 Port (默认 10086): " ss_port
                    [ -z "$ss_port" ] && ss_port=10086
                    
                    echo -e "\n   加密协议选择:"
                    echo "   1) aes-256-gcm"
                    echo "   2) aes-128-gcm"
                    echo "   3) chacha20-ietf-poly1305"
                    echo "   4) 2022-blake3-aes-128-gcm (默认)"
                    echo "   5) 2022-blake3-aes-256-gcm"
                    read -p "   选择 [1-5, 默认4]: " m_choice
                    case "$m_choice" in
                        1) ss_method="aes-256-gcm" ;;
                        2) ss_method="aes-128-gcm" ;;
                        3) ss_method="chacha20-ietf-poly1305" ;;
                        5) ss_method="2022-blake3-aes-256-gcm" ;;
                        *) ss_method="2022-blake3-aes-128-gcm" ;;
                    esac
                    
                    read -p "   密码 (留空随机生成): " ss_pass
                    if [ -z "$ss_pass" ]; then
                        ss_pass=$(openssl rand -base64 16)
                        echo -e "   ${GREEN}已生成密码: $ss_pass${NC}"
                    fi
                fi
                
                # Auto Assign Port (Start 20000, check used)
                local new_port=20000
                while true; do
                    if jq -e ".transit_nodes[] | select(.port == $new_port)" "$USER_CONFIG" >/dev/null; then
                        new_port=$((new_port+1))
                    else
                        break
                    fi
                done
                
                # Append to JSON
                local new_node_json=$(jq -n --arg p "$new_path" --argjson pt "$new_port" \
                    --arg si "$ss_ip" --argjson sp "$ss_port" --arg sm "$ss_method" --arg spa "$ss_pass" \
                    '{path:$p, port:$pt, ss:{server:$si, port:$sp, method:$sm, password:$spa}}')
                
                local tmp=$(mktemp)
                jq ".transit_nodes += [$new_node_json]" "$USER_CONFIG" > "$tmp" && mv "$tmp" "$USER_CONFIG"
                
                echo -e "${GREEN}[OK] 添加成功 (本地端口: $new_port)${NC}"
                func_apply_changes
                sleep 1
                ;;
            2)
                read -p "请输入要删除的 ID: " del_id
                if [[ "$del_id" =~ ^[0-9]+$ ]] && [ "$del_id" -lt "$count" ]; then
                     local tmp=$(mktemp)
                     jq "del(.transit_nodes[$del_id])" "$USER_CONFIG" > "$tmp" && mv "$tmp" "$USER_CONFIG"
                     echo -e "${GREEN}[OK] 节点已删除${NC}"
                     func_apply_changes
                else
                    echo -e "${RED}无效 ID${NC}"
                    sleep 1
                fi
                ;;
            0) break ;;
        esac
    done
}

# ====================================================
# 5. 状态与链接 (Option 4)
# ====================================================

func_show_links() {
    if [ ! -f "$USER_CONFIG" ]; then echo "No Config"; return; fi
    
    local domain=$(jq -r '.domain' "$USER_CONFIG")
    local uuid=$(jq -r '.uuid' "$USER_CONFIG")
    local direct_path=$(jq -r '.ws_direct_path' "$USER_CONFIG")
    
    echo -e "${CYAN}=== 客户端配置信息 ===${NC}"
    echo -e "地址 (Address): ${GREEN}${domain}${NC}"
    echo -e "端口 (Port): ${GREEN}443${NC}"
    echo -e "用户 ID (UUID): ${GREEN}${uuid}${NC}"
    echo -e "传输协议 (Network): ${GREEN}ws${NC}"
    echo -e "伪装类型 (Type): ${GREEN}none${NC}"
    echo -e "传输安全 (TLS): ${GREEN}tls${NC}"
    echo -e "跳过证书验证 (AllowInsecure): ${GREEN}false${NC}"
    echo "------------------------------------------------------"
    
    echo -e "${CYAN}=== 节点详情与链接 ===${NC}"
    
    # Direct Node
    echo -e "${GREEN}[节点 1: 直连节点]${NC}"
    echo -e "路径 (Path): ${YELLOW}${direct_path}${NC}"
    echo "链接:"
    echo "vless://${uuid}@${domain}:443?encryption=none&security=tls&type=ws&host=${domain}&path=${direct_path}&sni=${domain}#${domain}-Direct"
    echo "------------------------------------------------------"
    
    # Transit Nodes
    local count=$(jq '.transit_nodes | length' "$USER_CONFIG")
    if [ "$count" -gt 0 ]; then
        for ((i=0; i<count; i++)); do
            local path=$(jq -r ".transit_nodes[$i].path" "$USER_CONFIG")
            local port=$(jq -r ".transit_nodes[$i].ss.port" "$USER_CONFIG")
            # Extract SS details
            local ss_server=$(jq -r ".transit_nodes[$i].ss.server" "$USER_CONFIG")
            local ss_port=$(jq -r ".transit_nodes[$i].ss.port" "$USER_CONFIG")
            local ss_method=$(jq -r ".transit_nodes[$i].ss.method" "$USER_CONFIG")
            local ss_pass=$(jq -r ".transit_nodes[$i].ss.password" "$USER_CONFIG")
            
            local node_idx=$((i+2))
            
            echo -e "${YELLOW}[节点 ${node_idx}: 中转节点 (落地端口: $port)]${NC}"
            echo -e "本机路径 (Path): ${YELLOW}${path}${NC}"
            echo -e "落地 IP (Target IP): ${CYAN}${ss_server}${NC}"
            echo -e "落地端口 (Target Port): ${CYAN}${ss_port}${NC}"
            echo -e "加密方式 (Method): ${CYAN}${ss_method}${NC}"
            echo -e "密码 (Password): ${CYAN}${ss_pass}${NC}"
            echo "链接:"
            echo "vless://${uuid}@${domain}:443?encryption=none&security=tls&type=ws&host=${domain}&path=${path}&sni=${domain}#${domain}-Transit-${port}"
            echo "------------------------------------------------------"
        done
    fi
    echo ""
    read -n 1 -s -p "按任意键返回..."
}

# ====================================================
# 6. Service Management (Option 5)
# ====================================================

# 显示详细状态
func_show_service_status() {
    echo -e "${BLUE}[详细运行状态]${NC}"
    
    # Xray
    local x_pid=$(pgrep -x xray | head -n 1)
    if [ -n "$x_pid" ]; then
        local x_mem=$(ps -o rss= -p $x_pid | awk '{print int($1/1024)}')
        local x_time=$(ps -o etime= -p $x_pid)
        echo -e "  Xray: ${GREEN}Running${NC} (PID: $x_pid, Mem: ${x_mem}MB, Time: $x_time)"
    else
        echo -e "  Xray: ${RED}Stopped${NC}"
    fi

    # Caddy
    local c_pid=$(pgrep -x caddy | head -n 1)
    if [ -n "$c_pid" ]; then
        local c_mem=$(ps -o rss= -p $c_pid | awk '{print int($1/1024)}')
        local c_time=$(ps -o etime= -p $c_pid)
        echo -e "  Caddy: ${GREEN}Running${NC} (PID: $c_pid, Mem: ${c_mem}MB, Time: $c_time)"
    else
        echo -e "  Caddy: ${RED}Stopped${NC}"
    fi
    echo ""
}

func_service_mgr() {
    clear
    echo -e "${CYAN}=== 服务管理 & 状态监控 ===${NC}"
    func_show_service_status
    
    echo "1. 启动服务"
    echo "2. 停止服务"
    echo "3. 重启服务"
    echo "0. 返回"
    read -p "选择: " ch
    case "$ch" in
        1) systemctl start xray caddy; echo "已执行启动指令" ;;
        2) systemctl stop xray caddy; echo "已执行停止指令" ;;
        3) systemctl restart xray caddy; echo "已执行重启指令" ;;
        0) return ;;
    esac
    sleep 1
    # 刷新显示
    clear
    echo -e "${CYAN}=== 服务管理 & 状态监控 ===${NC}"
    func_show_service_status
    read -n 1 -s -p "按任意键继续..."
}

# ====================================================
# 7. 卸载管理 (Option 7)
# ====================================================

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
            rm -rf "$CONFIG_DIR" "$LOG_DIR" /usr/local/etc/xray/config.json /etc/caddy/Caddyfile
            systemctl restart xray caddy 2>/dev/null
            echo "配置已清除 (证书已保留)"
            ;;
        2)
            rm -rf /var/www/tech-blog
            echo "网站文件已清除"
            ;;
        3)
            systemctl stop xray caddy 2>/dev/null || true
            systemctl disable xray caddy 2>/dev/null || true
            
            # 删除 Xray 二进制
            rm -f /usr/local/bin/xray
            
            # 删除 Caddy 二进制（新版本）
            rm -f /usr/local/bin/caddy /usr/bin/caddy
            
            # 兼容旧版本：尝试通过 APT 卸载 Caddy（如果是APT安装的）
            if dpkg -l | grep -q "^ii.*caddy"; then
                apt-get remove --purge -y caddy 2>/dev/null || true
            fi
            
            echo "核心程序已清除 (证书已保留)"
            ;;
        4)
            # 询问是否保留证书
            echo ""
            echo -e "${YELLOW}是否保留 SSL 证书？${NC}"
            echo "证书位置: /usr/local/etc/xray/certs/"
            read -p "保留证书? [Y/n]: " keep_cert
            
            systemctl stop xray caddy 2>/dev/null || true
            systemctl disable xray caddy 2>/dev/null || true
            rm -f /etc/systemd/system/xray.service /etc/systemd/system/caddy.service
            systemctl daemon-reload
            
            # 删除配置和数据目录
            rm -rf "$BASE_DIR" /etc/caddy /var/www/tech-blog /usr/local/share/xray
            
            # 根据用户选择处理证书
            if [[ "$keep_cert" == "n" || "$keep_cert" == "N" ]]; then
                rm -rf /usr/local/etc/xray
                echo -e "${YELLOW}证书已删除${NC}"
            else
                # 只删除配置文件，保留证书
                rm -f /usr/local/etc/xray/config.json
                echo -e "${GREEN}证书已保留在 /usr/local/etc/xray/certs/${NC}"
            fi
            
            # 删除二进制文件（新版本）
            rm -f /usr/local/bin/xray /usr/local/bin/caddy /usr/bin/caddy
            
            # 兼容旧版本：清理 APT 安装的 Caddy
            if dpkg -l | grep -q "^ii.*caddy"; then
                apt-get remove --purge -y caddy 2>/dev/null || true
            fi
            
            # 清理 APT 仓库配置文件（旧版本遗留）
            rm -f /etc/apt/sources.list.d/caddy-stable.list 2>/dev/null || true
            rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null || true
            
            # 卸载 acme.sh
            if [ -d ~/.acme.sh ]; then ~/.acme.sh/acme.sh --uninstall 2>/dev/null || true; rm -rf ~/.acme.sh; fi
            
            # 注意：保留系统依赖 (jq, curl, wget, openssl 等)
            # 这些工具可能被其他程序使用，不建议删除
            
            echo "彻底卸载完成"
            if [[ "$keep_cert" != "n" && "$keep_cert" != "N" ]]; then
                echo -e "${GREEN}提示: 证书已保留，下次安装可直接复用${NC}"
            fi
            ;;
    esac
    sleep 2
}

# ====================================================
# Main Menu
# ====================================================


main() {
    chmod +x "$0"
    check_root  # Global root check

    while true; do
        mkdir -p "$BASE_DIR" "$CONFIG_DIR" "$LOG_DIR" # Ensure dirs exist (in case deleted by uninstall)
        clear
        echo -e "${CYAN}======================================================${NC}"
        echo -e "${CYAN}         Xray VLESS 一键部署脚本 v5.0 (Modular)      ${NC}"
        echo -e "${CYAN}======================================================${NC}"
        echo "  1. 初始化/更新运行环境"
        echo "  2. 配置基础直连服务 (+Block CN)"
        echo "  3. 管理中转落地节点"
        echo "  4. 查看配置链接与状态"
        echo "  5. 服务管理 (详细状态)"
        echo "  6. 卸载管理"
        echo "  0. 退出脚本"
        echo -e "${CYAN}======================================================${NC}"
        read -p "请选择: " choice
        
        case "$choice" in
            1) func_install_core ;;
            2) check_dependencies_ready && func_configure_base ;;
            3) check_dependencies_ready && func_manage_transits ;;
            4) check_dependencies_ready && func_show_links ;;
            5) check_dependencies_ready && func_service_mgr ;;
            6) func_uninstall_menu ;;
            0) exit 0 ;;
            *) echo "无效选择" ;;
        esac
    done
}

main
