#!/bin/bash

# ====================================================
# Xray VLESS 一键部署脚本 v3.0 (Modular Edition)
# Author: Antigravity
# Description: Modular VLESS setup with Multi-Path Transit Support
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

# 解析 SS 链接
parse_ss_link() {
    local ss_link=$1
    ss_link=$(echo "$ss_link" | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\r\n' | tr -d '[:cntrl:]')
    ss_link=${ss_link#ss://}
    local main_part=${ss_link%%#*}
    
    if [[ ! "$main_part" =~ @ ]]; then
        echo "[ERROR] SS 链接格式错误：缺少 @" >&2
        return 1
    fi
    
    local auth_part=${main_part%%@*}
    local server_part=${main_part##*@}
    
    if [[ ! "$server_part" =~ : ]]; then
        echo "[ERROR] SS 链接格式错误：服务器地址格式无效" >&2
        return 1
    fi
    
    local server=${server_part%:*}
    local port=${server_part##*:}
    local decoded=$(echo "$auth_part" | base64 -d 2>/dev/null)
    
    if [ -z "$decoded" ] || [[ ! "$decoded" =~ : ]]; then
        echo "[ERROR] Base64 解码失败/格式无效" >&2
        return 1
    fi
    
    local method=${decoded%%:*}
    local password=${decoded##*:}
    
    echo "$server|$port|$method|$password"
    return 0
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
    
    # 安装 Caddy
    if ! command -v caddy >/dev/null; then
        echo -e "${BLUE}[INFO]${NC} 正在安装 Caddy..."
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
        apt-get update && apt-get install -y caddy
    else
         echo -e "${GREEN}[INFO]${NC} Caddy 已安装"
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
    
    # 生成 Block CN 规则
    local block_rules=""
    if [ "$block_cn" == "true" ]; then
        block_rules="{ \"type\": \"field\", \"outboundTag\": \"direct\", \"domain\": [\"geosite:google\", \"geosite:google-cn\"] }, { \"type\": \"field\", \"outboundTag\": \"block\", \"domain\": [\"geosite:cn\"] }, { \"type\": \"field\", \"outboundTag\": \"block\", \"ip\": [\"geoip:cn\"] },"
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
      $block_rules
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
    if [ -f /usr/local/etc/xray/certs/fullchain.pem ]; then
        echo -e "${GREEN}[INFO]${NC} 证书已存在，跳过申请"
        return
    fi
    
    echo -e "${BLUE}[INFO]${NC} 正在通过 acme.sh 申请证书..."
    if [ ! -f ~/.acme.sh/acme.sh ]; then curl https://get.acme.sh | sh -s email=admin@${domain}; fi
    
    # Port 80 Check
    local port80_pid
    port80_pid=$(lsof -t -i:80)
    if [ -n "$port80_pid" ]; then
        local p_name=$(ps -p $port80_pid -o comm=)
        if [[ "$p_name" == "caddy" ]]; then
             systemctl stop caddy >/dev/null 2>&1
        else
             echo -e "${RED}[WARN] 端口 80 被进程 $p_name (PID: $port80_pid) 占用！${NC}"
             echo -e "acme.sh standalone 模式需要 80 端口。"
             read -p "是否尝试停止该进程? [y/N]: " stop_p
             if [[ "$stop_p" == "y" ]]; then
                 kill -9 $port80_pid
             else
                 echo -e "${RED}[ERROR] 端口 80 被占用，无法申请证书。${NC}"
                 return 1
             fi
        fi
    else
        # No process on 80, but just in case check firewall? 
        # (Assuming user has UFW configured correctly or open)
        :
    fi
    
    mkdir -p /usr/local/etc/xray/certs
    ~/.acme.sh/acme.sh --issue -d "$domain" --standalone --force
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR] 证书申请失败！${NC}"
        echo -e "请检查: 1.用于申请的域名 $domain 是否解析到本机 IP"
        echo -e "         2.防火墙是否放行 80 端口"
        systemctl start caddy >/dev/null 2>&1
        return 1
    fi

    ~/.acme.sh/acme.sh --install-cert -d "$domain" \
        --fullchain-file /usr/local/etc/xray/certs/fullchain.pem \
        --key-file /usr/local/etc/xray/certs/private.key \
        --reloadcmd "systemctl restart xray"
        
    # Grant read permission to nobody (for Xray)
    chmod 644 /usr/local/etc/xray/certs/fullchain.pem
    chmod 644 /usr/local/etc/xray/certs/private.key
    # 确保目录也是可读的
    chown -R nobody:nogroup /usr/local/etc/xray/certs
}

func_configure_base() {
    echo -e "${CYAN}=== 配置基础直连服务 ===${NC}"
    
    if [ -f "$USER_CONFIG" ]; then
        echo -e "${YELLOW}[WARN] 检测到已有配置文件！${NC}"
        echo -e "当前域名: ${GREEN}$(jq -r '.domain' "$USER_CONFIG")${NC}"
        echo -e "若继续配置将覆盖现有设置 (中转节点列表会尝试保留)。"
        echo "y: 继续配置"
        echo "n: 返回主菜单"
        read -p "请选择 [y/n]: " choice
        if [[ "$choice" != "y" ]]; then return; fi
    fi
    
    # 域名
    while true; do
        read -p "请输入解析域名: " domain
        if func_is_valid_domain "$domain"; then break; else echo -e "${RED}格式错误${NC}"; fi
    done
    
    # UUID
    local auto_uuid=$(generate_uuid)
    read -p "UUID (默认 $auto_uuid): " uuid
    [ -z "$uuid" ] && uuid="$auto_uuid"
    
    # 路径
    read -p "直连 WS 路径 (默认 /direct): " ws_path
    [ -z "$ws_path" ] && ws_path="/direct"
    [[ ! "$ws_path" =~ ^/ ]] && ws_path="/$ws_path"
    
    # Block CN
    read -p "是否屏蔽回国流量 (Block CN)? [y/n]: " block_cn_input
    local block_cn="false"
    [[ "$block_cn_input" == "y" ]] && block_cn="true"
    
    # 申请证书
    func_apply_cert "$domain"
    
    # 初始化/保存 Config
    # 如果已存在，保留 transit_nodes
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
                
                if [ "$ss_mode" == "2" ]; then
                    read -p "   粘贴 SS 链接: " link
                    local res
                    if ! res=$(parse_ss_link "$link"); then
                        echo -e "${RED}[ERROR] 链接解析失败，请检查格式。${NC}"
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
                    echo "   1) aes-256-gcm (默认)"
                    echo "   2) aes-128-gcm"
                    echo "   3) chacha20-ietf-poly1305"
                    echo "   4) 2022-blake3-aes-128-gcm"
                    echo "   5) 2022-blake3-aes-256-gcm"
                    read -p "   选择 [1-5]: " m_choice
                    case "$m_choice" in
                        2) ss_method="aes-128-gcm" ;;
                        3) ss_method="chacha20-ietf-poly1305" ;;
                        4) ss_method="2022-blake3-aes-128-gcm" ;;
                        5) ss_method="2022-blake3-aes-256-gcm" ;;
                        *) ss_method="aes-256-gcm" ;;
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
    echo "1. 仅删除配置与日志 (保留核心程序)"
    echo "2. 仅删除伪装网站文件"
    echo "3. 仅删除核心程序 (Xray/Caddy Binaries)"
    echo "4. 彻底卸载所有 (全部清除)"
    echo "0. 返回"
    read -p "警告：操作不可逆。请选择: " ch
    
    case "$ch" in
        1)
            rm -rf "$CONFIG_DIR" "$LOG_DIR" /usr/local/etc/xray /etc/caddy
            systemctl restart xray caddy 2>/dev/null
            echo "配置已清除"
            ;;
        2)
            rm -rf /var/www/tech-blog
            echo "网站文件已清除"
            ;;
        3)
            systemctl stop xray caddy
            rm -f /usr/local/bin/xray /usr/bin/caddy /usr/local/bin/caddy
            apt-get remove -y caddy
            echo "核心程序已清除"
            ;;
        4)
            systemctl stop xray caddy
            systemctl disable xray caddy
            rm -f /etc/systemd/system/xray.service /etc/systemd/system/caddy.service
            systemctl daemon-reload
            
            rm -rf "$BASE_DIR" /usr/local/etc/xray /etc/caddy /var/www/tech-blog /usr/local/share/xray
            rm -f /usr/local/bin/xray /usr/bin/caddy
            apt-get purge -y caddy
            if [ -d ~/.acme.sh ]; then ~/.acme.sh/acme.sh --uninstall; rm -rf ~/.acme.sh; fi
            echo "彻底卸载完成"
            ;;
    esac
    sleep 1
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
        echo -e "${CYAN}         Xray VLESS 一键部署脚本 v3.0 (Modular)      ${NC}"
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
