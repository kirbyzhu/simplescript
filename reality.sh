#!/bin/bash

# 检查是否为root用户
[[ $EUID -ne 0 ]] && echo "请以root用户运行此脚本" && exit 1

# 颜色定义
green='\033[0;32m'
plain='\033[0m'
red='\033[0;31m'

show_menu() {
    echo -e "${green}Reality + Caddy 一键管理脚本${plain}"
    echo "1) 安装 Reality 环境"
    echo "2) 查看客户端配置"
    echo "3) 一键卸载 Reality"
    echo "0) 退出脚本"
    read -p "请输入数字选择: " num
}

install_reality() {
    # 1. 环境准备
    apt update && apt install -y curl debian-keyring debian-archive-keyring apt-transport-https uuid-runtime openssl tar || { echo "${red}环境准备失败${plain}"; exit 1; }

    # 2. 安装 Caddy
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt update && apt install caddy -y

    # 3. 安装 Xray-core
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

    # 4. 获取用户输入
    read -p "请输入你的解析域名 (例如 myweb.com): " MY_DOMAIN
    read -p "请输入你的邮箱 (用于 Let's Encrypt): " MY_EMAIL
    
    V_UUID=$(uuidgen)
    PRIV_KEY=$(xray x25519 | grep "Private key" | awk '{print $3}')
    PUB_KEY=$(xray x25519 -i "$PRIV_KEY" | grep "Public key" | awk '{print $3}')
    SHORT_ID=$(openssl rand -hex 8)

    # 5. 配置 Caddy 伪装网站
    mkdir -p /var/www/html
    curl -L https://github.com/cloud-annotations/docusaurus-template/archive/refs/heads/main.tar.gz | tar -xz -C /var/www/html --strip-components=1

    cat <<EOF > /etc/caddy/Caddyfile
{
    email $MY_EMAIL
}

$MY_DOMAIN {
    # 强制使用 Let's Encrypt
    tls {
        issuer acme {
            dir "https://acme-v02.api.letsencrypt.org/directory"
        }
    }
    reverse_proxy 127.0.0.1:8080
}

http://$MY_DOMAIN:8080 {
    root * /var/www/html
    file_server
}
EOF
    systemctl restart caddy

    # 6. 配置 Xray
    cat <<EOF > /usr/local/etc/xray/config.json
{
    "inbounds": [{
        "port": 443,
        "protocol": "vless",
        "settings": {
            "clients": [{"id": "$V_UUID", "flow": "xtls-rprx-vision"}],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": false,
                "dest": "127.0.0.1:8080",
                "xver": 0,
                "serverNames": ["$MY_DOMAIN"],
                "privateKey": "$PRIV_KEY",
                "shortIds": ["$SHORT_ID"]
            }
        }
    }],
    "outbounds": [{"protocol": "freedom"}]
}
EOF

    # 7. 保存记录
    cat <<EOF > /etc/reality_info.conf
DOMAIN=$MY_DOMAIN
UUID=$V_UUID
PUBKEY=$PUB_KEY
SID=$SHORT_ID
EOF

    systemctl restart xray
    systemctl enable xray
    echo -e "${green}安装完成！${plain}"
    show_config
}

show_config() {
    if [[ ! -f /etc/reality_info.conf ]]; then
        echo -e "${red}未检测到安装记录。${plain}"
        return
    fi
    source /etc/reality_info.conf
    SERVER_IP=$(curl -s ipv4.icanhazip.com)

    echo -e "
${green}========== 客户端 JSON 配置 ==========${plain}
"
    cat <<EOF
{
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "$SERVER_IP",
        "port": 443,
        "users": [{ "id": "$UUID", "encryption": "none", "flow": "xtls-rprx-vision" }]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "publicKey": "$PUBKEY",
        "fingerprint": "chrome",
        "serverName": "$DOMAIN",
        "shortId": "$SID"
      }
    }
  }]
}
EOF
}

uninstall_reality() {
    read -p "确认卸载？(y/n): " confirm
    if [[ "$confirm" == "y" ]]; then
        systemctl stop xray caddy
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove
        apt purge -y caddy
        rm -rf /usr/local/etc/xray /etc/caddy /var/www/html /etc/reality_info.conf
        echo -e "${green}卸载成功。${plain}"
    fi
}

# 脚本入口逻辑
clear
show_menu
if [ "$num" == "1" ]; then
    install_reality
elif [ "$num" == "2" ]; then
    show_config
elif [ "$num" == "3" ]; then
    uninstall_reality
elif [ "$num" == "0" ]; then
    exit 0
else
    echo -e "${red}无效输入${plain}"
fi
