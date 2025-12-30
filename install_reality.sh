#!/bin/bash

# 1. 环境准备
apt update && apt install -y curl nginx uuid-runtime openssl

# 2. 获取用户输入
read -p "请输入你的域名 (例如 myweb.com): " MY_DOMAIN
V_UUID=$(uuidgen)
KEYS=$(/usr/local/bin/xray x25519) # 假设已安装xray，若无则先装
# 简易安装 Xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# 3. 生成密钥
PRIV_KEY=$(xray x25519 | grep "Private key" | awk '{print $3}')
PUB_KEY=$(xray x25519 -i "$PRIV_KEY" | grep "Public key" | awk '{print $3}')
SHORT_ID=$(openssl rand -hex 8)

# 4. 配置伪装网页
rm -rf /var/www/html/*
curl -L https://github.com/cloud-annotations/docusaurus-template/archive/refs/heads/main.tar.gz | tar -xz -C /var/www/html --strip-components=1
systemctl restart nginx

# 5. 配置 Xray
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
                "dest": "127.0.0.1:80",
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

# 6. 启动服务
systemctl restart xray
systemctl enable xray

# 7. 输出配置信息
echo "--------------------------------"
echo "Reality 部署完成！"
echo "域名: $MY_DOMAIN"
echo "UUID: $V_UUID"
echo "公钥 (PublicKey): $PUB_KEY"
echo "Short ID: $SHORT_ID"
echo "端口: 443"
echo "SNI: $MY_DOMAIN"
echo "流控: xtls-rprx-vision"
echo "--------------------------------"
