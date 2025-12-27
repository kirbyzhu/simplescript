#!/usr/bin/env bash
set -e

# 1. 检测并更新 apt 源
if ! command -v apt-get >/dev/null 2>&1; then
    echo "本脚本仅适用于基于 apt 的 Debian/Ubuntu 系统。"
    exit 1
fi

# 2. 安装 rinetd
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y rinetd

# 3. 如果自带 init 脚本或 systemd 服务，先尝试关闭以避免冲突
if systemctl list-unit-files | grep -q '^rinetd\.service'; then
    systemctl disable rinetd.service || true
    systemctl stop rinetd.service || true
fi

# 4. 创建 systemd 单元文件
cat >/etc/systemd/system/rinetd.service <<'EOF'
[Unit]
Description=Internet TCP redirection server (rinetd)
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/rinetd -f -c /etc/rinetd.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# 5. 重新加载 systemd 配置
systemctl daemon-reload

# 6. 设置开机自启并立即启动
systemctl enable rinetd.service
systemctl restart rinetd.service

echo "rinetd 已安装并设置为开机自启。"
systemctl status rinetd.service --no-pager
