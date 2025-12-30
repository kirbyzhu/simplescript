#!/bin/bash

# 定义颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PLAIN='\033[0m'

# 检查 root 权限
[[ $EUID -ne 0 ]] && echo -e "${RED}错误：请使用 root 权限运行此脚本！${PLAIN}" && exit 1

# 卸载 SS-Rust
uninstall_ss_rust() {
    echo -e "${YELLOW}正在卸载 SS-Rust 及其配置文件...${PLAIN}"
    systemctl stop shadowsocks >/dev/null 2>&1
    systemctl disable shadowsocks >/dev/null 2>&1
    rm -f /usr/local/bin/ssserver
    rm -f /etc/systemd/system/shadowsocks.service
    rm -rf /etc/shadowsocks-rust /etc/shadowsocks # 删除可能存在的配置目录
    systemctl daemon-reload
    echo -e "${GREEN}SS-Rust 卸载并清理完成。${PLAIN}"
}

# 卸载 v2ray-wss
uninstall_v2ray_wss() {
    echo -e "${YELLOW}正在卸载 v2ray-wss 及 Nginx (含残留清理)...${PLAIN}"
    systemctl stop v2ray nginx >/dev/null 2>&1
    # 调用官方卸载逻辑
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) --remove
    # 彻底移除 nginx
    apt purge nginx nginx-common nginx-full -y
    apt autoremove -y
    # 清理残留目录
    rm -rf /etc/v2ray /usr/local/etc/v2ray /var/log/v2ray /etc/nginx
    systemctl daemon-reload
    echo -e "${GREEN}v2ray-wss 卸载并清理完成。${PLAIN}"
}

# 卸载 Reality (Xray)
uninstall_reality() {
    echo -e "${YELLOW}正在卸载 Reality (Xray) 及其配置文件...${PLAIN}"
    systemctl stop xray >/dev/null 2>&1
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove
    # 强制清理残留配置
    rm -rf /etc/xray /usr/local/etc/xray /var/log/xray
    echo -e "${GREEN}Reality 卸载并清理完成。${PLAIN}"
}

# 卸载 Hysteria2
uninstall_hysteria2() {
    echo -e "${YELLOW}正在卸载 Hysteria2 及其配置文件...${PLAIN}"
    bash <(curl -fsSL https://get.hy2.sh/) --remove
    rm -rf /etc/hysteria /var/log/hysteria # 删除配置与日志目录
    echo -e "${GREEN}Hysteria2 卸载并清理完成。${PLAIN}"
}

# 卸载 HTTPS 正向代理 (Caddy)
uninstall_caddy() {
    echo -e "${YELLOW}正在卸载 Caddy 及其配置文件...${PLAIN}"
    systemctl stop caddy >/dev/null 2>&1
    systemctl disable caddy >/dev/null 2>&1
    rm -f /usr/local/caddy
    rm -f /etc/systemd/system/caddy.service
    rm -rf /etc/caddy /var/lib/caddy # 删除配置和证书存储目录
    systemctl daemon-reload
    echo -e "${GREEN}Caddy 卸载并清理完成。${PLAIN}"
}

# 主菜单
show_menu() {
    clear
    echo "################################################"
    echo "#         代理服务一键卸载与清理脚本           #"
    echo "################################################"
    echo -e "  ${GREEN}1.${PLAIN} 卸载 SS-Rust"
    echo -e "  ${GREEN}2.${PLAIN} 卸载 v2ray-wss (含 Nginx)"
    echo -e "  ${GREEN}3.${PLAIN} 卸载 Reality (Xray)"
    echo -e "  ${GREEN}4.${PLAIN} 卸载 Hysteria2"
    echo -e "  ${GREEN}5.${PLAIN} 卸载 HTTPS 正向代理 (Caddy)"
    echo -e "  ${GREEN}0.${PLAIN} 退出脚本"
    echo "################################################"
    read -p "请输入数字选择: " choice

    case $choice in
        1) uninstall_ss_rust ;;
        2) uninstall_v2ray_wss ;;
        3) uninstall_reality ;;
        4) uninstall_hysteria2 ;;
        5) uninstall_caddy ;;
        0) exit 0 ;;
        *) echo -e "${RED}输入错误，请重新选择！${PLAIN}" && sleep 1 && show_menu ;;
    esac
}

show_menu
