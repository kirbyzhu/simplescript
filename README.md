# simplescript

这是一个专门为 Debian/Ubuntu 系统设计的交互式卸载脚本，旨在帮助用户快速、干净地移除各种常见的代理服务及相关配置文件。

🌟 功能特点

交互式菜单：支持逐一选择卸载，或一键清理所有服务。
深度清理：不仅删除二进制文件，还会清理 systemd 服务项、日志文件及 /etc/ 下的残留配置目录。
安全可靠：在执行“一键全删”前设有二次确认，防止误操作。
官方集成：对于 V2Ray 和 Xray，脚本会优先调用官方提供的 remove 逻辑。

🚀 终端一键执行

直接在你的终端粘贴并运行以下命令即可：

Bash

wget -P /root -N --no-check-certificate https://raw.githubusercontent.com/kirbyzhu/simplescript/refs/heads/main/uninstall-wss.sh && chmod +x /root/uninstall-wss.sh && /root/uninstall-wss.sh

🛠 支持卸载的服务列表选项服务名称清理内容

1 SS-Rust停止服务、删除二进制、删除 .service、清理 /etc/shadowsocks-rust
2 V2Ray-WSS停止 V2Ray/Nginx、调用官方卸载脚本、彻底卸载并清理 Nginx
3 Reality (Xray)调用官方 remove 脚本、清理 /etc/xray 及日志
4 Hysteria2调用官方卸载逻辑、清理 /etc/hysteria
5 Caddy 代理停止服务、删除二进制、清理 /etc/caddy 及证书目录
6 全部卸载依次执行上述所有清理操作

📝 使用要求操作系统：Debian 10+ / Ubuntu 20.04+ (Debian系)
用户权限：必须以 root 用户身份运行。
依赖工具：确保系统已安装 wget 或 curl。

⚠️ 注意事项
数据备份：卸载操作会永久删除配置文件和证书。如果有重要配置，请在操作前手动备份。
Nginx 说明：在卸载 v2ray-wss 时，脚本会执行 apt purge nginx，这会移除服务器上所有的 Nginx 站点配置。
