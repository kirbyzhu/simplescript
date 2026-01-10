#!/bin/bash

# =========================================================
# 智能网络优化脚本 (Smart Optimize)
# 专为 Linux VPS 设计，自适应低配/高配环境
# 功能：最大化性能、平衡优化、IPv6 开关、BBR 管理、系统限制调整
# =========================================================

# 定义颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PLAIN='\033[0m'

# 全局变量
TOTAL_RAM_MB=$(free -m | awk '/Mem:/ {print $2}')
SYSCTL_CONF="/etc/sysctl.conf" # 仅用于清理
SYSCTL_D_CONF="/etc/sysctl.d/99-smart-optimize.conf" # 新的配置位置

# 基础检查
check_root() {
    if [[ $EUID -ne 0 ]]; then
       echo -e "${RED}错误：必须使用 root 用户运行此脚本！${PLAIN}" 
       exit 1
    fi
}

# 备份配置
backup_sysctl() {
    if [ ! -f "${SYSCTL_CONF}.bak" ]; then
        echo -e "${YELLOW}正在备份 /etc/sysctl.conf ...${PLAIN}"
        cp "${SYSCTL_CONF}" "${SYSCTL_CONF}.bak"
    fi
}

# 优化系统级限制 (nofile, nproc) - 吸收自参考脚本
tune_system_limits() {
    echo -e "${GREEN}>>> 正在优化系统文件描述符限制 (ulimit)...${PLAIN}"
    
    # 1. 配置 limits.d
    cat > /etc/security/limits.d/99-nofile-nproc.conf <<EOF
* soft     nproc    131072
* hard     nproc    131072
* soft     nofile   262144
* hard     nofile   262144

root soft  nproc    131072
root hard  nproc    131072
root soft  nofile   262144
root hard  nofile   262144
EOF

    # 2. 确保 pam_limits 启用
    echo -e "${YELLOW}    检查 pam_limits 设置...${PLAIN}"
    if ! grep -q '^session\s\+required\s\+pam_limits.so' /etc/pam.d/common-session 2>/dev/null; then
        echo "session required pam_limits.so" >> /etc/pam.d/common-session
    fi
    if ! grep -q '^session\s\+required\s\+pam_limits.so' /etc/pam.d/common-session-noninteractive 2>/dev/null; then
        echo "session required pam_limits.so" >> /etc/pam.d/common-session-noninteractive
    fi

    # 3. 优化 systemd 全局限制
    echo -e "${YELLOW}    优化 systemd 默认限制...${PLAIN}"
    mkdir -p /etc/systemd/system.conf.d
    cat > /etc/systemd/system.conf.d/99-limits.conf <<EOF
[Manager]
DefaultLimitNOFILE=262144
DefaultLimitNPROC=131072
EOF
    systemctl daemon-reexec >/dev/null 2>&1
    echo -e "${GREEN}    系统限制优化完成。需要重启才能完全生效。${PLAIN}"
}

# 清理旧参数 (涵盖 sysctl.conf 和 sysctl.d)
clean_sysctl_keys() {
    echo -e "${YELLOW}正在清理旧的优化参数...${PLAIN}"
    local keys_to_remove=(
        "fs.file-max"
        "net.ipv4.tcp_max_syn_backlog"
        "net.ipv4.tcp_rmem"
        "net.ipv4.tcp_wmem"
        "net.ipv4.tcp_adv_win_scale"
        "net.ipv4.tcp_sack"
        "net.ipv4.tcp_timestamps"
        "net.ipv4.tcp_synack_retries"
        "net.ipv4.ip_forward"
        "net.ipv4.tcp_fin_timeout"
        "net.ipv4.tcp_keepalive_time"
        "net.ipv4.ip_local_port_range"
        "net.ipv4.tcp_window_scaling"
        "net.ipv4.tcp_mtu_probing"
        "net.core.netdev_max_backlog"
        "net.ipv4.tcp_fack"
        "net.ipv4.tcp_syncookies"
        "net.ipv4.tcp_low_latency"
        "net.ipv4.tcp_notsent_lowat"
        "net.ipv4.tcp_syn_retries"
        "net.ipv4.tcp_max_tw_buckets"
        "net.ipv4.tcp_fastopen"
        "net.ipv4.tcp_tw_reuse"
        "net.core.default_qdisc"
        "net.ipv4.tcp_congestion_control"
        "net.ipv4.tcp_collapse_max_bytes"
        "net.nf_conntrack_max"
        "net.netfilter.nf_conntrack_max"
        "net.core.rmem_max"
        "net.core.wmem_max"
        "net.core.somaxconn"
        "net.ipv4.udp_rmem_min"
        "net.ipv4.udp_wmem_min"
        "net.ipv4.neigh.default.gc_stale_time"
        "net.ipv4.conf.all.rp_filter"
        "net.ipv4.conf.default.rp_filter"
        "net.ipv4.conf.eth.*.rp_filter"
        "net.ipv4.neigh.eth.*"
    )

    # 暴力清理 /etc/sysctl.conf 中的旧配置 (为了迁移到 sysctl.d)
    sed -i '/net.ipv4.conf.eth/d' "${SYSCTL_CONF}"
    sed -i '/net.ipv4.neigh.eth/d' "${SYSCTL_CONF}"
    sed -i '/net.ipv4.conf.ens/d' "${SYSCTL_CONF}"
    sed -i '/net.ipv4.neigh.ens/d' "${SYSCTL_CONF}"
    sed -i '/# --- 智能优化脚本自动添加开始 ---/,/# --- 智能优化脚本自动添加结束 ---/d' "${SYSCTL_CONF}"

    for key in "${keys_to_remove[@]}"; do
        sed -i "/^${key}[[:space:]]*=/d" "${SYSCTL_CONF}"
    done
    
    # 清理 sysctl.d 中的旧配置
    rm -f "${SYSCTL_D_CONF}"
    rm -f /etc/sysctl.d/99-bbr.conf
    rm -f /etc/sysctl.d/99-ipv6-disable.conf
}

# 检测 Conntrack 支持
check_conntrack() {
    modprobe nf_conntrack >/dev/null 2>&1
    if lsmod | grep -q "nf_conntrack" || [ -f /proc/net/nf_conntrack ]; then
        return 0
    else
        return 1
    fi
}

# 核心优化逻辑 (通用层)
apply_optimization() {
    local mode=$1 # balanced, max
    
    clean_sysctl_keys
    tune_system_limits
    
    local tcp_max_syn_backlog
    local tcp_rmem_max
    local tcp_wmem_max
    local conntrack_max
    local netdev_max_backlog
    
    # 根据模式和内存计算参数
    if [[ "$mode" == "max" ]]; then
        echo -e "${GREEN}>>> 应用最大化性能配置 (Max Performance)...${PLAIN}"
        echo -e "${YELLOW}警告：此模式将使用较大的内存缓冲区，请确保 VPS 内存 > 1GB${PLAIN}"
        tcp_max_syn_backlog=16384
        # 吸收参考脚本的高性能值 (512MB)
        tcp_rmem_max=536870912   # 512MB
        tcp_wmem_max=536870912   # 512MB
        conntrack_max=2000000    # 200万连接
        netdev_max_backlog=20000
    else
        # Balanced / Auto Mode
        if [ "$TOTAL_RAM_MB" -lt 1024 ]; then
            echo -e "${YELLOW}>>> 检测到低内存环境 (<1GB)，应用低配保护配置 (Balanced)...${PLAIN}"
            tcp_max_syn_backlog=4096
            tcp_rmem_max=16777216     # 16MB
            tcp_wmem_max=16777216     # 16MB
            conntrack_max=65536       # 6.5万连接
            netdev_max_backlog=2048
        else
            echo -e "${GREEN}>>> 检测到充足内存，应用标准平衡配置 (Balanced)...${PLAIN}"
            tcp_max_syn_backlog=8192
            # 标准模式保持 64MB，避免过于激进
            tcp_rmem_max=67108864     # 64MB
            tcp_wmem_max=67108864     # 64MB
            conntrack_max=1000000     # 100万连接
            netdev_max_backlog=10000
        fi
    fi

    # 写入独立的 sysctl.d 文件 (更现代的做法)
    echo -e "${YELLOW}正在写入配置到 ${SYSCTL_D_CONF} ...${PLAIN}"
    cat > "${SYSCTL_D_CONF}" << CONF
# Smart Optimize Configuration
# Generated by script
fs.file-max = 524288
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = ${tcp_max_syn_backlog}
net.ipv4.tcp_rmem = 4096 87380 ${tcp_rmem_max}
net.ipv4.tcp_wmem = 4096 16384 ${tcp_wmem_max}
net.ipv4.tcp_adv_win_scale = -2
net.ipv4.tcp_sack = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_synack_retries = 1
net.ipv4.ip_forward = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 600
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_mtu_probing = 1
net.core.netdev_max_backlog = ${netdev_max_backlog}
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.neigh.default.gc_stale_time = 60
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_max_tw_buckets = 20000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
# 新增：防止空闲后速度下降
net.ipv4.tcp_slow_start_after_idle = 0
CONF

    if check_conntrack; then
        echo -e "${GREEN}启用连接追踪优化 (Max: ${conntrack_max})...${PLAIN}"
        cat >> "${SYSCTL_D_CONF}" << CONF
net.netfilter.nf_conntrack_max = ${conntrack_max}
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 15
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
CONF
    fi

    # 应用配置
    sysctl --system >/dev/null 2>&1
    echo -e "${GREEN}优化配置已加载 (sysctl --system)！${PLAIN}"
    echo -e "${YELLOW}注意：limits 参数需要重启服务器才会显示改动 (ulimit -n)。${PLAIN}"
}

# IPv6 开关
toggle_ipv6() {
    local status
    # 检查当前状态 (0=enabled, 1=disabled)
    local current_val
    current_val=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)
    
    if [[ "$current_val" == "0" ]]; then
        status="${GREEN}开启${PLAIN}"
    else
        status="${RED}关闭${PLAIN}"
    fi
    
    echo -e "当前 IPv6 状态: ${status}"
    echo -e "1. 开启 IPv6"
    echo -e "2. 关闭 IPv6"
    echo -e "0. 返回"
    read -p "请选择: " choice
    
    # 使用 sysctl.d 持久化 IPv6 设置
    local ipv6_conf="/etc/sysctl.d/99-ipv6-disable.conf"
    
    case $choice in
        1)
            # 要开启，删除禁用的配置
            rm -f "${ipv6_conf}"
            # 同时尝试即时生效
            sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null
            sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null
            sysctl -w net.ipv6.conf.lo.disable_ipv6=0 >/dev/null
            echo -e "${GREEN}IPv6 已开启 (重启后保持)${PLAIN}"
            ;;
        2)
            # 要关闭，写入禁用配置
            cat > "${ipv6_conf}" <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
            sysctl --system >/dev/null 2>&1
            echo -e "${YELLOW}IPv6 已关闭 (持久化)${PLAIN}"
            ;;
        *) return ;;
    esac
}

# 管理 BBR
manage_bbr() {
    echo -e "${YELLOW}正在检测 BBR/BBRPlus...${PLAIN}"
    local available_cc
    available_cc="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)"
    
    if [[ $available_cc == *"bbrplus"* ]]; then
        echo -e "${GREEN}发现 BBRPlus 模块，已启用。${PLAIN}"
        # 确保配置正确 (写入 sysctl.d)
        cat > /etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbrplus
EOF
    elif [[ $available_cc == *"bbr"* ]]; then
        echo -e "${GREEN}发现原生 BBR 模块，已启用。${PLAIN}"
         cat > /etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    else
        echo -e "${RED}未检测到 BBR/BBRPlus。${PLAIN}"
        read -p "是否安装加速内核 (ylx2016脚本)? [y/n]: " run_install
        if [[ "$run_install" == "y" ]]; then
            wget -N --no-check-certificate "https://github.com/ylx2016/Linux-NetSpeed/raw/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
            return
        fi
    fi
     sysctl --system >/dev/null 2>&1
}

# 主菜单
show_menu() {
    clear
    echo -e "=================================="
    echo -e "    智能网络优化工具 (Smart Optimize)"
    echo -e "=================================="
    echo -e "当前内存: ${GREEN}${TOTAL_RAM_MB} MB${PLAIN}"
    echo -e "----------------------------------"
    echo -e "1. 🚀 最大化网络性能 (Max Performance)"
    echo -e "   (适用于内存 >1GB，高并发，极限速度)"
    echo -e ""
    echo -e "2. ⚖️ 综合平衡性能 (Balanced/Recommended)"
    echo -e "   (智能适配内存，稳定与速度兼顾，推荐)"
    echo -e ""
    echo -e "3. 🌐 IPv6 功能开关 (Toggle IPv6)"
    echo -e "   (开启/关闭 IPv6 协议栈)"
    echo -e ""
    echo -e "4. 🔥 BBR/内核加速管理 (BBR Manager)"
    echo -e "   (安装或启用 BBR/BBRPlus)"
    echo -e "----------------------------------"
    echo -e "0. 退出 (Exit)"
    echo -e ""
    read -p "请选择 [0-4]: " num

    case "$num" in
        1) apply_optimization "max" ;;
        2) apply_optimization "balanced" ;;
        3) toggle_ipv6 ;;
        4) manage_bbr ;;
        0) exit 0 ;;
        *) echo -e "${RED}请输入正确的数字${PLAIN}" ;;
    esac
    
    echo -e ""
    read -p "按回车键继续..."
    show_menu
}

# 执行入口
check_root
backup_sysctl
show_menu
