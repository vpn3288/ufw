#!/bin/bash
# VPS 安全防护脚本
# 功能：自动开放代理节点/网站端口，防爆破，防扫描，防DoS
# 适用：个人博客、小网站、代理节点
# 作者：GPT定制安全版

YELLOW="\033[1;33m"
GREEN="\033[1;32m"
RESET="\033[0m"

clear_firewall() {
    echo -e "${YELLOW}=== [0] 清空所有防火墙规则（nftables + iptables + ufw） ===${RESET}"

    # 清空 nftables
    if command -v nft >/dev/null 2>&1; then
        nft flush ruleset
        echo -e "${GREEN}已清空 nftables 规则${RESET}"
    fi

    # 清空 iptables（IPv4）
    if command -v iptables >/dev/null 2>&1; then
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        iptables -t mangle -F
        iptables -t mangle -X
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        echo -e "${GREEN}已清空 iptables 规则（IPv4）${RESET}"
    fi

    # 清空 ip6tables（IPv6）
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -F
        ip6tables -X
        ip6tables -t nat -F
        ip6tables -t nat -X
        ip6tables -t mangle -F
        ip6tables -t mangle -X
        ip6tables -P INPUT ACCEPT
        ip6tables -P FORWARD ACCEPT
        ip6tables -P OUTPUT ACCEPT
        echo -e "${GREEN}已清空 iptables 规则（IPv6）${RESET}"
    fi

    # 清空 UFW
    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >/dev/null 2>&1
        echo -e "${GREEN}已清空 UFW 规则${RESET}"
    fi
}

# 如果参数是 clear，则只清空防火墙规则
if [[ "$1" == "clear" ]]; then
    clear_firewall
    echo -e "${GREEN}✅ 防火墙规则已清空（仅清空模式完成）${RESET}"
    exit 0
fi

# 执行完整防护流程
clear_firewall

echo -e "${YELLOW}=== [1] 初始化防火墙策略 ===${RESET}"
ufw default deny incoming
ufw default allow outgoing

# 必要端口（博客/网站）
echo -e "${YELLOW}=== [2] 开放网站常用端口 ===${RESET}"
ufw allow 80/tcp
ufw allow 443/tcp

# 危险端口
BAD_PORTS="135 137 138 139 445 1433 1521 3389 5900 5901 5985 5986 11211 27017 27018"
echo -e "${YELLOW}=== [3] 屏蔽危险端口 ===${RESET}"
for p in $BAD_PORTS; do
    ufw deny $p/tcp
    ufw deny $p/udp
done

# 自动识别并开放代理端口
echo -e "${YELLOW}=== [4] 自动识别并开放当前监听的服务端口 ===${RESET}"
ss -tulnpH -4 -6 | while read proto local _; do
    port=$(echo "$local" | awk -F':' '{print $NF}')
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    [[ "$BAD_PORTS" =~ (^|[[:space:]])"$port"($|[[:space:]]) ]] && continue

    if [[ "$proto" =~ tcp ]]; then
        ufw allow "${port}/tcp"
    elif [[ "$proto" =~ udp ]]; then
        ufw allow "${port}/udp"
    fi
done

# SSH 防护
echo -e "${YELLOW}=== [5] 配置 SSH 安全规则 ===${RESET}"
ufw limit 22/tcp comment "限制SSH防暴力破解"

# 防扫描 / 防DoS
echo -e "${YELLOW}=== [6] 添加防扫描、防DDoS规则 ===${RESET}"
ufw limit proto tcp from any to any port 80,443

# 启用防火墙
echo -e "${YELLOW}=== [7] 启用防火墙 ===${RESET}"
ufw --force enable

# 安装并配置 Fail2Ban
echo -e "${YELLOW}=== [8] 安装并配置 Fail2Ban 防护 SSH / Nginx ===${RESET}"
apt-get update -y
apt-get install -y fail2ban

cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = auto

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600

[nginx-http-auth]
enabled = true

[nginx-botsearch]
enabled  = true
EOF

systemctl enable fail2ban
systemctl restart fail2ban

# 完成提示
echo -e "${GREEN}✅ 防火墙和防护已全部配置完成！${RESET}"
ufw status verbose
fail2ban-client status
