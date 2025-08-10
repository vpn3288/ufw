#!/bin/bash
set -e

GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

echo -e "${YELLOW}== 🔥 一键智能安全防护脚本（代理 + 网站 + 防爆破） ==${RESET}"

# 检查 root
[ "$(id -u)" != "0" ] && echo -e "${RED}请用 root 运行${RESET}" && exit 1

############################################
# 0⃣ 彻底卸载清空防火墙规则
############################################
echo -e "${YELLOW}0⃣ 清空并卸载旧防火墙规则...${RESET}"
systemctl stop ufw 2>/dev/null || true
systemctl disable ufw 2>/dev/null || true
ufw --force reset 2>/dev/null || true

# 清空 iptables / ip6tables
iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X && iptables -t mangle -F && iptables -t mangle -X
ip6tables -F && ip6tables -X && ip6tables -t nat -F && ip6tables -t nat -X && ip6tables -t mangle -F && ip6tables -t mangle -X

# 清空 nftables
nft flush ruleset || true

############################################
# 1⃣ 安装 UFW
############################################
echo -e "${YELLOW}1⃣ 安装并配置 UFW...${RESET}"
apt update -y && apt install -y ufw

sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw || true
ufw default deny incoming
ufw default allow outgoing

############################################
# 2⃣ 端口设置
############################################
BAD_PORTS="135 137 138 139 445 1433 1521 3389 5900 5901 5985 5986 11211 27017 27018"
DB_PORTS="3306 5432 6379"
DB_ALLOWED_IP="127.0.0.1"

DEFAULT_TCP="22 80 443"
DEFAULT_UDP="80 443"

echo -e "${YELLOW}2⃣ 开放默认端口...${RESET}"
for p in $DEFAULT_TCP; do ufw allow ${p}/tcp; done
for p in $DEFAULT_UDP; do ufw allow ${p}/udp; done

############################################
# 3⃣ 自动识别系统监听端口
############################################
echo -e "${YELLOW}3⃣ 自动识别系统监听端口...${RESET}"
LISTEN_PORTS=$(ss -lnpH -4 -6 | awk '{print $1, $5}' | sed 's/.*://g' | awk '{print $1, $2}' | sort -u)

while read -r proto port; do
    [[ -z "$proto" || -z "$port" ]] && continue
    [[ "$port" -le 0 || "$port" -gt 65535 ]] && continue
    [[ "$BAD_PORTS" =~ (^|[[:space:]])"$port"($|[[:space:]]) ]] && continue
    [[ "$port" -gt 49151 ]] && continue
    if [[ "$DB_PORTS" =~ (^|[[:space:]])"$port"($|[[:space:]]) ]]; then
        ufw allow from "$DB_ALLOWED_IP" to any port "$port" proto "$proto"
    else
        ufw allow "${port}/${proto}"
    fi
done <<< "$LISTEN_PORTS"

############################################
# 4⃣ 检测 Docker 容器端口
############################################
if command -v docker &>/dev/null; then
    echo -e "${YELLOW}4⃣ 检测 Docker 映射端口...${RESET}"
    DOCKER_PORTS=$(docker ps --format '{{.Ports}}' | grep -Eo '[0-9]+->[0-9]+' | cut -d'>' -f1 | sort -u)
    for p in $DOCKER_PORTS; do
        [[ "$p" -gt 0 && "$p" -le 65535 ]] && ufw allow "${p}/tcp"
    done
fi

############################################
# 5⃣ 常见代理/Web端口
############################################
echo -e "${YELLOW}5⃣ 开放常见代理/Web端口...${RESET}"
EXTRA_PORTS_TCP="8080 8443 10000 3000 5000 7000 8000 8888 9443 10085 10086"
EXTRA_PORTS_UDP="53 1194 51820"
for p in $EXTRA_PORTS_TCP; do ufw allow ${p}/tcp; done
for p in $EXTRA_PORTS_UDP; do ufw allow ${p}/udp; done

############################################
# 6⃣ SSH 防护
############################################
echo -e "${YELLOW}6⃣ 启用 SSH 限速防护...${RESET}"
ufw limit 22/tcp

############################################
# 7⃣ 简单 DDoS 防御
############################################
echo -e "${YELLOW}7⃣ 添加简单 DDoS 防御规则...${RESET}"
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
iptables -A INPUT -f -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

############################################
# 8⃣ 安装并配置 Fail2Ban
############################################
echo -e "${YELLOW}8⃣ 安装并配置 Fail2Ban...${RESET}"
apt install -y fail2ban

cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 12h
findtime = 10m
maxretry = 5
banaction = ufw
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5

[nginx-http-auth]
enabled = true

[nginx-botsearch]
enabled = true

[nginx-req-limit]
enabled = true

[trojan]
enabled = true
port = 443
protocol = tcp
EOF

systemctl enable fail2ban
systemctl restart fail2ban

############################################
# 9⃣ 启用防火墙
############################################
echo -e "${YELLOW}9⃣ 启用防火墙...${RESET}"
ufw --force enable

echo -e "${GREEN}🎉 安全防护已完成，当前防火墙规则：${RESET}"
ufw status verbose
fail2ban-client status
