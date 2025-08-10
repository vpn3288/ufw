#!/bin/bash
set -e

GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

echo -e "${YELLOW}== 🔥 智能防火墙配置脚本（代理节点 + 网站专用版） ==${RESET}"

# 检查 root
[ "$(id -u)" != "0" ] && echo -e "${RED}请用 root 运行${RESET}" && exit 1

# 高危端口（不开放）
BAD_PORTS="135 137 138 139 445 1433 1521 3306 3389 5900 5901 5985 5986 6379 11211 27017 27018"

# 允许的数据库端口及来源 IP（如有需要可改）
DB_PORTS="3306 5432 6379"
DB_ALLOWED_IP="127.0.0.1"

# 默认开放端口
DEFAULT_TCP="22 80 443"
DEFAULT_UDP="80 443"

# 清空规则
echo -e "${YELLOW}1⃣ 清空所有防火墙规则...${RESET}"
ufw --force reset
iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X
ip6tables -F && ip6tables -X && ip6tables -t nat -F && ip6tables -t nat -X
nft flush ruleset || true

# 安装 UFW
echo -e "${YELLOW}2⃣ 安装并配置 UFW...${RESET}"
apt update -y && apt install -y ufw
sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw || true
ufw default deny incoming
ufw default allow outgoing

# 开放默认端口
echo -e "${YELLOW}3⃣ 开放默认端口...${RESET}"
for p in $DEFAULT_TCP; do ufw allow ${p}/tcp; done
for p in $DEFAULT_UDP; do ufw allow ${p}/udp; done

# 自动识别监听端口（系统）
echo -e "${YELLOW}4⃣ 识别当前监听端口并开放...${RESET}"
LISTEN_PORTS=$(ss -lnpH -4 -6 | awk '{print $1, $5}' | sed 's/.*://g' | awk '{print $1, $2}' | sort -u)

while read -r proto port; do
    [[ -z "$proto" || -z "$port" ]] && continue
    [[ "$port" -le 0 || "$port" -gt 65535 ]] && continue
    [[ "$BAD_PORTS" =~ (^|[[:space:]])"$port"($|[[:space:]]) ]] && continue
    [[ "$port" -gt 49151 ]] && continue
    # 数据库端口特殊处理
    if [[ "$DB_PORTS" =~ (^|[[:space:]])"$port"($|[[:space:]]) ]]; then
        ufw allow from "$DB_ALLOWED_IP" to any port "$port" proto "$proto"
    else
        ufw allow "${port}/${proto}"
    fi
done <<< "$LISTEN_PORTS"

# 检测 Docker 容器端口
if command -v docker &>/dev/null; then
    echo -e "${YELLOW}5⃣ 检测 Docker 映射端口...${RESET}"
    DOCKER_PORTS=$(docker ps --format '{{.Ports}}' | grep -Eo '[0-9]+->[0-9]+' | cut -d'>' -f1 | sort -u)
    for p in $DOCKER_PORTS; do
        [[ "$p" -gt 0 && "$p" -le 65535 ]] && ufw allow "${p}/tcp"
    done
fi

# Web/代理节点常用端口额外放行
echo -e "${YELLOW}6⃣ 开放常见代理和网站端口...${RESET}"
EXTRA_PORTS_TCP="443 80 8080 8443 10000 3000 5000 7000 8000 8888 9443 10085 10086"
EXTRA_PORTS_UDP="443 53 1194 51820"
for p in $EXTRA_PORTS_TCP; do ufw allow ${p}/tcp; done
for p in $EXTRA_PORTS_UDP; do ufw allow ${p}/udp; done

# SSH 防护
echo -e "${YELLOW}7⃣ 启用 SSH 限速防护...${RESET}"
ufw limit 22/tcp

# 简单防御（防 SYN Flood）
echo -e "${YELLOW}8⃣ 启用简单网络防御规则...${RESET}"
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
iptables -A INPUT -f -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# 启用防火墙
echo -e "${YELLOW}9⃣ 启用防火墙...${RESET}"
ufw --force enable

# 显示结果
echo -e "${GREEN}🎉 防火墙设置完成，当前规则如下：${RESET}"
ufw status verbose
