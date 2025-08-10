#!/bin/bash
set -e

GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

echo -e "${YELLOW}== 🔥 自动智能防火墙配置脚本（Bad port 修正版） ==${RESET}"

# 检查 root
[ "$(id -u)" != "0" ] && echo -e "${RED}请用 root 运行${RESET}" && exit 1

# 1. 清空所有规则
echo -e "${YELLOW}1⃣ 清除现有防火墙规则...${RESET}"
iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X
ip6tables -F && ip6tables -X && ip6tables -t nat -F && ip6tables -t nat -X
nft flush ruleset || true
ufw --force reset

# 2. 安装 UFW
echo -e "${YELLOW}2⃣ 安装并配置 UFW...${RESET}"
apt update -y && apt install -y ufw
sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw || true
ufw default deny incoming
ufw default allow outgoing

# 3. 开放默认端口
echo -e "${YELLOW}3⃣ 开放常用默认端口 (22, 80, 443)...${RESET}"
for port in 22 80 443; do
  ufw allow ${port}/tcp
done

# 4. 自动侦测并开放当前监听端口
echo -e "${YELLOW}4⃣ 自动侦测并开放当前监听端口...${RESET}"
TCP_PORTS=$(ss -tnlp 2>/dev/null | awk 'NR>1 {split($4,a,":"); p=a[length(a)]; if(p ~ /^[0-9]+$/ && p>=1 && p<=65535) print p}' | sort -un)
UDP_PORTS=$(ss -unlp 2>/dev/null | awk 'NR>1 {split($4,a,":"); p=a[length(a)]; if(p ~ /^[0-9]+$/ && p>=1 && p<=65535) print p}' | sort -un)

for p in $TCP_PORTS; do
  [[ "$p" =~ ^(22|80|443)$ ]] && continue
  ufw allow ${p}/tcp
done

for p in $UDP_PORTS; do
  [[ "$p" =~ ^(22|80|443)$ ]] && continue
  ufw allow ${p}/udp
done

# 5. 防 SSH 暴力破解
echo -e "${YELLOW}5⃣ 启用 SSH 登录限速防护...${RESET}"
ufw limit 22/tcp

# 6. 启动并固化
echo -e "${YELLOW}6⃣ 启用并保存防火墙规则...${RESET}"
ufw --force enable

# 7. 显示结果
echo -e "${GREEN}🎉 防火墙设置完成，当前规则如下：${RESET}"
ufw status verbose
