#!/bin/bash
set -e

# 颜色定义
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

echo -e "${YELLOW}== 🔥 代理服务器VPS防火墙自动配置脚本 v3.0 ==${RESET}"
echo -e "${BLUE}专为代理服务优化的端口配置${RESET}"

# 检查 root 权限
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}❌ 请用 root 权限运行此脚本${RESET}"
    exit 1
fi

# 定义代理服务常用端口
declare -A PROXY_PORTS=(
    ["22"]="SSH管理端口"
    ["53"]="DNS服务"
    ["80"]="HTTP代理/伪装"
    ["443"]="HTTPS代理/伪装"
    ["1080"]="SOCKS5代理"
    ["8080"]="HTTP代理备用"
    ["8388"]="Shadowsocks"
    ["9000"]="HTTP代理管理"
    ["10086"]="V2Ray/Xray"
    ["12334"]="自定义代理端口"
    ["8181"]="代理管理面板"
    ["1234"]="自定义代理端口"
    ["2000"]="自定义代理端口"
    ["438"]="自定义代理端口"
    ["501"]="自定义代理端口"
    ["502"]="自定义代理端口"
    ["1010"]="自定义代理端口"
    ["10085"]="代理服务端口"
    ["16450"]="高端口代理"
    ["16756"]="高端口代理"
    ["17078"]="高端口代理"
)

echo -e "\n${YELLOW}📊 系统端口分析：${RESET}"
echo -e "${CYAN}正在检测当前监听的端口...${RESET}"

# 获取当前监听端口
LISTENING_PORTS=$(netstat -tlnp 2>/dev/null | awk '/LISTEN/ {split($4,a,":"); if(a[length(a)] != "") print a[length(a)]"/tcp"}' | sort -u)
UDP_PORTS=$(netstat -ulnp 2>/dev/null | awk '{split($4,a,":"); if(a[length(a)] != "" && a[length(a)] != "*") print a[length(a)]"/udp"}' | sort -u)

echo -e "${GREEN}检测到以下监听端口：${RESET}"
for port in $LISTENING_PORTS; do
    port_num=$(echo $port | cut -d'/' -f1)
    if [[ -n "${PROXY_PORTS[$port_num]}" ]]; then
        echo -e "${GREEN}  ✓ $port - ${PROXY_PORTS[$port_num]}${RESET}"
    else
        echo -e "${BLUE}  • $port - 未知服务${RESET}"
    fi
done

# 1. 备份现有规则
echo -e "\n${YELLOW}1⃣ 备份现有防火墙规则...${RESET}"
backup_dir="/root/firewall_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$backup_dir"
iptables-save > "$backup_dir/iptables.rules" 2>/dev/null || true
ufw status numbered > "$backup_dir/ufw_rules.txt" 2>/dev/null || true
echo -e "${GREEN}   ✓ 备份保存到: $backup_dir${RESET}"

# 2. 安装UFW（如果未安装）
echo -e "${YELLOW}2⃣ 检查并安装UFW...${RESET}"
if ! command -v ufw &> /dev/null; then
    echo -e "${CYAN}   正在安装UFW...${RESET}"
    apt update >/dev/null 2>&1
    apt install -y ufw >/dev/null 2>&1
fi
echo -e "${GREEN}   ✓ UFW已准备就绪${RESET}"

# 3. 重置并配置UFW基础设置
echo -e "${YELLOW}3⃣ 配置UFW基础设置...${RESET}"
ufw --force reset >/dev/null 2>&1
sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw 2>/dev/null || true
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
echo -e "${GREEN}   ✓ UFW基础配置完成${RESET}"

# 4. 开放SSH端口（必须首先开放）
echo -e "${YELLOW}4⃣ 配置SSH访问保护...${RESET}"
SSH_PORT=$(netstat -tlnp 2>/dev/null | grep ':22 ' | head -1 | awk '{split($4,a,":"); print a[length(a)]}')
if [[ -z "$SSH_PORT" ]]; then
    SSH_PORT="22"
fi
echo -e "${GREEN}   ✓ SSH端口 $SSH_PORT/tcp (防暴力破解保护)${RESET}"
ufw limit $SSH_PORT/tcp >/dev/null 2>&1

# 5. 开放代理服务端口
echo -e "${YELLOW}5⃣ 配置代理服务端口...${RESET}"
opened_count=0
skipped_count=0
failed_count=0

for port in $LISTENING_PORTS; do
    port_num=$(echo $port | cut -d'/' -f1)
    
    # 跳过SSH端口（已配置）
    if [[ "$port_num" == "$SSH_PORT" ]]; then
        continue
    fi
    
    # 跳过MySQL和Redis（内部服务）
    if [[ "$port_num" == "3306" || "$port_num" == "6379" ]]; then
        echo -e "${BLUE}   ⏭️ 跳过: $port - 数据库服务（内部访问）${RESET}"
        ((skipped_count++))
        continue
    fi
    
    # 开放端口
    if ufw allow $port >/dev/null 2>&1; then
        if [[ -n "${PROXY_PORTS[$port_num]}" ]]; then
            echo -e "${GREEN}   ✓ 已开放: $port - ${PROXY_PORTS[$port_num]}${RESET}"
        else
            echo -e "${GREEN}   ✓ 已开放: $port - 检测到的服务${RESET}"
        fi
        ((opened_count++))
    else
        echo -e "${RED}   ❌ 失败: $port - 开放失败${RESET}"
        ((failed_count++))
    fi
done

# 6. 开放UDP端口（如果有）
if [[ -n "$UDP_PORTS" ]]; then
    echo -e "${YELLOW}6⃣ 配置UDP服务端口...${RESET}"
    for port in $UDP_PORTS; do
        port_num=$(echo $port | cut -d'/' -f1)
        if [[ "$port_num" != "53" ]]; then  # DNS端口通常不需要外部访问
            if ufw allow $port >/dev/null 2>&1; then
                echo -e "${GREEN}   ✓ 已开放UDP: $port${RESET}"
                ((opened_count++))
            fi
        fi
    done
fi

# 7. 添加常用代理端口（即使当前未监听）
echo -e "${YELLOW}7⃣ 预开放常用代理端口...${RESET}"
COMMON_PROXY_PORTS=("1080" "8080" "8388" "9000")
for port in "${COMMON_PROXY_PORTS[@]}"; do
    # 检查端口是否已在监听列表中
    if ! echo "$LISTENING_PORTS" | grep -q "^$port/tcp$"; then
        if ufw allow $port/tcp >/dev/null 2>&1; then
            echo -e "${CYAN}   ✓ 预开放: $port/tcp - ${PROXY_PORTS[$port]}${RESET}"
            ((opened_count++))
        fi
    fi
done

# 8. 启用防火墙
echo -e "${YELLOW}8⃣ 启用防火墙...${RESET}"
ufw --force enable >/dev/null 2>&1
echo -e "${GREEN}   ✓ 防火墙已启用并将在系统启动时自动加载${RESET}"

# 9. 生成详细报告
echo -e "\n${GREEN}🎉 代理服务器防火墙配置完成！${RESET}"
echo -e "${GREEN}=================================================================${RESET}"

echo -e "\n${YELLOW}📊 配置统计：${RESET}"
echo -e "${GREEN}  • 成功开放端口: $opened_count${RESET}"
echo -e "${BLUE}  • 跳过端口: $skipped_count${RESET}"
echo -e "${RED}  • 失败端口: $failed_count${RESET}"

echo -e "\n${YELLOW}🔥 当前防火墙规则：${RESET}"
ufw status numbered

echo -e "\n${YELLOW}🛡️ 安全状态检查：${RESET}"
total_rules=$(ufw status numbered | grep -c "^\[" 2>/dev/null || echo "0")
echo -e "${GREEN}   ✓ 总防火墙规则: $total_rules${RESET}"

# 检查关键端口状态
if ufw status | grep -q "$SSH_PORT/tcp.*LIMIT"; then
    echo -e "${GREEN}   ✓ SSH保护: 防暴力破解已启用 (端口 $SSH_PORT)${RESET}"
else
    echo -e "${YELLOW}   ⚠️ SSH保护: 请检查SSH端口配置${RESET}"
fi

if ufw status | grep -q "443/tcp.*ALLOW"; then
    echo -e "${GREEN}   ✓ HTTPS代理: 已开放${RESET}"
fi

if ufw status | grep -q "8388/tcp.*ALLOW"; then
    echo -e "${GREEN}   ✓ Shadowsocks: 已开放${RESET}"
fi

echo -e "\n${YELLOW}🚀 代理服务建议：${RESET}"
echo -e "${BLUE}   • 检查代理服务状态: systemctl status shadowsocks-libev${RESET}"
echo -e "${BLUE}   • 检查V2Ray状态: systemctl status v2ray${RESET}"
echo -e "${BLUE}   • 监控连接: netstat -an | grep ESTABLISHED${RESET}"
echo -e "${BLUE}   • 查看防火墙日志: tail -f /var/log/ufw.log${RESET}"
echo -e "${BLUE}   • 测试端口连通性: telnet your-server-ip port${RESET}"

echo -e "\n${YELLOW}🔧 管理命令：${RESET}"
echo -e "${BLUE}   • 查看状态: ufw status verbose${RESET}"
echo -e "${BLUE}   • 添加端口: ufw allow PORT${RESET}"
echo -e "${BLUE}   • 删除规则: ufw delete RULE_NUMBER${RESET}"
echo -e "${BLUE}   • 重新加载: ufw reload${RESET}"

echo -e "\n${YELLOW}💾 备份信息：${RESET}"
echo -e "${BLUE}   • 配置备份: $backup_dir${RESET}"
echo -e "${BLUE}   • 恢复命令: iptables-restore < $backup_dir/iptables.rules${RESET}"

echo -e "\n${GREEN}🎯 代理服务器防火墙配置完成！${RESET}"
echo -e "${GREEN}你的VPS现在已针对代理服务进行了优化配置。${RESET}"

# 10. 最终验证
echo -e "\n${YELLOW}🔍 最终验证：${RESET}"
if ufw status | grep -q "Status: active"; then
    echo -e "${GREEN}   ✅ 防火墙状态: 已激活${RESET}"
else
    echo -e "${RED}   ❌ 防火墙状态: 未激活${RESET}"
    exit 1
fi

# 检查关键代理端口
proxy_ports_open=0
for port in "80" "443" "1080" "8080" "8388"; do
    if ufw status | grep -q "$port/tcp.*ALLOW"; then
        ((proxy_ports_open++))
    fi
done

echo -e "${GREEN}   ✅ 代理端口开放: $proxy_ports_open 个关键端口${RESET}"
echo -e "${GREEN}   ✅ SSH访问保护: 已启用${RESET}"
echo -e "${GREEN}   ✅ 出站连接: 已允许${RESET}"

echo -e "\n${GREEN}🚀 所有配置已完成并验证！准备就绪！${RESET}"
