#!/bin/bash
set -e

# 颜色定义
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"
MAGENTA="\033[35m"
RESET="\033[0m"

# 脚本信息
SCRIPT_VERSION="3.0-Smart"
SCRIPT_NAME="智能VPS防火墙配置脚本"

echo -e "${YELLOW}== 🛡️  ${SCRIPT_NAME} v${SCRIPT_VERSION} ==${RESET}"

# 检查 root 权限
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}❌ 请用 root 权限运行此脚本${RESET}"
    exit 1
fi

# 全局变量
DEBUG_MODE=false
FORCE_MODE=false
DRY_RUN=false
BACKUP_DIR=""
SSH_PORT=""
OPENED_PORTS=0
BLOCKED_PORTS=0
ANALYZED_PORTS=0

# 记录实际监听的端口
declare -A LISTENING_PORTS
declare -A PORT_PROCESSES
declare -A PORT_PROTOCOLS
declare -A APPROVED_PORTS

# 服务端口识别规则 - 根据进程名判断是否应该对外开放
declare -A SERVICE_RULES=(
    # Web服务 - 对外开放
    ["nginx"]="ALLOW"
    ["apache"]="ALLOW" 
    ["apache2"]="ALLOW"
    ["httpd"]="ALLOW"
    ["lighttpd"]="ALLOW"
    ["caddy"]="ALLOW"
    
    # 代理服务 - 对外开放
    ["xray"]="ALLOW"
    ["v2ray"]="ALLOW"
    ["trojan"]="ALLOW"
    ["shadowsocks"]="ALLOW"
    ["ss-server"]="ALLOW"
    ["sing-box"]="ALLOW"
    ["hysteria"]="ALLOW"
    ["brook"]="ALLOW"
    ["gost"]="ALLOW"
    
    # VPN服务 - 对外开放
    ["openvpn"]="ALLOW"
    ["wireguard"]="ALLOW"
    ["wg-quick"]="ALLOW"
    ["strongswan"]="ALLOW"
    ["ipsec"]="ALLOW"
    
    # SSH服务 - 对外开放但限制
    ["sshd"]="SSH"
    ["dropbear"]="SSH"
    
    # DNS服务 - 谨慎开放
    ["named"]="DNS"
    ["bind"]="DNS"
    ["dnsmasq"]="DNS"
    ["unbound"]="DNS"
    
    # 数据库服务 - 内网访问
    ["mysql"]="INTERNAL"
    ["mysqld"]="INTERNAL"
    ["mariadb"]="INTERNAL"
    ["postgres"]="INTERNAL"
    ["postgresql"]="INTERNAL"
    ["redis"]="INTERNAL"
    ["redis-server"]="INTERNAL"
    ["mongodb"]="INTERNAL"
    ["mongod"]="INTERNAL"
    
    # 其他内网服务
    ["docker-proxy"]="INTERNAL"
    ["containerd"]="INTERNAL"
    ["node"]="INTERNAL"
    ["python"]="INTERNAL"
    ["java"]="INTERNAL"
    ["php-fpm"]="INTERNAL"
    ["memcached"]="INTERNAL"
    
    # 系统服务 - 禁止外网访问
    ["systemd"]="DENY"
    ["systemd-resolved"]="DENY"
    ["systemd-networkd"]="DENY"
    ["NetworkManager"]="DENY"
    ["dhclient"]="DENY"
    ["chronyd"]="DENY"
    ["ntpd"]="DENY"
    ["rsyslog"]="DENY"
    ["systemd-logind"]="DENY"
)

# 调试日志函数
debug_log() {
    if [ "$DEBUG_MODE" = true ]; then
        echo -e "${BLUE}[DEBUG] $1${RESET}" >&2
    fi
}

# 错误处理函数
error_exit() {
    echo -e "${RED}❌ 错误: $1${RESET}" >&2
    exit 1
}

# 警告函数
warning() {
    echo -e "${YELLOW}⚠️  警告: $1${RESET}" >&2
}

# 成功信息函数
success() {
    echo -e "${GREEN}✓ $1${RESET}"
}

# 信息函数
info() {
    echo -e "${CYAN}ℹ️  $1${RESET}"
}

# 高亮显示重要信息
highlight() {
    echo -e "${MAGENTA}🔥 $1${RESET}"
}

# 解析命令行参数
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)
                DEBUG_MODE=true
                info "调试模式已启用"
                shift
                ;;
            --force)
                FORCE_MODE=true
                info "强制模式已启用"
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                info "预演模式已启用 - 不会实际修改防火墙"
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                error_exit "未知参数: $1"
                ;;
        esac
    done
}

# 显示帮助信息
show_help() {
    cat << EOF
${SCRIPT_NAME} v${SCRIPT_VERSION}

专为VPS代理节点和Web服务器设计的智能防火墙配置脚本

特点:
  🔍 智能分析实际监听端口
  🛡️  严格安全策略，只开放必要端口
  🧹 完全清理历史防火墙规则
  📊 详细的端口分析报告
  🔒 SSH连接限速保护
  🚫 自动阻止危险服务对外暴露

用法: $0 [选项]

选项:
    --debug     启用调试模式，显示详细日志
    --force     强制模式，跳过确认提示
    --dry-run   预演模式，显示将要执行的操作但不实际执行
    --help, -h  显示此帮助信息

示例:
    $0                    # 正常运行
    $0 --debug            # 调试模式运行
    $0 --dry-run          # 预演模式，查看将要执行的操作
    $0 --force --debug    # 强制模式 + 调试模式

EOF
}

# 检查系统环境
check_system() {
    debug_log "检查系统环境"
    
    # 检查操作系统
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        debug_log "操作系统: $NAME $VERSION"
        info "系统: $NAME $VERSION"
    fi
    
    # 检查包管理器
    if command -v apt >/dev/null 2>&1; then
        PACKAGE_MANAGER="apt"
    elif command -v yum >/dev/null 2>&1; then
        PACKAGE_MANAGER="yum"
    elif command -v dnf >/dev/null 2>&1; then
        PACKAGE_MANAGER="dnf"
    else
        warning "未检测到支持的包管理器"
        PACKAGE_MANAGER=""
    fi
    
    debug_log "包管理器: ${PACKAGE_MANAGER:-"未知"}"
}

# 安装必要工具
install_dependencies() {
    debug_log "检查并安装依赖"
    
    local packages_to_install=()
    
    # 检查必要工具
    local required_tools=("ufw" "fail2ban-client" "ss" "netstat" "lsof")
    local tool_packages=("ufw" "fail2ban" "iproute2" "net-tools" "lsof")
    
    for i in "${!required_tools[@]}"; do
        if ! command -v "${required_tools[$i]}" >/dev/null 2>&1; then
            if [ "$PACKAGE_MANAGER" = "apt" ]; then
                packages_to_install+=("${tool_packages[$i]}")
            fi
        fi
    done
    
    # 安装缺失的包
    if [ ${#packages_to_install[@]} -gt 0 ]; then
        highlight "安装必要工具: ${packages_to_install[*]}"
        
        if [ "$DRY_RUN" = true ]; then
            info "[预演] 将安装: ${packages_to_install[*]}"
            return
        fi
        
        case "$PACKAGE_MANAGER" in
            "apt")
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq >/dev/null 2>&1
                apt-get install -y "${packages_to_install[@]}" >/dev/null 2>&1
                ;;
            "yum")
                yum install -y "${packages_to_install[@]}" >/dev/null 2>&1
                ;;
            "dnf")
                dnf install -y "${packages_to_install[@]}" >/dev/null 2>&1
                ;;
            *)
                warning "无法自动安装依赖，请手动安装: ${packages_to_install[*]}"
                ;;
        esac
        
        success "依赖安装完成"
    else
        success "所有必要工具已安装"
    fi
}

# 创建详细备份
create_backup() {
    debug_log "创建防火墙规则备份"
    
    BACKUP_DIR="/root/firewall_backup_$(date +%Y%m%d_%H%M%S)"
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将创建备份目录: $BACKUP_DIR"
        return
    fi
    
    mkdir -p "$BACKUP_DIR"
    
    # 备份各种防火墙规则
    {
        echo "=== iptables 规则 ==="
        iptables-save 2>/dev/null || echo "iptables备份失败"
        echo -e "\n=== ip6tables 规则 ==="
        ip6tables-save 2>/dev/null || echo "ip6tables备份失败"
        echo -e "\n=== nftables 规则 ==="
        nft list ruleset 2>/dev/null || echo "nftables备份失败"
        echo -e "\n=== UFW 状态 ==="
        ufw status numbered 2>/dev/null || echo "ufw状态获取失败"
    } > "$BACKUP_DIR/firewall_rules_backup.txt"
    
    # 备份当前网络状态
    ss -tulnp > "$BACKUP_DIR/listening_ports.txt" 2>/dev/null || true
    netstat -tulnp > "$BACKUP_DIR/netstat_output.txt" 2>/dev/null || true
    lsof -i > "$BACKUP_DIR/lsof_output.txt" 2>/dev/null || true
    
    # 备份系统服务状态
    systemctl list-units --type=service --state=running > "$BACKUP_DIR/running_services.txt" 2>/dev/null || true
    
    success "完整备份已保存到: $BACKUP_DIR"
}

# 彻底清理所有防火墙规则
complete_firewall_cleanup() {
    highlight "开始彻底清理所有防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将彻底清理所有防火墙规则"
        info "[预演] - 清理 iptables 规则"
        info "[预演] - 清理 ip6tables 规则"
        info "[预演] - 清理 nftables 规则"
        info "[预演] - 重置 UFW"
        info "[预演] - 停止相关服务"
        return
    fi
    
    # 停止相关防火墙服务
    echo -e "${YELLOW}停止防火墙服务...${RESET}"
    systemctl stop ufw 2>/dev/null || true
    systemctl stop firewalld 2>/dev/null || true
    systemctl stop nftables 2>/dev/null || true
    systemctl disable firewalld 2>/dev/null || true
    systemctl disable nftables 2>/dev/null || true
    
    # 清理 nftables 规则
    echo -e "${YELLOW}清理 nftables 规则...${RESET}"
    nft flush ruleset 2>/dev/null || true
    
    # 清理 iptables 规则 (IPv4)
    echo -e "${YELLOW}清理 iptables 规则...${RESET}"
    iptables -F 2>/dev/null || true
    iptables -X 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t nat -X 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true
    iptables -t mangle -X 2>/dev/null || true
    iptables -t raw -F 2>/dev/null || true
    iptables -t raw -X 2>/dev/null || true
    iptables -t security -F 2>/dev/null || true
    iptables -t security -X 2>/dev/null || true
    
    # 重置默认策略
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    
    # 清理 ip6tables 规则 (IPv6)
    echo -e "${YELLOW}清理 ip6tables 规则...${RESET}"
    ip6tables -F 2>/dev/null || true
    ip6tables -X 2>/dev/null || true
    ip6tables -t nat -F 2>/dev/null || true
    ip6tables -t nat -X 2>/dev/null || true
    ip6tables -t mangle -F 2>/dev/null || true
    ip6tables -t mangle -X 2>/dev/null || true
    ip6tables -t raw -F 2>/dev/null || true
    ip6tables -t raw -X 2>/dev/null || true
    ip6tables -t security -F 2>/dev/null || true
    ip6tables -t security -X 2>/dev/null || true
    
    # 重置IPv6默认策略
    ip6tables -P INPUT ACCEPT 2>/dev/null || true
    ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
    
    # 完全重置 UFW
    echo -e "${YELLOW}重置 UFW...${RESET}"
    ufw --force reset >/dev/null 2>&1 || true
    
    # 清理可能的其他防火墙配置文件
    rm -f /etc/iptables/rules.v4 2>/dev/null || true
    rm -f /etc/iptables/rules.v6 2>/dev/null || true
    
    success "所有防火墙规则已彻底清理"
}

# 智能分析监听端口
analyze_listening_ports() {
    highlight "智能分析当前监听端口..."
    
    # 清空数组
    LISTENING_PORTS=()
    PORT_PROCESSES=()
    PORT_PROTOCOLS=()
    
    echo -e "${YELLOW}正在扫描监听端口...${RESET}"
    
    # 使用ss命令获取监听端口信息
    while IFS= read -r line; do
        if [[ $line =~ LISTEN ]]; then
            # 解析端口信息
            if [[ $line =~ :([0-9]+)[[:space:]] ]]; then
                local port="${BASH_REMATCH[1]}"
                
                # 解析协议
                local protocol="tcp"
                if [[ $line =~ ^udp ]]; then
                    protocol="udp"
                fi
                
                # 解析进程信息
                local process="unknown"
                if [[ $line =~ users:\(\(\"([^\"]+)\" ]]; then
                    process="${BASH_REMATCH[1]}"
                elif [[ $line =~ users:\(\(\"([^,]+), ]]; then
                    process="${BASH_REMATCH[1]}"
                fi
                
                # 去掉进程名中的路径
                process=$(basename "$process" 2>/dev/null || echo "$process")
                
                # 存储信息
                LISTENING_PORTS["$port:$protocol"]=1
                PORT_PROCESSES["$port:$protocol"]="$process"
                PORT_PROTOCOLS["$port"]="$protocol"
                
                ANALYZED_PORTS=$((ANALYZED_PORTS + 1))
                debug_log "发现监听端口: $port/$protocol ($process)"
            fi
        fi
    done < <(ss -tulnp 2>/dev/null)
    
    # 如果ss失败，尝试使用netstat
    if [ ${#LISTENING_PORTS[@]} -eq 0 ]; then
        warning "ss命令未找到监听端口，尝试使用netstat..."
        while IFS= read -r line; do
            if [[ $line =~ LISTEN ]]; then
                if [[ $line =~ :([0-9]+)[[:space:]] ]]; then
                    local port="${BASH_REMATCH[1]}"
                    local protocol="tcp"
                    
                    # 获取进程信息
                    local process="unknown"
                    if [[ $line =~ ([^[:space:]]+)$ ]]; then
                        process="${BASH_REMATCH[1]}"
                        process=$(echo "$process" | cut -d'/' -f2)
                    fi
                    
                    LISTENING_PORTS["$port:$protocol"]=1
                    PORT_PROCESSES["$port:$protocol"]="$process"
                    PORT_PROTOCOLS["$port"]="$protocol"
                    
                    ANALYZED_PORTS=$((ANALYZED_PORTS + 1))
                fi
            fi
        done < <(netstat -tulnp 2>/dev/null)
    fi
    
    success "端口分析完成，发现 $ANALYZED_PORTS 个监听端口"
}

# 根据服务规则分类端口
classify_ports() {
    highlight "根据服务规则分类端口..."
    
    # 清空批准端口列表
    APPROVED_PORTS=()
    
    echo -e "\n${CYAN}=== 端口分类分析 ===${RESET}"
    
    for port_proto in "${!LISTENING_PORTS[@]}"; do
        IFS=: read -r port protocol <<< "$port_proto"
        local process="${PORT_PROCESSES[$port_proto]}"
        
        # 默认处理策略
        local action="DENY"
        local reason="未知服务"
        local color="$RED"
        
        # SSH端口检测
        if [ "$port" = "$SSH_PORT" ] || [[ $process =~ sshd|dropbear ]]; then
            action="SSH"
            reason="SSH服务"
            color="$GREEN"
            APPROVED_PORTS["$port:$protocol"]="SSH"
        # 根据进程名匹配服务规则
        else
            for service in "${!SERVICE_RULES[@]}"; do
                if [[ $process =~ $service ]]; then
                    action="${SERVICE_RULES[$service]}"
                    reason="$service 服务"
                    break
                fi
            done
            
            # 设置颜色和处理
            case "$action" in
                "ALLOW")
                    color="$GREEN"
                    APPROVED_PORTS["$port:$protocol"]="ALLOW"
                    ;;
                "SSH")
                    color="$GREEN"
                    APPROVED_PORTS["$port:$protocol"]="SSH"
                    ;;
                "DNS")
                    color="$YELLOW"
                    # DNS服务需要谨慎处理，默认允许但会提示
                    APPROVED_PORTS["$port:$protocol"]="ALLOW"
                    reason="$reason (谨慎开放)"
                    ;;
                "INTERNAL")
                    color="$BLUE"
                    reason="$reason (仅内网)"
                    ;;
                "DENY")
                    color="$RED"
                    reason="$reason (拒绝外网)"
                    BLOCKED_PORTS=$((BLOCKED_PORTS + 1))
                    ;;
            esac
        fi
        
        echo -e "${color}  [$action] $port/$protocol - $process ($reason)${RESET}"
    done
    
    echo -e "\n${YELLOW}分类统计：${RESET}"
    echo -e "${GREEN}  • 将开放到外网: ${#APPROVED_PORTS[@]} 个端口${RESET}"
    echo -e "${RED}  • 将阻止外网访问: $BLOCKED_PORTS 个端口${RESET}"
}

# 检测SSH端口
detect_ssh_port() {
    debug_log "开始检测SSH端口"
    local ssh_port="22"
    
    # 方法1: 检查当前SSH连接
    if [ -n "$SSH_CONNECTION" ]; then
        local conn_port=$(echo "$SSH_CONNECTION" | awk '{print $4}')
        if [[ "$conn_port" =~ ^[0-9]+$ ]] && [ "$conn_port" -gt 0 ] && [ "$conn_port" -le 65535 ]; then
            ssh_port="$conn_port"
            debug_log "从SSH_CONNECTION检测到端口: $ssh_port"
        fi
    fi
    
    # 方法2: 检查SSH配置文件
    if [ -f "/etc/ssh/sshd_config" ]; then
        local config_port=$(grep "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
        if [[ "$config_port" =~ ^[0-9]+$ ]] && [ "$config_port" -gt 0 ] && [ "$config_port" -le 65535 ]; then
            ssh_port="$config_port"
            debug_log "从配置文件检测到端口: $ssh_port"
        fi
    fi
    
    # 方法3: 从监听端口中查找SSH进程
    for port_proto in "${!LISTENING_PORTS[@]}"; do
        IFS=: read -r port protocol <<< "$port_proto"
        local process="${PORT_PROCESSES[$port_proto]}"
        if [[ $process =~ sshd|dropbear ]] && [ "$protocol" = "tcp" ]; then
            ssh_port="$port"
            debug_log "从监听端口检测到SSH: $ssh_port"
            break
        fi
    done
    
    echo "$ssh_port"
}

# 配置基础防火墙规则
setup_basic_firewall() {
    debug_log "配置基础防火墙规则"
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将设置UFW基础策略"
        info "[预演] - 默认拒绝入站连接"
        info "[预演] - 默认允许出站连接"
        info "[预演] - 启用IPv6支持"
        return
    fi
    
    echo -e "${YELLOW}配置基础安全策略...${RESET}"
    
    # 启用IPv6支持
    if [ -f /etc/default/ufw ]; then
        sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw 2>/dev/null || true
    fi
    
    # 设置默认策略
    ufw default deny incoming >/dev/null 2>&1 || error_exit "无法设置默认入站策略"
    ufw default allow outgoing >/dev/null 2>&1 || error_exit "无法设置默认出站策略"
    ufw default deny forward >/dev/null 2>&1 || true
    
    # 允许loopback接口
    ufw allow in on lo >/dev/null 2>&1 || true
    ufw allow out on lo >/dev/null 2>&1 || true
    
    success "基础防火墙策略已配置"
}

# 开放批准的端口
open_approved_ports() {
    highlight "开放已批准的端口..."
    
    if [ ${#APPROVED_PORTS[@]} -eq 0 ]; then
        warning "没有端口需要开放"
        return
    fi
    
    echo -e "${YELLOW}正在开放端口...${RESET}"
    
    for port_proto in "${!APPROVED_PORTS[@]}"; do
        IFS=: read -r port protocol <<< "$port_proto"
        local process="${PORT_PROCESSES[$port_proto]}"
        local action="${APPROVED_PORTS[$port_proto]}"
        
        if [ "$DRY_RUN" = true ]; then
            if [ "$action" = "SSH" ]; then
                info "[预演] 将开放SSH端口: $port/$protocol (限制连接频率)"
            else
                info "[预演] 将开放端口: $port/$protocol ($process)"
            fi
            continue
        fi
        
        debug_log "开放端口: $port/$protocol ($process) - $action"
        
        if [ "$action" = "SSH" ]; then
            # SSH端口使用limit规则防止暴力破解
            if ufw limit "$port/$protocol" comment "SSH-$process" >/dev/null 2>&1; then
                success "✓ SSH端口: $port/$protocol ($process) [限速保护]"
                OPENED_PORTS=$((OPENED_PORTS + 1))
            else
                warning "❌ 无法开放SSH端口: $port/$protocol"
            fi
        else
            # 普通端口
            if ufw allow "$port/$protocol" comment "$process" >/dev/null 2>&1; then
                success "✓ 已开放: $port/$protocol ($process)"
                OPENED_PORTS=$((OPENED_PORTS + 1))
            else
                warning "❌ 无法开放端口: $port/$protocol"
            fi
        fi
    done
}

# 添加高级安全规则
add_advanced_security_rules() {
    highlight "配置高级安全防护..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将添加反DDoS规则"
        info "[预演] 将阻止危险端口扫描"
        info "[预演] 将配置连接限制"
        return
    fi
    
    echo -e "${YELLOW}添加安全防护规则...${RESET}"
    
    # 阻止常见的恶意端口
    local malicious_ports=(
        "135" "137" "138" "139" "445"    # Windows文件共享
        "1433" "1521" "3306" "5432"      # 数据库端口
        "3389" "5900" "5901"             # 远程桌面
        "23" "69" "111" "161" "162"      # 不安全的服务
        "1900" "5353" "11211"            # 可被滥用的服务
        "27017" "27018" "27019"          # MongoDB默认端口
        "6379"                           # Redis默认端口
    )
    
    for port in "${malicious_ports[@]}"; do
        ufw deny "$port" comment "Block-Malicious" >/dev/null 2>&1 || true
    done
    
    # 使用iptables添加更细致的保护
    # 防止TCP SYN flood攻击
    iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP 2>/dev/null || true
    
    # 丢弃无效数据包
    iptables -A INPUT -m state --state INVALID -j DROP 2>/dev/null || true
    iptables -A FORWARD -m state --state INVALID -j DROP 2>/dev/null || true
    iptables -A OUTPUT -m state --state INVALID -j DROP 2>/dev/null || true
    
    # 防止分片攻击
    iptables -A INPUT -f -j DROP 2>/dev/null || true
    
    # 防止XMAS和NULL包攻击
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP 2>/dev/null || true
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP 2>/dev/null || true
    
    # 限制ICMP ping
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 3 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || true
    
    success "高级安全规则配置完成"
}

# 配置Fail2Ban高级保护
setup_advanced_fail2ban() {
    debug_log "配置Fail2Ban高级保护"
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将配置Fail2Ban服务"
        info "[预演] - SSH暴破保护"
        info "[预演] - Web服务保护"
        info "[预演] - 代理服务保护"
        return
    fi
    
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        warning "Fail2Ban未安装，跳过配置"
        return
    fi
    
    echo -e "${YELLOW}配置Fail2Ban高级保护...${RESET}"
    
    # 停止fail2ban以便重新配置
    systemctl stop fail2ban 2>/dev/null || true
    
    # 创建增强版fail2ban配置
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# 基本设置
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
banaction = ufw
banaction_allports = ufw

# 忽略本地IP
ignoreip = 127.0.0.1/8 ::1

# SSH保护 - 更严格的设置
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 24h
findtime = 10m

# Nginx/Apache保护
[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/*error.log
          /var/log/apache2/*error.log
maxretry = 3
bantime = 6h

[nginx-noscript]
enabled = true
filter = nginx-noscript
logpath = /var/log/nginx/*access.log
maxretry = 6
bantime = 6h

[nginx-badbots]
enabled = true
filter = nginx-badbots
logpath = /var/log/nginx/*access.log
maxretry = 2
bantime = 12h

[nginx-req-limit]
enabled = true
filter = nginx-req-limit
logpath = /var/log/nginx/*error.log
maxretry = 10
findtime = 60
bantime = 1h

# 代理服务保护
[proxy-connect]
enabled = true
port = 80,443,8080,8443
protocol = tcp
filter = apache-common
logpath = /var/log/nginx/*access.log
          /var/log/apache2/*access.log
maxretry = 20
findtime = 60
bantime = 6h

# 通用端口扫描保护
[port-scan]
enabled = true
filter = port-scan
logpath = /var/log/syslog
maxretry = 1
bantime = 24h

EOF

    # 创建端口扫描过滤器
    cat > /etc/fail2ban/filter.d/port-scan.conf << 'EOF'
[Definition]
failregex = UFW BLOCK.*SRC=<HOST>
ignoreregex =
EOF

    # 启动fail2ban
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl start fail2ban >/dev/null 2>&1 || true
    
    # 等待服务启动
    sleep 2
    
    # 验证fail2ban状态
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        success "Fail2Ban高级保护已配置并启动"
    else
        warning "Fail2Ban启动失败，请手动检查配置"
    fi
}

# 启用防火墙和优化设置
enable_optimized_firewall() {
    debug_log "启用防火墙并优化设置"
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将启用UFW防火墙"
        info "[预演] 将优化内核网络参数"
        return
    fi
    
    echo -e "${YELLOW}启用防火墙并优化系统...${RESET}"
    
    # 启用UFW
    if ufw --force enable >/dev/null 2>&1; then
        success "✓ UFW防火墙已启用"
    else
        error_exit "无法启用UFW防火墙"
    fi
    
    # 设置开机自启动
    systemctl enable ufw >/dev/null 2>&1 || true
    
    # 优化网络内核参数以提高安全性
    cat > /etc/sysctl.d/99-firewall-security.conf << EOF
# 网络安全优化参数
# 防止SYN flood攻击
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# 防止IP欺骗
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 不接受ICMP重定向
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# 不发送ICMP重定向
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# 不接受源路由
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# 记录可疑数据包
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# 忽略ping
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1

# 防止缓冲区溢出攻击
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# 连接跟踪优化
net.netfilter.nf_conntrack_max = 65536
net.netfilter.nf_conntrack_tcp_timeout_established = 1800

# 限制连接数
net.core.somaxconn = 1024
net.ipv4.tcp_max_orphans = 65536
net.ipv4.tcp_fin_timeout = 10
EOF

    # 应用sysctl设置
    sysctl -p /etc/sysctl.d/99-firewall-security.conf >/dev/null 2>&1 || true
    
    success "防火墙和系统优化配置完成"
}

# 验证防火墙配置
verify_firewall_configuration() {
    highlight "验证防火墙配置..."
    
    echo -e "${YELLOW}正在验证配置...${RESET}"
    
    local verification_passed=0
    local verification_failed=0
    
    # 验证UFW状态
    if ufw status | grep -q "Status: active"; then
        success "✓ UFW防火墙已激活"
        verification_passed=$((verification_passed + 1))
    else
        warning "❌ UFW防火墙未激活"
        verification_failed=$((verification_failed + 1))
    fi
    
    # 验证已开放的端口
    echo -e "\n${CYAN}验证已开放端口：${RESET}"
    for port_proto in "${!APPROVED_PORTS[@]}"; do
        IFS=: read -r port protocol <<< "$port_proto"
        local process="${PORT_PROCESSES[$port_proto]}"
        
        if ufw status | grep -q "$port/$protocol"; then
            success "✓ $port/$protocol ($process) - 规则存在"
            verification_passed=$((verification_passed + 1))
        else
            warning "❌ $port/$protocol ($process) - 规则缺失"
            verification_failed=$((verification_failed + 1))
        fi
    done
    
    # 验证Fail2Ban
    if command -v fail2ban-client >/dev/null 2>&1; then
        if systemctl is-active fail2ban >/dev/null 2>&1; then
            success "✓ Fail2Ban服务正在运行"
            verification_passed=$((verification_passed + 1))
            
            # 显示活跃的jail
            local active_jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | tr -d ',' | wc -w)
            if [ "$active_jails" -gt 0 ]; then
                success "✓ Fail2Ban活跃监狱: $active_jails 个"
            fi
        else
            warning "❌ Fail2Ban服务未运行"
            verification_failed=$((verification_failed + 1))
        fi
    fi
    
    echo -e "\n${YELLOW}验证统计：${RESET}"
    echo -e "${GREEN}  • 通过验证: $verification_passed 项${RESET}"
    echo -e "${RED}  • 验证失败: $verification_failed 项${RESET}"
    
    if [ $verification_failed -eq 0 ]; then
        success "所有验证项目都通过了！"
    else
        warning "部分验证项目未通过，请检查配置"
    fi
}

# 显示详细的安全报告
show_security_report() {
    echo -e "\n${MAGENTA}════════════════════════════════════════${RESET}"
    echo -e "${MAGENTA}🛡️  VPS安全防护配置报告${RESET}"
    echo -e "${MAGENTA}════════════════════════════════════════${RESET}"
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${CYAN}⚠️  这是预演模式报告，实际配置未被修改${RESET}"
    fi
    
    # 基本统计信息
    echo -e "\n${YELLOW}📊 配置统计：${RESET}"
    echo -e "${GREEN}  • 分析的监听端口: $ANALYZED_PORTS 个${RESET}"
    echo -e "${GREEN}  • 开放的外网端口: $OPENED_PORTS 个${RESET}"
    echo -e "${RED}  • 阻止的危险端口: $BLOCKED_PORTS 个${RESET}"
    
    # 显示开放的端口详情
    if [ ${#APPROVED_PORTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔓 已开放到外网的端口：${RESET}"
        for port_proto in "${!APPROVED_PORTS[@]}"; do
            IFS=: read -r port protocol <<< "$port_proto"
            local process="${PORT_PROCESSES[$port_proto]}"
            local action="${APPROVED_PORTS[$port_proto]}"
            
            if [ "$action" = "SSH" ]; then
                echo -e "${GREEN}  🔐 $port/$protocol - $process (SSH限速保护)${RESET}"
            else
                echo -e "${GREEN}  🌐 $port/$protocol - $process${RESET}"
            fi
        done
    fi
    
    # 显示被阻止的服务
    if [ $BLOCKED_PORTS -gt 0 ]; then
        echo -e "\n${RED}🚫 被阻止外网访问的端口：${RESET}"
        for port_proto in "${!LISTENING_PORTS[@]}"; do
            if [[ ! "${APPROVED_PORTS[$port_proto]}" ]]; then
                IFS=: read -r port protocol <<< "$port_proto"
                local process="${PORT_PROCESSES[$port_proto]}"
                echo -e "${RED}  ❌ $port/$protocol - $process (仅内网访问)${RESET}"
            fi
        done
    fi
    
    if [ "$DRY_RUN" = false ]; then
        # 显示当前防火墙规则
        echo -e "\n${YELLOW}🔥 当前防火墙规则：${RESET}"
        echo -e "${CYAN}"
        ufw status numbered 2>/dev/null || echo "无法获取UFW状态"
        echo -e "${RESET}"
        
        # Fail2Ban状态
        if command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active fail2ban >/dev/null 2>&1; then
            echo -e "\n${YELLOW}🛡️  Fail2Ban保护状态：${RESET}"
            fail2ban-client status 2>/dev/null || echo "无法获取Fail2Ban状态"
        fi
        
        # 备份信息
        if [ -n "$BACKUP_DIR" ]; then
            echo -e "\n${BLUE}💾 配置备份位置：${RESET}"
            echo -e "${CYAN}  $BACKUP_DIR${RESET}"
        fi
    fi
    
    # 安全建议
    echo -e "\n${YELLOW}💡 安全建议：${RESET}"
    echo -e "${CYAN}  • 定期更新系统和软件包${RESET}"
    echo -e "${CYAN}  • 监控 /var/log/ufw.log 查看被阻止的访问${RESET}"
    echo -e "${CYAN}  • 使用 fail2ban-client status 查看攻击统计${RESET}"
    echo -e "${CYAN}  • 考虑更换SSH默认端口以减少扫描${RESET}"
    echo -e "${CYAN}  • 定期检查 ss -tulnp 确认服务状态${RESET}"
    
    # 管理命令
    echo -e "\n${YELLOW}🔧 常用管理命令：${RESET}"
    echo -e "${CYAN}  • 查看防火墙状态: ufw status verbose${RESET}"
    echo -e "${CYAN}  • 查看防火墙日志: tail -f /var/log/ufw.log${RESET}"
    echo -e "${CYAN}  • 查看Fail2Ban状态: fail2ban-client status${RESET}"
    echo -e "${CYAN}  • 查看被ban的IP: fail2ban-client status sshd${RESET}"
    echo -e "${CYAN}  • 手动ban IP: fail2ban-client set sshd banip <IP>${RESET}"
    echo -e "${CYAN}  • 解封IP: fail2ban-client set sshd unbanip <IP>${RESET}"
    
    # 重要警告
    echo -e "\n${RED}⚠️  重要提醒：${RESET}"
    echo -e "${YELLOW}  • 请确保SSH连接正常后再断开当前会话${RESET}"
    echo -e "${YELLOW}  • 如果SSH端口被意外阻止，请通过VPS控制台访问${RESET}"
    echo -e "${YELLOW}  • 建议保持一个备用的SSH连接以防配置错误${RESET}"
    echo -e "${YELLOW}  • 新增服务时记得更新防火墙规则${RESET}"
    
    echo -e "\n${GREEN}🎉 VPS防火墙安全配置完成！${RESET}"
    echo -e "${MAGENTA}════════════════════════════════════════${RESET}"
}

# 主函数
main() {
    echo -e "${YELLOW}开始智能VPS防火墙配置...${RESET}"
    echo -e "${CYAN}此脚本将：${RESET}"
    echo -e "${CYAN}  ✓ 彻底清理所有旧防火墙规则${RESET}"
    echo -e "${CYAN}  ✓ 智能分析当前监听端口${RESET}"
    echo -e "${CYAN}  ✓ 只开放必要的服务端口${RESET}"
    echo -e "${CYAN}  ✓ 配置高级安全防护${RESET}"
    echo -e "${CYAN}  ✓ 提供详细的安全报告${RESET}"
    
    # 确认操作
    if [ "$FORCE_MODE" = false ] && [ "$DRY_RUN" = false ]; then
        echo -e "\n${YELLOW}⚠️  警告：此操作将完全重置防火墙配置！${RESET}"
        read -p "是否继续？(y/N): " -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${RED}操作已取消${RESET}"
            exit 0
        fi
    fi
    
    echo -e "\n${YELLOW}开始执行配置...${RESET}"
    
    # 1. 解析参数
    parse_arguments "$@"
    
    # 2. 检查系统环境
    echo -e "\n${YELLOW}1️⃣ 检查系统环境...${RESET}"
    check_system
    
    # 3. 安装依赖
    echo -e "\n${YELLOW}2️⃣ 安装必要工具...${RESET}"
    install_dependencies
    
    # 4. 创建备份
    echo -e "\n${YELLOW}3️⃣ 备份现有配置...${RESET}"
    create_backup
    
    # 5. 彻底清理防火墙
    echo -e "\n${YELLOW}4️⃣ 彻底清理防火墙规则...${RESET}"
    complete_firewall_cleanup
    
    # 6. 智能分析监听端口
    echo -e "\n${YELLOW}5️⃣ 智能分析监听端口...${RESET}"
    analyze_listening_ports
    
    # 7. 检测SSH端口
    echo -e "\n${YELLOW}6️⃣ 检测SSH配置...${RESET}"
    SSH_PORT=$(detect_ssh_port)
    success "SSH端口: $SSH_PORT"
    
    # 8. 分类端口
    echo -e "\n${YELLOW}7️⃣ 分类分析端口...${RESET}"
    classify_ports
    
    # 9. 配置基础防火墙
    echo -e "\n${YELLOW}8️⃣ 配置基础防火墙...${RESET}"
    setup_basic_firewall
    
    # 10. 开放批准的端口
    echo -e "\n${YELLOW}9️⃣ 开放必要端口...${RESET}"
    open_approved_ports
    
    # 11. 添加安全规则
    echo -e "\n${YELLOW}🔟 配置高级安全防护...${RESET}"
    add_advanced_security_rules
    
    # 12. 配置Fail2Ban
    echo -e "\n${YELLOW}1️⃣1️⃣ 配置Fail2Ban保护...${RESET}"
    setup_advanced_fail2ban
    
    # 13. 启用防火墙
    echo -e "\n${YELLOW}1️⃣2️⃣ 启用防火墙和优化...${RESET}"
    enable_optimized_firewall
    
    # 14. 验证配置
    echo -e "\n${YELLOW}1️⃣3️⃣ 验证防火墙配置...${RESET}"
    verify_firewall_configuration
    
    # 15. 显示安全报告
    show_security_report
}

# 信号处理 - 清理函数
cleanup_on_exit() {
    echo -e "\n${RED}⚠️  脚本被中断${RESET}"
    if [ -n "$BACKUP_DIR" ] && [ "$DRY_RUN" = false ]; then
        echo -e "${YELLOW}如需恢复，备份文件位于: $BACKUP_DIR${RESET}"
    fi
    exit 1
}

# 设置信号处理
trap cleanup_on_exit INT TERM

# 检查是否直接运行脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
