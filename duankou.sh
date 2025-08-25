#!/bin/bash
set -e

# 颜色定义
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

# 脚本信息
SCRIPT_VERSION="5.2 (修复版)"
SCRIPT_NAME="代理服务器智能防火墙脚本 (nftables版)"

echo -e "${YELLOW}== 🔥 ${SCRIPT_NAME} v${SCRIPT_VERSION} ==${RESET}"

# 检查 root 权限
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}❌ 请用 root 权限运行此脚本${RESET}"
    exit 1
fi

# 全局变量
DEBUG_MODE=false
FORCE_MODE=false
DRY_RUN=false
SSH_PORT=""
OPENED_PORTS=0
SKIPPED_PORTS=0

# 端口记录数组
declare -a OPENED_PORTS_LIST=()
declare -a SKIPPED_PORTS_LIST=()

# 新增全局数组，用于存储从配置文件中检测到的端口
declare -a CONFIG_PORTS_LIST=()

# ==============================================================================
# 核心配置数据库
# ==============================================================================

# 代理软件核心进程名 (严格筛选)
PROXY_PROCESSES=(
    "xray" "v2ray" "sing-box" "hysteria" "hysteria2" "tuic"
    "trojan-go" "trojan" "naive" "shadowsocks-rust" "ss-server"
    "brook" "gost" "juicity" "shadowtls"
)

# Web服务器进程
WEB_PROCESSES=(
    "nginx" "apache2" "httpd" "caddy" "haproxy" "lighttpd"
)

# 代理软件进程模式匹配
PROXY_PATTERNS=(
    ".*ray.*"           # xray, v2ray
    ".*hysteria.*"      # hysteria系列
    ".*trojan.*"        # trojan系列
    ".*shadowsocks.*"   # shadowsocks系列
    "ss-server"         # shadowsocks server
    "tuic-.*"          # tuic系列
    "sing-box"         # sing-box
)

# 配置文件路径
CONFIG_PATHS=(
    "/usr/local/etc/xray/config.json"
    "/etc/xray/config.json"
    "/usr/local/etc/v2ray/config.json"
    "/etc/v2ray/config.json"
    "/etc/sing-box/config.json"
    "/opt/hiddify/config.json"
    "/etc/hysteria/config.json"
    "/etc/tuic/config.json"
    "/etc/trojan/config.json"
)

# 系统保留端口 (不应该对外开放的)
SYSTEM_RESERVED_PORTS=(
    53    # DNS (通常只需内部)
    67 68 # DHCP
    123   # NTP
    135   # Windows RPC
    137 138 139 # NetBIOS
    445   # SMB
    546 547 # DHCPv6
    631   # CUPS
    5353  # mDNS
    49152-65535 # 临时端口范围上半部分
)

# 明确危险的端口 (需要用户确认)
DANGEROUS_PORTS=(
    23    # Telnet
    1433  # MSSQL
    1521  # Oracle
    3306  # MySQL
    3389  # RDP
    5432  # PostgreSQL
    6379  # Redis
    27017 # MongoDB
)

# ==============================================================================
# 辅助函数
# ==============================================================================

debug_log() { if [ "$DEBUG_MODE" = true ]; then echo -e "${BLUE}[DEBUG] $1${RESET}" >&2; fi; }
error_exit() { echo -e "${RED}❌ 错误: $1${RESET}" >&2; exit 1; }
warning() { echo -e "${YELLOW}⚠️  警告: $1${RESET}" >&2; }
success() { echo -e "${GREEN}✓ $1${RESET}"; }
info() { echo -e "${CYAN}ℹ️  $1${RESET}"; }

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug) DEBUG_MODE=true; info "调试模式已启用"; shift ;;
            --force) FORCE_MODE=true; info "强制模式已启用"; shift ;;
            --dry-run) DRY_RUN=true; info "预演模式已启用"; shift ;;
            --help|-h) show_help; exit 0 ;;
            *) error_exit "未知参数: $1" ;;
        es-ac
    done
}

show_help() {
    cat << EOF
${SCRIPT_NAME} v${SCRIPT_VERSION}

专为代理服务器设计的智能防火墙配置脚本，使用nftables提供更好的性能和端口范围支持。

用法: sudo $0 [选项]

选项:
    --debug      启用调试模式
    --force      强制模式，跳过危险端口确认
    --dry-run    预演模式，不实际修改防火墙
    --help, -h   显示帮助信息

特性:
    ✓ 智能识别代理软件端口 (Xray, V2Ray, Sing-box, Hysteria2, TUIC等)
    ✓ 支持端口范围和端口跳跃
    ✓ 自动过滤系统保留端口
    ✓ nftables高性能防火墙规则
    ✓ SSH暴力破解防护

示例:
    bash <(curl -sSL your-script-url)
    sudo ./firewall.sh --debug --dry-run
EOF
}

# ==============================================================================
# 系统检查与环境准备
# ==============================================================================

check_system() {
    info "检查系统环境..."
    
    if ! command -v ss >/dev/null 2>&1; then 
        error_exit "缺少 'ss' 命令，请安装 'iproute2'"
    fi

    # [修复] 检查并安装 jq
    if ! command -v jq >/dev/null 2>&1; then
        info "缺少 'jq' 命令，尝试安装以支持配置文件解析..."
        if [ "$DRY_RUN" = true ]; then
            info "[预演] 将安装 jq"
        else
            if command -v apt-get >/dev/null 2>&1; then 
                apt-get update -y && apt-get install -y jq
            elif command -v dnf >/dev/null 2>&1; then 
                dnf install -y jq
            elif command -v yum >/dev/null 2>&1; then 
                yum install -y jq
            else 
                warning "无法自动安装 jq，配置文件端口检测功能将无法使用"
            fi
        fi
    fi
    
    if ! command -v nft >/dev/null 2>&1; then
        info "安装 nftables..."
        if [ "$DRY_RUN" = true ]; then 
            info "[预演] 将安装 nftables"
        else
            if command -v apt-get >/dev/null 2>&1; then 
                apt-get update -y && apt-get install -y nftables
            elif command -v dnf >/dev/null 2>&1; then 
                dnf install -y nftables
            elif command -v yum >/dev/null 2>&1; then 
                yum install -y nftables
            else 
                error_exit "无法自动安装 nftables"
            fi
        fi
    fi
    
    success "系统环境检查完成"
}

cleanup_existing_firewalls() {
    info "清理现有防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then 
        info "[预演] 将停止并禁用 ufw, firewalld"
        info "[预演] 将清空所有 iptables 和 nftables 规则"
        return
    fi
    
    # 停止 UFW
    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >/dev/null 2>&1 || true
        ufw --force disable >/dev/null 2>&1 || true
    fi
    
    # 停止 firewalld
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        systemctl stop firewalld >/dev/null 2>&1 || true
        systemctl disable firewalld >/dev/null 2>&1 || true
    fi
    
    # 清空 iptables
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    iptables -F 2>/dev/null || true
    iptables -X 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true
    
    # IPv6
    ip6tables -P INPUT ACCEPT 2>/dev/null || true
    ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
    ip6tables -F 2>/dev/null || true
    ip6tables -X 2>/dev/null || true
    
    # 清空 nftables
    nft flush ruleset 2>/dev/null || true
    
    success "防火墙清理完成"
}

# ==============================================================================
# 端口检测与分析
# ==============================================================================

detect_ssh_port() {
    debug_log "检测SSH端口..."
    local ssh_port
    
    # 通过监听进程检测
    ssh_port=$(ss -tlnp 2>/dev/null | grep -E 'sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -n 1)
    if [[ "$ssh_port" =~ ^[0-9]+$ ]] && [ "$ssh_port" -ge 1 ] && [ "$ssh_port" -le 65535 ]; then 
        echo "$ssh_port"
        return
    fi
    
    # 通过配置文件检测
    if [ -f /etc/ssh/sshd_config ]; then
        ssh_port=$(grep -i '^[[:space:]]*Port' /etc/ssh/sshd_config | awk '{print $2}' | head -n 1)
        if [[ "$ssh_port" =~ ^[0-9]+$ ]]; then 
            echo "$ssh_port"
            return
        fi
    fi
    
    # 通过环境变量检测
    if [ -n "$SSH_CONNECTION" ]; then
        ssh_port=$(echo "$SSH_CONNECTION" | awk '{print $4}')
        if [[ "$ssh_port" =~ ^[0-9]+$ ]]; then 
            echo "$ssh_port"
            return
        fi
    fi
    
    echo "22"
}

get_listening_ports() {
    ss -tulnp 2>/dev/null | awk '
    /LISTEN|UNCONN/ {
        protocol = tolower($1)
        address_port = $5
        process = "unknown"
        pid = ""
        
        # 解析进程信息
        if (match($0, /users:\(\("([^"]+)",[^,]*,([0-9]+)/, p)) {
            process = p[1]
            pid = p[2]
        }
        
        # 解析地址和端口
        if (match(address_port, /^(.*):([0-9]+)$/, parts)) {
            address = parts[1]
            port = parts[2]
            
            # 处理IPv6格式
            if (address ~ /^\[.*\]$/) {
                address = substr(address, 2, length(address)-2)
            }
            if (address == "*") address = "0.0.0.0"
            
            if (port > 0 && port <= 65535) {
                print protocol ":" port ":" address ":" process ":" pid
            }
        }
    }'
}

# [修复] 新增函数：从配置文件中解析端口
get_ports_from_config() {
    if ! command -v jq >/dev/null 2>&1; then
        return
    fi
    
    info "正在从代理配置文件中解析端口..."
    
    for config_file in "${CONFIG_PATHS[@]}"; do
        if [ -f "$config_file" ]; then
            debug_log "解析文件: $config_file"
            
            # 使用 jq 解析并提取端口
            local ports
            # 兼容多种格式：listen:port, port, inbounds[].port 等
            ports=$(jq -r '[.inbounds[]? | select(.port!=null) | .port, .inbounds[]? | select(.listen!=null) | .listen, .listen_port? // null] | flatten | unique | .[] | select(type=="number" or (type=="string" and (test("^[0-9]+$") or test("^[0-9]+-[0-9]+$"))))' "$config_file" 2>/dev/null)
            
            if [ -n "$ports" ]; then
                for port in $ports; do
                    # 处理端口范围
                    if [[ "$port" == *"-"* ]]; then
                        local start=${port%-*}
                        local end=${port#*-}
                        for ((p=start; p<=end; p++)); do
                            CONFIG_PORTS_LIST+=("$p")
                        done
                    else
                        CONFIG_PORTS_LIST+=("$port")
                    fi
                done
            fi
        fi
    done
    
    # 去重
    CONFIG_PORTS_LIST=($(printf "%s\n" "${CONFIG_PORTS_LIST[@]}" | sort -u))
    
    if [ ${#CONFIG_PORTS_LIST[@]} -gt 0 ]; then
        info "从配置文件中找到以下端口: ${CONFIG_PORTS_LIST[*]}"
    fi
}

is_public_listener() {
    local address="$1"
    case "$address" in 
        "127.0.0.1"|"::1"|"localhost"|127.*) return 1 ;;
        *) return 0 ;;
    esac
}

is_system_reserved_port() {
    local port="$1"
    for reserved in "${SYSTEM_RESERVED_PORTS[@]}"; do
        if [[ "$reserved" == *"-"* ]]; then
            # 端口范围检查
            local start="${reserved%-*}"
            local end="${reserved#*-}"
            if [ "$port" -ge "$start" ] && [ "$port" -le "$end" ]; then
                return 0
            fi
        elif [ "$port" = "$reserved" ]; then
            return 0
        fi
    done
    return 1
}

# [修复] 增加对Web服务器进程的识别
is_proxy_or_web_process() {
    local process="$1"
    local pid="$2"
    
    # 精确匹配
    for proxy_proc in "${PROXY_PROCESSES[@]}" "${WEB_PROCESSES[@]}"; do
        if [[ "$process" == "$proxy_proc" ]]; then
            debug_log "进程 '$process' 匹配代理或Web软件 (精确)"
            return 0
        fi
    done
    
    # 模式匹配
    for pattern in "${PROXY_PATTERNS[@]}"; do
        if [[ "$process" =~ $pattern ]]; then
            debug_log "进程 '$process' 匹配代理模式 '$pattern'"
            return 0
        fi
    done
    
    # 检查完整命令行
    if [ -n "$pid" ] && [ -f "/proc/$pid/cmdline" ]; then
        local cmdline
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        
        for proxy_proc in "${PROXY_PROCESSES[@]}" "${WEB_PROCESSES[@]}"; do
            if [[ "$cmdline" == *"$proxy_proc"* ]]; then
                debug_log "进程命令行包含代理或Web软件: $proxy_proc"
                return 0
            fi
        done
        
        # 检查配置文件路径
        for config_path in "${CONFIG_PATHS[@]}"; do
            if [[ "$cmdline" == *"$config_path"* ]]; then
                debug_log "进程使用代理配置文件: $config_path"
                return 0
            fi
        done
    fi
    
    return 1
}

is_dangerous_port() {
    local port="$1"
    for dangerous in "${DANGEROUS_PORTS[@]}"; do
        if [ "$port" = "$dangerous" ]; then
            return 0
        fi
    done
    return 1
}

analyze_port() {
    local protocol=$1 port=$2 address=$3 process=$4 pid=$5
    
    debug_log "分析端口: $protocol/$port, 地址: $address, 进程: $process"
    
    # SSH端口跳过
    if [ "$port" = "$SSH_PORT" ]; then 
        echo "skip:SSH端口单独处理"
        return
    fi
    
    # 非公网监听跳过
    if ! is_public_listener "$address"; then 
        echo "skip:内部监听($address)"
        return
    fi
    
    # 系统保留端口跳过
    if is_system_reserved_port "$port"; then
        echo "skip:系统保留端口"
        return
    fi
    
    # [修复] 优先级最高：检查是否为配置文件中定义的端口
    if [[ " ${CONFIG_PORTS_LIST[@]} " =~ " $port " ]]; then
        echo "open:配置文件定义($process)"
        return
    fi
    
    # 代理或Web进程端口开放
    if is_proxy_or_web_process "$process" "$pid"; then
        echo "open:代理或Web服务($process)"
        return
    fi
    
    # 危险端口需要确认
    if is_dangerous_port "$port"; then
        if [ "$FORCE_MODE" = true ]; then
            echo "open:危险端口(强制模式)"
            return
        else
            warning "检测到危险端口 $port，进程: $process"
            read -p "确认开放此端口? [y/N]: " -r response
            if [[ "$response" =~ ^[yY]([eE][sS])?$ ]]; then
                echo "open:危险端口(用户确认)"
            else
                echo "skip:危险端口(用户拒绝)"
            fi
            return
        fi
    fi
    
    # 其他公网端口需要确认
    if [ "$FORCE_MODE" = true ]; then
        echo "open:公网服务(强制模式)"
    else
        warning "检测到公网监听端口 $port，进程: $process"
        read -p "开放此端口? [y/N]: " -r response
        if [[ "$response" =~ ^[yY]([eE][sS])?$ ]]; then
            echo "open:公网服务(用户确认)"
        else
            echo "skip:公网服务(用户拒绝)"
        fi
    fi
}

# ==============================================================================
# nftables 防火墙配置
# ==============================================================================

setup_nftables() {
    info "配置 nftables 防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then 
        info "[预演] 将创建 nftables 基础规则和SSH保护"
        return
    fi
    
    # 创建基础规则集
    cat > /tmp/nftables.conf << EOF
#!/usr/sbin/nft -f

# 清空现有规则
flush ruleset

# 定义主表
table inet filter {
    # SSH暴力破解保护集合
    set ssh_bruteforce {
        type ipv4_addr
        flags timeout, dynamic
        timeout 1h
        size 65536
    }
    
    # 输入链
    chain input {
        type filter hook input priority filter; policy drop;
        
        # 基础规则
        ct state invalid drop
        ct state {established, related} accept
        iif lo accept
        
        # ICMPv4/ICMPv6
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
        
        # SSH保护规则
        tcp dport $SSH_PORT ct state new \\
            add @ssh_bruteforce { ip saddr timeout 1h limit rate over 3/minute burst 3 packets } \\
            drop comment "SSH暴力破解保护"
        tcp dport $SSH_PORT accept comment "SSH访问"
        
        # 代理端口规则将在这里添加
        %PROXY_RULES%
        
        # 记录并丢弃其他包
        limit rate 1/minute log prefix "nft-drop: "
        drop
    }
    
    # 转发链
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
    
    # 输出链
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF
    
    success "nftables 基础规则已生成"
}

add_port_rule() {
    local port="$1"
    local protocol="$2"
    local comment="$3"
    
    if [ "$DRY_RUN" = true ]; then 
        info "[预演] 将添加规则: $protocol dport $port accept # $comment"
        return
    fi
    
    # 添加到临时规则文件
    echo "        $protocol dport $port accept comment \"$comment\"" >> /tmp/proxy_rules.tmp
}

apply_nftables_rules() {
    if [ "$DRY_RUN" = true ]; then 
        info "[预演] 将应用所有 nftables 规则并启用服务"
        return
    fi
    
    # 读取代理规则
    local proxy_rules=""
    if [ -f /tmp/proxy_rules.tmp ]; then
        proxy_rules=$(cat /tmp/proxy_rules.tmp)
        rm -f /tmp/proxy_rules.tmp
    fi
    
    # 替换规则占位符
    sed "s|%PROXY_RULES%|$proxy_rules|g" /tmp/nftables.conf > /etc/nftables.conf
    
    # 应用规则
    if nft -f /etc/nftables.conf; then
        success "nftables 规则应用成功"
    else
        error_exit "nftables 规则应用失败"
    fi
    
    # 启用服务
    systemctl enable nftables >/dev/null 2>&1 || true
    systemctl start nftables >/dev/null 2>&1 || true
    
    # 清理临时文件
    rm -f /tmp/nftables.conf
}

# ==============================================================================
# 主要处理流程
# ==============================================================================

process_ports() {
    info "开始分析监听端口..."
    
    # 初始化临时规则文件
    > /tmp/proxy_rules.tmp
    
    local port_data
    port_data=$(get_listening_ports)
    
    if [ -z "$port_data" ]; then 
        warning "未检测到监听端口"
        return
    fi
    
    local total_ports
    total_ports=$(echo "$port_data" | wc -l)
    info "检测到 $total_ports 个监听端口"
    
    # [修复] 修复子shell问题，使用进程替换 < <(...)
    while IFS=: read -r protocol port address process pid; do
        [ -z "$port" ] && continue
        
        local result
        result=$(analyze_port "$protocol" "$port" "$address" "$process" "$pid")
        local action="${result%%:*}"
        local reason="${result#*:}"

        # 记录处理结果到临时文件
        echo "$action:$port:$protocol:$reason:$process" >> /tmp/port_analysis_results
        
    done < <(echo "$port_data")

    # [修复] 统一从临时文件读取并更新变量
    if [ -f "/tmp/port_analysis_results" ]; then
        while IFS=: read -r action port protocol reason process; do
            if [ "$action" = "open" ]; then
                OPENED_PORTS=$((OPENED_PORTS + 1))
                OPENED_PORTS_LIST+=("$port/$protocol ($process)")
            else
                SKIPPED_PORTS=$((SKIPPED_PORTS + 1))
                SKIPPED_PORTS_LIST+=("$port/$protocol ($reason)")
            fi
            # 显示实时分析结果
            if [ "$action" = "open" ]; then
                echo -e "  ${GREEN}✓ 开放: ${CYAN}$port/$protocol${GREEN} - $reason${RESET}"
                add_port_rule "$port" "$protocol" "$reason"
            else
                echo -e "  ${BLUE}⏭️ 跳过: ${CYAN}$port/$protocol${BLUE} - $reason${RESET}"
            fi
        done < "/tmp/port_analysis_results"
        rm -f "/tmp/port_analysis_results"
    fi
}

show_final_status() {
    echo -e "\n${GREEN}========================================"
    echo -e "🎉 防火墙配置完成！"
    echo -e "========================================${RESET}"
    
    echo -e "\n${YELLOW}配置统计：${RESET}"
    echo -e "  - ${GREEN}开放端口: $OPENED_PORTS${RESET}"
    echo -e "  - ${BLUE}跳过端口: $SKIPPED_PORTS${RESET}"
    echo -e "  - ${CYAN}SSH端口: $SSH_PORT (已启用暴力破解保护)${RESET}"
    
    # 显示详细的开放端口列表
    if [ ${#OPENED_PORTS_LIST[@]} -gt 0 ]; then
        echo -e "\n${GREEN}✅ 已开放的端口：${RESET}"
        for port_info in "${OPENED_PORTS_LIST[@]}"; do
            echo -e "  ${GREEN}• $port_info${RESET}"
        done
    else
        echo -e "\n${YELLOW}⚠️ 没有代理端口被自动开放！${RESET}"
        echo -e "  ${YELLOW}可能原因：${RESET}"
        echo -e "    - 代理服务未运行或监听在内网地址"
        echo -e "    - 进程名不在预定义列表中，且配置文件无法解析"
        echo -e "    - 用户选择不开放"
    fi
    
    # 显示跳过端口的原因
    if [ ${#SKIPPED_PORTS_LIST[@]} -gt 0 ]; then
        echo -e "\n${BLUE}ℹ️ 跳过的端口：${RESET}"
        for port_info in "${SKIPPED_PORTS_LIST[@]}"; do
            echo -e "  ${BLUE}• $port_info${RESET}"
        done
    fi
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${CYAN}>>> 预演模式结束，没有实际修改防火墙 <<<${RESET}"
        return
    fi
    
    echo -e "\n${YELLOW}当前防火墙规则：${RESET}"
    if command -v nft >/dev/null 2>&1; then
        # 显示所有允许的端口规则
        local rule_count=0
        while IFS= read -r line; do
            if [[ "$line" == *"dport"* && "$line" == *"accept"* ]]; then
                echo -e "  ${CYAN}$line${RESET}"
                rule_count=$((rule_count + 1))
            fi
        done < <(nft list ruleset 2>/dev/null)
        
        if [ "$rule_count" -eq 0 ]; then
            echo -e "  ${YELLOW}没有检测到开放端口的规则${RESET}"
        fi
    else
        echo -e "  ${RED}nftables 未正确安装或配置${RESET}"
    fi
    
    echo -e "\n${YELLOW}安全提醒：${RESET}"
    echo -e "  - 使用 nftables 高性能防火墙"
    echo -e "  - SSH端口($SSH_PORT)已启用暴力破解保护"
    echo -e "  - 自动过滤系统保留端口"
    echo -e "  - 支持端口范围和端口跳跃"
    
    echo -e "\n${CYAN}常用命令：${RESET}"
    echo -e "  - 查看规则: ${YELLOW}sudo nft list ruleset${RESET}"
    echo -e "  - 查看开放端口: ${YELLOW}sudo nft list ruleset | grep dport${RESET}"
    echo -e "  - 重启防火墙: ${YELLOW}sudo systemctl restart nftables${RESET}"
    echo -e "  - 禁用防火墙: ${YELLOW}sudo systemctl stop nftables${RESET}"
    echo -e "  - 手动添加端口: ${YELLOW}sudo nft add rule inet filter input tcp dport [端口] accept${RESET}"
    
    # 如果没有代理端口被开放，给出建议
    if [ ${#OPENED_PORTS_LIST[@]} -eq 0 ]; then
        echo -e "\n${YELLOW}🔧 故障排除建议：${RESET}"
        echo -e "  1. 确认代理服务正在运行: ${CYAN}sudo systemctl status xray v2ray sing-box${RESET}"
        echo -e "  2. 检查代理服务监听地址: ${CYAN}sudo ss -tlnp | grep -E 'xray|v2ray|sing-box|hysteria'${RESET}"
        echo -e "  3. 使用强制模式重新运行: ${CYAN}sudo $0 --force${RESET}"
        echo -e "  4. 手动添加端口规则 (例如8080端口): ${CYAN}sudo nft add rule inet filter input tcp dport 8080 accept${RESET}"
    fi
}

# ==============================================================================
# 主函数
# ==============================================================================

main() {
    trap 'echo -e "\n${RED}操作被中断${RESET}"; exit 130' INT TERM
    
    parse_arguments "$@"
    
    echo -e "\n${CYAN}--- 1. 系统环境检查 ---${RESET}"
    check_system
    
    echo -e "\n${CYAN}--- 2. 清理现有防火墙 ---${RESET}"
    cleanup_existing_firewalls
    
    echo -e "\n${CYAN}--- 3. 检测SSH端口 ---${RESET}"
    SSH_PORT=$(detect_ssh_port)
    info "SSH端口: $SSH_PORT"
    
    echo -e "\n${CYAN}--- 4. 配置基础防火墙 ---${RESET}"
    setup_nftables

    # [修复] 在处理端口之前，先从配置文件中提取端口
    get_ports_from_config
    
    echo -e "\n${CYAN}--- 5. 分析和处理端口 ---${RESET}"
    process_ports
    
    echo -e "\n${CYAN}--- 6. 应用防火墙规则 ---${RESET}"
    apply_nftables_rules
    
    show_final_status
    
    echo -e "\n${GREEN}✨ 脚本执行完毕！${RESET}"
}

# 脚本入口
main "$@"
