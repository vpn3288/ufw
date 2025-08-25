process_ports() {
    info "开始分析监听端口和配置文件..."
    
    # 初始化临时文件
    > "$TEMP_RESULTS"
    
    # 1. 获取监听端口
    local listening_data
    listening_data=$(get_listening_ports)
    
    # 2. 获取配置文件端口
    local config_data
    config_data=$(extract_ports_from_configs)
    
    # 统计信息
    local listening_count=0
    local config_count=0
    
    if [ -n "$listening_data" ]; then
        listening_count=$(echo "$listening_data" | wc -l)
    fi
    
    if [ -n "$config_data" ]; then
        config_count=$(echo "$config_data" | wc -l)
    fi
    
    info "检测到 $listening_count 个监听端口, $config_count 个配置文件端口"
    
    # 处理监听端口
    if [ -n "$listening_data" ]; then
        echo "$listening_data" | while IFS=: read -r protocol port address process pid; do
            [ -z "$port" ] && continue
            
            local result
            result=$(analyze_port "$protocol" "$port" "$address" "$process" "$pid" "listening")
            local action="${result%%:*}"
            local reason="${result#*:}"
            
            # 写入结果到临时文件
            echo "$action:$port:$protocol:$reason:$process" >> "$TEMP_RESULTS"
            
            if [ "$action" = "open" ]; then
                echo -e "  ${GREEN}✓ 开放: ${CYAN}$port/$protocol${GREEN} - $reason${RESET}"
                add_port_rule "$port" "$protocol" "$reason"
            else
                echo -e "  ${BLUE}⏭️ 跳过: ${CYAN}$port/$protocol${BLUE} - $reason${RESET}"
            fi
        done
    fi
    
    # 处理配置文件端口
    if [ -n "$config_data" ]; then
        echo -e "\n${YELLOW}处理配置文件中的端口:${RESET}"
        echo "$config_data" | while IFS=: read -r port source config_file; do
            [ -z "$port" ] && continue
            
            # 检查是否已经在监听端口中处理过
            if [ -n "$listening_data" ] && echo "$listening_data" | grep -q ":$port:"; then
                debug_log "端口 $port 已在监听端口中处理，跳过"
                continue
            fi
            
            local result
            result=$(analyze_port "tcp" "$port" "config" "config-file" "" "config")
            local action="${result%%:*}"
            local reason="${result#*:}"
            
            # 写入结果到临时文件
            echo "$action:$port:tcp:$reason:config($(basename "$config_file"))" >> "$TEMP_RESULTS"
            
            if [ "$action" = "open" ]; then
                echo -e "  ${GREEN}✓ 配置: ${CYAN}$port/tcp${GREEN} - $reason${RESET}"
                add_port_rule "$port" "tcp" "$reason"
                # 同时添加UDP规则 (某些代理需要)
                add_port_rule "$port" "udp" "$reason"
            else
                echo -e "  ${BLUE}⏭️ 跳过配置: ${CYAN}$port/tcp${BLUE} - $reason${RESET}"
            fi
        done
    fi
    
    # 从结果文件统计数据 (解决子shell变量问题)
    if [ -f "$TEMP_RESULTS" ]; then
        while IFS=: read -r action port protocol reason process; do
            [ -z "$action" ] && continue
            if [ "$action" = "open" ]; then
                OPENED_PORTS=$((OPENED_PORTS + 1))
                OPENED_PORTS_LIST+=("$port/$protocol ($process)")
            else
                SKIPPED_PORTS=$((SKIPPED_PORTS + 1))
                SKIPPED_PORTS_LIST+=("$port/$protocol ($reason)")
            fi
        done < "$TEMP_RESULTS"
    fi
    
    # 统计手动添加的端口
    local manual_count=0
    manual_count=$((${#PORT_RANGES_TCP[@]} + ${#PORT_RANGES_UDP[@]} + ${#SINGLE_PORTS_TCP[@]} + ${#SINGLE_PORTS_UDP[@]}))
    
    if [ $manual_count -gt 0 ]; then
        OPENED_PORTS=$((OPENED_PORTS + manual_count))
        
        # 添加手动端口到显示列表
        for range in "${PORT_RANGES_TCP[@]}"; do
            OPENED_PORTS_LIST+=("$range/tcp (手动范围)")
        done
        for range in "${PORT_RANGES_UDP[@]}"; do
            OPENED_PORTS_LIST+=("$range/udp (手动范围)")
        done
        for port in "${SINGLE_PORTS_TCP[@]}"; do
            OPENED_PORTS_LIST+=("$port/tcp (手动端口)")
        done
        for port in "${SINGLE_PORTS_UDP[@]}"; do
            OPENED_PORTS_LIST+=("$port/udp (手动端口)")
        done
    fi
    
    info "端口处理完成: 开放 $OPENED_PORTS 个, 跳过 $SKIPPED_PORTS 个"
}
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
SCRIPT_VERSION="6.1"
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
MANUAL_PORTS=""

# 修复：使用临时文件记录处理结果，解决子shell变量问题
TEMP_RESULTS="/tmp/firewall_results_$"
OPENED_PORTS_LIST=()
SKIPPED_PORTS_LIST=()

# 端口范围和单独端口的存储
declare -a PORT_RANGES_TCP=()
declare -a PORT_RANGES_UDP=()
declare -a SINGLE_PORTS_TCP=()
declare -a SINGLE_PORTS_UDP=()

# ==============================================================================
# 核心配置数据库 - 扩展和完善
# ==============================================================================

# 代理软件核心进程名 (扩展版本)
PROXY_PROCESSES=(
    # 主流代理软件
    "xray" "v2ray" "sing-box" "hysteria" "hysteria2" "tuic"
    "trojan-go" "trojan" "naive" "shadowsocks-rust" "ss-server"
    "brook" "gost" "juicity" "shadowtls"
    # 扩展支持
    "clash" "clash-meta" "v2raya" "v2rayA" "mihomo"
    "shadowsocks" "ss-local" "ss-tunnel" "ssr-server"
    "outline-ss-server" "go-shadowsocks2" "shadowsocks-libev"
    "trojan-plus" "trojan-gfw" "haproxy" "squid"
    # Hiddify 相关
    "hiddify" "hiddify-panel" "singbox" "sing_box"
    # 其他代理
    "vmess" "vless" "xtls" "reality" "wireguard" "wg"
    "openvpn" "stunnel" "3proxy" "dante" "tinyproxy"
)

# Web服务器进程
WEB_PROCESSES=(
    "nginx" "apache2" "httpd" "caddy" "haproxy" "lighttpd"
    "traefik" "envoy" "cloudflare" "panel" "dashboard"
)

# 代理软件进程模式匹配 (更宽松)
PROXY_PATTERNS=(
    ".*ray.*"           # xray, v2ray, v2raya等
    ".*hysteria.*"      # hysteria系列
    ".*trojan.*"        # trojan系列
    ".*shadowsocks.*"   # shadowsocks系列
    ".*clash.*"         # clash系列
    ".*sing.*box.*"     # sing-box变体
    ".*hiddify.*"       # hiddify系列
    "ss-.*"            # shadowsocks工具
    "tuic.*"           # tuic系列
    ".*vmess.*"        # vmess协议
    ".*vless.*"        # vless协议
    ".*wireguard.*"    # wireguard
    "wg.*"             # wireguard工具
)

# 配置文件路径 (大幅扩展)
CONFIG_PATHS=(
    # Xray/V2ray
    "/usr/local/etc/xray/config.json"
    "/etc/xray/config.json"
    "/opt/xray/config.json"
    "/usr/local/etc/v2ray/config.json"
    "/etc/v2ray/config.json"
    "/opt/v2ray/config.json"
    
    # Sing-box
    "/etc/sing-box/config.json"
    "/opt/sing-box/config.json"
    "/usr/local/etc/sing-box/config.json"
    
    # Hiddify
    "/opt/hiddify/config.json"
    "/opt/hiddify-manager/config.json"
    "/etc/hiddify/config.json"
    "/var/lib/hiddify/config.json"
    
    # Hysteria
    "/etc/hysteria/config.json"
    "/etc/hysteria/config.yaml"
    "/opt/hysteria/config.json"
    
    # TUIC
    "/etc/tuic/config.json"
    "/opt/tuic/config.json"
    
    # Trojan
    "/etc/trojan/config.json"
    "/etc/trojan-go/config.json"
    "/opt/trojan/config.json"
    
    # Clash
    "/etc/clash/config.yaml"
    "/opt/clash/config.yaml"
    "/etc/mihomo/config.yaml"
    
    # Shadowsocks
    "/etc/shadowsocks-rust/config.json"
    "/etc/shadowsocks/config.json"
    "/opt/outline/config.json"
    
    # 其他常见位置
    "/root/config.json"
    "/home/*/config.json"
    "config.json"
    "config.yaml"
)

# 常见代理端口范围 (用于智能检测)
COMMON_PROXY_PORTS=(
    80 443 8080 8443 8880 8888 9090 9443
    1080 1443 2080 2443 3128 3389 5080 5443 6080 6443 7080 7443
    10080 10443 20080 20443 30080 30443
    # Hysteria2 常用
    36712 36713 36714 36715 36716
    # TUIC 常用  
    8443 9443 10443 11443 12443
    # Wireguard
    51820 51821 51822
    # 其他常用
    1194 1723 4444 5555 6666 7777 8964 9001 9002
)

# 系统保留端口 (适度调整)
SYSTEM_RESERVED_PORTS=(
    53    # DNS (通常只需内部)
    67 68 # DHCP
    123   # NTP (除非作为NTP服务器)
    135   # Windows RPC
    137 138 139 # NetBIOS
    445   # SMB (除非需要文件共享)
    631   # CUPS (打印服务)
    5353  # mDNS
    # 移除高端口范围，因为很多代理使用高端口
)

# 明确危险的端口 (需要用户确认)
DANGEROUS_PORTS=(
    23    # Telnet
    1433  # MSSQL
    1521  # Oracle
    3306  # MySQL
    5432  # PostgreSQL
    6379  # Redis
    27017 # MongoDB
    3389  # RDP (Windows)
    5900  # VNC
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
            --manual-ports) MANUAL_PORTS="$2"; info "手动端口设置: $2"; shift 2 ;;
            --help|-h) show_help; exit 0 ;;
            *) error_exit "未知参数: $1" ;;
        esac
    done
}

show_help() {
    cat << EOF
${SCRIPT_NAME} v${SCRIPT_VERSION}

专为代理服务器设计的智能防火墙配置脚本，使用nftables提供更好的性能和端口范围支持。

用法: bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/ufw/refs/heads/main/duankou.sh)
      sudo $0 [选项]

选项:
    --debug           启用调试模式，显示详细检测信息
    --force           强制模式，自动开放所有检测到的代理端口
    --dry-run         预演模式，不实际修改防火墙，仅显示将要执行的操作
    --manual-ports    手动指定端口 (格式: "tcp:80,443,8080-8090;udp:53,16800-16900")
    --help, -h        显示帮助信息

特性:
    ✓ 智能识别代理软件端口 (Xray, V2Ray, Sing-box, Hysteria2, TUIC, Hiddify等)
    ✓ 支持端口范围和端口跳跃 (如: 1000-2000, 8080,8443,9090)
    ✓ 自动检测配置文件中的端口设置
    ✓ 智能识别 Hysteria2 端口范围需求
    ✓ 手动添加端口范围功能
    ✓ 优先开放代理相关端口，保守处理系统端口
    ✓ nftables高性能防火墙规则 (按优先级排序)
    ✓ SSH暴力破解防护 (连接速率限制)
    ✓ 支持所有主流代理软件和面板

支持的代理软件:
    - Xray, V2Ray, V2RayA
    - Sing-box, Mihomo, Clash
    - Hysteria, Hysteria2 (自动检测端口范围)
    - TUIC, Trojan, Trojan-Go
    - Shadowsocks (所有变体)
    - Hiddify Panel
    - WireGuard, OpenVPN
    - 其他常见代理软件

端口格式示例:
    --manual-ports "tcp:80,443,8080-8090;udp:53,16800-16900"
    --manual-ports "tcp:16800-16900;udp:36712-36720"

示例:
    bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/ufw/refs/heads/main/duankou.sh)
    sudo ./firewall.sh --debug --dry-run
    sudo ./firewall.sh --force
    sudo ./firewall.sh --manual-ports "tcp:16800-16900;udp:36712-36720"
EOF
}

# 新增：解析手动端口参数
parse_manual_ports() {
    if [ -z "$MANUAL_PORTS" ]; then
        return
    fi
    
    info "解析手动端口设置..."
    
    # 分割 TCP 和 UDP 部分 (格式: "tcp:80,443,8080-8090;udp:53,16800-16900")
    IFS=';' read -ra PORT_SECTIONS <<< "$MANUAL_PORTS"
    
    for section in "${PORT_SECTIONS[@]}"; do
        if [[ "$section" =~ ^tcp:(.+)$ ]]; then
            local tcp_ports="${BASH_REMATCH[1]}"
            debug_log "TCP端口部分: $tcp_ports"
            parse_port_list "$tcp_ports" "tcp"
        elif [[ "$section" =~ ^udp:(.+)$ ]]; then
            local udp_ports="${BASH_REMATCH[1]}"
            debug_log "UDP端口部分: $udp_ports"
            parse_port_list "$udp_ports" "udp"
        else
            warning "无法解析端口部分: $section"
        fi
    done
}

# 新增：解析端口列表（支持单个端口、范围、逗号分隔）
parse_port_list() {
    local port_list="$1"
    local protocol="$2"
    
    IFS=',' read -ra PORTS <<< "$port_list"
    
    for port_spec in "${PORTS[@]}"; do
        port_spec=$(echo "$port_spec" | tr -d ' ') # 移除空格
        
        if [[ "$port_spec" =~ ^[0-9]+-[0-9]+$ ]]; then
            # 端口范围
            if [ "$protocol" = "tcp" ]; then
                PORT_RANGES_TCP+=("$port_spec")
                success "添加TCP端口范围: $port_spec"
            else
                PORT_RANGES_UDP+=("$port_spec")
                success "添加UDP端口范围: $port_spec"
            fi
        elif [[ "$port_spec" =~ ^[0-9]+$ ]]; then
            # 单个端口
            if [ "$port_spec" -ge 1 ] && [ "$port_spec" -le 65535 ]; then
                if [ "$protocol" = "tcp" ]; then
                    SINGLE_PORTS_TCP+=("$port_spec")
                    success "添加TCP端口: $port_spec"
                else
                    SINGLE_PORTS_UDP+=("$port_spec")
                    success "添加UDP端口: $port_spec"
                fi
            else
                warning "无效端口号: $port_spec"
            fi
        else
            warning "无法解析端口规格: $port_spec"
        fi
    done
}

# 新增：手动输入端口功能
prompt_for_manual_ports() {
    if [ "$FORCE_MODE" = true ] || [ "$DRY_RUN" = true ]; then
        return
    fi
    
    echo -e "\n${YELLOW}🎯 手动端口配置 (可选)${RESET}"
    echo -e "${CYAN}如果需要开放特定的端口范围（如 Hysteria2 端口跳跃），请在此配置${RESET}"
    echo -e "${BLUE}格式示例: tcp:80,443,8080-8090 或 udp:16800-16900,36712-36720${RESET}"
    echo -e "${BLUE}多个协议用分号分隔: tcp:80,443;udp:53,16800-16900${RESET}"
    
    read -p "请输入要开放的端口 (直接回车跳过): " -r manual_input
    
    if [ -n "$manual_input" ]; then
        MANUAL_PORTS="$manual_input"
        parse_manual_ports
    fi
}

# 新增：智能检测 Hysteria2 端口跳跃需求
detect_hysteria_port_ranges() {
    debug_log "检测 Hysteria2 端口跳跃配置..."
    
    # 检查配置文件中的端口跳跃设置
    for config_path in "${CONFIG_PATHS[@]}"; do
        for config_file in $config_path; do
            if [ -f "$config_file" ]; then
                # 检查 Hysteria2 端口跳跃配置
                if command -v jq >/dev/null 2>&1; then
                    local hop_ports
                    hop_ports=$(jq -r '.listen_ports? // .hop_ports? // empty' "$config_file" 2>/dev/null || true)
                    
                    if [ -n "$hop_ports" ] && [ "$hop_ports" != "null" ]; then
                        debug_log "检测到端口跳跃配置: $hop_ports"
                        
                        # 解析端口跳跃范围 (如: "16800-16900")
                        if [[ "$hop_ports" =~ ^\"([0-9]+-[0-9]+)\"$ ]]; then
                            local range="${BASH_REMATCH[1]}"
                            PORT_RANGES_UDP+=("$range")
                            info "自动检测到 Hysteria2 UDP端口范围: $range"
                        fi
                    fi
                fi
                
                # 基于文本的检测作为备用
                if grep -q "hop_ports\|listen_ports" "$config_file" 2>/dev/null; then
                    local range_match
                    range_match=$(grep -oE '"[0-9]+-[0-9]+"' "$config_file" 2>/dev/null | tr -d '"' | head -1)
                    if [ -n "$range_match" ]; then
                        PORT_RANGES_UDP+=("$range_match")
                        info "检测到端口跳跃范围: $range_match"
                    fi
                fi
            fi
        done
    done
}

check_system() {
    info "检查系统环境..."
    
    if ! command -v ss >/dev/null 2>&1; then 
        error_exit "缺少 'ss' 命令，请安装 'iproute2'"
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
            elif command -v apk >/dev/null 2>&1; then
                apk add nftables
            else 
                error_exit "无法自动安装 nftables，请手动安装后重新运行"
            fi
        fi
    fi
    
    # 检查 jq 是否可用 (用于解析JSON配置)
    if ! command -v jq >/dev/null 2>&1; then
        info "安装 jq (JSON解析器)..."
        if [ "$DRY_RUN" = false ]; then
            if command -v apt-get >/dev/null 2>&1; then 
                apt-get install -y jq >/dev/null 2>&1 || true
            elif command -v dnf >/dev/null 2>&1; then 
                dnf install -y jq >/dev/null 2>&1 || true
            elif command -v yum >/dev/null 2>&1; then 
                yum install -y jq >/dev/null 2>&1 || true
            elif command -v apk >/dev/null 2>&1; then
                apk add jq >/dev/null 2>&1 || true
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
# 端口检测与分析 - 完善版本
# ==============================================================================

detect_ssh_port() {
    debug_log "检测SSH端口..."
    local ssh_port
    
    # 通过监听进程检测 (优先级最高)
    ssh_port=$(ss -tlnp 2>/dev/null | grep -E 'sshd|ssh' | awk '{print $4}' | awk -F: '{print $NF}' | head -n 1)
    if [[ "$ssh_port" =~ ^[0-9]+$ ]] && [ "$ssh_port" -ge 1 ] && [ "$ssh_port" -le 65535 ]; then 
        debug_log "通过进程检测到SSH端口: $ssh_port"
        echo "$ssh_port"
        return
    fi
    
    # 通过配置文件检测
    if [ -f /etc/ssh/sshd_config ]; then
        ssh_port=$(grep -i '^[[:space:]]*Port' /etc/ssh/sshd_config | awk '{print $2}' | head -n 1)
        if [[ "$ssh_port" =~ ^[0-9]+$ ]]; then 
            debug_log "通过配置文件检测到SSH端口: $ssh_port"
            echo "$ssh_port"
            return
        fi
    fi
    
    # 通过环境变量检测
    if [ -n "$SSH_CONNECTION" ]; then
        ssh_port=$(echo "$SSH_CONNECTION" | awk '{print $4}')
        if [[ "$ssh_port" =~ ^[0-9]+$ ]]; then 
            debug_log "通过环境变量检测到SSH端口: $ssh_port"
            echo "$ssh_port"
            return
        fi
    fi
    
    debug_log "使用默认SSH端口: 22"
    echo "22"
}

get_listening_ports() {
    ss -tulnp 2>/dev/null | awk '
    /LISTEN|UNCONN/ {
        protocol = tolower($1)
        address_port = $5
        process = "unknown"
        pid = ""
        
        # 解析进程信息 - 更灵活的匹配
        if (match($0, /users:\(\("([^"]+)",[^,]*,([0-9]+)/, p)) {
            process = p[1]
            pid = p[2]
        } else if (match($0, /users:\(\(.*"([^"]+)"/, p)) {
            process = p[1]
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

# 新增：从配置文件中提取端口
extract_ports_from_configs() {
    debug_log "从配置文件提取端口信息..."
    local found_ports=()
    
    for config_path in "${CONFIG_PATHS[@]}"; do
        # 支持通配符路径
        for config_file in $config_path; do
            if [ -f "$config_file" ]; then
                debug_log "检查配置文件: $config_file"
                
                # JSON 配置文件
                if [[ "$config_file" == *.json ]]; then
                    if command -v jq >/dev/null 2>&1; then
                        # 使用jq提取端口
                        local ports
                        ports=$(jq -r '
                            [
                                .inbounds[]?.port?,
                                .inbounds[]?.listen_port?,
                                .inbounds[]?.settings?.port?,
                                .listen_port?,
                                .port?,
                                .server_port?,
                                .local_port?
                            ] | .[] | select(. != null)' "$config_file" 2>/dev/null | grep -E '^[0-9]+$' || true)
                        
                        for port in $ports; do
                            if [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
                                found_ports+=("$port:config:$config_file")
                                debug_log "配置文件端口: $port (来源: $config_file)"
                            fi
                        done
                    else
                        # 简单文本匹配作为备用
                        local ports
                        ports=$(grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" 2>/dev/null | grep -oE '[0-9]+$' || true)
                        for port in $ports; do
                            if [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
                                found_ports+=("$port:config:$config_file")
                                debug_log "配置文件端口 (文本匹配): $port"
                            fi
                        done
                    fi
                fi
                
                # YAML 配置文件 (基础支持)
                if [[ "$config_file" == *.yaml ]] || [[ "$config_file" == *.yml ]]; then
                    local ports
                    ports=$(grep -oE 'port[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" 2>/dev/null | grep -oE '[0-9]+$' || true)
                    for port in $ports; do
                        if [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
                            found_ports+=("$port:config:$config_file")
                            debug_log "YAML配置文件端口: $port"
                        fi
                    done
                fi
            fi
        done
    done
    
    # 输出找到的端口
    printf '%s\n' "${found_ports[@]}"
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

# 改进：更宽松的代理进程检测
is_proxy_process() {
    local process="$1"
    local pid="$2"
    
    debug_log "检查进程: $process (PID: $pid)"
    
    # 精确匹配
    for proxy_proc in "${PROXY_PROCESSES[@]}"; do
        if [[ "$process" == "$proxy_proc" ]]; then
            debug_log "进程 '$process' 精确匹配代理软件: $proxy_proc"
            return 0
        fi
    done
    
    # Web服务器匹配 (通常也承载代理服务)
    for web_proc in "${WEB_PROCESSES[@]}"; do
        if [[ "$process" == "$web_proc" ]]; then
            debug_log "进程 '$process' 匹配Web服务器: $web_proc"
            return 0
        fi
    done
    
    # 模式匹配 (更宽松)
    for pattern in "${PROXY_PATTERNS[@]}"; do
        if [[ "$process" =~ $pattern ]]; then
            debug_log "进程 '$process' 匹配代理模式: $pattern"
            return 0
        fi
    done
    
    # 检查完整命令行
    if [ -n "$pid" ] && [ -f "/proc/$pid/cmdline" ]; then
        local cmdline
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "")
        debug_log "命令行: $cmdline"
        
        for proxy_proc in "${PROXY_PROCESSES[@]}"; do
            if [[ "$cmdline" == *"$proxy_proc"* ]]; then
                debug_log "命令行包含代理软件: $proxy_proc"
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
        
        # 检查常见代理相关关键词
        local proxy_keywords=("proxy" "tunnel" "forward" "relay" "bridge" "vpn" "tls" "vmess" "vless" "trojan" "shadowsocks" "hysteria")
        for keyword in "${proxy_keywords[@]}"; do
            if [[ "$cmdline" == *"$keyword"* ]]; then
                debug_log "命令行包含代理关键词: $keyword"
                return 0
            fi
        done
    fi
    
    return 1
}

is_common_proxy_port() {
    local port="$1"
    for common_port in "${COMMON_PROXY_PORTS[@]}"; do
        if [ "$port" = "$common_port" ]; then
            debug_log "端口 $port 在常见代理端口列表中"
            return 0
        fi
    done
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

# 改进：更智能的端口分析策略
analyze_port() {
    local protocol=$1 port=$2 address=$3 process=$4 pid=$5 source=${6:-"listening"}
    
    debug_log "分析端口: $protocol/$port, 地址: $address, 进程: $process, 来源: $source"
    
    # SSH端口跳过
    if [ "$port" = "$SSH_PORT" ]; then 
        echo "skip:SSH端口单独处理"
        return
    fi
    
    # 对于配置文件中的端口，采用更宽松的策略
    if [ "$source" = "config" ]; then
        echo "open:配置文件端口(${address#*:})"
        return
    fi
    
    # 非公网监听跳过
    if [ "$source" != "config" ] && ! is_public_listener "$address"; then 
        echo "skip:内部监听($address)"
        return
    fi
    
    # 代理进程端口 - 优先开放
    if is_proxy_process "$process" "$pid"; then
        echo "open:代理服务($process)"
        return
    fi
    
    # 常见代理端口 - 如果在强制模式或常见端口列表中
    if is_common_proxy_port "$port"; then
        if [ "$FORCE_MODE" = true ]; then
            echo "open:常见代理端口(强制模式)"
            return
        else
            echo "open:常见代理端口($process)"
            return
        fi
    fi
    
    # 系统保留端口跳过 (但给出说明)
    if is_system_reserved_port "$port"; then
        echo "skip:系统保留端口"
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
    
    # 其他端口 - 在强制模式下开放
    if [ "$FORCE_MODE" = true ]; then
        echo "open:其他端口(强制模式)"
    else
        # 非强制模式下，询问用户
        warning "检测到其他公网监听端口 $port，进程: $process"
        read -p "开放此端口? [y/N]: " -r response
        if [[ "$response" =~ ^[yY]([eE][sS])?$ ]]; then
            echo "open:其他端口(用户确认)"
        else
            echo "skip:其他端口(用户拒绝)"
        fi
    fi
}

# ==============================================================================
# nftables 防火墙配置 - 修复的版本
# ==============================================================================

setup_nftables() {
    info "配置 nftables 防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then 
        info "[预演] 将创建 nftables 基础规则和SSH保护"
        return
    fi
    
    success "nftables 基础规则已生成"
}

# 改进的端口规则添加函数
add_port_rule() {
    local port="$1"
    local protocol="$2"
    local comment="$3"
    
    debug_log "添加端口规则: $protocol/$port - $comment"
    
    if [ "$DRY_RUN" = true ]; then 
        info "[预演] 将添加规则: $protocol dport $port accept # $comment"
        return
    fi
    
    # 根据端口类型分类存储，而不是直接写入文件
    if [[ "$port" =~ ^[0-9]+-[0-9]+$ ]]; then
        # 端口范围
        if [ "$protocol" = "tcp" ]; then
            PORT_RANGES_TCP+=("$port")
        else
            PORT_RANGES_UDP+=("$port")
        fi
    elif [[ "$port" =~ ^[0-9]+$ ]]; then
        # 单个端口
        if [ "$protocol" = "tcp" ]; then
            SINGLE_PORTS_TCP+=("$port")
        else
            SINGLE_PORTS_UDP+=("$port")
        fi
    elif [[ "$port" == *","* ]]; then
        # 端口列表 - 拆分为单个端口
        IFS=',' read -ra PORT_LIST <<< "$port"
        for single_port in "${PORT_LIST[@]}"; do
            single_port=$(echo "$single_port" | tr -d ' ')
            if [[ "$single_port" =~ ^[0-9]+$ ]]; then
                if [ "$protocol" = "tcp" ]; then
                    SINGLE_PORTS_TCP+=("$single_port")
                else
                    SINGLE_PORTS_UDP+=("$single_port")
                fi
            fi
        done
    fi
}

# 新增：生成优化的 nftables 规则
generate_optimized_rules() {
    local rules=""
    
    # 1. 首先添加端口范围（优先级最高，避免被单个端口覆盖）
    if [ ${#PORT_RANGES_TCP[@]} -gt 0 ]; then
        rules+="\n        # TCP 端口范围\n"
        for range in "${PORT_RANGES_TCP[@]}"; do
            rules+="        tcp dport $range accept comment \"TCP端口范围\"\n"
        done
    fi
    
    if [ ${#PORT_RANGES_UDP[@]} -gt 0 ]; then
        rules+="\n        # UDP 端口范围\n"
        for range in "${PORT_RANGES_UDP[@]}"; do
            rules+="        udp dport $range accept comment \"UDP端口范围\"\n"
        done
    fi
    
    # 2. 然后添加单个端口（优化：合并为集合）
    if [ ${#SINGLE_PORTS_TCP[@]} -gt 0 ]; then
        # 去重并排序
        local unique_tcp_ports=($(printf '%s\n' "${SINGLE_PORTS_TCP[@]}" | sort -nu))
        if [ ${#unique_tcp_ports[@]} -eq 1 ]; then
            rules+="\n        # TCP 单个端口\n"
            rules+="        tcp dport ${unique_tcp_ports[0]} accept comment \"代理服务端口\"\n"
        else
            # 多个端口使用集合语法
            local tcp_port_set=$(IFS=','; echo "${unique_tcp_ports[*]}")
            rules+="\n        # TCP 端口集合\n"
            rules+="        tcp dport { $tcp_port_set } accept comment \"代理服务端口集合\"\n"
        fi
    fi
    
    if [ ${#SINGLE_PORTS_UDP[@]} -gt 0 ]; then
        # 去重并排序
        local unique_udp_ports=($(printf '%s\n' "${SINGLE_PORTS_UDP[@]}" | sort -nu))
        if [ ${#unique_udp_ports[@]} -eq 1 ]; then
            rules+="\n        # UDP 单个端口\n"
            rules+="        udp dport ${unique_udp_ports[0]} accept comment \"代理服务端口\"\n"
        else
            # 多个端口使用集合语法
            local udp_port_set=$(IFS=','; echo "${unique_udp_ports[*]}")
            rules+="\n        # UDP 端口集合\n"
            rules+="        udp dport { $udp_port_set } accept comment \"代理服务端口集合\"\n"
        fi
    fi
    
    # 如果没有规则，添加注释
    if [ -z "$rules" ]; then
        rules="        # 没有检测到需要开放的代理端口"
    fi
    
    echo -e "$rules"
}
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
    
    # 如果没有任何代理规则，添加一个注释
    if [ -z "$proxy_rules" ]; then
        proxy_rules="        # 没有检测到需要开放的代理端口"
    fi
    
    # 直接创建完整的 nftables 配置文件，避免使用 sed 替换
    cat > /etc/nftables.conf << EOF
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
        
        # ICMPv4/ICMPv6 (网络诊断必需)
        ip protocol icmp limit rate 10/second accept
        ip6 nexthdr icmpv6 limit rate 10/second accept
        
        # SSH保护规则 (防暴力破解)
        tcp dport $SSH_PORT ct state new \\
            add @ssh_bruteforce { ip saddr timeout 1h limit rate over 5/minute burst 5 packets } \\
            drop comment "SSH暴力破解保护"
        tcp dport $SSH_PORT accept comment "SSH访问"
        
        # 代理端口规则
$proxy_rules
        
        # 记录并丢弃其他包 (限制日志频率)
        limit rate 5/minute log prefix "nft-drop: "
        drop
    }
    
    # 转发链 (如果需要NAT转发可以修改)
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
    
    # 输出链 (允许所有出站连接)
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF
    
    # 设置正确的权限
    chmod 755 /etc/nftables.conf
    
    # 测试规则语法
    if ! nft -c -f /etc/nftables.conf; then
        error_exit "nftables 规则语法错误，请检查配置"
    fi
    
    # 应用规则
    if nft -f /etc/nftables.conf; then
        success "nftables 规则应用成功"
    else
        error_exit "nftables 规则应用失败"
    fi
    
    # 启用和启动服务
    if systemctl enable nftables >/dev/null 2>&1; then
        debug_log "nftables 服务已设为开机启动"
    fi
    
    if systemctl start nftables >/dev/null 2>&1; then
        debug_log "nftables 服务已启动"
    fi
    
    # 验证规则是否生效
    if nft list ruleset >/dev/null 2>&1; then
        success "防火墙规则验证通过"
    else
        warning "防火墙规则可能未正确加载"
    fi
    
    # 清理临时文件
    rm -f /tmp/nftables.conf
}

# ==============================================================================
# 主要处理流程 - 修复子shell问题
# ==============================================================================

process_ports() {
    info "开始分析监听端口和配置文件..."
    
    # 初始化临时文件
    > /tmp/proxy_rules.tmp
    > "$TEMP_RESULTS"
    
    # 1. 获取监听端口
    local listening_data
    listening_data=$(get_listening_ports)
    
    # 2. 获取配置文件端口
    local config_data
    config_data=$(extract_ports_from_configs)
    
    # 统计信息
    local listening_count=0
    local config_count=0
    
    if [ -n "$listening_data" ]; then
        listening_count=$(echo "$listening_data" | wc -l)
    fi
    
    if [ -n "$config_data" ]; then
        config_count=$(echo "$config_data" | wc -l)
    fi
    
    info "检测到 $listening_count 个监听端口, $config_count 个配置文件端口"
    
    # 处理监听端口
    if [ -n "$listening_data" ]; then
        echo "$listening_data" | while IFS=: read -r protocol port address process pid; do
            [ -z "$port" ] && continue
            
            local result
            result=$(analyze_port "$protocol" "$port" "$address" "$process" "$pid" "listening")
            local action="${result%%:*}"
            local reason="${result#*:}"
            
            # 写入结果到临时文件
            echo "$action:$port:$protocol:$reason:$process" >> "$TEMP_RESULTS"
            
            if [ "$action" = "open" ]; then
                echo -e "  ${GREEN}✓ 开放: ${CYAN}$port/$protocol${GREEN} - $reason${RESET}"
                add_port_rule "$port" "$protocol" "$reason"
            else
                echo -e "  ${BLUE}⏭️ 跳过: ${CYAN}$port/$protocol${BLUE} - $reason${RESET}"
            fi
        done
    fi
    
    # 处理配置文件端口
    if [ -n "$config_data" ]; then
        echo -e "\n${YELLOW}处理配置文件中的端口:${RESET}"
        echo "$config_data" | while IFS=: read -r port source config_file; do
            [ -z "$port" ] && continue
            
            # 检查是否已经在监听端口中处理过
            if [ -n "$listening_data" ] && echo "$listening_data" | grep -q ":$port:"; then
                debug_log "端口 $port 已在监听端口中处理，跳过"
                continue
            fi
            
            local result
            result=$(analyze_port "tcp" "$port" "config" "config-file" "" "config")
            local action="${result%%:*}"
            local reason="${result#*:}"
            
            # 写入结果到临时文件
            echo "$action:$port:tcp:$reason:config($(basename "$config_file"))" >> "$TEMP_RESULTS"
            
            if [ "$action" = "open" ]; then
                echo -e "  ${GREEN}✓ 配置: ${CYAN}$port/tcp${GREEN} - $reason${RESET}"
                add_port_rule "$port" "tcp" "$reason"
                # 同时添加UDP规则 (某些代理需要)
                add_port_rule "$port" "udp" "$reason"
            else
                echo -e "  ${BLUE}⏭️ 跳过配置: ${CYAN}$port/tcp${BLUE} - $reason${RESET}"
            fi
        done
    fi
    
    # 从结果文件统计数据 (解决子shell变量问题)
    if [ -f "$TEMP_RESULTS" ]; then
        while IFS=: read -r action port protocol reason process; do
            [ -z "$action" ] && continue
            if [ "$action" = "open" ]; then
                OPENED_PORTS=$((OPENED_PORTS + 1))
                OPENED_PORTS_LIST+=("$port/$protocol ($process)")
            else
                SKIPPED_PORTS=$((SKIPPED_PORTS + 1))
                SKIPPED_PORTS_LIST+=("$port/$protocol ($reason)")
            fi
        done < "$TEMP_RESULTS"
    fi
    
    info "端口处理完成: 开放 $OPENED_PORTS 个, 跳过 $SKIPPED_PORTS 个"
}

show_final_status() {
    echo -e "\n${GREEN}========================================"
    echo -e "🎉 防火墙配置完成！"
    echo -e "========================================${RESET}"
    
    echo -e "\n${YELLOW}📊 配置统计：${RESET}"
    echo -e "  - ${GREEN}开放端口: $OPENED_PORTS 个${RESET}"
    echo -e "  - ${BLUE}跳过端口: $SKIPPED_PORTS 个${RESET}"
    echo -e "  - ${CYAN}SSH端口: $SSH_PORT (已启用暴力破解保护)${RESET}"
    echo -e "  - ${YELLOW}防火墙类型: nftables (高性能)${RESET}"
    
    # 显示详细的开放端口列表
    if [ ${#OPENED_PORTS_LIST[@]} -gt 0 ]; then
        echo -e "\n${GREEN}✅ 已开放的端口：${RESET}"
        for port_info in "${OPENED_PORTS_LIST[@]}"; do
            echo -e "  ${GREEN}• $port_info${RESET}"
        done
        
        success "所有代理端口已成功开放！"
    else
        echo -e "\n${YELLOW}⚠️ 没有代理端口被自动开放！${RESET}"
        echo -e "\n${YELLOW}🔍 可能原因：${RESET}"
        echo -e "  - 代理服务未运行: ${CYAN}systemctl status xray v2ray sing-box${RESET}"
        echo -e "  - 代理监听在内网地址 (127.0.0.1)，这是安全的"
        echo -e "  - 进程名不在预定义列表中"
        echo -e "  - 配置文件位置不在检测路径中"
        echo -e "  - 用户选择不开放某些端口"
        
        echo -e "\n${CYAN}💡 建议操作：${RESET}"
        echo -e "  1. 使用强制模式: ${YELLOW}curl -sSL <script_url> | bash -s -- --force${RESET}"
        echo -e "  2. 启动代理服务后重新运行脚本"
        echo -e "  3. 检查代理配置文件路径是否正确"
        echo -e "  4. 手动添加端口 (见下方命令)"
    fi
    
    # 显示跳过端口的统计 (简化显示)
    if [ ${#SKIPPED_PORTS_LIST[@]} -gt 0 ]; then
        local skip_count=${#SKIPPED_PORTS_LIST[@]}
        echo -e "\n${BLUE}ℹ️ 跳过了 $skip_count 个端口 (系统保留、内网监听等)${RESET}"
        if [ "$DEBUG_MODE" = true ]; then
            for port_info in "${SKIPPED_PORTS_LIST[@]}"; do
                echo -e "  ${BLUE}• $port_info${RESET}"
            done
        fi
    fi
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${CYAN}🔍 >>> 预演模式结束，没有实际修改防火墙 <<<${RESET}"
        echo -e "如需实际应用，请去掉 --dry-run 参数重新运行"
        return
    fi
    
    echo -e "\n${YELLOW}🔥 当前防火墙规则：${RESET}"
    if command -v nft >/dev/null 2>&1; then
        local rule_count=0
        local accept_rules
        accept_rules=$(nft list ruleset 2>/dev/null | grep -E "dport.*accept" || echo "")
        
        if [ -n "$accept_rules" ]; then
            echo "$accept_rules" | while IFS= read -r line; do
                if [[ "$line" == *"dport"* && "$line" == *"accept"* ]]; then
                    echo -e "  ${CYAN}$line${RESET}"
                    rule_count=$((rule_count + 1))
                fi
            done
        fi
        
        if [ -z "$accept_rules" ]; then
            echo -e "  ${YELLOW}只有SSH端口和基础规则生效${RESET}"
        fi
    else
        echo -e "  ${RED}❌ nftables 未正确安装或配置${RESET}"
    fi
    
    echo -e "\n${YELLOW}🛡️ 安全特性：${RESET}"
    echo -e "  - ${GREEN}✓ 使用 nftables 高性能防火墙${RESET}"
    echo -e "  - ${GREEN}✓ SSH端口($SSH_PORT) 暴力破解保护 (5次/分钟)${RESET}"
    echo -e "  - ${GREEN}✓ 自动过滤系统保留端口${RESET}"
    echo -e "  - ${GREEN}✓ 支持端口范围和端口跳跃${RESET}"
    echo -e "  - ${GREEN}✓ 连接状态跟踪 (stateful firewall)${RESET}"
    echo -e "  - ${GREEN}✓ ICMP 限速保护${RESET}"
    echo -e "  - ${GREEN}✓ 日志记录可疑连接${RESET}"
    
    echo -e "\n${CYAN}🔧 常用管理命令：${RESET}"
    echo -e "  ${YELLOW}查看所有规则:${RESET} sudo nft list ruleset"
    echo -e "  ${YELLOW}查看开放端口:${RESET} sudo nft list ruleset | grep dport"
    echo -e "  ${YELLOW}查看SSH保护:${RESET} sudo nft list set inet filter ssh_bruteforce"
    echo -e "  ${YELLOW}重启防火墙:${RESET} sudo systemctl restart nftables"
    echo -e "  ${YELLOW}查看防火墙状态:${RESET} sudo systemctl status nftables"
    echo -e "  ${YELLOW}临时关闭防火墙:${RESET} sudo systemctl stop nftables"
    echo -e "  ${YELLOW}查看监听端口:${RESET} sudo ss -tulnp"
    
    echo -e "\n${CYAN}➕ 手动管理端口：${RESET}"
    echo -e "  ${YELLOW}添加TCP端口:${RESET} sudo nft add rule inet filter input tcp dport [端口] accept"
    echo -e "  ${YELLOW}添加UDP端口:${RESET} sudo nft add rule inet filter input udp dport [端口] accept"
    echo -e "  ${YELLOW}添加端口范围:${RESET} sudo nft add rule inet filter input tcp dport 8080-8090 accept"
    echo -e "  ${YELLOW}添加端口集合:${RESET} sudo nft add rule inet filter input tcp dport { 80, 443, 8080 } accept"
    echo -e "  ${YELLOW}删除规则:${RESET} sudo nft -a list ruleset (查看句柄), sudo nft delete rule inet filter input handle [句柄]"
    echo -e "  ${YELLOW}重新运行脚本添加端口:${RESET} sudo ./firewall.sh --manual-ports \"tcp:16800-16900;udp:36712-36720\""
    
    # 高级故障排除
    if [ ${#OPENED_PORTS_LIST[@]} -eq 0 ]; then
        echo -e "\n${YELLOW}🔍 高级故障排除：${RESET}"
        echo -e "  ${CYAN}1. 检查代理服务状态:${RESET}"
        echo -e "     sudo systemctl status xray v2ray sing-box hysteria2"
        echo -e "  ${CYAN}2. 查看所有监听端口:${RESET}"
        echo -e "     sudo ss -tulnp | grep LISTEN"
        echo -e "  ${CYAN}3. 查找代理进程:${RESET}"
        echo -e "     ps aux | grep -E 'xray|v2ray|sing-box|hysteria|trojan'"
        echo -e "  ${CYAN}4. 检查配置文件:${RESET}"
        echo -e "     find /etc /opt /usr/local -name '*.json' -o -name '*.yaml' | grep -E 'xray|v2ray|sing-box'"
        echo -e "  ${CYAN}5. 强制模式重新运行:${RESET}"
        echo -e "     bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/ufw/refs/heads/main/duankou.sh) --force"
        echo -e "  ${CYAN}6. 手动指定 Hysteria2 端口范围:${RESET}"
        echo -e "     sudo ./firewall.sh --manual-ports \"udp:16800-16900\""
    fi
    
    # 显示优化建议
    if [ ${#PORT_RANGES_TCP[@]} -gt 0 ] || [ ${#PORT_RANGES_UDP[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🎯 端口范围优化成功！${RESET}"
        echo -e "  - 端口范围规则优先级已调整到最高"
        echo -e "  - 避免了单个端口规则的覆盖问题"
        echo -e "  - 支持 Hysteria2 端口跳跃等高级功能"
    fi
    
    # 清理临时文件
    rm -f "$TEMP_RESULTS" /tmp/proxy_rules.tmp 2>/dev/null || true
}

# ==============================================================================
# 主函数
# ==============================================================================

main() {
    # 设置陷阱处理中断
    trap 'echo -e "\n${RED}❌ 操作被中断，正在清理...${RESET}"; rm -f "$TEMP_RESULTS" /tmp/proxy_rules.tmp /tmp/nftables.conf 2>/dev/null || true; exit 130' INT TERM
    
    # 解析命令行参数
    parse_arguments "$@"
    
    echo -e "\n${CYAN}=== 🚀 代理服务器智能防火墙配置开始 ===${RESET}"
    
    echo -e "\n${CYAN}--- 1️⃣ 系统环境检查 ---${RESET}"
    check_system
    
    echo -e "\n${CYAN}--- 2️⃣ 清理现有防火墙 ---${RESET}"
    cleanup_existing_firewalls
    
    echo -e "\n${CYAN}--- 3️⃣ 检测SSH端口 ---${RESET}"
    SSH_PORT=$(detect_ssh_port)
    info "SSH端口: $SSH_PORT"
    
    echo -e "\n${CYAN}--- 4️⃣ 手动端口配置 ---${RESET}"
    parse_manual_ports
    prompt_for_manual_ports
    detect_hysteria_port_ranges
    
    echo -e "\n${CYAN}--- 5️⃣ 配置基础防火墙 ---${RESET}"
    setup_nftables
    
    echo -e "\n${CYAN}--- 6️⃣ 智能分析和处理端口 ---${RESET}"
    process_ports
    
    echo -e "\n${CYAN}--- 7️⃣ 应用防火墙规则 ---${RESET}"
    apply_nftables_rules
    
    echo -e "\n${CYAN}--- 8️⃣ 配置完成报告 ---${RESET}"
    show_final_status
    
    echo -e "\n${GREEN}🎯 脚本执行完毕！代理服务器防火墙配置成功！${RESET}"
    
    # 最终提醒
    if [ "$FORCE_MODE" = false ] && [ ${#OPENED_PORTS_LIST[@]} -eq 0 ]; then
        echo -e "\n${YELLOW}💡 提示: 如果你确定要开放所有检测到的代理端口，可以使用:${RESET}"
        echo -e "${CYAN}bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/ufw/refs/heads/main/duankou.sh) --force${RESET}"
        echo -e "\n${YELLOW}或者为 Hysteria2 手动指定端口范围:${RESET}"
        echo -e "${CYAN}sudo ./firewall.sh --manual-ports \"udp:16800-16900\"${RESET}"
    fi
    
    # 特别提醒 Hysteria2 用户
    if [ ${#PORT_RANGES_UDP[@]} -eq 0 ] && (ps aux | grep -q hysteria 2>/dev/null); then
        echo -e "\n${YELLOW}🔔 Hysteria2 用户注意:${RESET}"
        echo -e "  检测到 Hysteria2 进程，但未找到 UDP 端口范围配置"
        echo -e "  如果使用端口跳跃功能，请手动添加端口范围："
        echo -e "  ${CYAN}sudo ./firewall.sh --manual-ports \"udp:16800-16900\"${RESET}"
    fi
}

# 脚本入口点
main "$@"
