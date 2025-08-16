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
SCRIPT_VERSION="4.1"
SCRIPT_NAME="All-in-One Firewall Configuration Script"
# 更新日志 v4.1:
# - [IMPROVE] 增强进程识别精度，新增多种进程名匹配模式
# - [IMPROVE] 优化端口检测算法，支持更多代理软件识别
# - [FEATURE] 新增配置文件检测，自动识别配置中的端口
# - [FEATURE] 增加端口范围检测和批量处理
# - [IMPROVE] 优化受信任进程列表，添加更多代理软件
# - [FEATURE] 新增智能端口用途分析
# - [BUGFIX] 修复进程名解析中的特殊字符处理问题

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
BACKUP_DIR=""
SSH_PORT=""
OPENED_PORTS=0
SKIPPED_PORTS=0
FAILED_PORTS=0

# ==============================================================================
# 核心配置与数据库
# ==============================================================================

# 服务端口描述数据库 (扩展版)
declare -A SERVICE_PORTS=(
    # 基础服务
    ["21"]="FTP" ["22"]="SSH/SFTP" ["23"]="Telnet" ["25"]="SMTP"
    ["53"]="DNS" ["80"]="HTTP" ["110"]="POP3" ["143"]="IMAP"
    ["443"]="HTTPS" ["465"]="SMTPS" ["587"]="SMTP-Submit" ["993"]="IMAPS"
    ["995"]="POP3S" ["1080"]="SOCKS" ["1194"]="OpenVPN" ["1433"]="MSSQL"
    ["1521"]="Oracle" ["2049"]="NFS" ["3306"]="MySQL" ["3389"]="RDP"
    ["5432"]="PostgreSQL" ["5900"]="VNC" ["6379"]="Redis"
    
    # 开发服务
    ["3000"]="Node.js-Dev" ["5000"]="Flask-Dev" ["8000"]="HTTP-Dev"
    ["8080"]="HTTP-Alt" ["8081"]="HTTP-Proxy" ["8443"]="HTTPS-Alt"
    ["8888"]="HTTP-Alt2" ["9000"]="HTTP-Alt3"
    
    # 代理服务常用端口
    ["1080"]="SOCKS5" ["8080"]="HTTP-Proxy" ["8388"]="Shadowsocks"
    ["10000"]="代理服务" ["10001"]="代理服务" ["10002"]="代理服务"
    ["20000"]="代理服务" ["30000"]="代理服务" ["40000"]="代理服务"
    ["50000"]="代理服务" ["60000"]="代理服务"
    
    # V2Ray/Xray 常用端口
    ["443"]="HTTPS/TLS" ["80"]="HTTP" ["8443"]="HTTPS-Alt"
    ["2053"]="V2Ray" ["2083"]="V2Ray" ["2087"]="V2Ray" ["2096"]="V2Ray"
    ["8080"]="V2Ray" ["8880"]="V2Ray" ["2052"]="V2Ray" ["2082"]="V2Ray"
    ["2086"]="V2Ray" ["2095"]="V2Ray"
    
    # 其他常见端口
    ["27017"]="MongoDB" ["500"]="IPSec" ["4500"]="IPSec-NAT"
)

# 受信任的进程名 (这些进程监听的公网端口将被自动开放)
TRUSTED_PROCESSES=(
    # Web服务器
    "nginx" "apache2" "httpd" "caddy" "haproxy" "lighttpd" "traefik"
    
    # 代理软件 - 核心进程名
    "xray" "v2ray" "sing-box" "trojan-go" "hysteria" "hysteria2"
    "shadowsocks" "ss-server" "ss-manager" "sslocal" "obfs-server"
    "brook" "gost" "frp" "npc" "nps" "clash"
    
    # Hiddify 相关
    "hiddify" "HiddifyCli" "hiddify-panel" "hiddify-core"
    "xray-core" "v2ray-core" "sing-box-core"
    
    # 其他代理工具
    "trojan" "trojan-plus" "naive" "tuic" "juicity"
    "shadowtls" "reality" "vless" "vmess"
    
    # Python/Node.js 应用 (常用于运行代理脚本)
    "python" "python3" "node" "nodejs"
    
    # Docker 容器中的进程
    "docker-proxy" "containerd"
    
    # 其他网络服务
    "openvpn" "wireguard" "strongswan" "ipsec"
)

# 进程名模糊匹配模式 (支持正则表达式)
TRUSTED_PROCESS_PATTERNS=(
    ".*ray.*"           # 匹配包含 ray 的所有进程 (xray, v2ray等)
    ".*shadowsocks.*"   # 匹配所有 shadowsocks 相关
    ".*trojan.*"        # 匹配所有 trojan 相关
    ".*hysteria.*"      # 匹配所有 hysteria 相关
    ".*hiddify.*"       # 匹配所有 hiddify 相关
    ".*clash.*"         # 匹配所有 clash 相关
    "ss-.*"             # 匹配 ss- 开头的进程
    "python.*proxy.*"   # Python 代理脚本
    "node.*proxy.*"     # Node.js 代理脚本
)

# 明确定义为危险的端口 (开放前需要强制确认)
DANGEROUS_PORTS=(23 135 139 445 1433 1521 3389 5432 6379 27017)

# 配置文件路径 (用于自动检测端口)
CONFIG_PATHS=(
    "/usr/local/etc/xray/config.json"
    "/etc/xray/config.json"
    "/usr/local/etc/v2ray/config.json"
    "/etc/v2ray/config.json"
    "/etc/sing-box/config.json"
    "/opt/hiddify/config.json"
    "/root/config.json"
    "/etc/hysteria/config.json"
    "/etc/trojan/config.json"
    "/etc/shadowsocks-libev/config.json"
)

# ==============================================================================
# 辅助函数 (日志/错误/帮助等)
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
            --dry-run) DRY_RUN=true; info "预演模式已启用 - 不会实际修改防火墙"; shift ;;
            --help|-h) show_help; exit 0 ;;
            *) error_exit "未知参数: $1" ;;
        esac
    done
}

show_help() {
    cat << EOF
${SCRIPT_NAME} v${SCRIPT_VERSION}
一个全能的防火墙自动配置脚本。它会首先清理系统中其他防火墙，然后智能分析监听端口并自动生成UFW规则。

用法: sudo $0 [选项]

选项:
    --debug      启用调试模式，显示详细日志
    --force      强制模式，跳过所有交互式确认提示
    --dry-run    预演模式，显示将要执行的操作但不实际执行
    --help, -h   显示此帮助信息

特性:
    ✓ 自动识别 Xray, V2Ray, Sing-box, Hiddify 等代理软件端口
    ✓ 智能进程名匹配和配置文件检测
    ✓ 支持云服务器环境 (甲骨文云、AWS等)
    ✓ 自动清理冲突的防火墙规则
    ✓ SSH 端口保护和暴力破解防护

示例:
    bash <(curl -sSL https://raw.githubusercontent.com/你的用户名/ufw/main/duankou.sh)
    sudo ./duankou.sh --debug
    sudo ./duankou.sh --dry-run --force
EOF
}

# ==============================================================================
# 防火墙清理、系统检查与环境准备
# ==============================================================================

purge_existing_firewalls() {
    info "正在清理系统中可能存在的其他防火墙，以确保UFW能正常工作..."

    echo -e "${YELLOW}=========================== 警告 ==========================="
    echo -e "此步骤将禁用 firewalld, nftables 并清空所有 iptables 规则。"
    echo -e "这是确保UFW能够唯一管理防火墙所必需的步骤。"
    echo -e "${RED}注意: 此脚本无法修改云服务商(如甲骨文云, AWS, Google Cloud)"
    echo -e "网页控制台中的"安全组"或"网络安全列表"规则。请确保"
    echo -e "云平台级别的防火墙已放行您需要的端口（如SSH端口）。"
    echo -e "==============================================================${RESET}"

    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将会检测并尝试停止/禁用 firewalld 和 nftables 服务。"
        info "[预演] 将会清空所有 iptables 和 ip6tables 规则。"
        return
    fi

    # 禁用 firewalld
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        info "检测到正在运行的 firewalld，正在停止并禁用..."
        systemctl stop firewalld 2>/dev/null || true
        systemctl disable firewalld 2>/dev/null || true
        systemctl mask firewalld 2>/dev/null || true
        success "firewalld 已被禁用。"
    fi

    # 禁用 nftables
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nftables 2>/dev/null; then
        info "检测到正在运行的 nftables，正在停止并禁用..."
        systemctl stop nftables 2>/dev/null || true
        systemctl disable nftables 2>/dev/null || true
        success "nftables 已被禁用。"
    fi

    # 清理 iptables 和 ip6tables 规则
    info "正在清空所有 iptables 和 ip6tables 规则..."
    if command -v iptables >/dev/null 2>&1; then
        # 设置默认策略为接受，防止ssh中断
        iptables -P INPUT ACCEPT 2>/dev/null || true
        iptables -P FORWARD ACCEPT 2>/dev/null || true
        iptables -P OUTPUT ACCEPT 2>/dev/null || true
        # 清空所有表
        iptables -t nat -F 2>/dev/null || true
        iptables -t mangle -F 2>/dev/null || true
        iptables -F 2>/dev/null || true
        iptables -X 2>/dev/null || true
    fi
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -P INPUT ACCEPT 2>/dev/null || true
        ip6tables -P FORWARD ACCEPT 2>/dev/null || true
        ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
        ip6tables -t nat -F 2>/dev/null || true
        ip6tables -t mangle -F 2>/dev/null || true
        ip6tables -F 2>/dev/null || true
        ip6tables -X 2>/dev/null || true
    fi
    # 刷新 netfilter-persistent/iptables-persistent
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent flush 2>/dev/null || true
    fi
    success "iptables/ip6tables 规则已清空。"
}

check_system() {
    debug_log "检查系统环境"
    if ! command -v ss >/dev/null 2>&1; then 
        error_exit "关键命令 'ss' 未找到。请安装 'iproute2' 包。"
    fi
    
    if ! command -v ufw >/dev/null 2>&1; then
        warning "'ufw' 未找到。脚本将尝试安装它。"
        if [ "$DRY_RUN" = true ]; then 
            info "[预演] 将安装: ufw"
        else
            if command -v apt-get >/dev/null 2>&1; then 
                DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y ufw
            elif command -v dnf >/dev/null 2>&1; then 
                dnf install -y ufw
            elif command -v yum >/dev/null 2>&1; then 
                yum install -y ufw
            else 
                error_exit "无法自动安装 'ufw'。请手动安装后重试。"
            fi
        fi
    fi
    success "系统环境检查完成"
}

create_backup() {
    debug_log "创建防火墙规则备份"
    BACKUP_DIR="/root/firewall_backup_$(date +%Y%m%d_%H%M%S)"
    if [ "$DRY_RUN" = true ]; then 
        info "[预演] 将创建备份目录: $BACKUP_DIR"
        return
    fi
    
    mkdir -p "$BACKUP_DIR"
    {
        echo "# UFW Status Before Script Run"
        ufw status numbered 2>/dev/null || echo "UFW not enabled."
        echo -e "\n# Listening Ports"
        ss -tulnp 2>/dev/null || true
        echo -e "\n# Process List"
        ps aux 2>/dev/null || true
    } > "$BACKUP_DIR/firewall_state.bak"
    success "备份完成: $BACKUP_DIR"
}

# ==============================================================================
# 新增：配置文件检测功能
# ==============================================================================

extract_ports_from_config() {
    local config_file="$1"
    if [ ! -f "$config_file" ]; then
        return
    fi
    
    debug_log "检查配置文件: $config_file"
    
    # 检测 JSON 配置文件中的端口
    if [[ "$config_file" == *.json ]]; then
        # 提取各种可能的端口字段
        local ports
        ports=$(grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+|"listen"[[:space:]]*:[[:space:]]*"[^"]*:[0-9]+"|"address"[[:space:]]*:[[:space:]]*"[^"]*:[0-9]+"' "$config_file" 2>/dev/null | \
               grep -oE '[0-9]+' | sort -u)
        
        if [ -n "$ports" ]; then
            echo "$ports"
        fi
    fi
}

get_ports_from_configs() {
    local config_ports=""
    for config_path in "${CONFIG_PATHS[@]}"; do
        if [ -f "$config_path" ]; then
            local found_ports
            found_ports=$(extract_ports_from_config "$config_path")
            if [ -n "$found_ports" ]; then
                debug_log "从 $config_path 发现端口: $found_ports"
                config_ports="$config_ports $found_ports"
            fi
        fi
    done
    
    # 去重并排序
    if [ -n "$config_ports" ]; then
        echo "$config_ports" | tr ' ' '\n' | sort -u | tr '\n' ' '
    fi
}

# ==============================================================================
# 核心分析逻辑 (增强版)
# ==============================================================================

detect_ssh_port() {
    debug_log "开始检测SSH端口"
    local ssh_port
    
    # 方法1: 通过 ss 检测 sshd 进程监听的端口
    ssh_port=$(ss -tlnp 2>/dev/null | grep -E 'sshd|ssh' | awk '{print $4}' | awk -F: '{print $NF}' | sort -u | head -n 1)
    if [[ "$ssh_port" =~ ^[0-9]+$ ]] && [ "$ssh_port" -ge 1 ] && [ "$ssh_port" -le 65535 ]; then 
        debug_log "通过ss检测到sshd监听端口: $ssh_port"
        echo "$ssh_port"
        return
    fi
    
    # 方法2: 通过配置文件检测
    if [ -f /etc/ssh/sshd_config ]; then
        ssh_port=$(grep -i '^[[:space:]]*Port' /etc/ssh/sshd_config | awk '{print $2}' | head -n 1)
        if [[ "$ssh_port" =~ ^[0-9]+$ ]] && [ "$ssh_port" -ge 1 ] && [ "$ssh_port" -le 65535 ]; then 
            debug_log "通过sshd_config检测到端口: $ssh_port"
            echo "$ssh_port"
            return
        fi
    fi
    
    # 方法3: 检查当前SSH连接
    if [ -n "$SSH_CONNECTION" ]; then
        ssh_port=$(echo "$SSH_CONNECTION" | awk '{print $4}')
        if [[ "$ssh_port" =~ ^[0-9]+$ ]] && [ "$ssh_port" -ge 1 ] && [ "$ssh_port" -le 65535 ]; then 
            debug_log "通过SSH_CONNECTION环境变量检测到端口: $ssh_port"
            echo "$ssh_port"
            return
        fi
    fi
    
    debug_log "未检测到非标准SSH端口，使用默认端口 22"
    echo "22"
}

get_listening_ports() {
    # 增强版端口检测，更准确的进程名解析
    ss -tulnp 2>/dev/null | awk '
    /LISTEN|UNCONN/ {
        protocol = tolower($1)
        listen_addr_port = $5
        process = "unknown"
        pid = ""
        
        # 解析进程信息 - 支持多种格式
        if (match($0, /users:\(\("([^"]+)",[^,]*,([0-9]+)/, p)) {
            process = p[1]
            pid = p[2]
        } else if (match($0, /\("([^"]+)",pid=([0-9]+)/, p)) {
            process = p[1] 
            pid = p[2]
        } else if (match($0, /users:\(\([^)]*"([^"]+)"/, p)) {
            process = p[1]
        }
        
        # 解析监听地址和端口
        if (match(listen_addr_port, /^(.*):([0-9]+)$/, parts)) {
            address = parts[1]
            port = parts[2]
            
            # 处理IPv6地址格式 [::]:port
            if (address ~ /^\[.*\]$/) {
                address = substr(address, 2, length(address)-2)
            }
            
            # 通配符地址转换
            if (address == "*") {
                address = "0.0.0.0"
            } else if (address == "[::]") {
                address = "::"
            }
            
            # 验证端口范围
            if (port > 0 && port <= 65535) {
                line = protocol ":" port ":" address ":" process ":" pid
                if (!seen[line]++) {
                    print line
                }
            }
        }
    }'
}

is_public_listener() {
    local address="$1"
    case "$address" in 
        "127.0.0.1"|"::1"|"localhost"|127.*|"fe80:"*|"fd"*|"fc"*) 
            return 1 
            ;;
        *) 
            return 0 
            ;;
    esac
}

is_trusted_process() {
    local process="$1"
    local pid="$2"
    
    # 精确匹配
    for trusted_proc in "${TRUSTED_PROCESSES[@]}"; do
        if [[ "$process" == "$trusted_proc" ]]; then
            debug_log "进程 '$process' 匹配受信任列表 (精确匹配)"
            return 0
        fi
    done
    
    # 模糊匹配
    for pattern in "${TRUSTED_PROCESS_PATTERNS[@]}"; do
        if [[ "$process" =~ $pattern ]]; then
            debug_log "进程 '$process' 匹配受信任模式 '$pattern'"
            return 0
        fi
    done
    
    # 通过PID查找完整的命令行 (如果有PID)
    if [ -n "$pid" ] && [ -f "/proc/$pid/cmdline" ]; then
        local full_cmdline
        full_cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        debug_log "PID $pid 完整命令行: $full_cmdline"
        
        # 检查命令行中是否包含代理软件特征
        for trusted_proc in "${TRUSTED_PROCESSES[@]}"; do
            if [[ "$full_cmdline" == *"$trusted_proc"* ]]; then
                debug_log "进程 '$process' (PID: $pid) 通过命令行匹配受信任进程 '$trusted_proc'"
                return 0
            fi
        done
        
        # 检查是否是配置文件路径中的服务
        for config_path in "${CONFIG_PATHS[@]}"; do
            if [[ "$full_cmdline" == *"$config_path"* ]]; then
                debug_log "进程 '$process' (PID: $pid) 使用了代理配置文件 '$config_path'"
                return 0
            fi
        done
    fi
    
    return 1
}

analyze_port() {
    local protocol=$1 port=$2 address=$3 process=$4 pid=$5
    local reason=""
    
    debug_log "分析端口: $protocol/$port, 地址: $address, 进程: $process (PID: $pid)"
    
    # SSH端口特殊处理
    if [ "$port" = "$SSH_PORT" ]; then 
        reason="SSH端口，单独处理"
        echo "skip:$reason"
        return
    fi
    
    # 内部监听地址跳过
    if ! is_public_listener "$address"; then 
        reason="内部监听于 $address"
        echo "skip:$reason"
        return
    fi
    
    # 检查是否为受信任进程
    if is_trusted_process "$process" "$pid"; then
        reason="受信任的进程 ($process)"
        echo "open:$reason"
        return
    fi
    
    # 检查危险端口
    for dangerous_port in "${DANGEROUS_PORTS[@]}"; do
        if [ "$port" = "$dangerous_port" ]; then
            local service_name=${SERVICE_PORTS[$port]:-"Unknown"}
            warning "检测到潜在危险端口 $port ($service_name) 由进程 '$process' 监听。"
            
            if [ "$FORCE_MODE" = true ]; then
                warning "强制模式已启用，自动开放危险端口 $port。"
                reason="危险端口 (强制开放)"
                echo "open:$reason"
            else
                read -p "你是否确认要向公网开放此端口? 这可能带来安全风险。 [y/N]: " -r response
                if [[ "$response" =~ ^[yY]([eE][sS])?$ ]]; then
                    info "用户确认开放危险端口 $port"
                    reason="危险端口 (用户确认)"
                    echo "open:$reason"
                else
                    info "用户拒绝开放危险端口 $port"
                    reason="危险端口 (用户拒绝)"
                    echo "skip:$reason"
                fi
            fi
            return
        fi
    done
    
    # 检查是否在配置文件中发现的端口
    local config_ports
    config_ports=$(get_ports_from_configs)
    if [[ " $config_ports " == *" $port "* ]]; then
        reason="配置文件中发现的端口 ($process)"
        echo "open:$reason"
        return
    fi
    
    # 默认：公网服务端口
    reason="公网服务 ($process)"
    echo "open:$reason"
}

# ==============================================================================
# 防火墙操作 (优化版)
# ==============================================================================

setup_basic_firewall() {
    info "配置UFW基础规则..."
    if [ "$DRY_RUN" = true ]; then 
        info "[预演] 将重置UFW, 设置默认策略 (deny incoming, allow outgoing)"
        return
    fi
    
    ufw --force reset >/dev/null 2>&1
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    success "UFW基础规则设置完毕"
}

setup_ssh_access() {
    info "配置SSH访问端口 $SSH_PORT..."
    if [ "$DRY_RUN" = true ]; then 
        info "[预演] 将允许并限制 (limit) SSH端口 $SSH_PORT/tcp"
        return
    fi
    
    ufw allow $SSH_PORT/tcp >/dev/null 2>&1
    ufw limit $SSH_PORT/tcp >/dev/null 2>&1
    success "SSH端口 $SSH_PORT/tcp 已配置访问限制"
}

process_ports() {
    info "开始分析和处理所有监听端口..."
    local port_data
    port_data=$(get_listening_ports)
    
    if [ -z "$port_data" ]; then 
        info "未检测到需要处理的监听端口。"
        return
    fi
    
    # 显示检测到的端口统计
    local total_ports
    total_ports=$(echo "$port_data" | wc -l)
    info "检测到 $total_ports 个监听端口，开始逐个分析..."
    
    echo "$port_data" | while IFS=: read -r protocol port address process pid; do
        [ -z "$port" ] && continue
        
        local analysis_result
        analysis_result=$(analyze_port "$protocol" "$port" "$address" "$process" "$pid")
        local action="${analysis_result%%:*}"
        local reason="${analysis_result#*:}"
        
        if [ "$action" = "open" ]; then
            local service_name=${SERVICE_PORTS[$port]:-"自定义服务"}
            
            if [ "$DRY_RUN" = true ]; then
                info "[预演] ${GREEN}开放: ${CYAN}$port/$protocol${GREEN} - ${YELLOW}$service_name${GREEN} (原因: $reason)${RESET}"
                OPENED_PORTS=$((OPENED_PORTS + 1))
            else
                if ufw allow "$port/$protocol" >/dev/null 2>&1; then
                    echo -e "  ${GREEN}✓ 开放: ${CYAN}$port/$protocol${GREEN} - ${YELLOW}$service_name${GREEN} (原因: $reason)${RESET}"
                    OPENED_PORTS=$((OPENED_PORTS + 1))
                else
                    echo -e "  ${RED}✗ 失败: ${CYAN}$port/$protocol${GREEN} - ${YELLOW}$service_name${RESET}"
                    FAILED_PORTS=$((FAILED_PORTS + 1))
                fi
            fi
        else
            local service_name=${SERVICE_PORTS[$port]:-"自定义服务"}
            echo -e "  ${BLUE}⏭️ 跳过: ${CYAN}$port/$protocol${BLUE} - ${YELLOW}$service_name${BLUE} (原因: $reason)${RESET}"
            SKIPPED_PORTS=$((SKIPPED_PORTS + 1))
        fi
    done
}

enable_firewall() {
    info "最后一步：启用防火墙..."
    if [ "$DRY_RUN" = true ]; then 
        info "[预演] 将执行 'ufw enable'"
        return
    fi
    
    if echo "y" | ufw enable 2>/dev/null | grep -q "Firewall is active"; then 
        success "防火墙已成功激活并将在系统启动时自启"
    else 
        error_exit "启用防火墙失败! 请检查UFW状态。"
    fi
}

show_final_status() {
    echo -e "\n${GREEN}======================================"
    echo -e "🎉 防火墙配置完成！"
    echo -e "======================================${RESET}"
    
    echo -e "${YELLOW}配置统计：${RESET}"
    echo -e "  - ${GREEN}成功开放端口: $OPENED_PORTS${RESET}"
    echo -e "  - ${BLUE}跳过内部/受限端口: $SKIPPED_PORTS${RESET}"
    echo -e "  - ${RED}失败端口: $FAILED_PORTS${RESET}"
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${CYAN}>>> 预演模式结束，未对系统做任何实际更改 <<<\n${RESET}"
        echo -e "${YELLOW}如果以上预演结果符合预期，请移除 '--dry-run' 参数以正式执行。${RESET}"
        return
    fi
    
    echo -e "\n${YELLOW}当前防火墙状态 (ufw status numbered):${RESET}"
    ufw status numbered
    
    echo -e "\n${YELLOW}检测到的代理服务端口：${RESET}"
    local config_ports
    config_ports=$(get_ports_from_configs)
    if [ -n "$config_ports" ]; then
        echo -e "  - 配置文件端口: ${CYAN}$config_ports${RESET}"
    fi
    
    # 显示正在运行的代理进程
    echo -e "\n${YELLOW}检测到的代理进程：${RESET}"
    ps aux 2>/dev/null | grep -E "(xray|v2ray|sing-box|hiddify|hysteria|trojan|shadowsocks)" | grep -v grep | while read -r line; do
        echo -e "  - ${CYAN}$(echo "$line" | awk '{print $11}')${RESET}"
    done || echo -e "  - ${BLUE}未检测到明显的代理进程${RESET}"
    
    echo -e "\n${YELLOW}🔒 安全提醒：${RESET}"
    echo -e "  - SSH端口 ${CYAN}$SSH_PORT${YELLOW} 已启用暴力破解防护 (limit)。"
    echo -e "  - 配置备份已保存至 ${CYAN}$BACKUP_DIR${YELLOW}。"
    echo -e "  - 建议定期使用 ${CYAN}'sudo ufw status'${YELLOW} 审查防火墙规则。"
    echo -e "  - 代理服务如有配置更改，请重新运行此脚本。"
    
    echo -e "\n${CYAN}📋 快速命令参考：${RESET}"
    echo -e "  - 查看状态: ${CYAN}sudo ufw status numbered${RESET}"
    echo -e "  - 删除规则: ${CYAN}sudo ufw delete [编号]${RESET}"
    echo -e "  - 手动开放: ${CYAN}sudo ufw allow [端口]/[协议]${RESET}"
    echo -e "  - 重载配置: ${CYAN}sudo ufw reload${RESET}"
}

# ==============================================================================
# 新增：智能诊断功能
# ==============================================================================

diagnose_proxy_services() {
    info "正在诊断代理服务状态..."
    
    # 检查常见代理服务状态
    local services=("xray" "v2ray" "sing-box" "hiddify" "hysteria" "trojan")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo -e "  ${GREEN}✓ $service 服务正在运行${RESET}"
        elif systemctl list-unit-files --type=service | grep -q "^$service"; then
            echo -e "  ${YELLOW}⚠ $service 服务已安装但未运行${RESET}"
        fi
    done
    
    # 检查配置文件
    echo -e "\n${CYAN}配置文件检查：${RESET}"
    for config_path in "${CONFIG_PATHS[@]}"; do
        if [ -f "$config_path" ]; then
            echo -e "  ${GREEN}✓ 发现配置: $config_path${RESET}"
            local ports
            ports=$(extract_ports_from_config "$config_path")
            if [ -n "$ports" ]; then
                echo -e "    端口: ${CYAN}$ports${RESET}"
            fi
        fi
    done
}

# ==============================================================================
# 新增：端口冲突检测
# ==============================================================================

check_port_conflicts() {
    info "检查端口冲突..."
    local conflicts_found=false
    
    # 检查常见端口冲突
    local common_conflicts=(
        "80:nginx apache2 httpd caddy"
        "443:nginx apache2 httpd caddy"
        "8080:nginx tomcat jetty"
        "3306:mysql mariadb"
        "5432:postgresql postgres"
    )
    
    for conflict_def in "${common_conflicts[@]}"; do
        local port="${conflict_def%%:*}"
        local services="${conflict_def#*:}"
        
        local listening_count
        listening_count=$(ss -tulnp 2>/dev/null | grep ":$port " | wc -l)
        
        if [ "$listening_count" -gt 1 ]; then
            warning "端口 $port 被多个进程监听，可能存在冲突"
            ss -tulnp 2>/dev/null | grep ":$port " | while read -r line; do
                echo -e "    ${YELLOW}$line${RESET}"
            done
            conflicts_found=true
        fi
    done
    
    if [ "$conflicts_found" = false ]; then
        success "未发现明显的端口冲突"
    fi
}

# ==============================================================================
# 主函数与信号处理 (增强版)
# ==============================================================================

main() {
    trap 'echo -e "\n${RED}操作被中断。${RESET}"; exit 130' INT TERM
    
    # 步骤 0: 解析命令行参数
    parse_arguments "$@"

    # 步骤 1: 清理现有防火墙
    echo -e "\n${CYAN}--- 1. 清理现有防火墙规则 ---${RESET}"
    purge_existing_firewalls

    # 步骤 2: 环境检查
    echo -e "\n${CYAN}--- 2. 检查系统环境与依赖 ---${RESET}"
    check_system

    # 步骤 3: 备份
    echo -e "\n${CYAN}--- 3. 创建备份 ---${RESET}"
    create_backup

    # 步骤 4: 智能诊断 (新功能)
    if [ "$DEBUG_MODE" = true ]; then
        echo -e "\n${CYAN}--- 4. 智能诊断 (调试模式) ---${RESET}"
        diagnose_proxy_services
        check_port_conflicts
    fi

    # 步骤 5: UFW 基础配置
    echo -e "\n${CYAN}--- 5. 配置UFW基础环境 ---${RESET}"
    setup_basic_firewall

    # 步骤 6: 处理SSH
    SSH_PORT=$(detect_ssh_port)
    echo -e "\n${CYAN}--- 6. 配置SSH端口 ($SSH_PORT) ---${RESET}"
    setup_ssh_access

    # 步骤 7: 核心 - 处理所有其他端口
    echo -e "\n${CYAN}--- 7. 智能分析并配置所有服务端口 ---${RESET}"
    process_ports

    # 步骤 8: 启用防火墙
    echo -e "\n${CYAN}--- 8. 启用防火墙 ---${RESET}"
    enable_firewall

    # 步骤 9: 显示最终报告
    show_final_status
    
    echo -e "\n${GREEN}✨ 脚本执行完毕！感谢使用！${RESET}"
    
    # 提供一键部署说明
    if [ "$DRY_RUN" = false ]; then
        echo -e "\n${CYAN}💡 提示: 如需再次使用，请执行：${RESET}"
        echo -e "${YELLOW}bash <(curl -sSL https://raw.githubusercontent.com/你的用户名/ufw/main/duankou.sh)${RESET}"
    fi
}

# ==============================================================================
# 脚本入口点
# ==============================================================================

# 检查是否通过管道执行 (curl | bash)
if [ -t 0 ]; then
    # 交互模式
    main "$@"
else
    # 管道模式，显示欢迎信息
    echo -e "${GREEN}🚀 正在通过网络获取并执行防火墙配置脚本...${RESET}"
    main "$@"
fi
