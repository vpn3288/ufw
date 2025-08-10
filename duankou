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
SCRIPT_VERSION="2.0"
SCRIPT_NAME="Auto Firewall Configuration Script"

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

# 服务端口数据库（扩展版）
declare -A SERVICE_PORTS=(
    ["22"]="SSH"
    ["80"]="HTTP"
    ["443"]="HTTPS"
    ["25"]="SMTP"
    ["53"]="DNS"
    ["110"]="POP3"
    ["143"]="IMAP"
    ["993"]="IMAPS"
    ["995"]="POP3S"
    ["465"]="SMTPS"
    ["587"]="SMTP-Submit"
    ["21"]="FTP"
    ["22"]="SFTP"
    ["3306"]="MySQL"
    ["5432"]="PostgreSQL"
    ["6379"]="Redis"
    ["27017"]="MongoDB"
    ["8080"]="HTTP-Alt"
    ["8443"]="HTTPS-Alt"
    ["3389"]="RDP"
    ["5900"]="VNC"
    ["2049"]="NFS"
    ["111"]="RPC"
    ["8000"]="HTTP-Dev"
    ["8888"]="HTTP-Alt2"
    ["9000"]="HTTP-Alt3"
    ["3000"]="Node.js-Dev"
    ["5000"]="Flask-Dev"
    ["8081"]="HTTP-Proxy"
    ["1080"]="SOCKS"
    ["8388"]="Shadowsocks"
    ["1194"]="OpenVPN"
    ["500"]="IPSec"
    ["4500"]="IPSec-NAT"
)

# 常见的内部服务端口（不应对外开放）
INTERNAL_PORTS=(
    631    # CUPS
    5353   # mDNS
    1900   # UPnP
    17500  # Dropbox
    32768 32769 32770 32771 32772 32773 32774 32775  # 临时端口
    2000   # 通常是内部服务
    1234   # 测试端口
    1010   # 内部应用
    502    # Modbus
    438    # 内部应用
    12334  # 游戏服务器内部端口
)

# 危险端口（需要特别注意）
DANGEROUS_PORTS=(
    23     # Telnet
    135    # RPC Endpoint Mapper
    139    # NetBIOS
    445    # SMB
    1433   # MSSQL
    1521   # Oracle
    3389   # RDP (如果不需要远程桌面)
    5060   # SIP (如果不是VoIP服务器)
    5432   # PostgreSQL
    6379   # Redis
    27017  # MongoDB
)

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
    
    # 检查ufw
    if ! command -v ufw >/dev/null 2>&1; then
        packages_to_install+=("ufw")
    fi
    
    # 检查ss或netstat
    if ! command -v ss >/dev/null 2>&1 && ! command -v netstat >/dev/null 2>&1; then
        if [ "$PACKAGE_MANAGER" = "apt" ]; then
            packages_to_install+=("iproute2" "net-tools")
        else
            packages_to_install+=("net-tools")
        fi
    fi
    
    # 安装缺失的包
    if [ ${#packages_to_install[@]} -gt 0 ]; then
        info "安装依赖包: ${packages_to_install[*]}"
        
        if [ "$DRY_RUN" = true ]; then
            info "[预演] 将安装: ${packages_to_install[*]}"
            return
        fi
        
        case "$PACKAGE_MANAGER" in
            "apt")
                DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
                DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages_to_install[@]}" >/dev/null 2>&1
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
    fi
}

# 创建备份
create_backup() {
    debug_log "创建防火墙规则备份"
    
    BACKUP_DIR="/root/firewall_backup_$(date +%Y%m%d_%H%M%S)"
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将创建备份目录: $BACKUP_DIR"
        return
    fi
    
    mkdir -p "$BACKUP_DIR"
    
    # 备份iptables规则
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > "$BACKUP_DIR/iptables.rules" 2>/dev/null || true
        debug_log "iptables规则已备份"
    fi
    
    # 备份ufw状态
    if command -v ufw >/dev/null 2>&1; then
        ufw status numbered > "$BACKUP_DIR/ufw.status" 2>/dev/null || true
        ufw --dry-run show raw > "$BACKUP_DIR/ufw.raw" 2>/dev/null || true
        debug_log "UFW状态已备份"
    fi
    
    # 备份系统信息
    {
        echo "# 系统信息备份 - $(date)"
        echo "# 主机名: $(hostname)"
        echo "# 内核: $(uname -r)"
        echo "# 发行版: $(lsb_release -d 2>/dev/null || cat /etc/os-release | head -1)"
        echo ""
        echo "# 网络接口:"
        ip addr show 2>/dev/null || ifconfig 2>/dev/null || true
        echo ""
        echo "# 监听端口:"
        ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || true
    } > "$BACKUP_DIR/system_info.txt"
    
    success "备份完成: $BACKUP_DIR"
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
    
    # 方法3: 检查systemd服务
    if command -v systemctl >/dev/null 2>&1; then
        local systemd_port=$(systemctl show ssh.service sshd.service 2>/dev/null | grep "ExecStart=" | grep -o "Port [0-9]*" | awk '{print $2}' | head -1)
        if [[ "$systemd_port" =~ ^[0-9]+$ ]] && [ "$systemd_port" -gt 0 ] && [ "$systemd_port" -le 65535 ]; then
            ssh_port="$systemd_port"
            debug_log "从systemd检测到端口: $ssh_port"
        fi
    fi
    
    # 验证端口是否真的在监听
    if command -v ss >/dev/null 2>&1; then
        if ! ss -tln | grep -q ":$ssh_port "; then
            debug_log "警告: 端口$ssh_port未在监听，使用默认端口22"
            ssh_port="22"
        fi
    fi
    
    echo "$ssh_port"
}

# 获取监听端口列表
get_listening_ports() {
    debug_log "获取系统监听端口"
    
    local ports_info=""
    
    if command -v ss >/dev/null 2>&1; then
        debug_log "使用ss命令检测端口"
        ports_info=$(ss -tlnp 2>/dev/null | awk '
        /LISTEN/ {
            # 解析地址和端口
            if (match($4, /^(.*):([0-9]+)$/, addr_parts)) {
                address = addr_parts[1]
                port = addr_parts[2]
                
                # 获取进程信息
                process = "unknown"
                if (match($0, /users:\(\("([^"]+)"/, proc_parts)) {
                    process = proc_parts[1]
                }
                
                # 验证端口范围
                if (port > 0 && port <= 65535) {
                    print port ":" address ":tcp:" process
                }
            }
        }' | sort -n)
    elif command -v netstat >/dev/null 2>&1; then
        debug_log "使用netstat命令检测端口"
        ports_info=$(netstat -tlnp 2>/dev/null | awk '
        /LISTEN/ {
            if (match($4, /^(.*):([0-9]+)$/, addr_parts)) {
                address = addr_parts[1]
                port = addr_parts[2]
                
                process = "unknown"
                if ($7 != "-") {
                    split($7, proc_parts, "/")
                    if (proc_parts[2] != "") {
                        process = proc_parts[2]
                    }
                }
                
                if (port > 0 && port <= 65535) {
                    print port ":" address ":tcp:" process
                }
            }
        }' | sort -n)
    else
        warning "无法找到端口检测工具 (ss 或 netstat)"
        return 1
    fi
    
    echo "$ports_info"
}

# 检查端口是否为内部端口
is_internal_port() {
    local port=$1
    local address=$2
    
    # 检查是否在内部端口列表中
    for internal_port in "${INTERNAL_PORTS[@]}"; do
        if [ "$port" = "$internal_port" ]; then
            return 0
        fi
    done
    
    # 检查是否只在本地监听
    case "$address" in
        "127.0.0.1"|"::1"|"localhost")
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# 检查端口是否为危险端口
is_dangerous_port() {
    local port=$1
    
    for dangerous_port in "${DANGEROUS_PORTS[@]}"; do
        if [ "$port" = "$dangerous_port" ]; then
            return 0
        fi
    done
    
    return 1
}

# 检查端口是否应该开放
should_open_port() {
    local port=$1
    local address=$2
    local process=$3
    
    debug_log "分析端口 $port (地址: $address, 进程: $process)"
    
    # 跳过SSH端口（已经处理）
    if [ "$port" = "$SSH_PORT" ]; then
        debug_log "端口 $port 是SSH端口，已处理"
        return 1
    fi
    
    # 检查是否是内部端口
    if is_internal_port "$port" "$address"; then
        debug_log "端口 $port 是内部端口，跳过"
        return 1
    fi
    
    # 检查高端口（通常是临时端口）
    if [ "$port" -gt 32768 ]; then
        debug_log "端口 $port 是高端口，可能是临时端口，跳过"
        return 1
    fi
    
    # 检查危险端口
    if is_dangerous_port "$port"; then
        warning "端口 $port 是潜在危险端口 (${SERVICE_PORTS[$port]:-"Unknown"})"
        if [ "$FORCE_MODE" != true ]; then
            echo -n "是否仍要开放此端口? [y/N]: "
            read -r response
            case "$response" in
                [yY]|[yY][eE][sS])
                    info "用户确认开放危险端口 $port"
                    ;;
                *)
                    info "跳过危险端口 $port"
                    return 1
                    ;;
            esac
        fi
    fi
    
    # 常见的Web服务端口
    case "$port" in
        80|443|8080|8443|8000|8888|3000|5000)
            debug_log "端口 $port 是Web服务端口，应该开放"
            return 0
            ;;
        25|587|465|110|995|143|993)
            debug_log "端口 $port 是邮件服务端口，应该开放"
            return 0
            ;;
        53)
            debug_log "端口 $port 是DNS服务端口，应该开放"
            return 0
            ;;
        21|22)
            debug_log "端口 $port 是文件传输服务端口，应该开放"
            return 0
            ;;
        *)
            # 基于进程名判断
            case "$process" in
                nginx|apache2|httpd)
                    debug_log "端口 $port 运行Web服务 ($process)，应该开放"
                    return 0
                    ;;
                sshd)
                    debug_log "端口 $port 运行SSH服务，应该开放"
                    return 0
                    ;;
                *)
                    debug_log "端口 $port 可能需要开放"
                    return 0
                    ;;
            esac
            ;;
    esac
}

# 开放单个端口
open_single_port() {
    local port=$1
    local protocol=$2
    local service_name=$3
    
    debug_log "尝试开放端口: $port/$protocol ($service_name)"
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将开放端口: $port/$protocol - $service_name"
        return 0
    fi
    
    # 检查端口格式
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        warning "无效的端口号: $port"
        return 1
    fi
    
    # 尝试开放端口
    local ufw_cmd="ufw allow $port/$protocol"
    debug_log "执行命令: $ufw_cmd"
    
    if $ufw_cmd >/dev/null 2>&1; then
        success "已开放: $port/$protocol - $service_name"
        OPENED_PORTS=$((OPENED_PORTS + 1))
        return 0
    else
        warning "无法开放端口 $port/$protocol"
        FAILED_PORTS=$((FAILED_PORTS + 1))
        return 1
    fi
}

# 处理所有端口
process_ports() {
    debug_log "开始处理端口"
    
    local port_data
    port_data=$(get_listening_ports)
    
    if [ -z "$port_data" ]; then
        info "未检测到额外的监听端口"
        return
    fi
    
    local total_ports
    total_ports=$(echo "$port_data" | wc -l)
    info "检测到 $total_ports 个监听端口"
    
    echo -e "${YELLOW}端口处理详情：${RESET}"
    
    # 处理每个端口
    echo "$port_data" | while IFS=: read -r port address protocol process; do
        # 跳过空行
        [ -z "$port" ] && continue
        
        local service_name="${SERVICE_PORTS[$port]:-"Unknown"}"
        
        if should_open_port "$port" "$address" "$process"; then
            if ! open_single_port "$port" "$protocol" "$service_name"; then
                echo -e "${RED}   ❌ 失败: $port/$protocol - $service_name${RESET}"
            fi
        else
            echo -e "${BLUE}   ⏭️ 跳过: $port/$protocol - $service_name (内部/受限)${RESET}"
            SKIPPED_PORTS=$((SKIPPED_PORTS + 1))
        fi
    done
}

# 配置基础防火墙规则
setup_basic_firewall() {
    debug_log "配置基础防火墙规则"
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将重置UFW配置"
        info "[预演] 将设置默认策略: 拒绝入站，允许出站"
        info "[预演] 将配置SSH端口: $SSH_PORT"
        return
    fi
    
    # 重置UFW（如果需要）
    if [ "$FORCE_MODE" = true ]; then
        debug_log "强制重置UFW"
        ufw --force reset >/dev/null 2>&1 || true
    fi
    
    # 设置默认策略
    ufw default deny incoming >/dev/null 2>&1 || error_exit "无法设置默认入站策略"
    ufw default allow outgoing >/dev/null 2>&1 || error_exit "无法设置默认出站策略"
    
    success "默认策略已设置"
}

# 配置SSH访问
setup_ssh_access() {
    debug_log "配置SSH访问"
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将允许SSH端口: $SSH_PORT/tcp"
        info "[预演] 将限制SSH连接频率"
        return
    fi
    
    # 允许SSH端口
    ufw allow "$SSH_PORT/tcp" >/dev/null 2>&1 || error_exit "无法开放SSH端口"
    
    # 限制SSH连接频率（防止暴力破解）
    ufw limit "$SSH_PORT/tcp" >/dev/null 2>&1 || warning "无法设置SSH频率限制"
    
    success "SSH端口 $SSH_PORT 已配置"
}

# 启用防火墙
enable_firewall() {
    debug_log "启用防火墙"
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将启用UFW防火墙"
        return
    fi
    
    if ufw --force enable >/dev/null 2>&1; then
        success "防火墙已启用"
    else
        error_exit "无法启用防火墙"
    fi
}

# 显示最终状态
show_final_status() {
    echo -e "\n${GREEN}🎉 防火墙配置完成！${RESET}"
    echo -e "${GREEN}================================${RESET}"
    
    # 显示统计信息
    echo -e "${YELLOW}配置统计：${RESET}"
    echo -e "${GREEN}  • 成功开放端口: $OPENED_PORTS${RESET}"
    echo -e "${BLUE}  • 跳过端口: $SKIPPED_PORTS${RESET}"
    echo -e "${RED}  • 失败端口: $FAILED_PORTS${RESET}"
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${CYAN}这是预演模式，实际配置未被修改${RESET}"
        return
    fi
    
    # 显示当前防火墙状态
    echo -e "\n${YELLOW}当前防火墙状态：${RESET}"
    if command -v ufw >/dev/null 2>&1; then
        ufw status numbered 2>/dev/null || ufw status
    fi
    
    # 显示规则统计
    local total_rules
    total_rules=$(ufw status 2>/dev/null | grep -c "ALLOW\|DENY\|LIMIT" || echo "0")
    echo -e "\n${BLUE}总计防火墙规则数: $total_rules${RESET}"
    
    # 安全提醒
    echo -e "\n${YELLOW}🔒 安全提醒：${RESET}"
    echo -e "${CYAN}  • SSH端口 $SSH_PORT 已启用连接频率限制${RESET}"
    if [ -n "$BACKUP_DIR" ]; then
        echo -e "${CYAN}  • 配置备份保存在: $BACKUP_DIR${RESET}"
    fi
    echo -e "${CYAN}  • 建议定期审查开放的端口${RESET}"
    echo -e "${CYAN}  • 建议启用fail2ban等入侵检测系统${RESET}"
    echo -e "${CYAN}  • 可以使用 'ufw status' 命令查看当前状态${RESET}"
    
    # 如果有失败的端口，给出建议
    if [ "$FAILED_PORTS" -gt 0 ]; then
        echo -e "\n${RED}⚠️  注意: 有 $FAILED_PORTS 个端口开放失败${RESET}"
        echo -e "${YELLOW}建议检查：${RESET}"
        echo -e "${CYAN}  • UFW是否正确安装${RESET}"
        echo -e "${CYAN}  • 系统是否有其他防火墙软件冲突${RESET}"
        echo -e "${CYAN}  • 是否有足够的系统权限${RESET}"
    fi
}

# 主函数
main() {
    echo -e "${YELLOW}开始防火墙自动配置...${RESET}"
    
    # 1. 解析参数
    parse_arguments "$@"
    
    # 2. 检查系统环境
    echo -e "${YELLOW}1⃣ 检查系统环境...${RESET}"
    check_system
    success "系统环境检查完成"
    
    # 3. 安装依赖
    echo -e "${YELLOW}2⃣ 安装必要依赖...${RESET}"
    install_dependencies
    success "依赖检查完成"
    
    # 4. 创建备份
    echo -e "${YELLOW}3⃣ 备份现有规则...${RESET}"
    create_backup
    
    # 5. 检测SSH端口
    echo -e "${YELLOW}4⃣ 检测SSH配置...${RESET}"
    SSH_PORT=$(detect_ssh_port)
    success "SSH端口检测完成: $SSH_PORT"
    
    # 6. 配置基础防火墙
    echo -e "${YELLOW}5⃣ 配置基础防火墙...${RESET}"
    setup_basic_firewall
    success "基础防火墙配置完成"
    
    # 7. 配置SSH访问
    echo -e "${YELLOW}6⃣ 配置SSH访问...${RESET}"
    setup_ssh_access
    
    # 8. 处理其他端口
    echo -e "${YELLOW}7⃣ 分析并处理监听端口...${RESET}"
    process_ports
    
    # 9. 启用防火墙
    echo -e "${YELLOW}8⃣ 启用防火墙...${RESET}"
    enable_firewall
    
    # 10. 显示最终状态
    show_final_status
    
    echo -e "\n${GREEN}✨ 脚本执行完成！${RESET}"
}

# 信号处理
cleanup() {
    echo -e "\n${RED}⚠️  脚本被中断${RESET}"
    if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
        echo -e "${CYAN}备份文件保存在: $BACKUP_DIR${RESET}"
    fi
    exit 130
}

# 捕获中断信号
trap cleanup INT TERM

# 运行主函数
main "$@"
