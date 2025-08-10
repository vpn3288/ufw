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
SCRIPT_VERSION="4.0"
SCRIPT_NAME="All-in-One Firewall Configuration Script"
# 更新日志 v4.0:
# - [FEATURE] 新增"防火墙大扫除"功能: 在脚本开始时自动禁用并清理 firewalld, nftables, 和所有 iptables 规则。
# - [FEATURE] 专门为甲骨文云和其他带有复杂默认规则的VPS优化，确保UFW能接管防火墙。
# - [IMPROVE] 调整主流程，将清理步骤置于最前，确保环境纯净。
#
# 更新日志 v3.1:
# - [BUGFIX] 修复了 get_listening_ports 函数中 awk 脚本的正则表达式语法错误。

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

# 服务端口描述数据库
declare -A SERVICE_PORTS=(
    ["21"]="FTP" ["22"]="SSH/SFTP" ["23"]="Telnet" ["25"]="SMTP"
    ["53"]="DNS" ["80"]="HTTP" ["110"]="POP3" ["143"]="IMAP"
    ["443"]="HTTPS" ["465"]="SMTPS" ["587"]="SMTP-Submit" ["993"]="IMAPS"
    ["995"]="POP3S" ["1080"]="SOCKS" ["1194"]="OpenVPN" ["1433"]="MSSQL"
    ["1521"]="Oracle" ["2049"]="NFS" ["3306"]="MySQL" ["3389"]="RDP"
    ["5432"]="PostgreSQL" ["5900"]="VNC" ["6379"]="Redis" ["8000"]="HTTP-Dev"
    ["8080"]="HTTP-Alt" ["8081"]="HTTP-Proxy" ["8388"]="Shadowsocks"
    ["8443"]="HTTPS-Alt" ["8888"]="HTTP-Alt2" ["9000"]="HTTP-Alt3"
    ["27017"]="MongoDB" ["500"]="IPSec" ["4500"]="IPSec-NAT"
    ["3000"]="Node.js-Dev" ["5000"]="Flask-Dev"
)

# 受信任的进程名 (这些进程监听的公网端口将被自动开放)
TRUSTED_PROCESSES=(
    "nginx" "apache2" "httpd" "caddy" "haproxy" "lighttpd"
    "xray" "v2ray" "sing-box" "trojan-go" "hysteria"
    "ss-server" "ss-manager" "sslocal" "obfs-server"
    "HiddifyCli" "python" # 根据你的ss输出添加
)

# 明确定义为危险的端口 (开放前需要强制确认)
DANGEROUS_PORTS=(23 135 139 445 1433 1521 3389 5432 6379 27017)


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
    echo -e "网页控制台中的“安全组”或“网络安全列表”规则。请确保"
    echo -e "云平台级别的防火墙已放行您需要的端口（如SSH端口）。"
    echo -e "==============================================================${RESET}"

    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将会检测并尝试停止/禁用 firewalld 和 nftables 服务。"
        info "[预演] 将会清空所有 iptables 和 ip6tables 规则。"
        return
    fi

    # 禁用 firewalld
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        info "检测到正在运行的 firewalld，正在停止并禁用..."
        systemctl stop firewalld
        systemctl disable firewalld
        systemctl mask firewalld 2>/dev/null || true
        success "firewalld 已被禁用。"
    fi

    # 禁用 nftables
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nftables; then
        info "检测到正在运行的 nftables，正在停止并禁用..."
        systemctl stop nftables
        systemctl disable nftables
        success "nftables 已被禁用。"
    fi

    # 清理 iptables 和 ip6tables 规则
    info "正在清空所有 iptables 和 ip6tables 规则..."
    if command -v iptables >/dev/null 2>&1; then
        # 设置默认策略为接受，防止ssh中断
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        # 清空所有表
        iptables -t nat -F
        iptables -t mangle -F
        iptables -F
        iptables -X
    fi
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -P INPUT ACCEPT
        ip6tables -P FORWARD ACCEPT
        ip6tables -P OUTPUT ACCEPT
        ip6tables -t nat -F
        ip6tables -t mangle -F
        ip6tables -F
        ip6tables -X
    fi
    # 刷新 netfilter-persistent/iptables-persistent
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent flush 2>/dev/null || true
    fi
    success "iptables/ip6tables 规则已清空。"
}


check_system() {
    debug_log "检查系统环境"
    if ! command -v ss >/dev/null 2>&1; then error_exit "关键命令 'ss' 未找到。请安装 'iproute2' 包。"; fi
    if ! command -v ufw >/dev/null 2>&1; then
        warning "'ufw' 未找到。脚本将尝试安装它。"
        if [ "$DRY_RUN" = true ]; then info "[预演] 将安装: ufw"; else
            if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get install -y ufw;
            elif command -v dnf >/dev/null 2>&1; then dnf install -y ufw;
            elif command -v yum >/dev/null 2>&1; then yum install -y ufw;
            else error_exit "无法自动安装 'ufw'。请手动安装后重试。"; fi
        fi
    fi
    success "系统环境检查完成"
}

create_backup() {
    debug_log "创建防火墙规则备份"
    BACKUP_DIR="/root/firewall_backup_$(date +%Y%m%d_%H%M%S)"
    if [ "$DRY_RUN" = true ]; then info "[预演] 将创建备份目录: $BACKUP_DIR"; return; fi
    mkdir -p "$BACKUP_DIR"
    {
        echo "# UFW Status Before Script Run"
        ufw status numbered 2>/dev/null || echo "UFW not enabled."
        echo -e "\n# Listening Ports"
        ss -tulnp
    } > "$BACKUP_DIR/firewall_state.bak"
    success "备份完成: $BACKUP_DIR"
}

# ==============================================================================
# 核心分析逻辑
# ==============================================================================

detect_ssh_port() {
    debug_log "开始检测SSH端口"
    local ssh_port
    ssh_port=$(ss -tlnp | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | sort -u | head -n 1)
    if [[ "$ssh_port" =~ ^[0-9]+$ ]]; then debug_log "通过ss检测到sshd监听端口: $ssh_port"; echo "$ssh_port"; return; fi
    ssh_port=$(grep -i '^Port' /etc/ssh/sshd_config | awk '{print $2}' | head -n 1)
    if [[ "$ssh_port" =~ ^[0-9]+$ ]]; then debug_log "通过sshd_config检测到端口: $ssh_port"; echo "$ssh_port"; return; fi
    debug_log "未检测到非标准SSH端口，使用默认端口 22"; echo "22"
}

get_listening_ports() {
    ss -tulnp 2>/dev/null | awk '
    /LISTEN|UNCONN/ {
        protocol = $1; listen_addr_port = $5
        process = "unknown"
        if (match($0, /users:\(\("([^"]+)"/, p)) { process = p[1] } 
        else if (match($0, /\("([^"]+)",pid=/ , p)) { process = p[1] }
        if (match(listen_addr_port, /^(.*):([0-9]+)$/, parts)) {
            address = parts[1]; port = parts[2]
            if (address ~ /^\[.*\]$/) { address = substr(address, 2, length(address)-2) }
            if (address == "*") { address = "0.0.0.0" }
            if (port > 0 && port <= 65535) {
                line = protocol ":" port ":" address ":" process
                if (!seen[line]++) { print line }
            }
        }
    }'
}

is_public_listener() {
    case "$1" in "127.0.0.1"|"::1"|"localhost"|127.*) return 1 ;; *) return 0 ;; esac
}

analyze_port() {
    local protocol=$1 port=$2 address=$3 process=$4 reason=""
    debug_log "分析端口: $protocol/$port, 地址: $address, 进程: $process"
    if [ "$port" = "$SSH_PORT" ]; then reason="SSH端口，单独处理"; echo "skip:$reason"; return; fi
    if ! is_public_listener "$address"; then reason="内部监听于 $address"; echo "skip:$reason"; return; fi
    for trusted_proc in "${TRUSTED_PROCESSES[@]}"; do
        if [[ "$process" == "$trusted_proc" ]]; then reason="受信任的进程 ($process)"; echo "open:$reason"; return; fi
    done
    for dangerous_port in "${DANGEROUS_PORTS[@]}"; do
        if [ "$port" = "$dangerous_port" ]; then
            local service_name=${SERVICE_PORTS[$port]:-"Unknown"}
            warning "检测到潜在危险端口 $port ($service_name) 由进程 '$process' 监听。"
            if [ "$FORCE_MODE" = true ]; then
                warning "强制模式已启用，自动开放危险端口 $port。"; reason="危险端口 (强制开放)"; echo "open:$reason"
            else
                read -p "你是否确认要向公网开放此端口? 这可能带来安全风险。 [y/N]: " -r response
                if [[ "$response" =~ ^[yY]([eE][sS])?$ ]]; then
                    info "用户确认开放危险端口 $port"; reason="危险端口 (用户确认)"; echo "open:$reason"
                else
                    info "用户拒绝开放危险端口 $port"; reason="危险端口 (用户拒绝)"; echo "skip:$reason"
                fi
            fi; return
        fi
    done
    reason="公网服务 ($process)"; echo "open:$reason"
}

# ==============================================================================
# 防火墙操作
# ==============================================================================

setup_basic_firewall() {
    info "配置UFW基础规则..."
    if [ "$DRY_RUN" = true ]; then info "[预演] 将重置UFW, 设置默认策略 (deny incoming, allow outgoing)"; return; fi
    ufw --force reset >/dev/null
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    success "UFW基础规则设置完毕"
}

setup_ssh_access() {
    info "配置SSH访问端口 $SSH_PORT..."
    if [ "$DRY_RUN" = true ]; then info "[预演] 将允许并限制 (limit) SSH端口 $SSH_PORT/tcp"; return; fi
    ufw allow $SSH_PORT/tcp >/dev/null
    ufw limit $SSH_PORT/tcp >/dev/null
    success "SSH端口 $SSH_PORT/tcp 已配置访问限制"
}

process_ports() {
    info "开始分析和处理所有监听端口..."
    local port_data; port_data=$(get_listening_ports)
    if [ -z "$port_data" ]; then info "未检测到需要处理的监听端口。"; return; fi
    
    echo "$port_data" | while IFS=: read -r protocol port address process; do
        [ -z "$port" ] && continue
        local analysis_result; analysis_result=$(analyze_port "$protocol" "$port" "$address" "$process")
        local action="${analysis_result%%:*}"; local reason="${analysis_result#*:}"
        if [ "$action" = "open" ]; then
            local service_name=${SERVICE_PORTS[$port]:-"自定义服务"}
            if [ "$DRY_RUN" = true ]; then
                info "[预演] ${GREEN}开放: ${CYAN}$port/$protocol${GREEN} - ${YELLOW}$service_name${GREEN} (原因: $reason)${RESET}"; OPENED_PORTS=$((OPENED_PORTS + 1))
            elif ufw allow "$port/$protocol" >/dev/null; then
                echo -e "  ${GREEN}✓ 开放: ${CYAN}$port/$protocol${GREEN} - ${YELLOW}$service_name${GREEN} (原因: $reason)${RESET}"; OPENED_PORTS=$((OPENED_PORTS + 1))
            else
                echo -e "  ${RED}✗ 失败: ${CYAN}$port/$protocol${GREEN} - ${YELLOW}$service_name${RESET}"; FAILED_PORTS=$((FAILED_PORTS + 1))
            fi
        else
            local service_name=${SERVICE_PORTS[$port]:-"自定义服务"}
            echo -e "  ${BLUE}⏭️ 跳过: ${CYAN}$port/$protocol${BLUE} - ${YELLOW}$service_name${BLUE} (原因: $reason)${RESET}"; SKIPPED_PORTS=$((SKIPPED_PORTS + 1))
        fi
    done
}

enable_firewall() {
    info "最后一步：启用防火墙..."
    if [ "$DRY_RUN" = true ]; then info "[预演] 将执行 'ufw enable'"; return; fi
    if ufw --force enable | grep -q "Firewall is active"; then success "防火墙已成功激活并将在系统启动时自启";
    else error_exit "启用防火墙失败! 请检查UFW状态。"; fi
}

show_final_status() {
    echo -e "\n${GREEN}======================================"; echo -e "🎉 防火墙配置完成！"; echo -e "======================================${RESET}"
    echo -e "${YELLOW}配置统计：${RESET}"; echo -e "  - ${GREEN}成功开放端口: $OPENED_PORTS${RESET}"; echo -e "  - ${BLUE}跳过内部/受限端口: $SKIPPED_PORTS${RESET}"; echo -e "  - ${RED}失败端口: $FAILED_PORTS${RESET}"
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${CYAN}>>> 预演模式结束，未对系统做任何实际更改 <<<\n${RESET}"; echo -e "${YELLOW}如果以上预演结果符合预期，请移除 '--dry-run' 参数以正式执行。${RESET}"; return
    fi
    echo -e "\n${YELLOW}当前防火墙状态 (ufw status numbered):${RESET}"; ufw status numbered
    echo -e "\n${YELLOW}🔒 安全提醒：${RESET}"; echo -e "  - SSH端口 ${CYAN}$SSH_PORT${YELLOW} 已启用暴力破解防护 (limit)。"; echo -e "  - 配置备份已保存至 ${CYAN}$BACKUP_DIR${YELLOW}。"; echo -e "  - 建议定期使用 ${CYAN}'sudo ufw status'${YELLOW} 审查防火墙规则。"
}

# ==============================================================================
# 主函数与信号处理
# ==============================================================================

main() {
    trap 'echo -e "\n${RED}操作被中断。${RESET}"; exit 130' INT TERM
    
    # 步骤 0: 解析命令行参数
    parse_arguments "$@"

    # 步骤 1: 清理现有防火墙 (新功能!)
    echo -e "\n${CYAN}--- 1. 清理现有防火墙规则 ---${RESET}"
    purge_existing_firewalls

    # 步骤 2: 环境检查
    echo -e "\n${CYAN}--- 2. 检查系统环境与依赖 ---${RESET}"
    check_system

    # 步骤 3: 备份
    echo -e "\n${CYAN}--- 3. 备份信息 ---${RESET}"
    create_backup

    # 步骤 4: UFW 基础配置
    echo -e "\n${CYAN}--- 4. 配置UFW基础环境 ---${RESET}"
    setup_basic_firewall

    # 步骤 5: 处理SSH
    SSH_PORT=$(detect_ssh_port)
    echo -e "\n${CYAN}--- 5. 配置SSH端口 ($SSH_PORT) ---${RESET}"
    setup_ssh_access

    # 步骤 6: 核心 - 处理所有其他端口
    echo -e "\n${CYAN}--- 6. 智能分析并配置所有服务端口 ---${RESET}"
    process_ports

    # 步骤 7: 启用防火墙
    echo -e "\n${CYAN}--- 7. 启用防火墙 ---${RESET}"
    enable_firewall

    # 步骤 8: 显示最终报告
    show_final_status
    
    echo -e "\n${GREEN}✨ 脚本执行完毕！${RESET}"
}

# 运行主函数
main "$@"
