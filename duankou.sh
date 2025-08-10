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
SCRIPT_VERSION="3.0"
SCRIPT_NAME="Smart Firewall Configuration Script"
# 更新日志 v3.0:
# - 重构端口判断逻辑: 基于监听地址(公网/内网)而非端口号, 解决高位端口被忽略问题。
# - 全面支持UDP: 同时检测并处理TCP和UDP端口。
# - 引入受信任进程列表: 对nginx, xray, sing-box等进程的端口优先开放。
# - 优化端口解析: 使用更健壮的awk脚本解析ss输出, 兼容IPv4/IPv6。
# - 优化输出信息: 明确显示跳过端口的原因(如: 内部监听)。

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

# 明确定义为内部服务的端口 (即使监听在公网地址, 也需要用户确认)
INTERNAL_SERVICE_PORTS=(
    631     # CUPS Printing
)

# 明确定义为危险的端口 (开放前需要强制确认)
DANGEROUS_PORTS=(
    23      # Telnet (极不安全)
    135     # RPC Endpoint Mapper
    139     # NetBIOS
    445     # SMB
    1433    # MSSQL (除非确实需要)
    1521    # Oracle (除非确实需要)
    3389    # RDP (高风险)
    5432    # PostgreSQL (建议限制IP访问)
    6379    # Redis (高风险, 易受攻击)
    27017   # MongoDB (高风险, 易受攻击)
)

# 受信任的进程名 (这些进程监听的公网端口将被自动开放)
TRUSTED_PROCESSES=(
    "nginx" "apache2" "httpd" "caddy" "haproxy" "lighttpd"
    "xray" "v2ray" "sing-box" "trojan-go" "hysteria"
    "ss-server" "ss-manager" "sslocal" "obfs-server"
    "HiddifyCli" # 根据你的ss输出添加
)

# ==============================================================================
# 辅助函数 (日志/错误/帮助等)
# ==============================================================================

debug_log() {
    if [ "$DEBUG_MODE" = true ]; then
        echo -e "${BLUE}[DEBUG] $1${RESET}" >&2
    fi
}
error_exit() {
    echo -e "${RED}❌ 错误: $1${RESET}" >&2
    exit 1
}
warning() {
    echo -e "${YELLOW}⚠️  警告: $1${RESET}" >&2
}
success() {
    echo -e "${GREEN}✓ $1${RESET}"
}
info() {
    echo -e "${CYAN}ℹ️  $1${RESET}"
}

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
一个智能的防火墙自动配置脚本，能分析监听端口并自动生成UFW规则。

用法: $0 [选项]

选项:
    --debug      启用调试模式，显示详细日志
    --force      强制模式，跳过所有交互式确认提示
    --dry-run    预演模式，显示将要执行的操作但不实际执行
    --help, -h   显示此帮助信息

示例:
    sudo $0                 # 正常运行
    sudo $0 --dry-run         # 预演模式，强烈建议首次运行使用
    sudo $0 --force --debug   # 强制模式 + 调试模式

EOF
}

# ==============================================================================
# 系统检查与环境准备
# ==============================================================================

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
        echo "# UFW Status Backup"
        ufw status numbered
        echo -e "\n# IPTables Rules Backup"
        iptables-save
        echo -e "\n# Listening Ports Backup"
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
    if [[ "$ssh_port" =~ ^[0-9]+$ ]]; then
        debug_log "通过ss检测到sshd监听端口: $ssh_port"
        echo "$ssh_port"
        return
    fi
    # 后备方案
    ssh_port=$(grep -i '^Port' /etc/ssh/sshd_config | awk '{print $2}' | head -n 1)
    if [[ "$ssh_port" =~ ^[0-9]+$ ]]; then
        debug_log "通过sshd_config检测到端口: $ssh_port"
        echo "$ssh_port"
        return
    fi
    debug_log "未检测到非标准SSH端口，使用默认端口 22"
    echo "22"
}

get_listening_ports() {
    debug_log "获取系统所有TCP/UDP监听端口"
    # 使用 awk 解析 ss -tulnp 的输出
    # 格式: protocol:port:address:process
    ss -tulnp 2>/dev/null | awk '
    /LISTEN|UNCONN/ {
        protocol = $1
        listen_addr_port = $5

        # 获取进程名, 兼容不同ss版本输出
        process = "unknown"
        if (match($0, /users:\(\("([^"]+)"/, p)) {
            process = p[1]
        } else if (match($0, /("([^"]+)",pid=/, p)) {
            process = p[2]
        }


        # 分离地址和端口, 兼容IPv4和IPv6
        if (match(listen_addr_port, /^(.*):([0-9]+)$/, parts)) {
            address = parts[1]
            port = parts[2]

            # 清理IPv6地址格式
            if (address ~ /^\[.*\]$/) {
                address = substr(address, 2, length(address)-2)
            }
            # 将 '*' 转换为更易读的 '0.0.0.0'
            if (address == "*") {
                address = "0.0.0.0"
            }

            if (port > 0 && port <= 65535) {
                # 去除重复行
                line = protocol ":" port ":" address ":" process
                if (!seen[line]++) {
                    print line
                }
            }
        }
    }'
}

is_public_listener() {
    local address=$1
    case "$address" in
        "127.0.0.1"|"::1"|"localhost"|127.*)
            return 1 # 否, 是内部监听
            ;;
        *)
            return 0 # 是, 是公网监听
            ;;
    esac
}

analyze_port() {
    local protocol=$1 port=$2 address=$3 process=$4
    local reason=""

    debug_log "分析端口: $protocol/$port, 地址: $address, 进程: $process"

    # 规则1: SSH端口由专门的函数处理, 此处跳过
    if [ "$port" = "$SSH_PORT" ]; then
        reason="SSH端口，单独处理"
        echo "skip:$reason"
        return
    fi

    # 规则2: 非公网监听的端口一律跳过
    if ! is_public_listener "$address"; then
        reason="内部监听于 $address"
        echo "skip:$reason"
        return
    fi

    # 规则3: 检查是否为受信任的进程 (如 nginx, xray, sing-box)
    for trusted_proc in "${TRUSTED_PROCESSES[@]}"; do
        if [[ "$process" == "$trusted_proc" ]]; then
            reason="受信任的进程 ($process)"
            echo "open:$reason"
            return
        fi
    done

    # 规则4: 检查是否为明确定义的内部服务端口
    for internal_serv_port in "${INTERNAL_SERVICE_PORTS[@]}"; do
        if [ "$port" = "$internal_serv_port" ]; then
            reason="内部服务端口 ($service_name)"
            echo "skip:$reason"
            return
        fi
    done

    # 规则 5: 检查是否为危险端口, 需要用户交互确认
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

    # 规则 6: 对于其他所有公网监听的端口, 默认开放 (根据用户需求)
    reason="公网服务 ($process)"
    echo "open:$reason"
}


# ==============================================================================
# 防火墙操作
# ==============================================================================

setup_basic_firewall() {
    info "配置UFW基础规则..."
    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将重置UFW, 设置默认策略 (deny incoming, allow outgoing)"
        return
    fi
    ufw --force reset >/dev/null
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    success "UFW基础规则设置完毕"
}

setup_ssh_access() {
    info "配置SSH访问端口 $SSH_PORT..."
    if [ "$DRY_RUN" = true ]; then
        info "[预演] 将允许并限制 (limit) SSH端口 $SSH_PORT/tcp"
        return
    fi
    ufw allow $SSH_PORT/tcp >/dev/null
    ufw limit $SSH_PORT/tcp >/dev/null
    success "SSH端口 $SSH_PORT/tcp 已配置访问限制"
}

open_single_port() {
    local protocol=$1 port=$2 reason=$3
    local service_name=${SERVICE_PORTS[$port]:-"自定义服务"}

    if [ "$DRY_RUN" = true ]; then
        info "[预演] ${GREEN}开放: ${CYAN}$port/$protocol${GREEN} - ${YELLOW}$service_name${GREEN} (原因: $reason)${RESET}"
        OPENED_PORTS=$((OPENED_PORTS + 1))
        return
    fi

    if ufw allow "$port/$protocol" >/dev/null; then
        echo -e "  ${GREEN}✓ 开放: ${CYAN}$port/$protocol${GREEN} - ${YELLOW}$service_name${GREEN} (原因: $reason)${RESET}"
        OPENED_PORTS=$((OPENED_PORTS + 1))
    else
        echo -e "  ${RED}✗ 失败: ${CYAN}$port/$protocol${GREEN} - ${YELLOW}$service_name${RESET}"
        FAILED_PORTS=$((FAILED_PORTS + 1))
    fi
}

process_ports() {
    info "开始分析和处理所有监听端口..."
    local port_data
    port_data=$(get_listening_ports)

    if [ -z "$port_data" ]; then
        info "未检测到需要处理的监听端口。"
        return
    fi

    echo "$port_data" | while IFS=: read -r protocol port address process; do
        [ -z "$port" ] && continue

        local analysis_result
        analysis_result=$(analyze_port "$protocol" "$port" "$address" "$process")
        
        local action="${analysis_result%%:*}"
        local reason="${analysis_result#*:}"

        if [ "$action" = "open" ]; then
            open_single_port "$protocol" "$port" "$reason"
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

    if ufw --force enable | grep -q "Firewall is active"; then
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

    echo -e "\n${YELLOW}🔒 安全提醒：${RESET}"
    echo -e "  - SSH端口 ${CYAN}$SSH_PORT${YELLOW} 已启用暴力破解防护 (limit)。"
    echo -e "  - 配置备份已保存至 ${CYAN}$BACKUP_DIR${YELLOW}。"
    echo -e "  - 建议定期使用 ${CYAN}'sudo ufw status'${YELLOW} 审查防火墙规则。"
    echo -e "  - 为进一步提高安全性，请考虑安装 ${CYAN}fail2ban${YELLOW}。"
}


# ==============================================================================
# 主函数与信号处理
# ==============================================================================

main() {
    trap 'echo -e "\n${RED}操作被中断。${RESET}"; exit 130' INT TERM
    
    parse_arguments "$@"

    # 步骤 1: 环境检查
    echo -e "\n${CYAN}--- 1. 检查系统环境 ---${RESET}"
    check_system

    # 步骤 2: 备份
    echo -e "\n${CYAN}--- 2. 备份当前防火墙规则 ---${RESET}"
    create_backup

    # 步骤 3: 基础配置
    echo -e "\n${CYAN}--- 3. 配置UFW基础环境 ---${RESET}"
    setup_basic_firewall

    # 步骤 4: 处理SSH
    SSH_PORT=$(detect_ssh_port)
    echo -e "\n${CYAN}--- 4. 配置SSH端口 ($SSH_PORT) ---${RESET}"
    setup_ssh_access

    # 步骤 5: 核心 - 处理所有其他端口
    echo -e "\n${CYAN}--- 5. 智能分析并配置所有服务端口 ---${RESET}"
    process_ports

    # 步骤 6: 启用防火墙
    echo -e "\n${CYAN}--- 6. 启用防火墙 ---${RESET}"
    enable_firewall

    # 步骤 7: 显示最终报告
    show_final_status
    
    echo -e "\n${GREEN}✨ 脚本执行完毕！${RESET}"
}

# 运行主函数
main "$@"
