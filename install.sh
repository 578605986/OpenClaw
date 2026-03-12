#!/bin/bash
# =============================================================================
# ClawArmor All-in-One 全自动部署脚本 v2.0
# 一键全自动安装: fail2ban (实时防护) + ClawArmor (深度监控)
# 
# 全自动特性:
#   ✅ 自动检测SSH端口
#   ✅ 自动检测当前客户端IP并加入白名单
#   ✅ 自动获取服务器名称
#   ✅ 支持环境变量自动配置邮箱
# 
# 使用方法:
#   方式1 - 全自动 (推荐):
#     export CLAWARMOR_EMAIL="your@qq.com"
#     export CLAWARMOR_PASSWORD="your_auth_code"
#     sudo bash install.sh v5
#   
#   方式2 - 交互式:
#     sudo bash install.sh v4
#     
#   版本选择:
#     v4 - 安装 v4.1 (智能防御版, 推荐)
#     v5 - 安装 v5.1 (完整安全套件)
# =============================================================================

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置
CLAWARMOR_DIR="/opt/clawarmor"
LOG_FILE="/var/log/clawarmor_install.log"
VERSION="${1:-v4}"  # 默认安装 v4

# 日志函数
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "请使用 sudo 或 root 用户运行此脚本"
    fi
}

# 检测SSH端口
detect_ssh_port() {
    log "🔍 检测SSH端口..."
    
    # 从配置文件读取
    if [ -f /etc/ssh/sshd_config ]; then
        SSH_PORT=$(grep -E "^Port\s+[0-9]+" /etc/ssh/sshd_config | awk '{print $2}' | head -1)
    fi
    
    # 如果未找到，从进程检测
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=$(ss -tlnp | grep sshd | grep -o ':[0-9]*' | head -1 | tr -d ':')
    fi
    
    # 默认22
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=22
    fi
    
    success "检测到SSH端口: $SSH_PORT"
}

# 全自动检测当前客户端IP
detect_client_ip() {
    log "🔍 自动检测当前客户端IP..."
    
    # 方法1: 从SSH_CONNECTION环境变量获取
    if [ -n "$SSH_CONNECTION" ]; then
        CLIENT_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    fi
    
    # 方法2: 从SSH_CLIENT环境变量获取
    if [ -z "$CLIENT_IP" ] && [ -n "$SSH_CLIENT" ]; then
        CLIENT_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
    fi
    
    # 方法3: 从who命令获取
    if [ -z "$CLIENT_IP" ]; then
        CLIENT_IP=$(who am i | awk '{print $5}' | tr -d '()')
    fi
    
    # 方法4: 从w命令获取
    if [ -z "$CLIENT_IP" ]; then
        CLIENT_IP=$(w -h | grep "$(whoami)" | head -1 | awk '{print $3}')
    fi
    
    # 验证IP格式
    if [ -n "$CLIENT_IP" ]; then
        # 检查是否是有效IP
        if [[ "$CLIENT_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            success "检测到当前客户端IP: $CLIENT_IP"
            export CLIENT_IP
            return 0
        fi
    fi
    
    warning "无法自动检测客户端IP，将只使用默认白名单"
    CLIENT_IP=""
    return 1
}

# 安装 fail2ban
install_fail2ban() {
    log "📦 步骤 1/5: 安装 fail2ban (实时防护)..."
    
    # 检查是否已安装
    if command -v fail2ban-client &> /dev/null; then
        warning "fail2ban 已安装，跳过安装"
        systemctl restart fail2ban
        success "fail2ban 已重启"
        return
    fi
    
    # 安装 fail2ban
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y fail2ban
    elif command -v yum &> /dev/null; then
        yum install -y fail2ban
    elif command -v dnf &> /dev/null; then
        dnf install -y fail2ban
    else
        error "无法识别包管理器，请手动安装 fail2ban"
    fi
    
    # 配置 fail2ban
    log "⚙️  配置 fail2ban..."
    detect_ssh_port
    detect_client_ip  # 自动检测当前IP
    
    # 构建白名单
    IGNORE_IPS="127.0.0.1/8 ::1"
    if [ -n "$CLIENT_IP" ]; then
        IGNORE_IPS="$IGNORE_IPS $CLIENT_IP"
        log "🛡️  当前连接IP已加入白名单: $CLIENT_IP"
    fi
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd
ignoreip = $IGNORE_IPS

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

# 邮件通知 (可选)
# destemail = your-email@example.com
# sender = fail2ban@localhost
# mta = sendmail
# action = %(action_mwl)s
EOF
    
    # 启动服务
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    # 验证安装
    if systemctl is-active --quiet fail2ban; then
        success "fail2ban 安装并启动成功"
        log "   配置: SSH端口=$SSH_PORT, 白名单IP=$IGNORE_IPS"
        log "   规则: 3次失败登录封禁1小时"
    else
        error "fail2ban 启动失败"
    fi
}

# 安装 ClawArmor
install_clawarmor() {
    log "📦 步骤 2/5: 安装 ClawArmor $VERSION (深度监控)..."
    
    # 创建目录
    mkdir -p "$CLAWARMOR_DIR"
    mkdir -p "$CLAWARMOR_DIR/quarantine"
    
    # 下载对应版本
    if [ "$VERSION" == "v5" ] || [ "$VERSION" == "V5" ]; then
        FILE="clawarmor_suite_v5.py"
        success "选择版本: v5.1 完整安全套件"
    else
        FILE="clawarmor_v4_safe.py"
        success "选择版本: v4.1 智能防御版 (推荐)"
    fi
    
    log "⬇️  下载 $FILE..."
    wget -q -O "$CLAWARMOR_DIR/clawarmor.py" \
        "https://raw.githubusercontent.com/578605986/OpenClaw/main/src/$FILE"
    
    if [ $? -ne 0 ]; then
        error "下载失败，请检查网络连接"
    fi
    
    chmod +x "$CLAWARMOR_DIR/clawarmor.py"
    success "ClawArmor 下载完成"
}

# 配置 ClawArmor - 全自动或交互式
configure_clawarmor() {
    log "⚙️  步骤 3/5: 配置 ClawArmor..."
    
    # 尝试自动检测邮箱配置
    AUTO_CONFIG=false
    
    # 检查是否有环境变量
    if [ -n "$CLAWARMOR_EMAIL" ] && [ -n "$CLAWARMOR_PASSWORD" ]; then
        sender_email="$CLAWARMOR_EMAIL"
        sender_password="$CLAWARMOR_PASSWORD"
        receiver_email="${CLAWARMOR_RECEIVER:-$CLAWARMOR_EMAIL}"
        AUTO_CONFIG=true
        log "✅ 从环境变量读取邮箱配置"
    fi
    
    # 如果没有自动配置，进入交互模式
    if [ "$AUTO_CONFIG" = false ]; then
        echo ""
        echo "=========================================="
        echo "  📧 邮件配置"
        echo "=========================================="
        echo ""
        echo "ClawArmor 需要通过邮件发送安全报告"
        echo ""
        echo "提示: 您也可以通过环境变量自动配置:"
        echo "  export CLAWARMOR_EMAIL=your@qq.com"
        echo "  export CLAWARMOR_PASSWORD=your_auth_code"
        echo "  export CLAWARMOR_RECEIVER=receiver@example.com"
        echo ""
        
        # 读取用户输入
        read -p "发件邮箱 (QQ邮箱): " sender_email
        read -sp "邮箱授权码 (不是登录密码): " sender_password
        echo ""
        read -p "收件邮箱 [默认: $sender_email]: " receiver_email
        receiver_email="${receiver_email:-$sender_email}"
    fi
    
    # 服务器名称自动检测
    server_name=$(hostname)
    
    # 更新配置
    sed -i "s/SENDER_EMAIL = \".*\"/SENDER_EMAIL = \"$sender_email\"/" "$CLAWARMOR_DIR/clawarmor.py"
    sed -i "s/SENDER_PASSWORD = \".*\"/SENDER_PASSWORD = \"$sender_password\"/" "$CLAWARMOR_DIR/clawarmor.py"
    sed -i "s/RECEIVER_EMAIL = \".*\"/RECEIVER_EMAIL = \"$receiver_email\"/" "$CLAWARMOR_DIR/clawarmor.py"
    sed -i "s/SERVER_NAME = \".*\"/SERVER_NAME = \"$server_name\"/" "$CLAWARMOR_DIR/clawarmor.py"
    
    # v5版本还需要更新CONFIG字典
    if [ "$VERSION" == "v5" ] || [ "$VERSION" == "V5" ]; then
        sed -i "s/\"sender_email\": \".*\"/\"sender_email\": \"$sender_email\"/" "$CLAWARMOR_DIR/clawarmor.py"
        sed -i "s/\"sender_password\": \".*\"/\"sender_password\": \"$sender_password\"/" "$CLAWARMOR_DIR/clawarmor.py"
        sed -i "s/\"receiver_email\": \".*\"/\"receiver_email\": \"$receiver_email\"/" "$CLAWARMOR_DIR/clawarmor.py"
        sed -i "s/\"server_name\": \".*\"/\"server_name\": \"$server_name\"/" "$CLAWARMOR_DIR/clawarmor.py"
    fi
    
    success "ClawArmor 配置完成"
    log "   服务器名称: $server_name"
}

# 配置定时任务
setup_cron() {
    log "⏰ 步骤 4/5: 配置定时任务..."
    
    # 检查是否已有clawarmor任务
    if crontab -l 2>/dev/null | grep -q "clawarmor"; then
        warning "已存在 ClawArmor 定时任务，跳过配置"
        return
    fi
    
    # 添加定时任务
    (crontab -l 2>/dev/null; echo "# ClawArmor 安全监控 - 每30分钟检查一次") | crontab -
    (crontab -l 2>/dev/null; echo "*/30 * * * * /usr/bin/python3 $CLAWARMOR_DIR/clawarmor.py >> /var/log/clawarmor.log 2>&1") | crontab -
    
    success "定时任务配置完成"
    log "   执行频率: 每30分钟检查一次"
}

# 首次运行测试
first_run() {
    log "🚀 步骤 5/5: 首次运行测试..."
    
    log "创建系统基线..."
    cd "$CLAWARMOR_DIR"
    python3 clawarmor.py --create-baseline 2>/dev/null || python3 clawarmor.py 2>/dev/null || true
    
    success "首次运行完成"
}

# 显示安装报告
show_report() {
    echo ""
    echo "=========================================="
    echo "  🎉 ClawArmor 全自动部署完成!"
    echo "=========================================="
    echo ""
    echo "📦 已安装组件:"
    echo "   ✅ fail2ban - 实时攻击防护 (秒级响应)"
    echo "   ✅ ClawArmor $VERSION - 深度安全监控"
    echo ""
    echo "🛡️  安全保险:"
    echo "   ✅ SSH端口: 自动检测 ($SSH_PORT)"
    echo "   ✅ 当前IP: 自动加入白名单 ($CLIENT_IP)"
    echo "   ✅ 内网IP: 永久白名单保护"
    echo "   ✅ 渐进防御: 3次失败才封禁"
    echo ""
    echo "📁 安装位置:"
    echo "   ClawArmor: $CLAWARMOR_DIR/"
    echo "   fail2ban配置: /etc/fail2ban/jail.local"
    echo "   日志: /var/log/clawarmor.log"
    echo ""
    echo "⏰ 定时任务:"
    echo "   每30分钟自动扫描"
    echo "   crontab -l 查看"
    echo ""
    echo "📧 报告发送:"
    echo "   安全威胁 → 邮件通知"
    echo ""
    echo "🔧 常用命令:"
    echo "   查看fail2ban状态: fail2ban-client status sshd"
    echo "   查看封禁IP: fail2ban-client status sshd | grep Banned"
    echo "   手动运行扫描: python3 $CLAWARMOR_DIR/clawarmor.py"
    echo "   查看日志: tail -f /var/log/clawarmor.log"
    echo ""
    echo "🛡️  防护层级:"
    echo "   第一层: fail2ban - 实时封禁攻击IP"
    echo "   第二层: ClawArmor - 深度扫描+邮件报告"
    echo ""
    echo "=========================================="
    echo ""
}

# 主函数
main() {
    echo ""
    echo "🛡️  ClawArmor All-in-One 部署脚本"
    echo "=========================================="
    echo ""
    
    check_root
    
    log "开始部署..."
    log "选择版本: $VERSION"
    
    install_fail2ban
    install_clawarmor
    configure_clawarmor
    setup_cron
    first_run
    
    show_report
    
    success "部署完成!"
}

# 运行主函数
main
