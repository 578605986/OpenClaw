#!/bin/bash
# =============================================================================
# ClawArmor v7.0 - 安全强化版一键安装脚本
# Security Hardened Edition Installer
# =============================================================================

set -euo pipefail  # 严格模式

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 配置
CLAWARMOR_DIR="/opt/clawarmor"
CONFIG_DIR="/etc/clawarmor"
LOG_FILE="/var/log/clawarmor_install_v7.log"

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

# 检查依赖
check_dependencies() {
    log "🔍 检查系统依赖..."
    
    # 检查Python3
    if ! command -v python3 &> /dev/null; then
        error "Python3 未安装"
    fi
    
    # 检查pip
    if ! command -v pip3 &> /dev/null; then
        log "📦 安装 pip3..."
        apt-get update && apt-get install -y python3-pip
    fi
    
    # 安装Python依赖
    log "📦 安装Python依赖..."
    pip3 install cryptography certifi --quiet || warning "部分依赖安装失败"
    
    success "依赖检查完成"
}

# 创建安全目录
setup_directories() {
    log "📁 创建安全目录结构..."
    
    # 主目录
    mkdir -p "$CLAWARMOR_DIR"/{src,quarantine,logs}
    chmod 750 "$CLAWARMOR_DIR"
    
    # 配置目录 - 严格权限
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    
    success "目录创建完成"
}

# 检测SSH端口
detect_ssh_port() {
    log "🔍 检测SSH端口..."
    
    SSH_PORT=22
    if [ -f /etc/ssh/sshd_config ]; then
        detected=$(grep -E "^Port\s+[0-9]+" /etc/ssh/sshd_config | awk '{print $2}' | head -1)
        [ -n "$detected" ] && SSH_PORT=$detected
    fi
    
    success "SSH端口: $SSH_PORT"
    echo "$SSH_PORT" > "$CONFIG_DIR/ssh_port"
}

# 检测客户端IP
detect_client_ip() {
    log "🔍 检测当前客户端IP..."
    
    CLIENT_IP=""
    
    # 方法1: SSH_CONNECTION
    if [ -n "${SSH_CONNECTION:-}" ]; then
        CLIENT_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    fi
    
    # 方法2: SSH_CLIENT
    if [ -z "$CLIENT_IP" ] && [ -n "${SSH_CLIENT:-}" ]; then
        CLIENT_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
    fi
    
    # 验证IP
    if [ -n "$CLIENT_IP" ]; then
        if [[ "$CLIENT_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            success "客户端IP: $CLIENT_IP (已加入白名单)"
            echo "$CLIENT_IP" > "$CONFIG_DIR/whitelist_ip"
            return
        fi
    fi
    
    warning "无法自动检测客户端IP，请手动配置白名单"
}

# 安装主程序
install_clawarmor() {
    log "📥 安装 ClawArmor v7.0..."
    
    # 复制主程序
    cp clawarmor_v7.py "$CLAWARMOR_DIR/src/"
    chmod 755 "$CLAWARMOR_DIR/src/clawarmor_v7.py"
    
    # 创建启动脚本
    cat > /usr/local/bin/clawarmor << 'EOF'
#!/bin/bash
python3 /opt/clawarmor/src/clawarmor_v7.py "$@"
EOF
    chmod 755 /usr/local/bin/clawarmor
    
    success "主程序安装完成"
}

# 创建系统服务
create_systemd_service() {
    log "⚙️  创建系统服务..."
    
    cat > /etc/systemd/system/clawarmor.service << EOF
[Unit]
Description=ClawArmor v7.0 - Security Hardened
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/clawarmor/src/clawarmor_v7.py monitor
ExecStop=/bin/kill -TERM \$MAINPID
Restart=always
RestartSec=10
User=root
StandardOutput=append:/var/log/clawarmor_v7.log
StandardError=append:/var/log/clawarmor_v7.log

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    success "系统服务创建完成"
}

# 配置邮件（可选）
setup_email() {
    echo
    echo "📧 邮件配置（可选）"
    echo "=================="
    read -p "是否配置邮件通知? [y/N]: " setup_email
    
    if [[ "$setup_email" =~ ^[Yy]$ ]]; then
        read -p "发件邮箱 (QQ邮箱): " email
        read -sp "邮箱授权码: " password
        echo
        read -p "收件邮箱: " receiver
        
        # 使用Python脚本加密保存
        python3 << EOFPYTHON
from cryptography.fernet import Fernet
import json
import os

config_dir = "$CONFIG_DIR"
key_file = os.path.join(config_dir, ".master.key")
config_file = os.path.join(config_dir, "config.enc")

# 生成密钥
key = Fernet.generate_key()
with open(key_file, 'wb') as f:
    f.write(key)
os.chmod(key_file, 0o400)

# 加密数据
f = Fernet(key)
data = {
    "sender_email": "$email",
    "sender_password": "$password",
    "receiver_email": "$receiver",
    "updated_at": "$(date -Iseconds)"
}
encrypted = f.encrypt(json.dumps(data).encode())

with open(config_file, 'wb') as file:
    file.write(encrypted)
os.chmod(config_file, 0o600)

print("✅ 邮件配置已加密保存")
EOFPYTHON
    else
        log "跳过邮件配置"
    fi
}

# 启动服务
start_service() {
    log "🚀 启动 ClawArmor 服务..."
    
    systemctl enable clawarmor
    systemctl start clawarmor
    
    sleep 2
    
    if systemctl is-active --quiet clawarmor; then
        success "✅ ClawArmor v7.0 启动成功!"
    else
        error "❌ 服务启动失败，请检查日志: journalctl -u clawarmor"
    fi
}

# 显示状态
show_status() {
    echo
    echo "=========================================="
    echo "🛡️  ClawArmor v7.0 安装完成!"
    echo "=========================================="
    echo
    echo "📍 安装位置: $CLAWARMOR_DIR"
    echo "📍 配置文件: $CONFIG_DIR"
    echo "📍 日志文件: /var/log/clawarmor_v7.log"
    echo
    echo "🚀 常用命令:"
    echo "  clawarmor monitor  - 启动监控"
    echo "  clawarmor list     - 查看封禁列表"
    echo "  clawarmor ban IP   - 手动封禁IP"
    echo "  clawarmor unban IP - 手动解封IP"
    echo
    echo "🔧 服务管理:"
    echo "  systemctl status clawarmor  - 查看状态"
    echo "  systemctl stop clawarmor    - 停止服务"
    echo "  systemctl restart clawarmor - 重启服务"
    echo
    echo "📋 安全特性:"
    echo "  ✅ 命令注入防护"
    echo "  ✅ SSL证书验证"
    echo "  ✅ 配置加密存储"
    echo "  ✅ 文件权限控制"
    echo "  ✅ 线程安全保护"
    echo "=========================================="
}

# 主函数
main() {
    echo "=========================================="
    echo "🛡️  ClawArmor v7.0 安全强化版安装器"
    echo "=========================================="
    
    check_root
    check_dependencies
    setup_directories
    detect_ssh_port
    detect_client_ip
    install_clawarmor
    create_systemd_service
    setup_email
    start_service
    show_status
}

main "$@"
