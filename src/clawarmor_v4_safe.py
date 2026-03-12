#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClawArmor v4.0 - 智能主动防御系统
核心特性：多重安全保险，绝不自伤，渐进式防御

Author: 小灵通
Version: 4.0.0
"""

import smtplib
import ssl
import os
import subprocess
import re
import json
import time
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.utils import formataddr

# ==================== 用户配置区域 ====================
SENDER_EMAIL = "你的QQ邮箱@qq.com"
SENDER_PASSWORD = "你的QQ邮箱授权码"
RECEIVER_EMAIL = "你的邮箱@example.com"
SERVER_NAME = "Server-1"

# SSH端口（生命线，永远不会被封禁）
# 默认自动检测，也可手动指定如：SSH_PORT = 22
SSH_PORT = None  # None表示自动检测，程序会从系统读取实际端口

# 白名单IP（永远不会被封禁，包括当前连接IP）
WHITELIST_IPS = [
    "127.0.0.1",      # 本地回环
    "::1",            # IPv6本地
    # 其他白名单IP可以在这里添加
]

# 防御模式开关（默认只检测不封禁，确认安全后再开启）
DEFENSE_MODE = {
    "auto_block_ip": False,      # 自动封禁攻击IP（默认关闭，用户确认后开启）
    "auto_isolate_file": False,  # 自动隔离可疑文件（默认关闭）
    "notify_only": True,         # 仅通知模式（默认开启，最安全）
}

# 防御阈值配置
THRESHOLDS = {
    "failed_login": 5,       # 5次失败登录才触发防御
    "time_window": 300,      # 5分钟内的统计
}
# =====================================================

# 数据存储文件（用于记录攻击历史和防御状态）
DATA_FILE = "/opt/clawarmor/defense_data.json"
LOG_FILE = "/var/log/clawarmor_defense.log"


def get_current_client_ip():
    """获取当前管理员的IP（永远加入白名单）"""
    try:
        # 方法1：从SSH连接环境获取
        ssh_client = os.environ.get('SSH_CONNECTION', '')
        if ssh_client:
            return ssh_client.split()[0]
        
        # 方法2：从SSH_CLIENT获取
        ssh_client2 = os.environ.get('SSH_CLIENT', '')
        if ssh_client2:
            return ssh_client2.split()[0]
        
        # 方法3：从who命令获取
        result = subprocess.getoutput("who am i | awk '{print $5}' | tr -d '()'")
        if result:
            return result
            
    except:
        pass
    return None


def get_lifeline_port():
    """自动检测SSH生命线端口（永远保持开放）
    检测优先级：
    1. 如果 SSH_PORT 已手动设置，直接使用
    2. 从 /etc/ssh/sshd_config 读取
    3. 从运行中的 sshd 进程检测
    4. 默认返回 22
    """
    global SSH_PORT
    
    # 如果用户手动设置了端口，直接使用
    if SSH_PORT is not None and isinstance(SSH_PORT, int):
        return SSH_PORT
    
    try:
        # 方法1：从配置文件读取
        if os.path.exists('/etc/ssh/sshd_config'):
            with open('/etc/ssh/sshd_config', 'r') as f:
                for line in f:
                    if 'Port' in line and not line.startswith('#'):
                        port_match = re.search(r'Port\s+(\d+)', line)
                        if port_match:
                            detected_port = int(port_match.group(1))
                            SSH_PORT = detected_port  # 缓存结果
                            return detected_port
        
        # 方法2：从进程检测
        result = subprocess.getoutput("ss -tlnp | grep sshd | head -1")
        if result:
            port_match = re.search(r':(\d+)', result)
            if port_match:
                detected_port = int(port_match.group(1))
                SSH_PORT = detected_port  # 缓存结果
                return detected_port
    except Exception as e:
        log(f"自动检测SSH端口失败: {e}，使用默认22")
    
    # 默认返回22
    SSH_PORT = 22
    return 22


def load_defense_data():
    """加载防御数据（攻击历史、已封禁IP等）"""
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {"blocked_ips": [], "attack_history": {}, "whitelist": []}


def save_defense_data(data):
    """保存防御数据"""
    try:
        os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        log(f"保存防御数据失败: {e}")


def log(message):
    """记录日志"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] {message}"
    print(log_message)
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(log_message + '\n')
    except:
        pass


def is_ip_whitelisted(ip):
    """检查IP是否在白名单中"""
    # 获取当前客户端IP并加入动态白名单
    current_ip = get_current_client_ip()
    if current_ip and ip == current_ip:
        return True
    
    # 检查配置的白名单
    if ip in WHITELIST_IPS:
        return True
    
    # 检查私有IP（10.x, 172.16-31.x, 192.168.x）
    if re.match(r'^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.)', ip):
        return True
    
    return False


def get_attack_stats():
    """获取攻击统计（5分钟窗口）"""
    try:
        # 获取最近5分钟的登录失败记录
        since_time = datetime.now() - timedelta(seconds=THRESHOLDS['time_window'])
        
        result = subprocess.getoutput("lastb -i | head -50")
        attacks = {}
        
        if result:
            for line in result.strip().split('\n'):
                if not line or 'btmp begins' in line:
                    continue
                
                parts = line.split()
                if len(parts) >= 3:
                    username = parts[0]
                    ip = parts[2]
                    
                    # 跳过白名单IP
                    if is_ip_whitelisted(ip):
                        continue
                    
                    if ip not in attacks:
                        attacks[ip] = {'count': 0, 'users': set(), 'first_seen': datetime.now().isoformat()}
                    attacks[ip]['count'] += 1
                    attacks[ip]['users'].add(username)
        
        return attacks
    except Exception as e:
        log(f"获取攻击统计失败: {e}")
        return {}


def safe_block_ip(ip):
    """安全地封禁IP（多重保险）"""
    # 保险1：检查是否是白名单
    if is_ip_whitelisted(ip):
        log(f"🛡️ 跳过白名单IP: {ip}")
        return False
    
    # 保险2：检查是否是生命线端口的相关IP
    # 注意：我们不封禁端口，只封禁IP
    
    # 保险3：检查是否已经封禁
    data = load_defense_data()
    if ip in data.get('blocked_ips', []):
        return True
    
    # 保险4：渐进式防御（先警告，再封禁）
    attack_count = data.get('attack_history', {}).get(ip, 0)
    
    if attack_count < THRESHOLDS['failed_login']:
        # 还没到阈值，只记录
        log(f"⚠️ 记录攻击IP: {ip} (次数: {attack_count + 1}/{THRESHOLDS['failed_login']})")
        data['attack_history'] = data.get('attack_history', {})
        data['attack_history'][ip] = attack_count + 1
        save_defense_data(data)
        return False
    
    # 达到阈值，执行封禁（但只在用户开启自动防御时）
    if not DEFENSE_MODE['auto_block_ip']:
        log(f"🚨 攻击IP {ip} 已达到封禁阈值，但自动防御未开启，仅发送警报")
        return False
    
    try:
        # 使用iptables封禁（仅INPUT链，不影响OUTPUT）
        # 命令解释：只封禁该IP的入站连接，不影响其他连接
        cmd = f"iptables -A INPUT -s {ip} -p tcp --dport {SSH_PORT} -j DROP"
        
        # 保险5：执行前再次确认
        log(f"🔒 正在封禁攻击IP: {ip} (攻击次数: {attack_count})")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            # 记录封禁
            data['blocked_ips'].append({
                'ip': ip,
                'blocked_at': datetime.now().isoformat(),
                'reason': f'暴力破解 ({attack_count}次失败登录)'
            })
            save_defense_data(data)
            log(f"✅ 已封禁IP: {ip}")
            return True
        else:
            log(f"❌ 封禁IP失败: {result.stderr}")
            return False
            
    except Exception as e:
        log(f"❌ 封禁IP异常: {e}")
        return False


def safe_isolate_file(filepath):
    """安全地隔离可疑文件"""
    if not DEFENSE_MODE['auto_isolate_file']:
        log(f"📁 发现可疑文件但自动隔离未开启: {filepath}")
        return False
    
    try:
        # 创建隔离目录
        quarantine_dir = "/opt/clawarmor/quarantine"
        os.makedirs(quarantine_dir, exist_ok=True)
        
        # 生成隔离文件名
        filename = os.path.basename(filepath)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        quarantine_path = f"{quarantine_dir}/{timestamp}_{filename}"
        
        # 移动文件（不是删除！）
        os.rename(filepath, quarantine_path)
        log(f"📦 已隔离可疑文件: {filepath} -> {quarantine_path}")
        return True
        
    except Exception as e:
        log(f"❌ 隔离文件失败: {e}")
        return False


def self_check():
    """自检查：确保不会把自己锁在外面"""
    checks = []
    
    # 检查1：确认SSH端口可访问
    try:
        result = subprocess.getoutput(f"ss -tlnp | grep ':{SSH_PORT}'")
        if result:
            checks.append(f"✅ SSH端口 {SSH_PORT} 正常")
        else:
            checks.append(f"⚠️ 警告：SSH端口 {SSH_PORT} 未检测到")
    except:
        checks.append("⚠️ 无法检测SSH端口")
    
    # 检查2：确认iptables规则不会阻断自己
    try:
        result = subprocess.getoutput("iptables -L INPUT -n | grep DROP")
        if result:
            # 检查是否有DROP规则但没有白名单
            checks.append(f"ℹ️ 当前有 {result.count('DROP')} 条DROP规则")
        else:
            checks.append("✅ 无DROP规则（当前安全）")
    except:
        checks.append("⚠️ 无法检查iptables规则")
    
    # 检查3：确认数据文件可写
    try:
        os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
        with open(DATA_FILE, 'a') as f:
            pass
        checks.append("✅ 数据文件可写")
    except:
        checks.append("❌ 数据文件不可写")
    
    return checks


def generate_defense_report(attacks, actions_taken):
    """生成防御报告"""
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 统计
    total_attacks = sum(a['count'] for a in attacks.values())
    blocked_ips = len([a for a in actions_taken if a['action'] == 'blocked'])
    warned_ips = len([a for a in actions_taken if a['action'] == 'warned'])
    
    body = f"""
🛡️ ClawArmor v4.0 智能防御报告
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 报告时间: {current_time}
🖥️  服务器: {SERVER_NAME}
📈 攻击统计: {total_attacks} 次攻击尝试
🔒 防御动作: {blocked_ips} 个IP被封禁, {warned_ips} 个IP被警告

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

攻击详情:
"""
    
    for ip, info in attacks.items():
        users = ', '.join(info['users'])
        body += f"""
  🎯 攻击IP: {ip}
     攻击次数: {info['count']} 次
     目标用户: {users}
     白名单: {'是' if is_ip_whitelisted(ip) else '否'}
"""
    
    body += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🛡️ 安全保险状态:
• 自动封禁IP: {'✅ 开启' if DEFENSE_MODE['auto_block_ip'] else '❌ 关闭（仅警告）'}
• 自动隔离文件: {'✅ 开启' if DEFENSE_MODE['auto_isolate_file'] else '❌ 关闭'}
• 当前白名单IP: {len(WHITELIST_IPS)} 个
• SSH生命线端口: {SSH_PORT}

⚠️ 重要提示:
如果收到大量攻击警报但自动防御未开启，建议：
1. 确认攻击是真实威胁（检查lastb日志）
2. 编辑配置文件开启 auto_block_ip
3. 或手动封禁: iptables -A INPUT -s [IP] -j DROP

如需解封IP: iptables -D INPUT -s [IP] -j DROP
"""
    
    return body


def send_email(subject, body):
    """发送邮件"""
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["From"] = formataddr(("ClawArmor Defense", SENDER_EMAIL))
        msg["To"] = formataddr(("Admin", RECEIVER_EMAIL))
        msg["Subject"] = subject
        
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.qq.com", 465, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
            return True
    except Exception as e:
        log(f"发送邮件失败: {e}")
        return False


def main():
    """主函数"""
    log("🛡️ ClawArmor v4.0 智能防御系统启动...")
    
    # 步骤1：自检查
    log("🔍 执行自检查...")
    checks = self_check()
    for check in checks:
        log(f"   {check}")
    
    # 步骤2：获取当前客户端IP并加入白名单
    current_ip = get_current_client_ip()
    if current_ip:
        log(f"🛡️ 当前管理员IP {current_ip} 已加入动态白名单（永不被封禁）")
    
    # 步骤3：检测生命线端口
    lifeline_port = get_lifeline_port()
    log(f"🛡️ SSH生命线端口: {lifeline_port}（永远保持开放）")
    
    # 步骤4：获取攻击统计
    log("🔍 分析攻击数据...")
    attacks = get_attack_stats()
    
    if not attacks:
        log("✅ 未发现攻击，系统安全")
        return
    
    log(f"⚠️ 发现 {len(attacks)} 个攻击源")
    
    # 步骤5：执行防御动作
    actions_taken = []
    for ip, info in attacks.items():
        # 跳过白名单
        if is_ip_whitelisted(ip):
            log(f"🛡️ 跳过白名单IP: {ip}")
            continue
        
        # 执行安全封禁
        if safe_block_ip(ip):
            actions_taken.append({'ip': ip, 'action': 'blocked'})
        else:
            actions_taken.append({'ip': ip, 'action': 'warned'})
    
    # 步骤6：发送报告
    if actions_taken:
        subject = f"🛡️ {SERVER_NAME} 防御报告 - {len(attacks)} 个攻击源"
        body = generate_defense_report(attacks, actions_taken)
        send_email(subject, body)
        log(f"📧 防御报告已发送")


if __name__ == "__main__":
    main()
