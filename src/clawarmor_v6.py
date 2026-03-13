#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClawArmor v6.0 - 零容忍IP封禁系统
触发即封禁，不给任何警告！

功能：
- 实时监控SSH暴力破解
- 触发阈值立即永久封禁IP
- 不发警告邮件，直接执行封禁
- 白名单保护机制

Author: 小灵通
Version: 6.0.0
"""

import os
import sys
import subprocess
import re
import time
import json
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import signal

# ==================== 配置 ====================
CONFIG = {
    "server_name": "Server-1",
    
    # 封禁阈值配置 - 零容忍模式
    "ban_threshold": 3,           # 3次失败立即封禁（可改为1次）
    "ban_duration": -1,           # -1 = 永久封禁, 3600 = 1小时, 86400 = 1天
    "whitelist_ips": ["127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    
    # 监控配置
    "monitor_interval": 5,        # 每5秒检查一次日志
    "log_file": "/var/log/clawarmor_ban.log",
    "ban_db": "/opt/clawarmor/ban_db.json",
    
    # 启用/禁用邮件（零容忍模式建议禁用邮件，直接封禁）
    "enable_email": False,        # 默认关闭邮件，只记录日志
    "sender_email": "你的QQ邮箱@qq.com",
    "sender_password": "你的QQ邮箱授权码", 
    "receiver_email": "你的邮箱@example.com",
}

# 被封禁的IP数据库
ban_database = {}
failed_attempts = defaultdict(list)  # IP -> [timestamp列表]


def log(message, level="INFO"):
    """记录日志"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    msg = f"[{timestamp}] [{level}] {message}"
    print(msg)
    try:
        with open(CONFIG["log_file"], 'a') as f:
            f.write(msg + '\n')
    except:
        pass


def is_whitelisted(ip):
    """检查IP是否在白名单"""
    # 检查精确匹配
    if ip in CONFIG["whitelist_ips"]:
        return True
    
    # 检查CIDR范围
    for whitelist_ip in CONFIG["whitelist_ips"]:
        if '/' in whitelist_ip:
            # CIDR范围检查
            import ipaddress
            try:
                network = ipaddress.ip_network(whitelist_ip, strict=False)
                if ipaddress.ip_address(ip) in network:
                    return True
            except:
                pass
    return False


def ban_ip(ip, reason="暴力破解"):
    """永久封禁IP - 零容忍模式"""
    if is_whitelisted(ip):
        log(f"🛡️ 跳过白名单IP: {ip}", "SKIP")
        return False
    
    if ip in ban_database:
        log(f"ℹ️ IP {ip} 已在封禁列表中", "INFO")
        return False
    
    try:
        # 使用iptables封禁（Linux）
        ban_cmd = f"iptables -A INPUT -s {ip} -j DROP"
        subprocess.run(ban_cmd, shell=True, check=True)
        
        # 记录到数据库
        ban_database[ip] = {
            "banned_at": datetime.now().isoformat(),
            "reason": reason,
            "duration": "permanent" if CONFIG["ban_duration"] == -1 else f"{CONFIG['ban_duration']}秒",
            "unban_at": None if CONFIG["ban_duration"] == -1 else (datetime.now() + timedelta(seconds=CONFIG["ban_duration"])).isoformat()
        }
        
        # 保存数据库
        save_ban_database()
        
        # 记录日志
        log(f"🔒 已永久封禁IP: {ip} | 原因: {reason}", "BAN")
        
        # 可选：发送邮件通知（如果启用）
        if CONFIG.get("enable_email", False):
            send_ban_notification(ip, reason)
        
        return True
        
    except Exception as e:
        log(f"❌ 封禁IP失败 {ip}: {e}", "ERROR")
        return False


def unban_ip(ip):
    """解封IP"""
    try:
        subprocess.run(f"iptables -D INPUT -s {ip} -j DROP", shell=True, check=True)
        if ip in ban_database:
            del ban_database[ip]
            save_ban_database()
        log(f"🔓 已解封IP: {ip}", "UNBAN")
        return True
    except Exception as e:
        log(f"❌ 解封IP失败 {ip}: {e}", "ERROR")
        return False


def save_ban_database():
    """保存封禁数据库"""
    try:
        os.makedirs(os.path.dirname(CONFIG["ban_db"]), exist_ok=True)
        with open(CONFIG["ban_db"], 'w') as f:
            json.dump(ban_database, f, indent=2)
    except Exception as e:
        log(f"保存封禁数据库失败: {e}", "ERROR")


def load_ban_database():
    """加载封禁数据库"""
    global ban_database
    try:
        if os.path.exists(CONFIG["ban_db"]):
            with open(CONFIG["ban_db"], 'r') as f:
                ban_database = json.load(f)
                log(f"📋 已加载封禁数据库: {len(ban_database)} 个IP")
    except Exception as e:
        log(f"加载封禁数据库失败: {e}", "ERROR")
        ban_database = {}


def restore_banned_ips():
    """重启后恢复所有封禁规则"""
    log("🔄 正在恢复封禁规则...")
    count = 0
    for ip, data in ban_database.items():
        # 检查是否永久封禁或尚未过期
        if data.get("duration") == "permanent":
            try:
                subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
                count += 1
            except:
                pass
        else:
            # 检查是否过期
            unban_time = datetime.fromisoformat(data.get("unban_at", "2000-01-01"))
            if datetime.now() < unban_time:
                try:
                    subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
                    count += 1
                except:
                    pass
            else:
                # 已过期，从数据库中移除
                del ban_database[ip]
    
    save_ban_database()
    log(f"✅ 已恢复 {count} 个封禁规则")


def parse_ssh_logs():
    """解析SSH日志，查找失败登录"""
    failed_ips = []
    
    # 尝试不同的日志文件
    log_files = ["/var/log/auth.log", "/var/log/secure", "/var/log/audit/audit.log"]
    
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                # 读取最近1000行
                result = subprocess.getoutput(f"tail -n 1000 {log_file}")
                
                # 匹配SSH失败登录
                # Failed password for root from 192.168.1.100 port 12345 ssh2
                pattern = r'Failed password.*from\s+(\d+\.\d+\.\d+\.\d+)'
                matches = re.findall(pattern, result)
                
                # 匹配Invalid user
                # Invalid user admin from 192.168.1.100 port 12345
                pattern2 = r'Invalid user.*from\s+(\d+\.\d+\.\d+\.\d+)'
                matches2 = re.findall(pattern2, result)
                
                failed_ips.extend(matches)
                failed_ips.extend(matches2)
                
            except Exception as e:
                log(f"读取日志失败 {log_file}: {e}", "ERROR")
    
    return failed_ips


def check_and_ban():
    """检查并封禁 - 核心功能"""
    global failed_attempts
    
    # 获取最近的失败登录
    failed_ips = parse_ssh_logs()
    current_time = datetime.now()
    
    for ip in failed_ips:
        # 跳过已封禁的IP
        if ip in ban_database:
            continue
        
        # 记录失败尝试
        failed_attempts[ip].append(current_time)
        
        # 清理5分钟前的记录
        failed_attempts[ip] = [
            t for t in failed_attempts[ip] 
            if current_time - t < timedelta(minutes=5)
        ]
        
        # 检查是否达到封禁阈值
        if len(failed_attempts[ip]) >= CONFIG["ban_threshold"]:
            log(f"🚨 触发封禁阈值: IP {ip} 在5分钟内失败 {len(failed_attempts[ip])} 次", "ALERT")
            ban_ip(ip, f"SSH暴力破解 ({len(failed_attempts[ip])}次失败)")
            # 清空记录
            failed_attempts[ip] = []


def monitor_loop():
    """监控循环"""
    log("🛡️ ClawArmor v6.0 启动 - 零容忍模式")
    log(f"📊 配置: 失败{CONFIG['ban_threshold']}次即永久封禁")
    log(f"📝 日志: {CONFIG['log_file']}")
    
    while True:
        try:
            check_and_ban()
            time.sleep(CONFIG["monitor_interval"])
        except KeyboardInterrupt:
            log("🛑 收到停止信号，正在退出...")
            break
        except Exception as e:
            log(f"监控循环错误: {e}", "ERROR")
            time.sleep(CONFIG["monitor_interval"])


def list_banned_ips():
    """列出所有被封禁的IP"""
    print("\n" + "="*60)
    print("🔒 封禁IP列表")
    print("="*60)
    
    if not ban_database:
        print("暂无封禁的IP")
        return
    
    for ip, data in ban_database.items():
        print(f"\nIP: {ip}")
        print(f"  封禁时间: {data['banned_at']}")
        print(f"  原因: {data['reason']}")
        print(f"  时长: {data['duration']}")
    
    print("="*60)


def manual_ban(ip):
    """手动封禁IP"""
    confirm = input(f"确认封禁IP {ip}? (yes/no): ")
    if confirm.lower() == 'yes':
        ban_ip(ip, "手动封禁")
    else:
        print("已取消")


def manual_unban(ip):
    """手动解封IP"""
    confirm = input(f"确认解封IP {ip}? (yes/no): ")
    if confirm.lower() == 'yes':
        unban_ip(ip)
    else:
        print("已取消")


def send_ban_notification(ip, reason):
    """发送封禁通知（可选）"""
    if not CONFIG.get("enable_email", False):
        return
    
    try:
        import smtplib
        import ssl
        from email.mime.text import MIMEText
        from email.utils import formataddr
        
        subject = f"🔒 [{CONFIG['server_name']}] 已封禁IP: {ip}"
        body = f"""
ClawArmor v6.0 自动封禁通知

服务器: {CONFIG['server_name']}
封禁IP: {ip}
封禁原因: {reason}
封禁时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
封禁时长: 永久

此IP已被iptables永久封禁，无法再次访问服务器。

---
ClawArmor v6.0 零容忍IP封禁系统
"""
        
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['From'] = formataddr(('ClawArmor Security', CONFIG['sender_email']))
        msg['To'] = formataddr(('Admin', CONFIG['receiver_email']))
        msg['Subject'] = subject
        
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.qq.com', 465, context=context) as server:
            server.login(CONFIG['sender_email'], CONFIG['sender_password'])
            server.sendmail(CONFIG['sender_email'], CONFIG['receiver_email'], msg.as_string())
        
        log(f"📧 封禁通知已发送: {ip}")
        
    except Exception as e:
        log(f"发送邮件失败: {e}", "ERROR")


def show_help():
    """显示帮助"""
    print("""
🛡️ ClawArmor v6.0 - 零容忍IP封禁系统

用法:
    python3 clawarmor_v6.py [命令] [参数]

命令:
    monitor     启动监控模式（持续运行，触发即封禁）
    ban <ip>    手动封禁指定IP
    unban <ip>  手动解封指定IP  
    list        显示所有封禁的IP
    status      显示系统状态
    help        显示此帮助

配置:
    编辑脚本开头的 CONFIG 字典修改配置

示例:
    # 启动监控（推荐后台运行）
    nohup python3 clawarmor_v6.py monitor &
    
    # 手动封禁IP
    python3 clawarmor_v6.py ban 192.168.1.100
    
    # 查看封禁列表
    python3 clawarmor_v6.py list

""")


def show_status():
    """显示系统状态"""
    print("\n" + "="*60)
    print("🛡️ ClawArmor v6.0 系统状态")
    print("="*60)
    print(f"服务器: {CONFIG['server_name']}")
    print(f"封禁阈值: {CONFIG['ban_threshold']}次失败")
    print(f"封禁时长: {'永久' if CONFIG['ban_duration'] == -1 else CONFIG['ban_duration'] + '秒'}")
    print(f"监控间隔: {CONFIG['monitor_interval']}秒")
    print(f"已封禁IP: {len(ban_database)}个")
    print(f"白名单IP: {len(CONFIG['whitelist_ips'])}个")
    print("="*60)


def main():
    """主函数"""
    # 加载封禁数据库
    load_ban_database()
    
    # 恢复封禁规则
    restore_banned_ips()
    
    # 命令行参数处理
    if len(sys.argv) < 2:
        show_help()
        return
    
    command = sys.argv[1].lower()
    
    if command == "monitor":
        monitor_loop()
    elif command == "ban":
        if len(sys.argv) < 3:
            print("❌ 请指定IP地址")
            return
        manual_ban(sys.argv[2])
    elif command == "unban":
        if len(sys.argv) < 3:
            print("❌ 请指定IP地址")
            return
        manual_unban(sys.argv[2])
    elif command == "list":
        list_banned_ips()
    elif command == "status":
        show_status()
    elif command == "help":
        show_help()
    else:
        print(f"❌ 未知命令: {command}")
        show_help()


if __name__ == "__main__":
    main()
