#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClawArmor v6.1 - 智能IP封禁系统 + 地理位置分析
触发即封禁，邮件显示攻击来源地理位置

Author: 小灵通
Version: 6.1.0
"""

import os
import sys
import subprocess
import re
import time
import json
import urllib.request
import ssl
from datetime import datetime, timedelta
from collections import defaultdict

# ==================== 配置 ====================
CONFIG = {
    "server_name": "Server-1",
    "ban_threshold": 3,           # 3次失败立即封禁
    "ban_duration": -1,           # -1 = 永久封禁
    "whitelist_ips": ["127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "monitor_interval": 5,
    "log_file": "/var/log/clawarmor_ban.log",
    "ban_db": "/opt/clawarmor/ban_db.json",
    
    # 邮件配置（启用邮件通知）
    "enable_email": True,
    "sender_email": "你的QQ邮箱@qq.com",
    "sender_password": "你的QQ邮箱授权码",
    "receiver_email": "你的邮箱@example.com",
}

ban_database = {}
failed_attempts = defaultdict(list)


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


def get_ip_location(ip):
    """查询IP地理位置"""
    try:
        # 使用 ip-api.com 免费API
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query&lang=zh-CN"
        
        with urllib.request.urlopen(url, timeout=5, context=ctx) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            if data.get('status') == 'success':
                return {
                    'country': data.get('country', '未知'),
                    'region': data.get('regionName', '未知'),
                    'city': data.get('city', '未知'),
                    'isp': data.get('isp', '未知'),
                    'org': data.get('org', '未知'),
                    'as': data.get('as', '未知'),
                }
    except Exception as e:
        log(f"查询IP地理位置失败 {ip}: {e}", "ERROR")
    
    return {
        'country': '未知',
        'region': '未知', 
        'city': '未知',
        'isp': '未知',
        'org': '未知',
        'as': '未知',
    }


def format_location(location):
    """格式化地理位置信息"""
    parts = []
    if location['country'] != '未知':
        parts.append(location['country'])
    if location['region'] != '未知':
        parts.append(location['region'])
    if location['city'] != '未知':
        parts.append(location['city'])
    
    location_str = ' - '.join(parts) if parts else '未知位置'
    
    details = []
    if location['isp'] != '未知':
        details.append(f"运营商: {location['isp']}")
    if location['org'] != '未知' and location['org'] != location['isp']:
        details.append(f"组织: {location['org']}")
    
    detail_str = ' | '.join(details) if details else ''
    
    return location_str, detail_str


def is_whitelisted(ip):
    """检查IP是否在白名单"""
    if ip in CONFIG["whitelist_ips"]:
        return True
    
    for whitelist_ip in CONFIG["whitelist_ips"]:
        if '/' in whitelist_ip:
            try:
                import ipaddress
                network = ipaddress.ip_network(whitelist_ip, strict=False)
                if ipaddress.ip_address(ip) in network:
                    return True
            except:
                pass
    return False


def ban_ip(ip, reason="暴力破解", attempt_count=0):
    """封禁IP"""
    if is_whitelisted(ip):
        log(f"🛡️ 跳过白名单IP: {ip}", "SKIP")
        return False
    
    if ip in ban_database:
        log(f"ℹ️ IP {ip} 已在封禁列表中", "INFO")
        return False
    
    try:
        # 封禁IP
        subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
        
        # 查询地理位置
        location = get_ip_location(ip)
        location_str, detail_str = format_location(location)
        
        # 记录到数据库
        ban_database[ip] = {
            "banned_at": datetime.now().isoformat(),
            "reason": reason,
            "attempt_count": attempt_count,
            "duration": "permanent" if CONFIG["ban_duration"] == -1 else f"{CONFIG['ban_duration']}秒",
            "location": location,
            "location_str": location_str,
        }
        
        save_ban_database()
        
        log(f"🔒 已封禁IP: {ip} | 位置: {location_str} | 原因: {reason}", "BAN")
        
        # 发送邮件通知
        if CONFIG.get("enable_email", False):
            send_ban_notification(ip, reason, attempt_count, location, location_str, detail_str)
        
        return True
        
    except Exception as e:
        log(f"❌ 封禁IP失败 {ip}: {e}", "ERROR")
        return False


def send_ban_notification(ip, reason, attempt_count, location, location_str, detail_str):
    """发送封禁通知邮件（含地理位置）"""
    try:
        import smtplib
        import ssl
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.utils import formataddr
        
        current_time = datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')
        server_name = CONFIG['server_name']
        
        # 构建HTML邮件
        html_body = f"""
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #ff4444 0%, #cc0000 100%); color: white; padding: 30px; text-align: center; }}
                .header h1 {{ margin: 0; font-size: 24px; }}
                .content {{ padding: 30px; }}
                .alert-box {{ background: #ffebee; border-left: 4px solid #ff4444; padding: 15px; margin: 20px 0; border-radius: 4px; }}
                .info-box {{ background: #e3f2fd; border-left: 4px solid #2196f3; padding: 15px; margin: 20px 0; border-radius: 4px; }}
                .location-box {{ background: #fff3e0; border-left: 4px solid #ff9800; padding: 15px; margin: 20px 0; border-radius: 4px; }}
                .stat {{ display: inline-block; background: #f5f5f5; padding: 10px 20px; margin: 5px; border-radius: 20px; font-size: 14px; }}
                .footer {{ background: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ ClawArmor 安全警报</h1>
                    <p style="margin: 10px 0 0 0; opacity: 0.9;">检测到暴力破解攻击并已封禁</p>
                </div>
                
                <div class="content">
                    <div class="alert-box">
                        <h3 style="margin-top: 0; color: #c62828;">⚠️ 攻击 detected</h3>
                        <p><strong>攻击IP:</strong> <span style="font-family: monospace; font-size: 18px; color: #c62828;">{ip}</span></p>
                        <p><strong>攻击类型:</strong> {reason}</p>
                        <p><strong>失败次数:</strong> <span style="color: #c62828; font-weight: bold;">{attempt_count} 次</span></p>
                        <p><strong>封禁时间:</strong> {current_time}</p>
                        <p><strong>封禁时长:</strong> <span style="color: #c62828; font-weight: bold;">永久封禁</span></p>
                    </div>
                    
                    <div class="location-box">
                        <h3 style="margin-top: 0; color: #e65100;">🌍 攻击来源分析</h3>
                        <p><strong>地理位置:</strong> <span style="font-size: 16px;">{location_str}</span></p>
                        <p><strong>详细信息:</strong> {detail_str}</p>
                        <hr style="border: none; border-top: 1px solid #ddd; margin: 15px 0;">
                        <p style="font-size: 13px; color: #666; margin: 0;">
                            <strong>原始数据:</strong><br>
                            国家: {location['country']}<br>
                            地区: {location['region']}<br>
                            城市: {location['city']}<br>
                            运营商: {location['isp']}<br>
                            AS: {location['as']}
                        </p>
                    </div>
                    
                    <div class="info-box">
                        <h3 style="margin-top: 0; color: #1565c0;">📊 服务器信息</h3>
                        <p><strong>服务器:</strong> {server_name}</p>
                        <p><strong>防护措施:</strong> 已自动封禁攻击IP</p>
                        <p><strong>状态:</strong> <span style="color: #4caf50; font-weight: bold;">🟢 安全</span></p>
                    </div>
                    
                    <div style="text-align: center; margin-top: 30px;">
                        <p style="color: #666; font-size: 14px;">
                            如需解封此IP，请登录服务器执行:<br>
                            <code style="background: #f5f5f5; padding: 5px 10px; border-radius: 4px; font-family: monospace;">iptables -D INPUT -s {ip} -j DROP</code>
                        </p>
                    </div>
                </div>
                
                <div class="footer">
                    <p><strong>ClawArmor v6.1</strong> - 智能服务器安全防护系统</p>
                    <p>此邮件由系统自动发送 | {current_time}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg = MIMEMultipart('alternative')
        msg['From'] = formataddr(('ClawArmor Security', CONFIG['sender_email']))
        msg['To'] = formataddr(('Admin', CONFIG['receiver_email']))
        msg['Subject'] = f"🚨 [{server_name}] 已封禁攻击IP: {ip} | 来源: {location_str}"
        
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.qq.com', 465, context=context) as server:
            server.login(CONFIG['sender_email'], CONFIG['sender_password'])
            server.sendmail(CONFIG['sender_email'], CONFIG['receiver_email'], msg.as_string())
        
        log(f"📧 封禁通知已发送: {ip} ({location_str})")
        
    except Exception as e:
        log(f"发送邮件失败: {e}", "ERROR")


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


def parse_ssh_logs():
    """解析SSH日志"""
    failed_ips = []
    log_files = ["/var/log/auth.log", "/var/log/secure"]
    
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                result = subprocess.getoutput(f"tail -n 1000 {log_file}")
                pattern = r'Failed password.*from\s+(\d+\.\d+\.\d+\.\d+)'
                matches = re.findall(pattern, result)
                failed_ips.extend(matches)
            except:
                pass
    
    return failed_ips


def check_and_ban():
    """检查并封禁"""
    global failed_attempts
    
    failed_ips = parse_ssh_logs()
    current_time = datetime.now()
    
    for ip in failed_ips:
        if ip in ban_database:
            continue
        
        failed_attempts[ip].append(current_time)
        failed_attempts[ip] = [
            t for t in failed_attempts[ip] 
            if current_time - t < timedelta(minutes=5)
        ]
        
        if len(failed_attempts[ip]) >= CONFIG["ban_threshold"]:
            log(f"🚨 触发封禁阈值: IP {ip} 失败 {len(failed_attempts[ip])} 次", "ALERT")
            ban_ip(ip, "SSH暴力破解", len(failed_attempts[ip]))
            failed_attempts[ip] = []


def monitor_loop():
    """监控循环"""
    log("🛡️ ClawArmor v6.1 启动 - 智能地理位置分析")
    log(f"📊 配置: 失败{CONFIG['ban_threshold']}次即封禁")
    
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
    print("\n" + "="*80)
    print("🔒 封禁IP列表 (含地理位置)")
    print("="*80)
    
    if not ban_database:
        print("暂无封禁的IP")
        return
    
    for ip, data in ban_database.items():
        print(f"\n📍 IP: {ip}")
        print(f"   封禁时间: {data['banned_at']}")
        print(f"   失败次数: {data.get('attempt_count', 'N/A')} 次")
        print(f"   地理位置: {data.get('location_str', '未知')}")
        print(f"   原因: {data['reason']}")
    
    print("="*80)


def main():
    """主函数"""
    load_ban_database()
    
    if len(sys.argv) < 2:
        print("用法: python3 clawarmor_v6.py [monitor|list|ban|unban]")
        return
    
    command = sys.argv[1].lower()
    
    if command == "monitor":
        monitor_loop()
    elif command == "list":
        list_banned_ips()
    else:
        print(f"未知命令: {command}")


if __name__ == "__main__":
    main()
