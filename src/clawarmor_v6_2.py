#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClawArmor v6.2 - 智能IP封禁系统 + 地理位置分析 + 优化邮件格式
Author: 小灵通
Version: 6.2.0
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
    "ban_threshold": 3,
    "ban_duration": -1,
    "whitelist_ips": ["127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "monitor_interval": 5,
    "log_file": "/var/log/clawarmor_ban.log",
    "ban_db": "/opt/clawarmor/ban_db.json",
    "enable_email": True,
    "sender_email": "你的QQ邮箱@qq.com",
    "sender_password": "你的QQ邮箱授权码",
    "receiver_email": "你的邮箱@example.com",
}

ban_database = {}
failed_attempts = defaultdict(list)


def log(message, level="INFO"):
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
    return {'country': '未知', 'region': '未知', 'city': '未知', 'isp': '未知', 'org': '未知', 'as': '未知'}


def is_whitelisted(ip):
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
    if is_whitelisted(ip):
        log(f"🛡️ 跳过白名单IP: {ip}", "SKIP")
        return False
    if ip in ban_database:
        log(f"ℹ️ IP {ip} 已在封禁列表中", "INFO")
        return False
    
    try:
        subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
        location = get_ip_location(ip)
        ban_database[ip] = {
            "banned_at": datetime.now().isoformat(),
            "reason": reason,
            "attempt_count": attempt_count,
            "duration": "permanent",
            "location": location,
        }
        save_ban_database()
        log(f"🔒 已封禁IP: {ip} | 位置: {location['country']}-{location['city']} | 原因: {reason}", "BAN")
        if CONFIG.get("enable_email", False):
            send_ban_notification(ip, reason, attempt_count, location)
        return True
    except Exception as e:
        log(f"❌ 封禁IP失败 {ip}: {e}", "ERROR")
        return False


def send_ban_notification(ip, reason, attempt_count, location):
    """发送封禁通知邮件（参考用户提供的格式）"""
    try:
        import smtplib
        import ssl
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.utils import formataddr
        
        current_time = datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')
        server_name = CONFIG['server_name']
        
        # 计算统计数据
        total_banned = len(ban_database)
        
        html_body = f"""
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Microsoft YaHei', Arial, sans-serif; 
                       line-height: 1.6; color: #333; margin: 0; padding: 20px; background: #f5f7fa; }}
                .container {{ max-width: 800px; margin: 0 auto; background: white; border-radius: 12px; 
                              overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }}
                
                /* 头部样式 - 紫色渐变 */
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                          color: white; padding: 40px 30px; text-align: center; }}
                .header h1 {{ margin: 0; font-size: 28px; font-weight: 600; }}
                .header .shield {{ font-size: 40px; margin-bottom: 10px; }}
                .alert-level {{ display: inline-flex; align-items: center; gap: 8px; 
                               background: rgba(255,255,255,0.2); padding: 8px 20px; 
                               border-radius: 20px; margin-top: 15px; font-size: 14px; }}
                .alert-dot {{ width: 12px; height: 12px; background: #ff4444; border-radius: 50%; 
                             animation: pulse 2s infinite; }}
                @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
                .server-info {{ margin-top: 15px; opacity: 0.9; font-size: 14px; }}
                
                /* 统计卡片 */
                .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; 
                          padding: 30px; background: #f8f9fa; }}
                .stat-card {{ background: white; padding: 25px 15px; border-radius: 10px; 
                              text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.04); }}
                .stat-number {{ font-size: 36px; font-weight: bold; margin-bottom: 8px; }}
                .stat-number.attack {{ color: #5b7cfa; }}
                .stat-number.banned {{ color: #ff6b6b; }}
                .stat-number.warning {{ color: #ffa726; }}
                .stat-number.source {{ color: #66bb6a; }}
                .stat-label {{ font-size: 13px; color: #666; }}
                
                /* 内容区域 */
                .content {{ padding: 30px; }}
                .section-title {{ font-size: 18px; font-weight: 600; margin-bottom: 20px; 
                                 display: flex; align-items: center; gap: 10px; }}
                
                /* 攻击警报板块 */
                .alert-box {{ background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%); 
                              border-left: 4px solid #f44336; padding: 20px; 
                              border-radius: 8px; margin-bottom: 25px; }}
                .alert-box h3 {{ margin: 0 0 15px 0; color: #c62828; font-size: 16px; }}
                .alert-row {{ display: flex; justify-content: space-between; padding: 10px 0; 
                              border-bottom: 1px dashed rgba(0,0,0,0.1); }}
                .alert-row:last-child {{ border-bottom: none; }}
                .alert-label {{ color: #666; }}
                .alert-value {{ font-weight: 600; color: #333; }}
                .alert-value.ip {{ font-family: monospace; font-size: 18px; color: #c62828; }}
                .alert-value.danger {{ color: #f44336; }}
                
                /* IP地理位置板块 */
                .location-box {{ background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%); 
                                border-left: 4px solid #2196f3; padding: 20px; 
                                border-radius: 8px; margin-bottom: 25px; }}
                .location-box h3 {{ margin: 0 0 15px 0; color: #1565c0; font-size: 16px; }}
                .location-grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; }}
                .location-item {{ background: rgba(255,255,255,0.6); padding: 12px; border-radius: 6px; }}
                .location-item.full {{ grid-column: 1 / -1; }}
                .location-item-label {{ font-size: 12px; color: #666; margin-bottom: 4px; }}
                .location-item-value {{ font-size: 14px; font-weight: 600; color: #333; }}
                
                /* 运营商信息板块 */
                .isp-box {{ background: linear-gradient(135deg, #fff3e0 0%, #ffe0b2 100%); 
                            border-left: 4px solid #ff9800; padding: 20px; 
                            border-radius: 8px; margin-bottom: 25px; }}
                .isp-box h3 {{ margin: 0 0 15px 0; color: #e65100; font-size: 16px; }}
                
                /* 服务器状态板块 */
                .server-box {{ background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%); 
                               border-left: 4px solid #4caf50; padding: 20px; 
                               border-radius: 8px; margin-bottom: 25px; }}
                .server-box h3 {{ margin: 0 0 15px 0; color: #2e7d32; font-size: 16px; }}
                .status-badge {{ display: inline-flex; align-items: center; gap: 6px; 
                                 background: #4caf50; color: white; padding: 6px 14px; 
                                 border-radius: 15px; font-size: 13px; font-weight: 500; }}
                .status-dot {{ width: 8px; height: 8px; background: white; border-radius: 50%; }}
                
                /* 解封命令板块 */
                .unban-box {{ background: linear-gradient(135deg, #f3e5f5 0%, #e1bee7 100%); 
                              border-left: 4px solid #9c27b0; padding: 20px; 
                              border-radius: 8px; margin-bottom: 25px; }}
                .unban-box h3 {{ margin: 0 0 15px 0; color: #6a1b9a; font-size: 16px; }}
                .code-block {{ background: #263238; color: #aed581; padding: 15px; 
                               border-radius: 6px; font-family: 'Consolas', 'Monaco', monospace; 
                               font-size: 13px; overflow-x: auto; margin-top: 10px; }}
                
                /* 底部 */
                .footer {{ background: #f5f5f5; padding: 25px; text-align: center; 
                           font-size: 12px; color: #888; border-top: 1px solid #e0e0e0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <!-- 头部 -->
                <div class="header">
                    <div class="shield">🛡️</div>
                    <h1>ClawArmor v6.2 智能防御报告</h1>
                    <div class="alert-level">
                        <span class="alert-dot"></span>
                        <span>警报级别：紧急</span>
                    </div>
                    <div class="server-info">
                        服务器: {server_name} | 时间: {current_time}
                    </div>
                </div>
                
                <!-- 统计卡片 -->
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-number attack">{attempt_count}</div>
                        <div class="stat-label">攻击次数</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number banned">{total_banned}</div>
                        <div class="stat-label">已封禁IP</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number warning">0</div>
                        <div class="stat-label">已警告IP</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number source">1</div>
                        <div class="stat-label">攻击源</div>
                    </div>
                </div>
                
                <!-- 内容区域 -->
                <div class="content">
                    
                    <!-- 1. 攻击警报 -->
                    <div class="alert-box">
                        <h3>🚨 攻击警报</h3>
                        <div class="alert-row">
                            <span class="alert-label">攻击IP</span>
                            <span class="alert-value ip">{ip}</span>
                        </div>
                        <div class="alert-row">
                            <span class="alert-label">攻击类型</span>
                            <span class="alert-value">{reason}</span>
                        </div>
                        <div class="alert-row">
                            <span class="alert-label">失败次数</span>
                            <span class="alert-value danger">{attempt_count} 次</span>
                        </div>
                        <div class="alert-row">
                            <span class="alert-label">封禁时间</span>
                            <span class="alert-value">{current_time}</span>
                        </div>
                        <div class="alert-row">
                            <span class="alert-label">封禁时长</span>
                            <span class="alert-value danger">永久封禁</span>
                        </div>
                    </div>
                    
                    <!-- 2. IP地理位置 -->
                    <div class="location-box">
                        <h3>🌍 IP地理位置</h3>
                        <div class="location-grid">
                            <div class="location-item">
                                <div class="location-item-label">国家/地区</div>
                                <div class="location-item-value">{location['country']}</div>
                            </div>
                            <div class="location-item">
                                <div class="location-item-label">省份/州</div>
                                <div class="location-item-value">{location['region']}</div>
                            </div>
                            <div class="location-item">
                                <div class="location-item-label">城市</div>
                                <div class="location-item-value">{location['city']}</div>
                            </div>
                            <div class="location-item">
                                <div class="location-item-label">查询IP</div>
                                <div class="location-item-value" style="font-family: monospace;">{ip}</div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- 3. 运营商信息 -->
                    <div class="isp-box">
                        <h3>📡 运营商信息</h3>
                        <div class="location-grid">
                            <div class="location-item full">
                                <div class="location-item-label">互联网服务提供商 (ISP)</div>
                                <div class="location-item-value">{location['isp']}</div>
                            </div>
                            <div class="location-item">
                                <div class="location-item-label">组织</div>
                                <div class="location-item-value">{location['org']}</div>
                            </div>
                            <div class="location-item">
                                <div class="location-item-label">AS号码</div>
                                <div class="location-item-value" style="font-family: monospace;">{location['as']}</div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- 4. 服务器状态 -->
                    <div class="server-box">
                        <h3>🖥️ 服务器状态</h3>
                        <div class="location-grid">
                            <div class="location-item">
                                <div class="location-item-label">服务器名称</div>
                                <div class="location-item-value">{server_name}</div>
                            </div>
                            <div class="location-item">
                                <div class="location-item-label">防护状态</div>
                                <div class="location-item-value">
                                    <span class="status-badge">
                                        <span class="status-dot"></span>
                                        已自动封禁攻击IP
                                    </span>
                                </div>
                            </div>
                            <div class="location-item">
                                <div class="location-item-label">系统状态</div>
                                <div class="location-item-value" style="color: #4caf50; font-weight: 600;">🟢 安全</div>
                            </div>
                            <div class="location-item">
                                <div class="location-item-label">已封禁IP总数</div>
                                <div class="location-item-value">{total_banned} 个</div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- 5. 解封命令 -->
                    <div class="unban-box">
                        <h3>🔓 解封命令</h3>
                        <p style="margin: 0 0 10px 0; color: #666; font-size: 13px;">
                            如需手动解封此IP，请在服务器执行以下命令：
                        </p>
                        <div class="code-block">
                            iptables -D INPUT -s {ip} -j DROP
                        </div>
                        <p style="margin: 10px 0 0 0; color: #888; font-size: 12px;">
                            💡 提示：封禁是永久性的，除非手动解封，否则该IP将无法访问服务器
                        </p>
                    </div>
                    
                </div>
                
                <!-- 底部 -->
                <div class="footer">
                    <p><strong>ClawArmor v6.2</strong> - 智能服务器安全防护系统</p>
                    <p>此邮件由系统自动发送 | {current_time}</p>
                    <p style="color: #aaa; margin-top: 10px;">🛡️ 全天候守护您的服务器安全</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg = MIMEMultipart('alternative')
        msg['From'] = formataddr(('ClawArmor Security', CONFIG['sender_email']))
        msg['To'] = formataddr(('Admin', CONFIG['receiver_email']))
        msg['Subject'] = f"🚨 [{server_name}] 已封禁攻击IP: {ip} | 来源: {location['country']}-{location['city']}"
        
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL('smtp.qq.com', 465, context=context) as server:
            server.login(CONFIG['sender_email'], CONFIG['sender_password'])
            server.sendmail(CONFIG['sender_email'], CONFIG['receiver_email'], msg.as_string())
        
        log(f"📧 封禁通知已发送: {ip}")
        
    except Exception as e:
        log(f"发送邮件失败: {e}", "ERROR")


def save_ban_database():
    try:
        os.makedirs(os.path.dirname(CONFIG["ban_db"]), exist_ok=True)
        with open(CONFIG["ban_db"], 'w') as f:
            json.dump(ban_database, f, indent=2)
    except Exception as e:
        log(f"保存封禁数据库失败: {e}", "ERROR")


def load_ban_database():
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
    log("🛡️ ClawArmor v6.2 启动 - 优化邮件格式")
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
    print("\n" + "="*80)
    print("🔒 封禁IP列表")
    print("="*80)
    if not ban_database:
        print("暂无封禁的IP")
        return
    for ip, data in ban_database.items():
        loc = data.get('location', {})
        print(f"\n📍 IP: {ip}")
        print(f"   封禁时间: {data['banned_at']}")
        print(f"   地理位置: {loc.get('country', '未知')} - {loc.get('city', '未知')}")
        print(f"   运营商: {loc.get('isp', '未知')}")
    print("="*80)


def main():
    load_ban_database()
    if len(sys.argv) < 2:
        print("用法: python3 clawarmor_v6_2.py [monitor|list]")
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
