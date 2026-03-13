#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClawArmor Monitor v6.3.2 - 强制中文显示版
"""

import smtplib
import ssl
import os
import subprocess
import sys
import json
import urllib.request
import time
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr

sys.path.insert(0, "/opt/clawarmor")
try:
    from config import SENDER_EMAIL, SENDER_PASSWORD, RECEIVER_EMAIL, SERVER_NAME
except:
    SENDER_EMAIL = "your-email@qq.com"
    SENDER_PASSWORD = "your-auth-code"
    RECEIVER_EMAIL = "receiver@qq.com"
    SERVER_NAME = "Server"

CACHE_FILE = "/opt/clawarmor/ip_cache.json"

# 英文转中文映射
COUNTRY_EN_TO_CN = {
    'Korea': '韩国', 'South Korea': '韩国', 'Republic of Korea': '韩国',
    'Iraq': '伊拉克',
    'India': '印度',
    'Malaysia': '马来西亚',
    'China': '中国',
    'United States': '美国', 'US': '美国', 'USA': '美国',
    'Taiwan': '台湾',
    'Japan': '日本',
    'United Kingdom': '英国', 'UK': '英国',
    'Germany': '德国',
    'France': '法国',
    'Russia': '俄罗斯', 'Russian Federation': '俄罗斯',
    'Brazil': '巴西',
    'Canada': '加拿大',
    'Australia': '澳大利亚',
    'Singapore': '新加坡',
    'Thailand': '泰国',
    'Vietnam': '越南',
    'Indonesia': '印度尼西亚',
    'Philippines': '菲律宾',
    'Hong Kong': '香港',
    'Macau': '澳门',
    'Turkey': '土耳其',
    'Egypt': '埃及',
    'South Africa': '南非',
    'Mexico': '墨西哥',
    'Argentina': '阿根廷',
    'Ukraine': '乌克兰',
    'Poland': '波兰',
    'Italy': '意大利',
    'Spain': '西班牙',
    'Netherlands': '荷兰',
    'Sweden': '瑞典',
    'Norway': '挪威',
    'Switzerland': '瑞士',
}

def translate_to_chinese(text, is_country=True):
    """将英文翻译为中文"""
    if not text or text in ['-', '查询失败', '查询中']:
        return text
    if is_country:
        return COUNTRY_EN_TO_CN.get(text, text)
    # 省份/城市翻译（简单处理）
    return text

def load_cache():
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_cache(cache):
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f, ensure_ascii=False)
    except:
        pass

def get_ip_location_cn(ip, cache):
    """查询IP地理位置（强制中文）"""
    if ip in cache and cache[ip].get('country') not in ['查询中', '查询失败', '-']:
        return cache[ip]
    
    if not ip or ip in ['127.0.0.1', 'localhost']:
        result = {'country': '本地', 'region': '-', 'city': '-', 'isp': '-'}
        cache[ip] = result
        return result
    
    if ip.startswith(('10.', '192.168.')) or (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31):
        result = {'country': '内网', 'region': '-', 'city': '-', 'isp': '-'}
        cache[ip] = result
        return result
    
    # 方法1: ip-api.com (中文)
    try:
        import ssl as ssl_module
        ctx = ssl_module.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_module.CERT_NONE
        
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp&lang=zh-CN"
        req = urllib.request.Request(url, headers={'User-Agent': 'ClawArmor/6.3'})
        
        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
            data = json.loads(r.read().decode())
            
            if data.get('status') == 'success':
                country = data.get('country', '-')
                # 确保是中文（如果不是，尝试翻译）
                if country in COUNTRY_EN_TO_CN:
                    country = COUNTRY_EN_TO_CN[country]
                
                result = {
                    'country': country,
                    'region': data.get('regionName', '-'),
                    'city': data.get('city', '-'),
                    'isp': data.get('isp', '-')[:18]
                }
                cache[ip] = result
                time.sleep(0.6)
                return result
    except Exception as e:
        print(f"  ip-api失败: {e}")
    
    # 方法2: ipapi.co (英文，需要翻译)
    try:
        import ssl as ssl_module
        ctx = ssl_module.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_module.CERT_NONE
        
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={'User-Agent': 'ClawArmor/6.3'})
        
        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
            data = json.loads(r.read().decode())
            if 'error' not in data:
                country_en = data.get('country_name', data.get('country', '-'))
                country = translate_to_chinese(country_en, True)
                
                result = {
                    'country': country,
                    'region': translate_to_chinese(data.get('region', '-'), False),
                    'city': translate_to_chinese(data.get('city', '-'), False),
                    'isp': str(data.get('org', '-'))[:18]
                }
                cache[ip] = result
                time.sleep(0.4)
                return result
    except Exception as e:
        print(f"  ipapi失败: {e}")
    
    result = {'country': '查询失败', 'region': '-', 'city': '-', 'isp': '-'}
    cache[ip] = result
    return result

def get_fail2ban_status():
    try:
        result = subprocess.getoutput("fail2ban-client status sshd 2>/dev/null")
        banned = []
        for line in result.split('\n'):
            if 'Banned IP list' in line:
                ips = line.split(':', 1)[1].strip()
                if ips:
                    banned = [ip.strip() for ip in ips.split(',') if ip.strip()]
        return banned
    except:
        return []

def get_attack_stats():
    attacks = {}
    try:
        result = subprocess.getoutput("lastb -i 2>/dev/null | head -30")
        for line in result.strip().split('\n'):
            if not line or 'btmp' in line.lower():
                continue
            parts = line.split()
            if len(parts) >= 3:
                user = parts[0]
                ip = parts[2]
                if ip not in attacks:
                    attacks[ip] = {'count': 0, 'users': set()}
                attacks[ip]['count'] += 1
                attacks[ip]['users'].add(user)
    except:
        pass
    
    cache = load_cache()
    top_ips = sorted(attacks.items(), key=lambda x: x[1]['count'], reverse=True)[:8]
    
    for ip, _ in top_ips:
        print(f"  查询 {ip}...")
        attacks[ip]['location'] = get_ip_location_cn(ip, cache)
        save_cache(cache)
        print(f"    结果: {attacks[ip]['location']['country']}/{attacks[ip]['location']['region']}")
    
    return attacks

def generate_html(attacks):
    now = datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')
    total = sum(a['count'] for a in attacks.values())
    banned_ips = get_fail2ban_status()
    banned_count = len(banned_ips)
    unique_ips = len(attacks)
    
    cache = load_cache()
    for ip in attacks:
        if 'location' not in attacks[ip]:
            attacks[ip]['location'] = cache.get(ip, {'country':'-', 'region':'-', 'city':'-', 'isp':'-'})
    
    stats_html = f"""
    <div style="display:flex;justify-content:space-around;margin:30px 0;">
        <div style="text-align:center;padding:20px;background:#fff;border-radius:12px;box-shadow:0 4px 15px rgba(102,126,234,0.2);min-width:120px;">
            <div style="font-size:36px;font-weight:bold;color:#667eea;">{total}</div>
            <div style="color:#666;font-size:14px;margin-top:5px;">攻击次数</div>
        </div>
        <div style="text-align:center;padding:20px;background:#fff;border-radius:12px;box-shadow:0 4px 15px rgba(255,71,71,0.2);min-width:120px;">
            <div style="font-size:36px;font-weight:bold;color:#ff4757;">{banned_count}</div>
            <div style="color:#666;font-size:14px;margin-top:5px;">已封禁IP</div>
        </div>
        <div style="text-align:center;padding:20px;background:#fff;border-radius:12px;box-shadow:0 4px 15px rgba(255,165,2,0.2);min-width:120px;">
            <div style="font-size:36px;font-weight:bold;color:#ffa502;">0</div>
            <div style="color:#666;font-size:14px;margin-top:5px;">已警告IP</div>
        </div>
        <div style="text-align:center;padding:20px;background:#fff;border-radius:12px;box-shadow:0 4px 15px rgba(46,213,115,0.2);min-width:120px;">
            <div style="font-size:36px;font-weight:bold;color:#2ed573;">{unique_ips}</div>
            <div style="color:#666;font-size:14px;margin-top:5px;">攻击源</div>
        </div>
    </div>"""
    
    geo_rows = ""
    for ip, info in sorted(attacks.items(), key=lambda x: x[1]['count'], reverse=True)[:12]:
        loc = info.get('location', {})
        is_banned = "🚫 已封禁" if ip in banned_ips else "⚠️ 监控中"
        geo_rows += f"""
        <tr>
            <td style="padding:12px;border-bottom:1px solid #eee;font-family:monospace;font-size:13px;">{ip}</td>
            <td style="padding:12px;border-bottom:1px solid #eee;text-align:center;font-weight:bold;color:#ff4757;">{info['count']}</td>
            <td style="padding:12px;border-bottom:1px solid #eee;">{', '.join(info['users'])}</td>
            <td style="padding:12px;border-bottom:1px solid #eee;"><b style="color:#667eea;">{loc.get('country','-')}</b></td>
            <td style="padding:12px;border-bottom:1px solid #eee;">{loc.get('region','-')}</td>
            <td style="padding:12px;border-bottom:1px solid #eee;">{loc.get('city','-')}</td>
            <td style="padding:12px;border-bottom:1px solid #eee;font-size:12px;color:#666;">{loc.get('isp','-')}</td>
            <td style="padding:12px;border-bottom:1px solid #eee;text-align:center;">{is_banned}</td>
        </tr>"""
    
    banned_list = ""
    for ip in banned_ips[:8]:
        loc = cache.get(ip, {})
        banned_list += f"<li style='padding:8px 0;border-bottom:1px solid #eee;'>{ip} <span style='color:#999;font-size:12px;'>({loc.get('country','-')})</span></li>"
    if not banned_list:
        banned_list = "<li style='padding:8px;color:#999;'>暂无封禁记录</li>"
    
    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:20px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
    <table style="max-width:900px;margin:0 auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.3);">
        
        <tr>
            <td style="background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);padding:40px 30px;text-align:center;color:#fff;">
                <div style="font-size:48px;margin-bottom:10px;">🛡️</div>
                <h1 style="margin:0;font-size:28px;font-weight:600;">ClawArmor v6.3.2 智能防御报告</h1>
                <p style="margin:15px 0 0 0;font-size:16px;">🔴 <span style="background:#ff4757;padding:4px 12px;border-radius:20px;font-size:14px;">警戒</span></p>
                <p style="margin:10px 0 0 0;font-size:14px;opacity:0.9;">服务器: {SERVER_NAME} | 时间: {now}</p>
            </td>
        </tr>
        
        <tr>
            <td style="padding:20px;background:#f8f9fa;">
                {stats_html}
            </td>
        </tr>
        
        <tr>
            <td style="padding:30px;">
                <h2 style="color:#333;margin:0 0 20px 0;font-size:20px;">📍 攻击IP地理位置（强制中文）</h2>
                
                <table style="width:100%;border-collapse:collapse;font-size:13px;">
                    <thead>
                        <tr style="background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;">
                            <th style="padding:15px;text-align:left;border-radius:8px 0 0 0;">IP地址</th>
                            <th style="padding:15px;text-align:center;">次数</th>
                            <th style="padding:15px;text-align:left;">用户</th>
                            <th style="padding:15px;text-align:left;">国家</th>
                            <th style="padding:15px;text-align:left;">省份</th>
                            <th style="padding:15px;text-align:left;">城市</th>
                            <th style="padding:15px;text-align:left;">运营商</th>
                            <th style="padding:15px;text-align:center;border-radius:0 8px 0 0;">状态</th>
                        </tr>
                    </thead>
                    <tbody>{geo_rows}</tbody>
                </table>
            </td>
        </tr>
        
        <tr>
            <td style="padding:0 30px 30px 30px;">
                <div style="background:#fff3cd;border-radius:12px;padding:20px;border-left:4px solid #ffa502;">
                    <h3 style="margin:0 0 15px 0;color:#856404;font-size:16px;">🚫 已封禁IP列表</h3>
                    <ul style="margin:0;padding-left:20px;color:#856404;">{banned_list}</ul>
                </div>
            </td>
        </tr>
        
        <tr>
            <td style="padding:0 30px 30px 30px;">
                <div style="background:#e3f2fd;border-radius:12px;padding:20px;border-left:4px solid #2196f3;">
                    <h3 style="margin:0 0 15px 0;color:#1565c0;font-size:16px;">🔧 管理命令</h3>
                    <code style="display:block;background:#fff;padding:10px;border-radius:6px;margin:5px 0;font-size:12px;font-family:monospace;">fail2ban-client status sshd</code>
                    <code style="display:block;background:#fff;padding:10px;border-radius:6px;margin:5px 0;font-size:12px;font-family:monospace;">fail2ban-client set sshd unbanip [IP]</code>
                </div>
            </td>
        </tr>
        
        <tr>
            <td style="background:#f8f9fa;padding:20px;text-align:center;border-top:1px solid #e0e0e0;">
                <p style="color:#999;margin:0;font-size:12px;">ClawArmor Security Suite v6.3.2 | fail2ban + ClawArmor 智能防护</p>
                <p style="color:#bbb;margin:5px 0 0 0;font-size:11px;">生成时间: {now}</p>
            </td>
        </tr>
    </table>
</body>
</html>"""
    return html

def send_email(subject, html):
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = formataddr(("ClawArmor", SENDER_EMAIL))
        msg['To'] = formataddr(("Admin", RECEIVER_EMAIL))
        msg['Subject'] = subject
        msg.attach(MIMEText(html, 'html', 'utf-8'))
        
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.qq.com", 465, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        return True
    except Exception as e:
        print(f"邮件失败: {e}")
        return False

def main():
    print("🛡️ ClawArmor v6.3.2 启动...")
    print("强制中文显示版")
    
    attacks = get_attack_stats()
    
    print(f"\n攻击统计:")
    print(f"  总攻击: {sum(a['count'] for a in attacks.values())} 次")
    print(f"  攻击源: {len(attacks)} 个IP")
    
    html = generate_html(attacks)
    subject = f"🛡️ {SERVER_NAME} 安全报告 - {datetime.now().strftime('%m月%d日 %H:%M')}"
    
    if send_email(subject, html):
        print(f"\n✅ 邮件已发送至 {RECEIVER_EMAIL}")
    else:
        print("\n❌ 邮件发送失败")

if __name__ == "__main__":
    main()
