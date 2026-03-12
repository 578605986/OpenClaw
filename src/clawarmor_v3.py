#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClawArmor v3.0 - 智能体服务器安全防御系统
增强版：详细威胁检测与报告

Author: 小灵通
Version: 3.0.0
"""

import smtplib
import ssl
import os
import subprocess
import re
from datetime import datetime
from email.mime.text import MIMEText
from email.utils import formataddr

# ==================== 用户配置区域 ====================
SENDER_EMAIL = "你的QQ邮箱@qq.com"           # QQ邮箱
SENDER_PASSWORD = "你的QQ邮箱授权码"          # QQ邮箱授权码（不是登录密码！）
RECEIVER_EMAIL = "你的邮箱@example.com"       # 接收警报的邮箱
SERVER_NAME = "Server-1"                      # 服务器名称
# =====================================================

def get_failed_logins():
    """获取失败的登录尝试，提取攻击IP"""
    threats = []
    try:
        # 获取最近24小时的失败登录
        result = subprocess.getoutput("lastb -i | head -20")
        if result and "still logged in" not in result:
            lines = result.strip().split('\n')
            seen_ips = set()  # 去重
            
            for line in lines:
                if not line or 'btmp begins' in line:
                    continue
                    
                # 解析 lastb 输出格式: username tty ip date time
                parts = line.split()
                if len(parts) >= 3:
                    username = parts[0]
                    ip = parts[2] if len(parts) > 2 else "未知"
                    
                    # 跳过重复的IP
                    if ip in seen_ips or ip == "unknown":
                        continue
                    seen_ips.add(ip)
                    
                    # 提取时间信息
                    time_str = " ".join(parts[3:7]) if len(parts) > 6 else "未知时间"
                    
                    threats.append({
                        'type': '暴力破解尝试',
                        'severity': '高',
                        'source_ip': ip,
                        'target_user': username,
                        'time': time_str,
                        'detail': f'攻击者尝试使用用户名 "{username}" 从 IP {ip} 登录服务器',
                        'recommendation': f'建议立即封禁IP: iptables -A INPUT -s {ip} -j DROP'
                    })
                    
                    if len(threats) >= 5:  # 最多显示5个
                        break
    except Exception as e:
        print(f"检查登录失败时出错: {e}")
    
    return threats


def check_suspicious_files():
    """检查可疑文件"""
    threats = []
    try:
        # 检查/tmp目录下的可疑脚本
        dangerous_patterns = [
            ("/tmp", "*.sh", "可疑Shell脚本"),
            ("/tmp", "*.py", "可疑Python脚本"),
            ("/tmp", "wget*", "可疑下载文件"),
            ("/tmp", "curl*", "可疑网络工具"),
        ]
        
        for directory, pattern, file_type in dangerous_patterns:
            if os.path.exists(directory):
                cmd = f"find {directory} -name '{pattern}' -type f -mtime -1 2>/dev/null | head -3"
                result = subprocess.getoutput(cmd)
                
                if result:
                    for file_path in result.strip().split('\n'):
                        if file_path:
                            # 检查文件内容是否包含危险命令
                            content_check = ""
                            try:
                                with open(file_path, 'r', errors='ignore') as f:
                                    content = f.read(500)  # 读取前500字符
                                    dangerous_cmds = ['rm -rf /', 'curl.*|.*bash', '> /etc/passwd']
                                    for cmd_pattern in dangerous_cmds:
                                        if re.search(cmd_pattern, content, re.IGNORECASE):
                                            content_check = f" [包含危险命令: {cmd_pattern}]"
                                            break
                            except:
                                pass
                            
                            threats.append({
                                'type': file_type,
                                'severity': '中' if not content_check else '高',
                                'source_ip': '本地',
                                'target_user': '系统',
                                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'detail': f'发现可疑文件: {file_path}{content_check}',
                                'recommendation': f'建议检查文件内容: cat {file_path} | head -20'
                            })
    except Exception as e:
        print(f"检查可疑文件时出错: {e}")
    
    return threats


def check_system_integrity():
    """检查系统完整性"""
    threats = []
    try:
        # 检查关键系统文件最近是否被修改
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/root/.ssh/authorized_keys',
        ]
        
        for filepath in critical_files:
            if os.path.exists(filepath):
                # 检查修改时间
                stat = os.stat(filepath)
                mtime = datetime.fromtimestamp(stat.st_mtime)
                hours_since_modified = (datetime.now() - mtime).total_seconds() / 3600
                
                if hours_since_modified < 24:  # 24小时内被修改
                    threats.append({
                        'type': '系统关键文件变更',
                        'severity': '高',
                        'source_ip': '本地',
                        'target_user': '系统',
                        'time': mtime.strftime('%Y-%m-%d %H:%M:%S'),
                        'detail': f'关键文件 {filepath} 在 {hours_since_modified:.1f} 小时前被修改',
                        'recommendation': f'立即检查文件变更: diff {filepath} {filepath}.backup 或查看: ls -la {filepath}'
                    })
    except Exception as e:
        print(f"检查系统完整性时出错: {e}")
    
    return threats


def check_active_connections():
    """检查活跃连接，发现异常"""
    threats = []
    try:
        # 检查来自可疑地区的连接（这里简化，实际可用GeoIP）
        result = subprocess.getoutput("netstat -tn | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -5")
        
        if result:
            for line in result.strip().split('\n'):
                parts = line.strip().split()
                if len(parts) == 2:
                    count, ip = parts
                    if int(count) > 10 and ip not in ['127.0.0.1', '::1']:
                        threats.append({
                            'type': '异常网络连接',
                            'severity': '中',
                            'source_ip': ip,
                            'target_user': '系统',
                            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'detail': f'IP {ip} 有 {count} 个活跃连接，可能存在异常',
                            'recommendation': f'检查连接详情: netstat -tn | grep {ip}'
                        })
    except Exception as e:
        print(f"检查网络连接时出错: {e}")
    
    return threats


def generate_html_report(threats):
    """生成详细的HTML格式警报邮件"""
    current_time = datetime.now().strftime('%Y年%m月%d日 %H:%M:%S')
    
    # 统计威胁
    high_count = len([t for t in threats if t['severity'] == '高'])
    medium_count = len([t for t in threats if t['severity'] == '中'])
    low_count = len([t for t in threats if t['severity'] == '低'])
    
    # 威胁等级颜色
    if high_count > 0:
        alert_level = "🔴 紧急"
        alert_color = "#ff4444"
    elif medium_count > 0:
        alert_level = "🟡 警告"
        alert_color = "#ffaa00"
    else:
        alert_level = "🟢 提醒"
        alert_color = "#44aa44"
    
    # 生成威胁详情
    threat_html = ""
    for i, threat in enumerate(threats, 1):
        severity_color = {"高": "#ff4444", "中": "#ffaa00", "低": "#44aa44"}.get(threat['severity'], "#888888")
        
        threat_html += f"""
        <div style="background-color: #f8f9fa; border-left: 4px solid {severity_color}; padding: 15px; margin: 15px 0; border-radius: 4px;">
            <h3 style="margin-top: 0; color: #333;">威胁 #{i}: {threat['type']}</h3>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 5px; width: 100px;"><strong>威胁等级:</strong></td><td style="padding: 5px; color: {severity_color}; font-weight: bold;">{threat['severity']} 风险</td></tr>
                <tr><td style="padding: 5px;"><strong>攻击来源IP:</strong></td><td style="padding: 5px; font-family: monospace; background: #eee; display: inline-block; padding: 2px 8px; border-radius: 3px;">{threat['source_ip']}</td></tr>
                <tr><td style="padding: 5px;"><strong>目标用户:</strong></td><td style="padding: 5px;">{threat['target_user']}</td></tr>
                <tr><td style="padding: 5px;"><strong>发现时间:</strong></td><td style="padding: 5px;">{threat['time']}</td></tr>
                <tr><td style="padding: 5px;"><strong>详细描述:</strong></td><td style="padding: 5px;">{threat['detail']}</td></tr>
                <tr><td style="padding: 5px;"><strong>建议操作:</strong></td><td style="padding: 5px; background: #fff3cd; border-radius: 3px;"><code style="background: #f4f4f4; padding: 2px 6px; border-radius: 3px;">{threat['recommendation']}</code></td></tr>
            </table>
        </div>
        """
    
    html = f"""
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px; }}
            .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
            .stat-box {{ text-align: center; padding: 20px; background: #f8f9fa; border-radius: 8px; min-width: 100px; }}
            .high {{ color: #ff4444; font-size: 24px; font-weight: bold; }}
            .medium {{ color: #ffaa00; font-size: 24px; font-weight: bold; }}
            .low {{ color: #44aa44; font-size: 24px; font-weight: bold; }}
            .footer {{ margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 8px; font-size: 12px; color: #666; text-align: center; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ ClawArmor 安全警报系统</h1>
            <p style="font-size: 18px; margin: 10px 0;">警报级别: <span style="color: {alert_color}; font-weight: bold;">{alert_level}</span></p>
            <p>服务器: <strong>{SERVER_NAME}</strong> | 时间: {current_time}</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="high">{high_count}</div>
                <div>高风险</div>
            </div>
            <div class="stat-box">
                <div class="medium">{medium_count}</div>
                <div>中风险</div>
            </div>
            <div class="stat-box">
                <div class="low">{low_count}</div>
                <div>低风险</div>
            </div>
        </div>
        
        <h2>📋 威胁详情</h2>
        {threat_html if threat_html else '<p style="color: #44aa44; text-align: center; padding: 40px;">✅ 未发现威胁，系统安全</p>'}
        
        <div style="background: #e7f3ff; padding: 20px; border-radius: 8px; margin-top: 30px;">
            <h3>🔧 通用排查命令</h3>
            <ul>
                <li>查看登录失败: <code>lastb -i | head -20</code></li>
                <li>查看当前连接: <code>netstat -tn | grep ESTABLISHED</code></li>
                <li>查看进程: <code>ps aux | grep -i suspicious</code></li>
                <li>封禁IP: <code>iptables -A INPUT -s [IP] -j DROP</code></li>
            </ul>
        </div>
        
        <div class="footer">
            <p>此邮件由 ClawArmor v3.0 智能安全系统自动发送</p>
            <p>发送时间: {current_time} | 如有疑问请联系管理员</p>
        </div>
    </body>
    </html>
    """
    
    return html


def send_email(subject, html_content):
    """发送邮件"""
    try:
        msg = MIMEText(html_content, "html", "utf-8")
        msg["From"] = formataddr(("ClawArmor Security System", SENDER_EMAIL))
        msg["To"] = formataddr(("Administrator", RECEIVER_EMAIL))
        msg["Subject"] = subject
        
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.qq.com", 465, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
            print(f"[{datetime.now()}] 邮件发送成功: {subject}")
            return True
    except Exception as e:
        print(f"[{datetime.now()}] 邮件发送失败: {e}")
        return False


def main():
    """主函数"""
    print(f"[{datetime.now()}] 🔍 ClawArmor v3.0 开始安全巡检...")
    
    # 收集所有威胁
    all_threats = []
    all_threats.extend(get_failed_logins())
    all_threats.extend(check_suspicious_files())
    all_threats.extend(check_system_integrity())
    all_threats.extend(check_active_connections())
    
    # 去重（基于IP和类型）
    unique_threats = []
    seen = set()
    for t in all_threats:
        key = f"{t['type']}_{t['source_ip']}"
        if key not in seen:
            seen.add(key)
            unique_threats.append(t)
    
    # 发送警报（仅当发现威胁时）
    if unique_threats:
        high_count = len([t for t in unique_threats if t['severity'] == '高'])
        subject = f"🚨 {SERVER_NAME} 安全警报 - 发现 {len(unique_threats)} 个威胁 ({high_count}个高风险)"
        html_content = generate_html_report(unique_threats)
        send_email(subject, html_content)
    else:
        print(f"[{datetime.now()}] ✅ 巡检完成，未发现安全威胁")


if __name__ == "__main__":
    main()
