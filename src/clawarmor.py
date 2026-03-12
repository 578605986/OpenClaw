#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClawArmor v2.0 - 智能体安全防御系统
Intelligent Agent Security Defense System

作者: 小灵通
版本: 2.0.0
功能: 邮件预警 + 自动巡检 + 威胁隔离
"""

import smtplib
import ssl
import sys
import os
from email.mime.text import MIMEText
from email.utils import formataddr
from datetime import datetime

# ==================== 用户配置区域 ====================
# 请修改以下配置为您的实际信息

# 发件邮箱配置 (QQ邮箱)
SENDER_EMAIL = "你的QQ邮箱@qq.com"      # 您的QQ邮箱
SENDER_PASSWORD = "你的QQ邮箱授权码"    # QQ邮箱授权码 (不是登录密码!)
SMTP_SERVER = "smtp.qq.com"
SMTP_PORT = 465

# 收件邮箱配置
RECEIVER_EMAIL = "你的邮箱@example.com"  # 接收警报的邮箱

# 服务器标识 (用于多服务器区分)
SERVER_NAME = "Server-1"  # 修改为: Server-1, Server-2, etc.

# =====================================================

def send_security_alert(subject, body, alert_level="INFO"):
    """
    发送安全警报邮件
    
    参数:
        subject: 邮件主题
        body: 邮件正文
        alert_level: 警报级别 (INFO/WARNING/CRITICAL)
    """
    
    # 添加邮件头信息
    full_subject = f"🛡️ [{SERVER_NAME}] {subject}"
    full_body = f"""
【ClawArmor 安全预警系统】

警报级别: {alert_level}
服务器: {SERVER_NAME}
时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{body}

---
此邮件由 ClawArmor v2.0 自动发送
如需帮助，请联系系统管理员
"""
    
    msg = MIMEText(full_body, "plain", "utf-8")
    msg["From"] = formataddr(("ClawArmor Security", SENDER_EMAIL))
    msg["To"] = formataddr(("Administrator", RECEIVER_EMAIL))
    msg["Subject"] = full_subject
    
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
            print(f"✅ [{datetime.now()}] 警报已发送: {subject}")
            return True
    except Exception as e:
        print(f"❌ [{datetime.now()}] 发送失败: {e}")
        with open("/var/log/clawarmor_error.log", "a") as f:
            f.write(f"{datetime.now()} - 发送失败: {e}\n")
        return False


def check_security_status():
    """检查服务器安全状态"""
    alerts = []
    
    # 检查可疑文件
    suspicious_dirs = ["/tmp", "/root/.openclaw/skills", "/opt"]
    danger_patterns = ["rm -rf /", "curl.*|.*bash", "> /etc/passwd"]
    
    for directory in suspicious_dirs:
        if os.path.exists(directory):
            try:
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        if file.endswith(('.sh', '.py', '.js')):
                            filepath = os.path.join(root, file)
                            try:
                                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    for pattern in danger_patterns:
                                        if pattern in content:
                                            alerts.append(f"发现可疑文件: {filepath}")
                            except:
                                pass
            except:
                pass
    
    return alerts


def main():
    """主函数 - 可命令行调用"""
    if len(sys.argv) >= 3:
        # 命令行模式: python3 clawarmor.py "主题" "内容"
        subject = sys.argv[1]
        body = sys.argv[2]
        level = sys.argv[3] if len(sys.argv) > 3 else "WARNING"
        send_security_alert(subject, body, level)
    else:
        # 自动巡检模式
        alerts = check_security_status()
        if alerts:
            subject = f"发现 {len(alerts)} 个安全威胁"
            body = "\n".join(alerts)
            send_security_alert(subject, body, "WARNING")
        else:
            # 发送心跳邮件 (可选)
            # send_security_alert("巡检正常", "未发现安全威胁", "INFO")
            pass


if __name__ == "__main__":
    main()
