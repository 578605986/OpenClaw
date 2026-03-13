#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Feishu通知模块 - 带IP地址和中文地理位置
"""

import json
import urllib.request
import ssl
from datetime import datetime

# 飞书机器人配置
FEISHU_WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/YOUR_WEBHOOK_TOKEN"

def send_feishu_card(server_name, attack_count, top_ips, attacks_info):
    """发送飞书卡片通知（带IP和中文地理位置）"""
    
    # 构建IP列表（带中文地理位置）
    ip_list_text = ""
    for i, ip in enumerate(top_ips[:5], 1):
        info = attacks_info.get(ip, {})
        loc = info.get('location', {})
        country = loc.get('country', '-')
        region = loc.get('region', '-')
        city = loc.get('city', '-')
        count = info.get('count', 0)
        
        # 格式：1. 192.168.1.1 | 中国/北京/北京 | 攻击3次
        ip_list_text += f"{i}. `{ip}` | {country}/{region}/{city} | 攻击**{count}**次\n"
    
    if not ip_list_text:
        ip_list_text = "暂无攻击记录"
    
    # 获取当前时间
    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    
    # 构建卡片内容
    card = {
        "msg_type": "interactive",
        "card": {
            "config": {
                "wide_screen_mode": True
            },
            "header": {
                "title": {
                    "tag": "plain_text",
                    "content": f"🛡️ {server_name} 安全预警报告"
                },
                "template": "red"
            },
            "elements": [
                {
                    "tag": "div",
                    "text": {
                        "tag": "lark_md",
                        "content": f"**⏰ 报告时间：**{now}\n**🎯 攻击统计：**发现 **{attack_count}** 个攻击源"
                    }
                },
                {
                    "tag": "div",
                    "text": {
                        "tag": "lark_md",
                        "content": f"**📍 TOP攻击IP（实时中文定位）：**\n{ip_list_text}"
                    }
                },
                {
                    "tag": "hr"
                },
                {
                    "tag": "div",
                    "text": {
                        "tag": "lark_md",
                        "content": "**🔧 管理命令：**\n`fail2ban-client status sshd` - 查看封禁状态\n`fail2ban-client set sshd unbanip [IP]` - 解封IP"
                    }
                },
                {
                    "tag": "hr"
                },
                {
                    "tag": "note",
                    "elements": [
                        {
                            "tag": "plain_text",
                            "content": "📧 详细报告已发送至邮箱，请查收！"
                        }
                    ]
                }
            ]
        }
    }
    
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        data = json.dumps(card).encode('utf-8')
        req = urllib.request.Request(FEISHU_WEBHOOK, data=data, headers={'Content-Type': 'application/json'})
        
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            result = json.loads(response.read().decode())
            if result.get('code') == 0:
                print("📱 飞书通知已发送")
                return True
            else:
                print(f"飞书通知失败: {result}")
                return False
    except Exception as e:
        print(f"飞书通知异常: {e}")
        return False


# 兼容旧版本调用
def send_feishu_notification(server_name, attack_count, top_ips):
    """旧版兼容函数"""
    attacks_info = {}
    for ip in top_ips:
        attacks_info[ip] = {'count': 0, 'location': {'country': '-', 'region': '-', 'city': '-'}}
    return send_feishu_card(server_name, attack_count, top_ips, attacks_info)
