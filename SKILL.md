---
name: clawarmor-v2
description: 智能体服务器安全防御系统 - 邮件预警 + 自动巡检 + 威胁隔离
version: 2.0.0
author: 小灵通
tags: [security, monitoring, email-alert, automation]
---

# 🛡️ ClawArmor v2.0 使用指南

## 一句话介绍
为你的 OpenClaw 智能体服务器打造专属安全铠甲，检测到威胁立即邮件预警，7×24小时自动守护。

## 核心能力

### 1. 邮件实时预警
- 发现可疑文件/进程立即发送邮件
- 支持 QQ邮箱/Outlook/Gmail 等主流邮箱
- 秒级送达，不错过任何威胁

### 2. 自动巡检
- 每10分钟自动扫描安全风险
- 每日生成安全报告
- 支持自定义检测规则

### 3. 多服务器管理
- 一台脚本，多处部署
- 自动区分服务器来源
- 统一管理安全状态

## 快速部署

### 第一步：安装脚本
```bash
# 创建目录
sudo mkdir -p /opt/clawarmor

# 下载脚本 (请替换为实际URL)
curl -o /opt/clawarmor/clawarmor.py https://raw.githubusercontent.com/578605986/OpenClaw/main/ClawArmor-v2-Release/src/clawarmor.py

chmod +x /opt/clawarmor/clawarmor.py
```

### 第二步：配置邮箱
编辑脚本，修改以下配置：
```python
SENDER_EMAIL = "您的QQ邮箱@qq.com"
SENDER_PASSWORD = "QQ邮箱授权码"  # 不是登录密码!
RECEIVER_EMAIL = "接收警报的邮箱@example.com"
SERVER_NAME = "Server-1"
```

### 第三步：配置自动巡检
```bash
sudo crontab -e

# 添加定时任务
*/10 * * * * /usr/bin/python3 /opt/clawarmor/clawarmor.py
```

### 第四步：测试
```bash
python3 /opt/clawarmor/clawarmor.py "测试警报" "ClawArmor部署成功!"
```

## 使用场景

- 🔍 **技能安全检查**: 扫描下载的技能是否包含恶意代码
- 🚨 **异常登录预警**: 检测到暴力破解尝试立即通知
- 📊 **每日安全报告**: 定时发送服务器健康状态
- 🛡️ **文件变动监控**: 核心文件被篡改立即警报

## 技术特点

| 特性 | 说明 |
|:---|:---|
| 零依赖 | 仅使用 Python 标准库，无需 pip 安装 |
| 高兼容 | 支持 Python 3.6+，兼容各类 Linux 发行版 |
| 低资源 | 内存占用 < 10MB，不影响服务器性能 |
| 易扩展 | 模块化设计，可自定义检测规则 |

## 作者信息

- **作者**: 小灵通
- **GitHub**: https://github.com/578605986/OpenClaw
- **版本**: v2.0.0
- **更新日期**: 2026-03-12

## 注意事项

1. 请妥善保管邮箱授权码，不要上传到公共仓库
2. 建议定期更换 QQ 邮箱授权码 (每3个月)
3. 首次部署后请检查邮件是否能正常接收

## 反馈与支持

如有问题，欢迎通过以下方式联系：
- GitHub Issues
- MOMOCLAW 广场留言

---

**🛡️ 守护你的智能体，从 ClawArmor 开始!**
