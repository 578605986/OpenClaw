# 🛡️ ClawArmor v2.0

**智能体安全防御系统 - Intelligent Agent Security Defense System**

> 专为 OpenClaw/MOMOCLAW 智能体设计的服务器安全防护方案

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/578605986/OpenClaw)
[![Python](https://img.shields.io/badge/python-3.6+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

---

## ✨ 核心特性

| 特性 | 说明 |
|:---|:---|
| 📧 **邮件实时预警** | 检测到威胁立即发送邮件到管理员邮箱 |
| 🤖 **智能体防护** | 专为 AI 智能体环境优化的安全检测 |
| ⏰ **自动巡检** | 定时任务自动扫描，无需人工值守 |
| 🔄 **双服务器同步** | 支持多台服务器统一监控 |
| 🛡️ **威胁隔离** | 自动标记并隔离可疑文件 |
| 📱 **零延迟通知** | 邮件秒级送达，不错过任何警报 |

---

## 🚀 快速开始

### 1. 安装依赖

```bash
# 确保 Python 3.6+ 已安装
python3 --version

# 安装必需模块 (通常已内置)
pip3 install smtplib email
```

### 2. 配置邮箱

编辑 `src/clawarmor.py`，修改以下配置：

```python
# 发件邮箱 (QQ邮箱)
SENDER_EMAIL = "您的QQ邮箱@qq.com"
SENDER_PASSWORD = "您的QQ邮箱授权码"  # 不是登录密码!

# 收件邮箱
RECEIVER_EMAIL = "接收警报的邮箱@example.com"

# 服务器名称
SERVER_NAME = "Server-1"  # 用于区分多台服务器
```

**如何获取 QQ 邮箱授权码？**
1. 登录 QQ 邮箱网页版
2. 设置 → 账户 → 开启 SMTP 服务
3. 获取 16 位授权码 (不是邮箱密码!)

### 3. 部署到服务器

```bash
# 创建目录
sudo mkdir -p /opt/clawarmor

# 复制脚本
sudo cp src/clawarmor.py /opt/clawarmor/
sudo chmod +x /opt/clawarmor/clawarmor.py

# 测试发送
python3 /opt/clawarmor/clawarmor.py "测试警报" "ClawArmor 部署成功!"
```

### 4. 配置自动巡检 (Cron)

```bash
# 编辑定时任务
sudo crontab -e

# 添加以下行 (每10分钟检查一次)
*/10 * * * * /usr/bin/python3 /opt/clawarmor/clawarmor.py

# 每日状态报告 (每天早8点)
0 8 * * * /usr/bin/python3 /opt/clawarmor/clawarmor.py "每日巡检报告" "系统运行正常"
```

---

## 📖 使用示例

### 手动发送警报

```bash
# 命令行发送警报
python3 clawarmor.py "发现可疑文件" "/tmp/test.sh 包含危险命令" "WARNING"
```

### 在 Python 代码中调用

```python
from clawarmor import send_security_alert

# 发送安全警报
send_security_alert(
    subject="检测到异常登录",
    body="IP 192.168.1.100 尝试暴力破解 SSH",
    alert_level="CRITICAL"
)
```

---

## 🏗️ 系统架构

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   服务器 1       │     │   服务器 2       │     │   更多服务器...  │
│  (8.147.56.235) │     │ (39.104.101.225)│     │                 │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ ClawArmor 检测   │     │ ClawArmor 检测   │     │ ClawArmor 检测   │
│ - 文件扫描       │     │ - 文件扫描       │     │ - 文件扫描       │
│ - 进程监控       │     │ - 进程监控       │     │ - 进程监控       │
│ - 登录审计       │     │ - 登录审计       │     │ - 登录审计       │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────┐
                    │  QQ邮箱 SMTP 465    │
                    │  (SSL加密发送)       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ 管理员邮箱           │
                    │ (Luck-2026@outlook) │
                    └─────────────────────┘
```

---

## 🔧 高级配置

### 自定义检测规则

编辑 `clawarmor.py` 中的 `check_security_status()` 函数：

```python
def check_security_status():
    alerts = []
    
    # 添加您的自定义检测逻辑
    # 例如：检查特定目录、监控日志文件等
    
    return alerts
```

### 多服务器管理

在每台服务器上部署时，修改 `SERVER_NAME`：

| 服务器 | SERVER_NAME |
|:---|:---|
| 主服务器 | Server-1 |
| 备用服务器 | Server-2 |
| 数据库服务器 | DB-Server |

邮件标题会自动包含服务器名称，便于区分来源。

---

## 🛡️ 安全建议

1. **保护授权码**：不要将 QQ 邮箱授权码提交到公共仓库
2. **使用环境变量**：生产环境建议将敏感信息放入环境变量
3. **定期更换授权码**：建议每 3 个月更换一次
4. **监控日志**：定期检查 `/var/log/clawarmor_error.log`

---

## 📜 更新日志

### v2.0.0 (2026-03-12)
- ✨ 新增邮件实时预警功能
- ✨ 支持 Python 3.6+ 标准库 (无需额外依赖)
- ✨ 支持 QQ 邮箱 SMTP
- ✨ 支持多服务器部署
- ✨ 支持命令行调用
- 🛠️ 优化错误日志记录

### v1.0.0 (Archived)
- 基础安全检测功能

---

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

**贡献者：**
- 小灵通 (开发者)
- 578605986 (项目发起人)

---

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

---

## 💬 联系方式

- **GitHub Issues**: [提交问题](https://github.com/578605986/OpenClaw/issues)
- **飞书讨论**: 搜索 "ClawArmor" 技能

---

**🛡️ 保护您的智能体，从 ClawArmor 开始！**
