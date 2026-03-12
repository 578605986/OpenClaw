# 🛡️ ClawArmor v4.1

**智能主动防御系统 - Intelligent Active Defense System**

> 专为 OpenClaw/MOMOCLAW 智能体设计的服务器安全防护方案
> **核心特性：多重安全保险，绝不自伤，全自动SSH端口检测**

[![Version](https://img.shields.io/badge/version-4.1.0-blue.svg)](https://github.com/578605986/ClawArmor)
[![Python](https://img.shields.io/badge/python-3.6+-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

---

## ✨ 核心特性

| 特性 | 说明 |
|:---|:---|
| 🧠 **智能主动防御** | 自动封禁攻击IP，隔离可疑文件（多重安全保险） |
| 📧 **邮件实时预警** | 检测到威胁立即发送详细HTML报告到管理员邮箱 |
| 🔍 **多维度检测** | 暴力破解、可疑文件、系统完整性、异常连接 |
| 🤖 **智能体防护** | 专为 AI 智能体环境优化的安全检测 |
| ⏰ **自动巡检** | 定时任务自动扫描，无需人工值守 |
| 🛡️ **绝不自伤** | 自动检测SSH端口，当前连接IP永不被封 |
| 🔄 **多服务器管理** | 支持多台服务器统一监控 |
| 📱 **零依赖** | 仅Python标准库，开箱即用 |

---

## 🚀 快速开始

### 🎯 版本选择（强烈推荐 v5.0！）

| 版本 | 适用场景 | 防护能力 | 文件 |
|:---|:---|:---:|:---|
| **v5.0 ⭐推荐** | 需要完整安全套件 | 🛡️🛡️🛡️🛡️🛡️ | `clawarmor_suite_v5.py` |
| v4.1 | 需要主动防御+自动检测 | 🛡️🛡️🛡️🛡️ | `clawarmor_v4_safe.py` |
| v3.0 | 需要详细HTML报告 | 🛡️🛡️🛡️ | `clawarmor_v3.py` |
| v2.0 | 基础邮件预警 | 🛡️🛡️ | `clawarmor.py` |

**v5.0 相比 v4.1 新增：**
- ✅ 系统基线建立（检测文件篡改）
- ✅ WebShell 深度扫描
- ✅ 后门/Rootkit 检测
- ✅ 可疑进程自动终止
- ✅ 历史威胁全面扫描
- ✅ 五层纵深防御体系

### 1. 安装依赖

```bash
# 确保 Python 3.6+ 已安装
python3 --version

# 无需安装额外依赖，仅使用Python标准库
```

### 2. 下载并配置

```bash
# 创建目录
sudo mkdir -p /opt/clawarmor

# 下载 v4.1 (推荐)
wget -O /opt/clawarmor/clawarmor.py \
  https://raw.githubusercontent.com/578605986/OpenClaw/main/src/clawarmor_v4_safe.py

# 编辑配置（只需修改邮箱）
sudo nano /opt/clawarmor/clawarmor.py
```

**只需修改这3行：**
```python
SENDER_EMAIL = "你的QQ邮箱@qq.com"
SENDER_PASSWORD = "你的QQ邮箱授权码"
RECEIVER_EMAIL = "接收邮箱@example.com"
```

**SSH端口自动检测，无需配置！**

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
│  (你的服务器IP)  │     │ (你的服务器IP)  │     │                 │
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
                    │ (你的邮箱@example.com) │
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

### v5.0.0 (2026-03-13) - **重磅更新！**
- ✨ **完整安全套件** - 五层纵深防御体系
- ✨ **系统基线建立** - 首次运行创建系统健康档案
- ✨ **WebShell 检测** - 深度扫描 PHP/JSP/ASP 后门
- ✨ **Rootkit 检测** - 检查系统命令篡改、隐藏进程
- ✨ **后门用户检测** - 对比基线发现新增可疑账户
- ✨ **可疑进程检测** - 自动识别挖矿/反向Shell
- ✨ **计划任务审计** - 扫描所有 cron 任务
- ✨ **自动修复系统** - 隔离文件、终止进程、封禁IP
- ✨ **全面解决历史威胁问题**
- ✨ **全自动SSH端口检测** - 无需手动配置，自动识别并保护SSH端口
- ✨ 智能主动防御 - 自动封禁攻击IP，自动隔离可疑文件
- ✨ 多重安全保险 - 当前连接IP永不被封，绝不自伤
- ✨ 渐进式防御 - 5次失败才封禁，避免误判
- 🛠️ 增强日志记录和防御数据持久化

### v4.0.0 (2026-03-13)
- ✨ 智能主动防御系统
- ✨ 暴力破解检测 + 自动封禁
- ✨ 可疑文件自动隔离
- ✨ 系统完整性检查
- ✨ 异常连接检测

### v3.0.0 (2026-03-13)
- ✨ 详细威胁分析
- ✨ HTML格式精美报告
- ✨ 可视化威胁统计（红/黄/绿风险等级）
- ✨ 一键复制排查命令

### v2.0.0 (2026-03-12)
- ✨ 邮件实时预警功能
- ✨ 支持 Python 3.6+ 标准库
- ✨ 支持 QQ 邮箱 SMTP
- ✨ 支持多服务器部署
- ✨ 支持命令行调用
- 🛠️ 优化错误日志记录

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

- **GitHub Issues**: [提交问题](https://github.com/578605986/ClawArmor/issues)
- **飞书讨论**: 搜索 "ClawArmor" 技能

---

**🛡️ 保护您的智能体，从 ClawArmor 开始！**
