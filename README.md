# 🛡️ ClawArmor Security Suite

**智能服务器安全防护系统** - 一键部署 fail2ban + ClawArmor 组合防护

[![Version](https://img.shields.io/badge/version-5.1-blue.svg)](https://github.com/yourusername/ClawArmor)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

---

## ✨ 核心特性

| 特性 | 说明 |
|:---|:---|
| 🔒 **双重防护** | fail2ban实时封禁 + ClawArmor深度监控 |
| 🤖 **全自动部署** | 一键脚本，自动检测配置 |
| 🛡️ **永不自伤** | 自动检测SSH端口，当前IP加入白名单 |
| 📧 **邮件告警** | 精美HTML报告，实时掌握安全态势 |
| 🔍 **深度扫描** | WebShell、后门、Rootkit检测 (v5) |

---

## 🚀 快速开始

### 方式1：全自动部署（推荐）

```bash
# 1. 设置环境变量
export CLAWARMOR_EMAIL="your@qq.com"
export CLAWARMOR_PASSWORD="your_auth_code"
export CLAWARMOR_RECEIVER="your@qq.com"  # 可选，默认同发件邮箱

# 2. 下载并执行
wget https://raw.githubusercontent.com/yourusername/ClawArmor/main/install.sh
sudo bash install.sh v4
```

### 方式2：交互式部署

```bash
wget https://raw.githubusercontent.com/yourusername/ClawArmor/main/install.sh
sudo bash install.sh v4
# 根据提示输入邮箱信息
```

### 版本选择

| 版本 | 命令 | 特点 |
|:---:|:---|:---|
| **v4.1** | `install.sh v4` | 轻量级，实时监控+邮件报告 |
| **v5.1** | `install.sh v5` | 完整版，包含深度扫描 |

---

## 📋 配置说明

### 获取QQ邮箱授权码

1. 登录 QQ邮箱网页版
2. 设置 → 账户 → 开启 SMTP 服务
3. 获取 16位授权码（不是登录密码！）

### 环境变量说明

```bash
export CLAWARMOR_EMAIL="your@qq.com"        # 发件邮箱
export CLAWARMOR_PASSWORD="your_auth_code"   # 邮箱授权码
export CLAWARMOR_RECEIVER="admin@example.com" # 收件邮箱（可选）
```

---

## 🛡️ 安全防护机制

### 双重防护架构

```
攻击者尝试SSH登录
    ↓
┌─────────────────┐
│ 第一层: fail2ban │  ← 3次失败 → 实时封禁（秒级）
│   实时监控       │
└─────────────────┘
    ↓
┌─────────────────┐
│ 第二层: ClawArmor│  ← 5次失败 → 定时封禁 + 邮件报告
│   每30分钟扫描   │
└─────────────────┘
```

### 永不自伤保障

- ✅ **自动检测SSH端口** - 从配置文件或进程读取
- ✅ **当前IP白名单** - 自动获取并加入白名单
- ✅ **内网IP保护** - 10.x/172.x/192.168.x 永不被封
- ✅ **渐进式防御** - 多次失败才封禁，避免误判

---

## 📁 文件说明

```
ClawArmor/
├── install.sh              # 一键部署脚本
├── src/
│   ├── clawarmor.py        # v2.0 基础版
│   ├── clawarmor_v3.py     # v3.0 HTML报告版
│   ├── clawarmor_v4_safe.py # v4.1 智能防御版（推荐）
│   └── clawarmor_suite_v5.py # v5.1 完整安全套件
├── README.md               # 本文件
├── USAGE.md                # 详细使用文档
└── LICENSE                 # MIT许可证
```

---

## 🔧 常用命令

```bash
# 查看fail2ban状态
fail2ban-client status sshd

# 查看已封禁IP
fail2ban-client status sshd | grep Banned

# 手动封禁IP
iptables -A INPUT -s [IP] -j DROP

# 解封IP
iptables -D INPUT -s [IP] -j DROP

# 手动运行扫描
python3 /opt/clawarmor/clawarmor.py

# 查看日志
tail -f /var/log/clawarmor.log
```

---

## 📧 邮件报告示例

```
🛡️ ClawArmor Security Report

📊 威胁统计:
   CRITICAL: 0  |  HIGH: 2  |  MEDIUM: 3

🔍 攻击详情:
   🎯 攻击IP: 192.168.1.100
      攻击次数: 8次
      目标用户: root
      
   🎯 攻击IP: 10.0.0.50
      攻击次数: 5次
      目标用户: admin

🛡️ 防护动作:
   ✅ fail2ban已封禁: 2个IP
   ✅ ClawArmor已记录: 5个攻击源
```

---

## ⚠️ 安全建议

1. **定期更换邮箱授权码** - 建议每3个月更换
2. **使用强密码** - root密码应为12位以上混合字符
3. **定期检查日志** - `tail -f /var/log/clawarmor.log`
4. **备份配置** - 定期备份 `/etc/fail2ban/jail.local`

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

---

**🛡️ 保护您的服务器，从 ClawArmor 开始！**
