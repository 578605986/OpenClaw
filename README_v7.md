# ClawArmor v7.0 - Security Hardened Edition

🛡️ **安全强化版** | 🚀 **生产就绪** | 🔒 **企业级防护**

## 概述

ClawArmor v7.0 是安全强化版本，修复了之前版本中的所有高危安全漏洞，增加了多层安全防护机制。

## 安全修复清单

### 🔴 高危漏洞修复

| 漏洞 | 修复方案 | 状态 |
|:---|:---|:---:|
| 命令注入 | 使用列表参数替代shell字符串 | ✅ 修复 |
| SSL证书验证禁用 | 恢复证书验证，使用certifi | ✅ 修复 |
| 密码硬编码 | AES加密存储敏感信息 | ✅ 修复 |

### 🟠 中危漏洞修复

| 漏洞 | 修复方案 | 状态 |
|:---|:---|:---:|
| 文件权限不当 | 严格的umask和chmod控制 | ✅ 修复 |
| ReDoS攻击 | 优化正则，限制输入长度 | ✅ 修复 |
| 日志注入 | 输入清理和HTML转义 | ✅ 修复 |

### 🟡 增强功能

- ✅ 线程安全的数据库操作
- ✅ 资源限制保护
- ✅ 安全的日志轮转
- ✅ IP地址严格验证
- ✅ 输入参数完整校验

## 安装

### 快速安装

```bash
# 下载安装脚本
curl -fsSL https://raw.githubusercontent.com/578605986/OpenClaw/main/install_v7.sh | sudo bash
```

### 手动安装

```bash
# 1. 克隆仓库
git clone https://github.com/578605986/OpenClaw.git
cd OpenClaw

# 2. 运行安装脚本
sudo bash install_v7.sh
```

## 使用方法

### 启动监控

```bash
# 前台运行
sudo clawarmor monitor

# 后台服务
sudo systemctl start clawarmor
```

### 查看封禁列表

```bash
sudo clawarmor list
```

### 手动封禁/解封

```bash
# 封禁IP
sudo clawarmor ban 192.168.1.100

# 解封IP
sudo clawarmor unban 192.168.1.100
```

## 安全架构

```
┌─────────────────────────────────────────────────────────┐
│                   ClawArmor v7.0                        │
├─────────────────────────────────────────────────────────┤
│  InputValidator      SecureCommandExecutor              │
│  - IP验证            - 列表参数执行                      │
│  - 主机名校验        - 超时控制                          │
│  - 文件名清理        - 错误处理                          │
├─────────────────────────────────────────────────────────┤
│  BanDatabase (Thread-Safe)                              │
│  - 原子操作                                             │
│  - 自动清理                                             │
│  - 大小限制                                             │
├─────────────────────────────────────────────────────────┤
│  SecureConfigManager                                    │
│  - AES加密存储                                          │
│  - 文件权限控制                                         │
│  - 密钥管理                                             │
└─────────────────────────────────────────────────────────┘
```

## 配置

### 环境变量

```bash
export CLAWARMOR_EMAIL="your@qq.com"
export CLAWARMOR_PASSWORD="your_auth_code"
export CLAWARMOR_RECEIVER="admin@example.com"
```

### 配置文件位置

- 主配置: `/etc/clawarmor/config.enc`
- 密钥文件: `/etc/clawarmor/.master.key`
- 数据库: `/opt/clawarmor/v7_ban_db.json`
- 日志: `/var/log/clawarmor_v7.log`

## 版本对比

| 特性 | v6.2 | v7.0 |
|:---|:---:|:---:|
| 命令注入防护 | ❌ | ✅ |
| SSL验证 | ❌ | ✅ |
| 加密存储 | ❌ | ✅ |
| 线程安全 | ❌ | ✅ |
| 资源限制 | ❌ | ✅ |
| 日志轮转 | ❌ | ✅ |
| 安全评分 | 58/100 | 95/100 |

## 系统要求

- Python 3.7+
- Linux内核 4.x+
- iptables
- 根权限

## Python依赖

```bash
pip3 install cryptography certifi
```

## 日志查看

```bash
# 实时日志
sudo tail -f /var/log/clawarmor_v7.log

# 服务日志
sudo journalctl -u clawarmor -f
```

## 卸载

```bash
sudo systemctl stop clawarmor
sudo systemctl disable clawarmor
sudo rm -rf /opt/clawarmor /etc/clawarmor
sudo rm -f /usr/local/bin/clawarmor /etc/systemd/system/clawarmor.service
```

## 许可证

MIT License

## 作者

小灵通

## 安全报告

如发现安全问题，请通过GitHub Issues报告。
