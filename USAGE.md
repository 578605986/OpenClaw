# 📖 ClawArmor 详细使用文档

## 目录

1. [快速开始](#快速开始)
2. [版本选择](#版本选择)
3. [配置详解](#配置详解)
4. [故障排查](#故障排查)
5. [安全最佳实践](#安全最佳实践)

---

## 快速开始

### 系统要求

- Linux 系统 (Ubuntu/Debian/CentOS/RHEL)
- Python 3.6+
- root 权限
- 外网连接 (下载和邮件发送)

### 最小化安装 (30秒)

```bash
# 下载部署脚本
wget https://raw.githubusercontent.com/yourusername/ClawArmor/main/install.sh

# 交互式安装
sudo bash install.sh v4
```

---

## 版本选择

### v4.1 智能防御版 ⭐推荐

**适用场景：**
- 需要实时防护 + 邮件告警
- 服务器资源有限
- 追求简单稳定

**包含功能：**
- fail2ban 实时封禁 (3次失败)
- ClawArmor 定时扫描 (5次失败封禁)
- HTML 邮件报告
- 自动IP白名单

### v5.1 完整安全套件

**适用场景：**
- 需要深度安全扫描
- 怀疑已被入侵
- 首次安全加固

**包含功能：**
- v4.1 所有功能
- WebShell 检测
- Rootkit 检测
- 系统基线检查
- 文件完整性监控

---

## 配置详解

### 邮箱配置

#### 方式1：环境变量（全自动）

```bash
export CLAWARMOR_EMAIL="your@qq.com"
export CLAWARMOR_PASSWORD="your_auth_code"
export CLAWARMOR_RECEIVER="admin@example.com"

sudo bash install.sh v4
```

#### 方式2：交互式

```bash
sudo bash install.sh v4
# 根据提示输入信息
```

#### 方式3：手动修改

```bash
sudo nano /opt/clawarmor/clawarmor.py

# 修改以下行：
SENDER_EMAIL = "your@qq.com"
SENDER_PASSWORD = "your_auth_code"
RECEIVER_EMAIL = "admin@example.com"
```

### 获取QQ邮箱授权码

1. 登录 [QQ邮箱](https://mail.qq.com)
2. 设置 → 账户 → 开启SMTP服务
3. 发送短信验证
4. 保存16位授权码（如：`abcdxyz123456789`）

### 调整防护强度

编辑 `/opt/clawarmor/clawarmor.py`：

```python
# 防御阈值
THRESHOLDS = {
    "failed_login": 5,    # 5次失败才封禁（建议3-10）
    "time_window": 300,   # 5分钟统计窗口
}

# 防御模式
DEFENSE_MODE = {
    "auto_block_ip": True,      # True=自动封禁, False=只告警
    "auto_isolate_file": False, # 自动隔离可疑文件
}
```

---

## 故障排查

### 无法收到邮件

**检查1：授权码是否正确**
```bash
# 测试SMTP连接
python3 -c "
import smtplib
s = smtplib.SMTP_SSL('smtp.qq.com', 465)
s.login('your@qq.com', 'your_auth_code')
print('登录成功')
"
```

**检查2：防火墙端口**
```bash
# 确保能访问QQ邮箱服务器
telnet smtp.qq.com 465
```

**检查3：日志查看**
```bash
tail -f /var/log/clawarmor.log
```

### 无法SSH连接

**情况1：被fail2ban误封**
```bash
# 通过控制台登录，执行：
fail2ban-client unban [YOUR_IP]
# 或
iptables -D INPUT -s [YOUR_IP] -j DROP
```

**情况2：白名单未生效**
```bash
# 检查白名单配置
grep ignoreip /etc/fail2ban/jail.local

# 重启fail2ban
systemctl restart fail2ban
```

### 定时任务不执行

```bash
# 检查cron服务
systemctl status cron

# 查看任务列表
crontab -l | grep clawarmor

# 手动执行测试
python3 /opt/clawarmor/clawarmor.py
```

---

## 安全最佳实践

### 1. 使用SSH密钥认证

```bash
# 生成密钥
ssh-keygen -t ed25519

# 复制公钥到服务器
ssh-copy-id -p 2222 root@your_server

# 禁用密码登录
sudo nano /etc/ssh/sshd_config
# 修改：PasswordAuthentication no

sudo systemctl restart sshd
```

### 2. 定期更换凭证

| 项目 | 周期 | 操作 |
|:---|:---:|:---|
| 邮箱授权码 | 3个月 | 重新生成并更新配置 |
| root密码 | 6个月 | 更换强密码 |
| SSH密钥 | 1年 | 重新生成密钥对 |

### 3. 备份配置

```bash
# 备份脚本
sudo tar -czvf clawarmor-backup-$(date +%Y%m%d).tar.gz \
  /opt/clawarmor/ \
  /etc/fail2ban/jail.local \
  /var/spool/cron/crontabs/root
```

### 4. 监控日志

```bash
# 查看攻击趋势
lastb -i | awk '{print $3}' | sort | uniq -c | sort -rn

# 查看被封禁IP
fail2ban-client status sshd | grep Banned

# 实时日志
tail -f /var/log/clawarmor.log
```

---

## 高级用法

### 自定义扫描规则

编辑 `/opt/clawarmor/clawarmor.py`：

```python
# 添加自定义检测
def my_custom_check():
    threats = []
    # 您的自定义检测逻辑
    return threats

# 在主函数中调用
threats.extend(my_custom_check())
```

### 集成企业微信/钉钉

修改邮件发送函数，替换为 webhook 调用：

```python
import requests

def send_wechat(msg):
    webhook = "https://qyapi.weixin.qq.com/..."
    requests.post(webhook, json={"text": {"content": msg}})
```

---

## 常见问题

**Q: 会误封自己的IP吗？**  
A: 不会。脚本自动检测当前连接IP并加入白名单。

**Q: 支持其他邮箱吗？**  
A: 支持。修改SMTP服务器地址和端口即可。

**Q: 可以在Docker中使用吗？**  
A: 可以，但需要特权模式和主机网络。

**Q: 支持Windows吗？**  
A: 不支持。仅支持Linux系统。

---

**更多问题请提交 Issue！** 🛡️
