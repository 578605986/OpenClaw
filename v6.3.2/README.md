# 🛡️ ClawArmor v6.3.2

## 核心特性

- ✅ **实时IP地理位置查询**（中文显示）
- ✅ **v4.1紫色渐变风格** + 统计卡片
- ✅ **每3小时汇总通知**
- ✅ **飞书通知**（带IP和中文定位）

## 文件说明

| 文件 | 用途 |
|:---|:---|
| `clawarmor-monitor.py` | 主监控程序 |
| `feishu_module.py` | 飞书通知模块 |

## 快速开始

```bash
sudo mkdir -p /opt/clawarmor
sudo cp v6.3.2/*.py /opt/clawarmor/
sudo nano /opt/clawarmor/config.py  # 配置邮件
crontab -e  # 添加定时任务
```

**版本**: v6.3.2 | **发布时间**: 2024-03-13
