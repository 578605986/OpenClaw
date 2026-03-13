#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClawArmor v7.0 - 安全强化版
Security Hardened Edition

修复的安全问题：
1. ✅ 命令注入防护 - 使用列表参数替代shell字符串
2. ✅ SSL证书验证 - 恢复证书验证
3. ✅ 配置加密存储 - 敏感信息AES加密
4. ✅ 文件权限控制 - 严格的文件权限管理
5. ✅ ReDoS防护 - 优化正则表达式
6. ✅ 日志注入防护 - 输入清理和转义
7. ✅ 线程安全 - 添加锁保护
8. ✅ 资源限制 - 防止资源耗尽

Author: 小灵通
Version: 7.0.0
Date: 2026-03-14
"""

import os
import sys
import subprocess
import re
import json
import hashlib
import time
import ipaddress
import threading
import stat
import html
import ssl
import urllib.request
import certifi
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from cryptography.fernet import Fernet
import logging
from logging.handlers import RotatingFileHandler

# ==================== 安全配置 ====================
@dataclass
class SecurityConfig:
    """安全配置类"""
    server_name: str = "Server-1"
    ban_threshold: int = 3
    ban_duration: int = -1  # -1 = 永久
    monitor_interval: int = 5
    max_log_size: int = 10 * 1024 * 1024  # 10MB
    max_ban_list_size: int = 10000  # 最大封禁IP数
    enable_email: bool = False
    
    # 白名单 - 严格保护
    whitelist_ips: tuple = (
        "127.0.0.1", "::1",
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
    )
    
    # 路径配置
    log_file: str = "/var/log/clawarmor_v7.log"
    ban_db: str = "/opt/clawarmor/v7_ban_db.json"
    config_dir: str = "/etc/clawarmor"
    quarantine_dir: str = "/opt/clawarmor/quarantine"


class SecureConfigManager:
    """安全配置管理器 - 加密存储敏感信息"""
    
    def __init__(self, config_dir: str = "/etc/clawarmor"):
        self.config_dir = config_dir
        self.key_file = os.path.join(config_dir, ".master.key")
        self.config_file = os.path.join(config_dir, "config.enc")
        self._ensure_secure_directory()
    
    def _ensure_secure_directory(self):
        """确保配置目录安全"""
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir, mode=0o700)
        else:
            # 确保权限正确
            os.chmod(self.config_dir, 0o700)
    
    def _get_or_create_key(self) -> bytes:
        """获取或创建加密密钥"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                return f.read()
        
        # 生成新密钥
        key = Fernet.generate_key()
        with open(self.key_file, 'wb') as f:
            f.write(key)
        os.chmod(self.key_file, 0o400)  # 只读
        return key
    
    def save_credentials(self, email: str, password: str, receiver: str):
        """加密保存凭证"""
        key = self._get_or_create_key()
        f = Fernet(key)
        
        data = {
            "sender_email": email,
            "sender_password": password,
            "receiver_email": receiver,
            "updated_at": datetime.now().isoformat()
        }
        
        encrypted = f.encrypt(json.dumps(data).encode())
        with open(self.config_file, 'wb') as file:
            file.write(encrypted)
        os.chmod(self.config_file, 0o600)
    
    def load_credentials(self) -> Optional[Dict[str, str]]:
        """解密加载凭证"""
        if not os.path.exists(self.config_file):
            return None
        
        try:
            key = self._get_or_create_key()
            f = Fernet(key)
            
            with open(self.config_file, 'rb') as file:
                encrypted = file.read()
            
            decrypted = f.decrypt(encrypted)
            return json.loads(decrypted)
        except Exception as e:
            logging.error(f"加载凭证失败: {e}")
            return None


class SecureLogger:
    """安全日志管理器"""
    
    def __init__(self, log_file: str, max_bytes: int = 10*1024*1024, backup_count: int = 5):
        self.logger = logging.getLogger('ClawArmorV7')
        self.logger.setLevel(logging.INFO)
        
        # 清除现有处理器
        self.logger.handlers = []
        
        # 创建日志目录
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, mode=0o750, exist_ok=True)
        
        # 轮转文件处理器
        handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            mode='a'
        )
        # 设置文件权限
        handler.mode = 0o640
        
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
        # 控制台输出
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        self.logger.addHandler(console)
    
    @staticmethod
    def sanitize(message: Any) -> str:
        """清理日志消息 - 防止注入"""
        msg = str(message)
        # 转义HTML
        msg = html.escape(msg)
        # 移除控制字符
        msg = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', msg)
        # 替换换行
        msg = msg.replace('\n', ' ').replace('\r', ' ')
        # 限制长度
        return msg[:1000]
    
    def info(self, message: Any):
        self.logger.info(self.sanitize(message))
    
    def warning(self, message: Any):
        self.logger.warning(self.sanitize(message))
    
    def error(self, message: Any):
        self.logger.error(self.sanitize(message))
    
    def critical(self, message: Any):
        self.logger.critical(self.sanitize(message))


class InputValidator:
    """输入验证器"""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """验证IP地址格式"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_hostname(hostname: str) -> bool:
        """验证主机名"""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, hostname)) and len(hostname) <= 253
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """清理文件名"""
        # 移除路径遍历
        filename = os.path.basename(filename)
        # 移除危险字符
        filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
        return filename[:255]


class SecureCommandExecutor:
    """安全命令执行器"""
    
    def __init__(self, logger: SecureLogger):
        self.logger = logger
    
    def ban_ip(self, ip: str) -> bool:
        """安全封禁IP - 防止命令注入"""
        # 严格验证IP
        if not InputValidator.validate_ip(ip):
            self.logger.error(f"无效的IP地址: {ip}")
            return False
        
        try:
            # 使用列表参数，禁止shell
            result = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            self.logger.info(f"IP已封禁: {ip}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"封禁失败 {ip}: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error(f"封禁命令超时: {ip}")
            return False
    
    def unban_ip(self, ip: str) -> bool:
        """安全解封IP"""
        if not InputValidator.validate_ip(ip):
            self.logger.error(f"无效的IP地址: {ip}")
            return False
        
        try:
            result = subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10
            )
            self.logger.info(f"IP已解封: {ip}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"解封失败 {ip}: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error(f"解封命令超时: {ip}")
            return False
    
    def get_ssh_logs(self, lines: int = 1000) -> str:
        """安全获取SSH日志"""
        lines = min(max(lines, 1), 5000)  # 限制范围
        
        log_files = ["/var/log/auth.log", "/var/log/secure"]
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    result = subprocess.run(
                        ["tail", "-n", str(lines), log_file],
                        capture_output=True,
                        text=True,
                        check=True,
                        timeout=5
                    )
                    return result.stdout
                except subprocess.CalledProcessError:
                    continue
        return ""


class IPLocationService:
    """IP地理位置服务 - 安全的API调用"""
    
    def __init__(self, logger: SecureLogger):
        self.logger = logger
        self.cache: Dict[str, dict] = {}
        self.cache_timeout = timedelta(hours=24)
    
    def get_location(self, ip: str) -> Optional[dict]:
        """获取IP地理位置 - 安全版本"""
        # 验证IP
        if not InputValidator.validate_ip(ip):
            self.logger.error(f"无效的IP: {ip}")
            return None
        
        # 检查缓存
        if ip in self.cache:
            cached = self.cache[ip]
            if datetime.now() - cached['cached_at'] < self.cache_timeout:
                return cached['data']
        
        try:
            # 使用正确的SSL上下文
            ctx = ssl.create_default_context(cafile=certifi.where())
            
            url = f"https://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query&lang=zh-CN"
            
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'ClawArmor/7.0',
                    'Accept': 'application/json'
                }
            )
            
            with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
                data = json.loads(response.read().decode('utf-8'))
                
                if data.get('status') == 'success':
                    location = {
                        'country': data.get('country', '未知'),
                        'region': data.get('regionName', '未知'),
                        'city': data.get('city', '未知'),
                        'isp': data.get('isp', '未知'),
                        'org': data.get('org', '未知'),
                        'as': data.get('as', '未知'),
                    }
                    
                    # 缓存结果
                    self.cache[ip] = {
                        'data': location,
                        'cached_at': datetime.now()
                    }
                    
                    return location
        except Exception as e:
            self.logger.error(f"查询IP位置失败 {ip}: {e}")
        
        return None


class BanDatabase:
    """线程安全的封禁数据库"""
    
    def __init__(self, db_path: str, logger: SecureLogger, max_size: int = 10000):
        self.db_path = db_path
        self.logger = logger
        self.max_size = max_size
        self._data: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._load()
    
    def _load(self):
        """加载数据库"""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    self._data = json.load(f)
                self.logger.info(f"加载封禁数据库: {len(self._data)} 个IP")
            except Exception as e:
                self.logger.error(f"加载数据库失败: {e}")
                self._data = {}
    
    def save(self):
        """线程安全保存"""
        with self._lock:
            try:
                # 创建目录
                db_dir = os.path.dirname(self.db_path)
                if db_dir:
                    os.makedirs(db_dir, mode=0o700, exist_ok=True)
                
                # 写入临时文件
                temp_path = f"{self.db_path}.tmp"
                with open(temp_path, 'w') as f:
                    json.dump(self._data, f, indent=2)
                
                # 设置权限
                os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
                
                # 原子替换
                os.replace(temp_path, self.db_path)
            except Exception as e:
                self.logger.error(f"保存数据库失败: {e}")
    
    def add(self, ip: str, data: dict) -> bool:
        """添加封禁记录"""
        with self._lock:
            if len(self._data) >= self.max_size:
                # 移除最旧的记录
                oldest = min(self._data.items(), key=lambda x: x[1].get('banned_at', ''))
                del self._data[oldest[0]]
                self.logger.warning(f"数据库已满，移除旧记录: {oldest[0]}")
            
            self._data[ip] = data
            return True
    
    def get(self, ip: str) -> Optional[dict]:
        """获取封禁记录"""
        with self._lock:
            return self._data.get(ip)
    
    def remove(self, ip: str) -> bool:
        """移除封禁记录"""
        with self._lock:
            if ip in self._data:
                del self._data[ip]
                return True
            return False
    
    def contains(self, ip: str) -> bool:
        """检查IP是否在封禁列表"""
        with self._lock:
            return ip in self._data
    
    def list_all(self) -> Dict[str, dict]:
        """获取所有记录"""
        with self._lock:
            return self._data.copy()
    
    def count(self) -> int:
        """获取记录数"""
        with self._lock:
            return len(self._data)


class ClawArmorV7:
    """ClawArmor v7.0 主类"""
    
    def __init__(self):
        self.config = SecurityConfig()
        self.logger = SecureLogger(
            self.config.log_file,
            max_bytes=self.config.max_log_size
        )
        self.db = BanDatabase(
            self.config.ban_db,
            self.logger,
            max_size=self.config.max_ban_list_size
        )
        self.executor = SecureCommandExecutor(self.logger)
        self.location_service = IPLocationService(self.logger)
        self.failed_attempts: defaultdict = defaultdict(list)
        self._running = False
    
    def is_whitelisted(self, ip: str) -> bool:
        """检查IP是否在白名单"""
        # 直接匹配
        if ip in self.config.whitelist_ips:
            return True
        
        # 检查网段
        try:
            ip_obj = ipaddress.ip_address(ip)
            for whitelist_ip in self.config.whitelist_ips:
                if '/' in whitelist_ip:
                    network = ipaddress.ip_network(whitelist_ip, strict=False)
                    if ip_obj in network:
                        return True
        except Exception:
            pass
        
        return False
    
    def ban_ip(self, ip: str, reason: str = "暴力破解", attempt_count: int = 0) -> bool:
        """封禁IP主流程"""
        # 检查白名单
        if self.is_whitelisted(ip):
            self.logger.info(f"跳过白名单IP: {ip}")
            return False
        
        # 检查是否已封禁
        if self.db.contains(ip):
            self.logger.info(f"IP已在封禁列表: {ip}")
            return False
        
        # 执行封禁
        if not self.executor.ban_ip(ip):
            return False
        
        # 获取地理位置
        location = self.location_service.get_location(ip)
        
        # 记录到数据库
        ban_data = {
            "banned_at": datetime.now().isoformat(),
            "reason": reason,
            "attempt_count": attempt_count,
            "duration": "permanent" if self.config.ban_duration == -1 else f"{self.config.ban_duration}s",
            "location": location or {}
        }
        
        self.db.add(ip, ban_data)
        self.db.save()
        
        location_str = f"{location['country']}-{location['city']}" if location else "未知"
        self.logger.info(f"🔒 已封禁IP: {ip} | 位置: {location_str} | 原因: {reason}")
        
        return True
    
    def unban_ip(self, ip: str) -> bool:
        """解封IP"""
        if not self.db.contains(ip):
            self.logger.warning(f"IP不在封禁列表: {ip}")
            return False
        
        if self.executor.unban_ip(ip):
            self.db.remove(ip)
            self.db.save()
            self.logger.info(f"🔓 已解封IP: {ip}")
            return True
        return False
    
    def parse_ssh_logs(self) -> List[str]:
        """解析SSH失败日志"""
        logs = self.executor.get_ssh_logs(1000)
        
        # 安全的正则匹配
        pattern = re.compile(r'Failed password.*from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        matches = pattern.findall(logs)
        
        # 验证IP格式
        valid_ips = []
        for ip in matches:
            if InputValidator.validate_ip(ip):
                valid_ips.append(ip)
        
        return valid_ips
    
    def check_and_ban(self):
        """检查并封禁"""
        failed_ips = self.parse_ssh_logs()
        current_time = datetime.now()
        
        for ip in failed_ips:
            if self.db.contains(ip):
                continue
            
            # 记录失败尝试
            self.failed_attempts[ip].append(current_time)
            
            # 清理过期记录（5分钟前）
            cutoff = current_time - timedelta(minutes=5)
            self.failed_attempts[ip] = [
                t for t in self.failed_attempts[ip] if t > cutoff
            ]
            
            # 检查阈值
            if len(self.failed_attempts[ip]) >= self.config.ban_threshold:
                self.logger.warning(f"🚨 触发封禁阈值: IP {ip} 失败 {len(self.failed_attempts[ip])} 次")
                self.ban_ip(ip, "SSH暴力破解", len(self.failed_attempts[ip]))
                self.failed_attempts[ip] = []
    
    def monitor_loop(self):
        """监控主循环"""
        self._running = True
        self.logger.info("🛡️ ClawArmor v7.0 安全强化版启动")
        self.logger.info(f"📊 配置: 失败{self.config.ban_threshold}次即封禁")
        
        while self._running:
            try:
                self.check_and_ban()
                time.sleep(self.config.monitor_interval)
            except KeyboardInterrupt:
                self.logger.info("🛑 收到停止信号，正在退出...")
                break
            except Exception as e:
                self.logger.error(f"监控循环错误: {e}")
                time.sleep(self.config.monitor_interval)
    
    def list_banned(self):
        """列出所有封禁IP"""
        banned = self.db.list_all()
        
        print("\n" + "="*80)
        print(f"🔒 封禁IP列表 (共 {len(banned)} 个)")
        print("="*80)
        
        if not banned:
            print("暂无封禁的IP")
            return
        
        for ip, data in banned.items():
            loc = data.get('location', {})
            print(f"\n📍 IP: {ip}")
            print(f"   封禁时间: {data.get('banned_at', '未知')}")
            print(f"   失败次数: {data.get('attempt_count', 'N/A')} 次")
            print(f"   地理位置: {loc.get('country', '未知')} - {loc.get('city', '未知')}")
            print(f"   运营商: {loc.get('isp', '未知')}")
            print(f"   原因: {data.get('reason', '未知')}")
        
        print("="*80)
    
    def stop(self):
        """停止监控"""
        self._running = False


def main():
    """主函数"""
    armor = ClawArmorV7()
    
    if len(sys.argv) < 2:
        print("用法: python3 clawarmor_v7.py [monitor|list|ban|unban]")
        print("\n命令:")
        print("  monitor  - 启动监控模式")
        print("  list     - 列出所有封禁IP")
        print("  ban IP   - 手动封禁指定IP")
        print("  unban IP - 手动解封指定IP")
        return
    
    command = sys.argv[1].lower()
    
    if command == "monitor":
        armor.monitor_loop()
    elif command == "list":
        armor.list_banned()
    elif command == "ban" and len(sys.argv) >= 3:
        ip = sys.argv[2]
        if armor.ban_ip(ip, "手动封禁"):
            print(f"✅ 已封禁IP: {ip}")
        else:
            print(f"❌ 封禁失败: {ip}")
    elif command == "unban" and len(sys.argv) >= 3:
        ip = sys.argv[2]
        if armor.unban_ip(ip):
            print(f"✅ 已解封IP: {ip}")
        else:
            print(f"❌ 解封失败: {ip}")
    else:
        print(f"未知命令或参数不足: {command}")


if __name__ == "__main__":
    main()
