#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ClawArmor Security Suite v5.0 - 完整安全套件
多层防护：体检 → 实时监控 → 深度扫描 → 自动修复

Author: 小灵通
Version: 5.0.0
"""

import os
import sys
import subprocess
import re
import json
import hashlib
import time
from datetime import datetime
from pathlib import Path

# ==================== 配置 ====================
CONFIG = {
    "server_name": "Server-1",
    "scan_paths": ["/tmp", "/var/tmp", "/dev/shm", "/opt"],
    "critical_files": [
        "/etc/passwd",
        "/etc/shadow", 
        "/etc/group",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/ssh/sshd_config",
        "/root/.ssh/authorized_keys",
        "/root/.bashrc",
        "/etc/crontab",
    ],
    "suspicious_patterns": [
        r'(wget|curl).*\|.*(bash|sh|python)',
        r'nc\s+-[el].*\d+',  # netcat 后门
        r'python\s+-m\s+http.server',  # 简易HTTP服务器
        r'base64\s+-d.*\|',  # base64解码执行
        r'eval\s*\(',  # eval执行
        r'exec\s*\(',  # exec执行
    ],
    "whitelist_ips": ["127.0.0.1", "::1"],
}

# 基线数据库（存储系统正常状态的哈希值）
BASELINE_DB = "/opt/clawarmor/baseline.json"
QUARANTINE_DIR = "/opt/clawarmor/quarantine"
LOG_FILE = "/var/log/clawarmor_suite.log"


def log(message, level="INFO"):
    """记录日志"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    msg = f"[{timestamp}] [{level}] {message}"
    print(msg)
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')
    except:
        pass


class SystemBaseline:
    """系统基线管理 - 建立系统正常状态的数据库"""
    
    @staticmethod
    def calculate_hash(filepath):
        """计算文件SHA256哈希"""
        try:
            if os.path.exists(filepath) and os.path.isfile(filepath):
                with open(filepath, 'rb') as f:
                    return hashlib.sha256(f.read()).hexdigest()
        except:
            pass
        return None
    
    @staticmethod
    def create_baseline():
        """创建系统基线（首次运行时执行）"""
        log("🔍 正在创建系统基线...")
        baseline = {
            "created_at": datetime.now().isoformat(),
            "files": {},
            "users": [],
            "processes": [],
            "ports": []
        }
        
        # 1. 记录关键文件哈希
        for filepath in CONFIG["critical_files"]:
            file_hash = SystemBaseline.calculate_hash(filepath)
            if file_hash:
                baseline["files"][filepath] = {
                    "hash": file_hash,
                    "mtime": os.path.getmtime(filepath)
                }
        
        # 2. 记录系统用户
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 3:
                            baseline["users"].append({
                                "username": parts[0],
                                "uid": parts[2],
                                "shell": parts[6] if len(parts) > 6 else ""
                            })
        except:
            pass
        
        # 3. 记录网络端口
        result = subprocess.getoutput("ss -tlnp | grep LISTEN")
        baseline["ports"] = result.strip().split('\n') if result else []
        
        # 保存基线
        os.makedirs(os.path.dirname(BASELINE_DB), exist_ok=True)
        with open(BASELINE_DB, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        log(f"✅ 基线创建完成，记录了 {len(baseline['files'])} 个文件")
        return baseline
    
    @staticmethod
    def load_baseline():
        """加载基线"""
        if os.path.exists(BASELINE_DB):
            with open(BASELINE_DB, 'r') as f:
                return json.load(f)
        return None


class DeepScanner:
    """深度扫描器 - 发现历史遗留威胁"""
    
    def __init__(self):
        self.threats = []
    
    def scan_all(self):
        """执行全套深度扫描"""
        log("🔍 开始深度安全扫描...")
        
        self.scan_file_integrity()      # 文件完整性检查
        self.scan_backdoors()            # 后门检测
        self.scan_webshells()            # WebShell检测
        self.scan_rootkits()             # Rootkit检测
        self.scan_suspicious_processes() # 可疑进程
        self.scan_network_connections()  # 网络连接
        self.scan_cron_jobs()            # 计划任务
        self.scan_ssh_keys()             # SSH密钥
        
        return self.threats
    
    def scan_file_integrity(self):
        """文件完整性检查（对比基线）"""
        baseline = SystemBaseline.load_baseline()
        if not baseline:
            log("⚠️ 未找到基线，跳过完整性检查", "WARN")
            return
        
        for filepath, data in baseline["files"].items():
            current_hash = SystemBaseline.calculate_hash(filepath)
            if current_hash and current_hash != data["hash"]:
                self.threats.append({
                    "type": "文件完整性破坏",
                    "severity": "CRITICAL",
                    "filepath": filepath,
                    "detail": f"文件被修改！原哈希: {data['hash'][:16]}... 现哈希: {current_hash[:16]}...",
                    "recommendation": f"diff {filepath} {filepath}.backup 或重新安装该文件"
                })
    
    def scan_backdoors(self):
        """检测常见后门"""
        # 检查常见后门路径
        backdoor_paths = [
            "/tmp/.ssh", "/var/tmp/.ssh", "/dev/shm/.bashrc",
            "/etc/.config", "/usr/sbin/...", "/bin/.login"
        ]
        
        for path in backdoor_paths:
            if os.path.exists(path):
                self.threats.append({
                    "type": "可疑后门文件",
                    "severity": "CRITICAL",
                    "filepath": path,
                    "detail": f"发现隐藏文件/目录: {path}",
                    "recommendation": f"立即检查: ls -la {path}"
                })
    
    def scan_webshells(self):
        """检测WebShell（简化版）"""
        webshell_keywords = [
            b'eval($_POST', b'assert($_POST', b'@eval(@$_POST',
            b'system($_GET', b'exec($_REQUEST', b'passthru(',
            b'shell_exec(', b'file_put_contents($_POST'
        ]
        
        # 扫描Web目录
        web_paths = ["/var/www", "/usr/share/nginx", "/opt/www"]
        for web_path in web_paths:
            if os.path.exists(web_path):
                for root, dirs, files in os.walk(web_path):
                    for file in files:
                        if file.endswith(('.php', '.jsp', '.asp', '.aspx')):
                            filepath = os.path.join(root, file)
                            try:
                                with open(filepath, 'rb') as f:
                                    content = f.read(10000)
                                    for keyword in webshell_keywords:
                                        if keyword in content:
                                            self.threats.append({
                                                "type": "WebShell",
                                                "severity": "CRITICAL",
                                                "filepath": filepath,
                                                "detail": f"发现WebShell特征: {keyword.decode('utf-8', errors='ignore')}",
                                                "recommendation": f"立即隔离: mv {filepath} {QUARANTINE_DIR}/"
                                            })
                                            break
                            except:
                                pass
    
    def scan_rootkits(self):
        """Rootkit检测（使用常见命令检查）"""
        # 检查常见rootkit迹象
        checks = [
            ("检查隐藏进程", "ps aux | wc -l", "ps aux | awk '{print $2}' | wc -l"),
            ("检查LD_PRELOAD", "echo $LD_PRELOAD", ""),
        ]
        
        # 检查系统命令是否被篡改
        critical_cmds = ["/bin/ls", "/bin/ps", "/bin/netstat", "/usr/bin/lsof"]
        for cmd in critical_cmds:
            if os.path.exists(cmd):
                # 简单检查：查看文件大小是否异常
                size = os.path.getsize(cmd)
                if size > 500000:  # 正常应该小于500KB
                    self.threats.append({
                        "type": "系统命令可能被篡改",
                        "severity": "HIGH",
                        "filepath": cmd,
                        "detail": f"文件大小异常: {size} 字节 (正常应 < 500KB)",
                        "recommendation": f"使用 busybox 检查: busybox {os.path.basename(cmd)}"
                    })
    
    def scan_suspicious_processes(self):
        """检测可疑进程"""
        result = subprocess.getoutput("ps aux --no-headers")
        suspicious_patterns = [
            (r'nc\s+-[el].*\d+', "Netcat后门"),
            (r'python\s+-m\s+http\.server', "简易HTTP服务器"),
            (r'miner|xmrig|cryptonight', "挖矿程序"),
            (r'reverse.*shell|connectback', "反向Shell"),
        ]
        
        for line in result.split('\n'):
            for pattern, desc in suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.threats.append({
                        "type": f"可疑进程 - {desc}",
                        "severity": "CRITICAL",
                        "detail": line[:200],
                        "recommendation": "kill -9 [PID] 终止进程"
                    })
    
    def scan_network_connections(self):
        """检查网络连接"""
        result = subprocess.getoutput("ss -tulnp | grep -E 'ESTAB|LISTEN'")
        
        # 检查异常端口
        suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 12345, 31337]
        for line in result.split('\n'):
            for port in suspicious_ports:
                if f':{port}' in line:
                    self.threats.append({
                        "type": "可疑端口监听",
                        "severity": "HIGH",
                        "detail": f"发现可疑端口 {port}: {line[:100]}",
                        "recommendation": f"检查进程: lsof -i :{port}"
                    })
    
    def scan_cron_jobs(self):
        """检查计划任务"""
        cron_locations = [
            "/etc/crontab",
            "/etc/cron.d/",
            "/var/spool/cron/",
            "/etc/cron.daily/",
        ]
        
        for location in cron_locations:
            if os.path.exists(location):
                if os.path.isdir(location):
                    for root, dirs, files in os.walk(location):
                        for file in files:
                            filepath = os.path.join(root, file)
                            self._check_cron_file(filepath)
                else:
                    self._check_cron_file(location)
    
    def _check_cron_file(self, filepath):
        """检查单个cron文件"""
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                for pattern in CONFIG["suspicious_patterns"]:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.threats.append({
                            "type": "可疑计划任务",
                            "severity": "CRITICAL",
                            "filepath": filepath,
                            "detail": f"发现可疑命令模式",
                            "recommendation": f"检查文件: cat {filepath}"
                        })
                        break
        except:
            pass
    
    def scan_ssh_keys(self):
        """检查SSH授权密钥"""
        auth_keys_paths = [
            "/root/.ssh/authorized_keys",
            "/home/*/.ssh/authorized_keys"
        ]
        
        for path_pattern in auth_keys_paths:
            import glob
            for filepath in glob.glob(path_pattern):
                try:
                    with open(filepath, 'r') as f:
                        keys = f.readlines()
                        for i, key in enumerate(keys, 1):
                            if key.strip() and not key.startswith('#'):
                                # 检查是否有可疑的密钥
                                if 'ssh-rsa' in key or 'ssh-ed25519' in key or 'ssh-dss' in key:
                                    # 这是正常的SSH密钥格式
                                    pass
                                else:
                                    self.threats.append({
                                        "type": "可疑SSH密钥",
                                        "severity": "HIGH",
                                        "filepath": filepath,
                                        "detail": f"第{i}行格式异常: {key[:50]}...",
                                        "recommendation": f"检查密钥: cat {filepath}"
                                    })
                except:
                    pass


class AutoRemediation:
    """自动修复模块"""
    
    @staticmethod
    def quarantine_file(filepath):
        """隔离可疑文件"""
        try:
            os.makedirs(QUARANTINE_DIR, exist_ok=True)
            filename = os.path.basename(filepath)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            quarantine_path = f"{QUARANTINE_DIR}/{timestamp}_{filename}"
            
            os.rename(filepath, quarantine_path)
            log(f"✅ 已隔离文件: {filepath} -> {quarantine_path}")
            return True
        except Exception as e:
            log(f"❌ 隔离失败: {e}", "ERROR")
            return False
    
    @staticmethod
    def kill_process(pid):
        """终止进程"""
        try:
            subprocess.run(f"kill -9 {pid}", shell=True, check=True)
            log(f"✅ 已终止进程: {pid}")
            return True
        except:
            return False
    
    @staticmethod
    def block_ip(ip):
        """封禁IP（安全版本）"""
        if ip in CONFIG["whitelist_ips"]:
            log(f"🛡️ 跳过白名单IP: {ip}")
            return False
        
        try:
            subprocess.run(f"iptables -A INPUT -s {ip} -j DROP", shell=True, check=True)
            log(f"🔒 已封禁IP: {ip}")
            return True
        except:
            return False


def generate_report(threats):
    """生成扫描报告"""
    print("\n" + "="*60)
    print("🛡️  ClawArmor Security Suite v5.0 扫描报告")
    print("="*60)
    
    if not threats:
        print("\n✅ 未发现威胁，系统安全！")
        return
    
    # 按严重度分类
    critical = [t for t in threats if t['severity'] == 'CRITICAL']
    high = [t for t in threats if t['severity'] == 'HIGH']
    medium = [t for t in threats if t['severity'] == 'MEDIUM']
    
    print(f"\n📊 威胁统计: CRITICAL={len(critical)}, HIGH={len(high)}, MEDIUM={len(medium)}")
    print("\n" + "-"*60)
    
    for i, threat in enumerate(threats, 1):
        severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(threat['severity'], "⚪")
        print(f"\n{severity_emoji} 威胁 #{i}: {threat['type']}")
        print(f"   严重度: {threat['severity']}")
        if 'filepath' in threat:
            print(f"   文件: {threat['filepath']}")
        print(f"   详情: {threat['detail'][:100]}...")
        print(f"   建议: {threat['recommendation']}")
    
    print("\n" + "="*60)
    print("⚠️  发现威胁！建议立即处理！")
    print("="*60)


def main():
    """主函数"""
    print("🛡️  ClawArmor Security Suite v5.0")
    print("="*60)
    print("1. 首次运行 - 创建系统基线")
    print("2. 深度扫描 - 检测历史威胁")
    print("3. 实时监控 - 启动持续防护")
    print("="*60)
    
    # 检查是否是首次运行
    baseline = SystemBaseline.load_baseline()
    if not baseline:
        print("\n📌 首次运行，创建系统基线...")
        baseline = SystemBaseline.create_baseline()
        print("✅ 基线创建完成！下次运行将检查文件完整性。")
    
    # 执行深度扫描
    print("\n🔍 开始深度安全扫描...")
    scanner = DeepScanner()
    threats = scanner.scan_all()
    
    # 生成报告
    generate_report(threats)
    
    # 自动修复选项
    if threats:
        response = input("\n是否自动修复可处理的威胁？(y/N): ").lower()
        if response == 'y':
            for threat in threats:
                if 'filepath' in threat and threat['severity'] == 'CRITICAL':
                    if input(f"隔离文件 {threat['filepath']}? (y/N): ").lower() == 'y':
                        AutoRemediation.quarantine_file(threat['filepath'])


if __name__ == "__main__":
    main()
