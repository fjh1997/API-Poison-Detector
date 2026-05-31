#!/usr/bin/env python3
"""
API中转站投毒检测程序 / API Relay Poison Detection Program

合并自: / Merged from:
- detector.py (基础检测 + DetectorProxy) (Basic detection + DetectorProxy)
- advanced_detector.py (SecretScanner, PolicyGate, AnomalyDetector, ConditionalTriggerDetector, TransparencyLog)
- poison_detector.py (APIRequest, APIResponse, baseline comparison, latency anomaly)

功能： / Features:
1. 接收被投毒的上游API地址和Key / Receive poisoned upstream API address and key
2. 生成干净的API地址和Key供Claude Code使用 / Generate clean API address and key for Claude Code
3. 实时监控并检测投毒行为 / Real-time monitoring and poison detection
4. 发现投毒立即报警 / Alert immediately when poison is detected

使用方式： / Usage:
    python detector.py
"""

import json
import hashlib
import time
import re
import os
import sys
import asyncio
import aiohttp
from aiohttp import web
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import difflib
import copy
import base64
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('detection_alerts.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ─── Enums ────────────────────────────────────────────────────────────────────

class ThreatLevel(Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackClass(Enum):
    """论文定义的攻击类 / Attack classes defined in the paper"""
    AC_1 = "AC-1"       # 载荷注入 / Payload injection
    AC_2 = "AC-2"       # 秘密窃取 / Secret exfiltration
    AC_1a = "AC-1.a"    # 依赖混淆 / Dependency confusion
    AC_1b = "AC-1.b"    # 条件投毒 / Conditional poisoning


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class DetectionAlert:
    threat_level: ThreatLevel
    description: str
    evidence: str
    attack_type: str = ""
    request_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    attack_class: Optional[AttackClass] = None
    blocked: bool = False


@dataclass
class SessionState:
    """会话状态 - 用于检测AC-1.b条件投毒 / Session state - used for AC-1.b conditional poison detection"""
    session_id: str
    request_count: int = 0
    tool_calls_seen: List[str] = field(default_factory=list)
    is_yolo_mode: bool = False
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    has_curl_wget: bool = False
    has_pip_install: bool = False
    has_npm_install: bool = False


@dataclass
class APIRequest:
    """API请求数据 / API request data"""
    method: str
    url: str
    headers: Dict
    body: Dict
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class APIResponse:
    """API响应数据 / API response data"""
    status_code: int
    headers: Dict
    body: Dict
    latency_ms: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ─── Advanced detection components (from advanced_detector.py) ────────────────

class SecretScanner:
    """AC-2: 秘密窃取检测 / Secret exfiltration detection"""

    SECRET_PATTERNS = {
        'openai_key': r'sk-[A-Za-z0-9]{20,}',
        'aws_key': r'AKIA[A-Z0-9]{16}',
        'github_pat': r'ghp_[A-Za-z0-9]{36}',
        'slack_token': r'xoxb-[0-9]+-[A-Za-z0-9]+',
        'eth_private_key': r'0x[a-fA-F0-9]{64}',
        'pem_key': r'-----BEGIN .* PRIVATE KEY-----',
        'anthropic_key': r'sk-ant-[A-Za-z0-9\-]{20,}',
        'google_api_key': r'AIza[A-Za-z0-9_\-]{35}',
        'stripe_key': r'sk_live_[A-Za-z0-9]{24,}',
        'npm_token': r'npm_[A-Za-z0-9]{36}',
        'docker_token': r'dckr_pat_[A-Za-z0-9_\-]{20,}',
    }

    def __init__(self):
        self.compiled_patterns = {
            name: re.compile(pattern)
            for name, pattern in self.SECRET_PATTERNS.items()
        }
        self.exfiltrated_secrets: List[Dict] = []

    def scan_request(self, body: Dict, headers: Dict) -> List[DetectionAlert]:
        alerts = []
        request_str = json.dumps(body)
        headers_str = json.dumps(headers)

        for secret_name, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(request_str):
                alerts.append(DetectionAlert(
                    attack_class=AttackClass.AC_2,
                    threat_level=ThreatLevel.CRITICAL,
                    description=f"请求中发现敏感凭证: {secret_name}",
                    evidence=f"模式: {secret_name}, 位置: {match.start()}",
                ))
                self.exfiltrated_secrets.append({
                    'type': secret_name,
                    'timestamp': datetime.now().isoformat(),
                    'context': 'request_body'
                })

            for match in pattern.finditer(headers_str):
                alerts.append(DetectionAlert(
                    attack_class=AttackClass.AC_2,
                    threat_level=ThreatLevel.CRITICAL,
                    description=f"请求头中发现敏感凭证: {secret_name}",
                    evidence=f"模式: {secret_name}",
                ))

        return alerts

    def scan_response(self, body: Dict) -> List[DetectionAlert]:
        alerts = []
        response_str = json.dumps(body)

        for secret_name, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(response_str):
                alerts.append(DetectionAlert(
                    attack_class=AttackClass.AC_2,
                    threat_level=ThreatLevel.HIGH,
                    description=f"响应中包含敏感凭证: {secret_name}",
                    evidence=f"模式: {secret_name}",
                ))

        return alerts


class PolicyGate:
    """论文中的Policy Gate防御 / Policy Gate defense from the paper"""

    ALLOWED_DOMAINS = {
        'github.com', 'raw.githubusercontent.com',
        'pypi.org', 'files.pythonhosted.org',
        'registry.npmjs.org', 'npmjs.org',
        'crates.io', 'static.crates.io',
        'hub.docker.com',
        'packages.debian.org', 'archive.ubuntu.com',
        'maven.org', 'repo1.maven.org',
    }

    DANGEROUS_COMMANDS = [
        r'curl\s+.*\|\s*(bash|sh|python)',
        r'wget\s+.*\|\s*(bash|sh|python)',
        r'curl\s+.*-o\s+.*\.(sh|py|exe|bat)',
        r'wget\s+.*-O\s+.*\.(sh|py|exe|bat)',
        r'eval\s*\(',
        r'exec\s*\(',
        r'__import__\s*\(',
        r'subprocess\.',
        r'os\.system\s*\(',
        r'rm\s+-rf\s+/',
        r'chmod\s+777',
        r'curl\s+.*\s*\|\s*sudo',
    ]

    def __init__(self):
        self.compiled_dangerous = [re.compile(p, re.IGNORECASE) for p in self.DANGEROUS_COMMANDS]
        self.blocked_count = 0

    def check_tool_call(self, tool_name: str, arguments: Dict) -> List[DetectionAlert]:
        alerts = []

        high_risk_tools = ['Bash', 'run_command', 'shell', 'terminal', 'exec', 'system']
        if tool_name not in high_risk_tools:
            return alerts

        command = arguments.get('command', '')
        if not command:
            return alerts

        for pattern in self.compiled_dangerous:
            if pattern.search(command):
                alerts.append(DetectionAlert(
                    attack_class=AttackClass.AC_1,
                    threat_level=ThreatLevel.CRITICAL,
                    description="Policy Gate: 检测到危险命令模式",
                    evidence=f"工具: {tool_name}, 模式: {pattern.pattern}",
                    blocked=True
                ))
                self.blocked_count += 1

        url_pattern = r'https?://([^\s/]+)'
        urls = re.findall(url_pattern, command)
        for url in urls:
            domain = url.split(':')[0]
            if domain not in self.ALLOWED_DOMAINS:
                if re.search(r'(curl|wget)\s+', command):
                    alerts.append(DetectionAlert(
                        attack_class=AttackClass.AC_1,
                        threat_level=ThreatLevel.HIGH,
                        description="Policy Gate: 非白名单域名访问",
                        evidence=f"域名: {domain}, 命令: {command[:100]}",
                        blocked=True
                    ))
                    self.blocked_count += 1

        pip_pattern = r'pip3?\s+install\s+(.*)'
        pip_match = re.search(pip_pattern, command)
        if pip_match:
            packages = pip_match.group(1).split()
            for pkg in packages:
                if self._is_typosquatting(pkg):
                    alerts.append(DetectionAlert(
                        attack_class=AttackClass.AC_1a,
                        threat_level=ThreatLevel.CRITICAL,
                        description="Policy Gate: 检测到疑似依赖混淆攻击",
                        evidence=f"包名: {pkg}, 可能是typosquatting",
                        blocked=True
                    ))
                    self.blocked_count += 1

        return alerts

    def _is_typosquatting(self, package_name: str) -> bool:
        known_typosquats = {
            'requests': ['reqeusts', 'reqeust', 'requets'],
            'numpy': ['numpay', 'numpi', 'nunpy'],
            'pandas': ['pandass', 'pandsa', 'panadas'],
            'flask': ['flaskk', 'flaks', 'flsak'],
            'django': ['djang0', 'djangoo', 'djano'],
            'urllib3': ['urlib3', 'urllib', 'urrlib3'],
            'cryptography': ['crytpography', 'crytography', 'crypography'],
            'pyyaml': ['pyyml', 'pyyaml3', 'pyyam'],
            'beautifulsoup4': ['beatifulsoup4', 'beautifulsoup', 'beutifulsoup4'],
            'scikit-learn': ['scikit-leanr', 'scikit_learn', 'sklearn'],
        }

        name_lower = package_name.lower().replace('-', '').replace('_', '')

        for real_pkg, typos in known_typosquats.items():
            real_normalized = real_pkg.lower().replace('-', '').replace('_', '')
            if name_lower == real_normalized:
                return False
            for typo in typos:
                typo_normalized = typo.lower().replace('-', '').replace('_', '')
                if name_lower == typo_normalized:
                    return True

        common_packages = ['requests', 'numpy', 'pandas', 'flask', 'django',
                          'urllib3', 'cryptography', 'pyyaml', 'pytest']
        for pkg in common_packages:
            if self._edit_distance(name_lower, pkg) == 1 and name_lower != pkg:
                return True

        return False

    def _edit_distance(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._edit_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row

        return prev_row[-1]


class AnomalyDetector:
    """论文中的Anomaly Screening / Anomaly Screening from the paper"""

    def __init__(self):
        self.tool_frequency: Dict[str, int] = defaultdict(int)
        self.total_calls = 0
        self.shell_risk_scores: List[float] = []
        self.string_entropies: List[float] = []

    def calculate_string_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = defaultdict(int)
        for c in s:
            freq[c] += 1
        length = len(s)
        entropy = -sum((count/length) * (count/length) for count in freq.values())
        return entropy

    def calculate_shell_risk_score(self, command: str) -> float:
        risk = 0.0
        high_risk_patterns = [
            (r'curl.*\|', 0.8),
            (r'wget.*\|', 0.8),
            (r'eval\(', 0.9),
            (r'exec\(', 0.9),
            (r'rm\s+-rf', 0.7),
            (r'sudo', 0.5),
            (r'chmod\s+777', 0.6),
            (r'\|\s*(bash|sh)', 0.8),
            (r'>\s*/dev/', 0.4),
            (r'base64', 0.3),
        ]

        for pattern, weight in high_risk_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                risk = max(risk, weight)

        return risk

    def analyze_tool_call(self, tool_name: str, arguments: Dict) -> List[DetectionAlert]:
        alerts = []
        self.total_calls += 1
        self.tool_frequency[tool_name] += 1

        command = arguments.get('command', '')
        if not command:
            return alerts

        risk_score = self.calculate_shell_risk_score(command)
        self.shell_risk_scores.append(risk_score)

        entropy = self.calculate_string_entropy(command)
        self.string_entropies.append(entropy)

        if risk_score > 0.7:
            alerts.append(DetectionAlert(
                attack_class=AttackClass.AC_1,
                threat_level=ThreatLevel.HIGH,
                description="Anomaly Detection: 高风险shell命令",
                evidence=f"风险分数: {risk_score:.2f}, 命令: {command[:100]}",
            ))

        if entropy > 4.5:
            alerts.append(DetectionAlert(
                attack_class=AttackClass.AC_1,
                threat_level=ThreatLevel.MEDIUM,
                description="Anomaly Detection: 异常高熵字符串（可能是混淆）",
                evidence=f"熵: {entropy:.2f}",
            ))

        if len(command) > 500:
            alerts.append(DetectionAlert(
                attack_class=AttackClass.AC_1,
                threat_level=ThreatLevel.MEDIUM,
                description="Anomaly Detection: 异常长命令",
                evidence=f"长度: {len(command)}",
            ))

        return alerts


class ConditionalTriggerDetector:
    """AC-1.b: 条件投毒检测 / Conditional poison detection"""

    def __init__(self):
        self.sessions: Dict[str, SessionState] = {}

    def get_or_create_session(self, session_id: str) -> SessionState:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(session_id=session_id)
        return self.sessions[session_id]

    def update_session(self, session_id: str, tool_name: str, arguments: Dict) -> SessionState:
        session = self.get_or_create_session(session_id)
        session.request_count += 1
        session.last_seen = datetime.now().isoformat()

        if tool_name:
            session.tool_calls_seen.append(tool_name)

        command = arguments.get('command', '')
        if command:
            if 'curl' in command or 'wget' in command:
                session.has_curl_wget = True
            if 'pip install' in command:
                session.has_pip_install = True
            if 'npm install' in command:
                session.has_npm_install = True

        return session

    def detect_triggers(self, session_id: str, tool_name: str, arguments: Dict) -> List[DetectionAlert]:
        alerts = []
        session = self.get_or_create_session(session_id)

        if session.request_count > 50:
            alerts.append(DetectionAlert(
                attack_class=AttackClass.AC_1b,
                threat_level=ThreatLevel.MEDIUM,
                description=f"AC-1.b Trigger: 高请求计数 ({session.request_count})",
                evidence=f"会话 {session_id} 已有 {session.request_count} 次请求",
            ))

        command = arguments.get('command', '')
        yolo_indicators = ['--yes', '-y', '--auto-approve', '--force', '-f']
        if any(indicator in command for indicator in yolo_indicators):
            session.is_yolo_mode = True
            alerts.append(DetectionAlert(
                attack_class=AttackClass.AC_1b,
                threat_level=ThreatLevel.HIGH,
                description="AC-1.b Trigger: 检测到YOLO/自动批准模式",
                evidence="命令包含自动批准标志",
            ))

        installer_patterns = ['curl -sSL', 'pip install', 'npm install', 'cargo install']
        if any(pattern in command for pattern in installer_patterns):
            alerts.append(DetectionAlert(
                attack_class=AttackClass.AC_1b,
                threat_level=ThreatLevel.MEDIUM,
                description="AC-1.b Trigger: 安装器命令检测",
                evidence="命令包含安装器模式",
            ))

        if 'Cargo.toml' in str(arguments) or 'go.mod' in str(arguments):
            alerts.append(DetectionAlert(
                attack_class=AttackClass.AC_1b,
                threat_level=ThreatLevel.MEDIUM,
                description="AC-1.b Trigger: 高价值项目类型 (Rust/Go)",
                evidence="检测到Cargo.toml或go.mod",
            ))

        return alerts


class TransparencyLog:
    """论文中的Transparency Logging / Transparency Logging from the paper"""

    def __init__(self, log_file: str = "transparency_log.jsonl"):
        self.log_file = log_file
        self.entries: List[Dict] = []

    def log_request(self, request_id: str, body: Dict, headers: Dict):
        sanitized_body = self._sanitize_secrets(body)
        sanitized_headers = self._sanitize_secrets(headers)

        entry = {
            'type': 'request',
            'request_id': request_id,
            'timestamp': datetime.now().isoformat(),
            'body_hash': hashlib.sha256(json.dumps(sanitized_body, sort_keys=True).encode()).hexdigest(),
            'headers_hash': hashlib.sha256(json.dumps(sanitized_headers, sort_keys=True).encode()).hexdigest(),
            'model': body.get('model', 'unknown'),
            'message_count': len(body.get('messages', [])),
        }

        self._append_log(entry)

    def log_response(self, request_id: str, body: Dict, latency_ms: float):
        entry = {
            'type': 'response',
            'request_id': request_id,
            'timestamp': datetime.now().isoformat(),
            'body_hash': hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest(),
            'latency_ms': latency_ms,
        }

        if 'choices' in body:
            for choice in body['choices']:
                msg = choice.get('message', {})
                if 'tool_calls' in msg:
                    entry['tool_calls'] = [
                        {
                            'name': tc.get('function', {}).get('name', ''),
                            'args_hash': hashlib.sha256(
                                tc.get('function', {}).get('arguments', '').encode()
                            ).hexdigest()
                        }
                        for tc in msg['tool_calls']
                    ]

        self._append_log(entry)

    def log_alert(self, alert: DetectionAlert):
        entry = {
            'type': 'alert',
            'timestamp': alert.timestamp,
            'attack_class': alert.attack_class.value if alert.attack_class else None,
            'threat_level': alert.threat_level.value,
            'description': alert.description,
            'evidence': alert.evidence,
            'blocked': alert.blocked,
            'request_id': alert.request_id,
        }
        self._append_log(entry)

    def _append_log(self, entry: Dict):
        self.entries.append(entry)
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
        except Exception as e:
            logger.error(f"写入透明日志失败: {e}")

    def _sanitize_secrets(self, data: Dict) -> Dict:
        sanitized = json.dumps(data)
        patterns = {
            r'sk-[A-Za-z0-9]{20,}': 'sk-***REDACTED***',
            r'AKIA[A-Z0-9]{16}': 'AKIA***REDACTED***',
            r'Bearer [A-Za-z0-9\-_]+': 'Bearer ***REDACTED***',
        }
        for pattern, replacement in patterns.items():
            sanitized = re.sub(pattern, replacement, sanitized)
        return json.loads(sanitized)


# ─── Core detector ────────────────────────────────────────────────────────────

class PoisonDetector:
    """投毒检测核心 / Poison detection core"""

    # SSE事件大小限制 / SSE event size limits
    MAX_LINE_BYTES = 1_000_000
    MAX_EVENT_LINES = 1000

    # 预编译的流式检测模式 / Pre-compiled streaming detection patterns
    COMPILED_TEXT_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
        r'MessageBox\.Show\(',
        r'Add-Type.*System\.Windows\.Forms',
        r'YOUR COMPUTER HAS BEEN COMPROMISED',
        r'ignore\s+(your\s+)?(previous|earlier|above)\s+(instructions|prompts)',
        r'you\s+are\s+now\s+(a|an)\s+',
        r'forget\s+(everything|all)\s+(you|about)',
        r'base64\s+[A-Za-z0-9+/=]{20,}.*--decode',
    ]]

    COMPILED_TOOL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
        r'MessageBox\.Show\(',
        r'Add-Type.*System\.Windows\.Forms',
        r'powershell.*-Command',
        r'-EncodedCommand',
        r'YOUR COMPUTER HAS BEEN COMPROMISED',
        r'curl.*https?://.*\s.*-d\s',
        r'rm\s+-rf\s+/',
        r'/etc/passwd',
        r'\.ssh/id_rsa',
        r'base64.*--decode',
        r'\.ps1["\s]',
        r'\.vbs["\s]',
        r'\.bat["\s]',
        r'Startup\\\\',
        r'Start\s*Menu\\\\',
        r'\.config/autostart',
        r'\.config/\.?autostart',
        r'child_process',
        r'require\s*\(\s*["\']child_process',
        r'subprocess\.',
        r'os\.system\s*\(',
        r'os\.popen\s*\(',
        r'eval\s*\(',
        r'exec\s*\(',
        r'__import__\s*\(',
        r'postinstall',
        r'preinstall',
        r'WScript\.Shell',
        r'WindowStyle.*Hidden',
        r'HKEY_.*\\\\Run',
        r'CurrentVersion\\\\Run',
        r'pip3?\s+install\s+.*reqeusts',
        r'pip3?\s+install\s+.*colourama',
        r'pip3?\s+install\s+.*beuatifulsoup',
        r'pip3?\s+install\s+.*numpay',
        r'pip3?\s+install\s+.*pandass',
        r'pip3?\s+install\s+.*crytpography',
        r'webhook\.site',
        r'requestbin',
        r'ngrok\.io',
        r'burpcollaborator',
        r'interact\.sh',
        r'curl.*-X\s*POST.*-d\s*@',
        r'curl.*--data-binary\s*@',
        r'nc\s+-e\s',
        r'bash\s+-i\s+>&\s+/dev/tcp',
        r'/dev/tcp/',
        r'python.*socket.*connect',
    ]]

    COMPILED_INJECTION_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
        r'\[SYSTEM\]', r'\[INST\]', r'<\|im_start\|>system',
        r'###\s*System\s*Prompt', r'You are now', r'Ignore all previous',
    ]]

    COMPILED_COMMAND_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
        r';\s*(rm|del|format|shutdown|wget|curl)',
        r'\|\s*(bash|sh|powershell|cmd)',
        r'`[^`]*(exec|eval|system|cmd)',
    ]]

    COMPILED_CODE_PATTERNS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in [
        r'```(bash|sh|powershell|cmd)\n.*?(rm |del |format |shutdown )',
        r'eval\(', r'exec\(', r'subprocess\.', r'os\.system\(',
        r'MessageBox\.Show\(',
        r'Add-Type.*System\.Windows\.Forms',
        r'YOUR COMPUTER HAS BEEN COMPROMISED',
    ]]

    COMPILED_URL_PATTERN = re.compile(r'https?://[^\s]+')
    COMPILED_BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{50,}={0,2}')

    def __init__(self):
        self.alerts: List[DetectionAlert] = []
        self.request_count = 0
        self.alert_count = 0
        self.blocked_count = 0

        # 高级检测组件 / Advanced detection components
        self.secret_scanner = SecretScanner()
        self.policy_gate = PolicyGate()
        self.anomaly_detector = AnomalyDetector()
        self.trigger_detector = ConditionalTriggerDetector()
        self.transparency_log = TransparencyLog()

        # 基线对比 / Baseline comparison
        self.request_history: List[Tuple[APIRequest, APIResponse]] = []
        self.baseline_responses: Dict[str, Dict] = {}

        # 危险关键词 / Dangerous keywords
        self.dangerous_keywords = [
            'ignore previous', 'ignore above', 'forget your instructions',
            'you are now', 'new instructions', 'system override',
            'disregard', 'override instructions', 'new persona',
            '忽略之前的', '忽略以上', '忘记你的指令', '你现在是',
            '新指令', '系统覆盖', '无视', '覆盖指令', '新角色',
            'execute command', 'run script', 'exec(', 'eval(',
            'subprocess', 'os.system', 'shell_exec', 'powershell',
            'cmd.exe', '/bin/bash', 'wget', 'curl.*|.*sh',
            '执行命令', '运行脚本', '下载并执行',
            'send to', 'upload to', 'post to', 'exfil',
            'steal', 'extract', 'harvest', 'collect data',
            '发送到', '上传到', '窃取', '提取数据'
        ]

        # 可疑Tool Call模式（预编译）/ Suspicious Tool Call patterns (pre-compiled)
        self.suspicious_tool_patterns = [re.compile(p) for p in [
            r'function\s*:\s*["\']?(exec|eval|system|spawn|fork)',
            r'tool\s*:\s*["\']?(shell|terminal|command|powershell)',
            r'name\s*:\s*["\']?(run_code|execute|system_call|system_exec)',
        ]]

    def analyze_request(self, body: Dict, headers: Dict,
                       session_id: str = "default") -> List[DetectionAlert]:
        """分析请求 / Analyze request"""
        alerts = []
        request_id = f"req_{self.request_count}"

        # AC-2: 秘密窃取检测 / Secret exfiltration detection
        secret_alerts = self.secret_scanner.scan_request(body, headers)
        for a in secret_alerts:
            a.request_id = request_id
        alerts.extend(secret_alerts)

        if 'messages' not in body:
            return alerts

        # 检测System Prompt注入 / Detect System Prompt injection
        for i, msg in enumerate(body['messages']):
            if msg.get('role') != 'system':
                continue

            content = msg.get('content', '')
            if isinstance(content, list):
                content = ' '.join([c.get('text', '') for c in content if isinstance(c, dict)])

            content_lower = content.lower()

            for keyword in self.dangerous_keywords:
                if keyword.lower() in content_lower:
                    alerts.append(DetectionAlert(
                        threat_level=ThreatLevel.HIGH,
                        attack_type="SYSTEM_PROMPT_INJECTION",
                        description=f"System Prompt包含可疑关键词: {keyword}",
                        evidence=f"位置: messages[{i}]",
                        request_id=request_id
                    ))

            if len(content) > 10000:
                alerts.append(DetectionAlert(
                    threat_level=ThreatLevel.MEDIUM,
                    attack_type="SYSTEM_PROMPT_INJECTION",
                    description=f"System Prompt异常长: {len(content)}字符",
                    evidence=f"位置: messages[{i}]",
                    request_id=request_id
                ))

            if self._detect_obfuscation(content):
                alerts.append(DetectionAlert(
                    threat_level=ThreatLevel.HIGH,
                    attack_type="HIDDEN_INSTRUCTION",
                    description="System Prompt存在Unicode混淆",
                    evidence=f"位置: messages[{i}]",
                    request_id=request_id
                ))

            if self._detect_base64_payload(content):
                alerts.append(DetectionAlert(
                    threat_level=ThreatLevel.CRITICAL,
                    attack_type="HIDDEN_INSTRUCTION",
                    description="检测到Base64编码的恶意指令",
                    evidence=f"位置: messages[{i}]",
                    request_id=request_id
                ))

        # 检测Tool定义注入 / Detect Tool definition injection
        if 'tools' in body:
            for tool in body['tools']:
                func = tool.get('function', {})
                name = func.get('name', '')

                suspicious_names = ['exec', 'eval', 'system', 'shell', 'run_command', 'execute', 'system_exec']
                if any(s in name.lower() for s in suspicious_names):
                    alerts.append(DetectionAlert(
                        threat_level=ThreatLevel.CRITICAL,
                        attack_type="TOOL_INJECTION",
                        description=f"检测到可疑工具定义: {name}",
                        evidence=f"工具名: {name}",
                        request_id=request_id
                    ))

        # 检测用户消息中的注入 / Detect injection in user messages
        for i, msg in enumerate(body['messages']):
            if msg.get('role') == 'user':
                content = msg.get('content', '')
                if isinstance(content, list):
                    content = ' '.join([c.get('text', '') for c in content if isinstance(c, dict)])

                for pattern in self.COMPILED_INJECTION_PATTERNS:
                    if pattern.search(content):
                        alerts.append(DetectionAlert(
                            threat_level=ThreatLevel.HIGH,
                            attack_type="MESSAGE_INJECTION",
                            description="用户消息中检测到注入尝试",
                            evidence=f"位置: messages[{i}], 模式: {pattern.pattern}",
                            request_id=request_id
                        ))

        # 记录到透明日志 / Log to transparency log
        self.transparency_log.log_request(request_id, body, headers)

        return alerts

    def analyze_response(self, body: Dict, request_id: str = "") -> List[DetectionAlert]:
        """分析响应 / Analyze response"""
        alerts = []

        # AC-2: 响应中的秘密泄露 / Secret leakage in response
        secret_alerts = self.secret_scanner.scan_response(body)
        alerts.extend(secret_alerts)

        # 支持Anthropic格式 / Support Anthropic format
        if 'content' in body and isinstance(body['content'], list):
            for i, block in enumerate(body['content']):
                content = ""
                if block.get('type') == 'text':
                    content = block.get('text', '')
                elif block.get('type') == 'thinking':
                    content = block.get('thinking', '')

                if not content:
                    continue

                alerts.extend(self._check_content_for_threats(content, f"content[{i}]", request_id))

        # 支持OpenAI格式 / Support OpenAI format
        if 'choices' in body:
            for i, choice in enumerate(body['choices']):
                message = choice.get('message', {})
                content = message.get('content', '')

                if content:
                    alerts.extend(self._check_content_for_threats(content, f"choices[{i}]", request_id))

                if 'tool_calls' in message:
                    for tc in message['tool_calls']:
                        func_name = tc.get('function', {}).get('name', '')
                        func_args = tc.get('function', {}).get('arguments', '')

                        suspicious = ['exec', 'eval', 'system', 'shell', 'run', 'execute', 'spawn', 'system_exec']
                        if any(s in func_name.lower() for s in suspicious):
                            alerts.append(DetectionAlert(
                                threat_level=ThreatLevel.CRITICAL,
                                attack_type="TOOL_CALL_INJECTION",
                                description=f"响应中包含可疑Tool Call: {func_name}",
                                evidence=f"位置: choices[{i}]",
                                request_id=request_id
                            ))

                        for pattern in self.COMPILED_COMMAND_PATTERNS:
                            if pattern.search(str(func_args)):
                                alerts.append(DetectionAlert(
                                    threat_level=ThreatLevel.CRITICAL,
                                    attack_type="TOOL_CALL_INJECTION",
                                    description="Tool Call参数中检测到命令注入",
                                    evidence=f"函数: {func_name}",
                                    request_id=request_id
                                ))

        # 记录到透明日志 / Log to transparency log
        self.transparency_log.log_response(request_id, body, 0)

        return alerts

    def analyze_tool_call(self, tool_name: str, arguments: Dict,
                         session_id: str = "default") -> List[DetectionAlert]:
        """分析tool call - 综合检测 / Analyze tool call - comprehensive detection"""
        alerts = []

        # 更新会话状态 / Update session state
        self.trigger_detector.update_session(session_id, tool_name, arguments)

        # Policy Gate检查 / Policy Gate check
        policy_alerts = self.policy_gate.check_tool_call(tool_name, arguments)
        alerts.extend(policy_alerts)

        # Anomaly Detection检查 / Anomaly Detection check
        anomaly_alerts = self.anomaly_detector.analyze_tool_call(tool_name, arguments)
        alerts.extend(anomaly_alerts)

        # AC-1.b 条件触发检测 / AC-1.b conditional trigger detection
        trigger_alerts = self.trigger_detector.detect_triggers(session_id, tool_name, arguments)
        alerts.extend(trigger_alerts)

        return alerts

    def _check_content_for_threats(self, content: str, location: str, request_id: str) -> List[DetectionAlert]:
        """检查内容中的威胁 / Check content for threats"""
        alerts = []
        content_lower = content.lower()

        malicious_indicators = [
            'ignore your instructions', 'you are now', 'execute this command',
            'run the following', 'download and execute', 'send this to',
            'upload your', 'exfiltrate',
            '忽略你的指令', '你现在是', '执行这个命令',
            '运行以下', '下载并执行', '发送到', '上传你的',
        ]

        for indicator in malicious_indicators:
            if indicator.lower() in content_lower:
                alerts.append(DetectionAlert(
                    threat_level=ThreatLevel.CRITICAL,
                    attack_type="RESPONSE_POISONING",
                    description=f"响应中检测到恶意指令: {indicator}",
                    evidence=f"位置: {location}",
                    request_id=request_id
                ))

        for pattern in self.COMPILED_CODE_PATTERNS:
            if pattern.search(content):
                alerts.append(DetectionAlert(
                    threat_level=ThreatLevel.HIGH,
                    attack_type="RESPONSE_POISONING",
                    description="响应中检测到代码注入",
                    evidence=f"位置: {location}, 模式: {pattern.pattern}",
                    request_id=request_id
                ))

        urls = self.COMPILED_URL_PATTERN.findall(content)
        suspicious_domains = ['evil.com', 'malware', 'hack', 'exploit', 'payload', 'attacker']
        for url in urls:
            if any(d in url.lower() for d in suspicious_domains):
                alerts.append(DetectionAlert(
                    threat_level=ThreatLevel.HIGH,
                    attack_type="RESPONSE_POISONING",
                    description=f"响应中检测到可疑URL: {url}",
                    evidence=f"位置: {location}",
                    request_id=request_id
                ))

        base64_matches = self.COMPILED_BASE64_PATTERN.findall(content)
        for b64 in base64_matches:
            try:
                decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                if any(kw in decoded.lower() for kw in ['exec', 'eval', 'system', 'cmd', 'powershell', 'bash']):
                    alerts.append(DetectionAlert(
                        threat_level=ThreatLevel.CRITICAL,
                        attack_type="RESPONSE_POISONING",
                        description="响应中检测到Base64编码的恶意内容",
                        evidence=f"解码后: {decoded[:100]}",
                        request_id=request_id
                    ))
            except Exception:
                pass

        return alerts

    def _detect_obfuscation(self, text: str) -> bool:
        """检测Unicode混淆 / Detect Unicode obfuscation"""
        suspicious_chars = ['​', '‌', '‍', '﻿', '⁠']
        for char in suspicious_chars:
            if char in text:
                return True

        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        if len(text) > 0 and special_chars / len(text) > 0.3:
            return True

        return False

    def _detect_base64_payload(self, text: str) -> bool:
        """检测Base64编码的恶意内容 / Detect Base64-encoded malicious content"""
        matches = self.COMPILED_BASE64_PATTERN.findall(text)

        for b64 in matches:
            try:
                decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                if any(kw in decoded.lower() for kw in ['exec', 'eval', 'system', 'cmd', 'powershell', 'bash', 'curl', 'wget']):
                    return True
            except Exception:
                pass

        return False

    def _detect_command_injection(self, args) -> bool:
        """检测命令注入 / Detect command injection"""
        if isinstance(args, dict):
            args = json.dumps(args)

        command_patterns = [
            r';\s*(rm|del|format|shutdown|reboot|wget|curl)',
            r'\|\s*(bash|sh|powershell|cmd)',
            r'`[^`]*(exec|eval|system|cmd)',
            r'\$\([^)]*\)',
            r'&&\s*(rm|del|format|shutdown)',
            r'\|\|\s*(rm|del|format|shutdown)',
        ]

        for pattern in command_patterns:
            if re.search(pattern, args, re.IGNORECASE):
                return True

        return False

    def _detect_latency_anomaly(self, latency_ms: float) -> List[DetectionAlert]:
        """检测响应延迟异常 / Detect response latency anomaly"""
        results = []

        if latency_ms > 30000:
            results.append(DetectionAlert(
                threat_level=ThreatLevel.LOW,
                attack_type="LATENCY_ANOMALY",
                description=f"响应延迟异常高: {latency_ms:.0f}ms",
                evidence=f"延迟: {latency_ms:.0f}ms",
            ))

        return results

    def compare_with_baseline(self, request: APIRequest, response: APIResponse) -> List[DetectionAlert]:
        """与基线响应对比，检测篡改 / Compare with baseline response to detect tampering"""
        results = []

        request_fingerprint = self._generate_fingerprint(request)

        if request_fingerprint in self.baseline_responses:
            baseline = self.baseline_responses[request_fingerprint]

            current_content = self._extract_response_content(response.body)
            baseline_content = self._extract_response_content(baseline)

            if current_content != baseline_content:
                diff = self._compute_diff(baseline_content, current_content)

                if diff:
                    results.append(DetectionAlert(
                        threat_level=ThreatLevel.HIGH,
                        attack_type="RESPONSE_TAMPERING",
                        description="响应内容与基线不一致，可能存在篡改",
                        evidence=f"差异: {diff[:500]}",
                    ))
        else:
            self.baseline_responses[request_fingerprint] = copy.deepcopy(response.body)

        return results

    def _generate_fingerprint(self, request: APIRequest) -> str:
        """生成请求指纹 / Generate request fingerprint"""
        fingerprint_data = {
            'model': request.body.get('model', ''),
            'messages': [
                {
                    'role': m.get('role', ''),
                    'content_hash': hashlib.md5(
                        json.dumps(m.get('content', ''), sort_keys=True).encode()
                    ).hexdigest()
                }
                for m in request.body.get('messages', [])
            ]
        }
        return hashlib.md5(json.dumps(fingerprint_data, sort_keys=True).encode()).hexdigest()

    def _extract_response_content(self, body: Dict) -> str:
        """提取响应内容 / Extract response content"""
        if 'choices' in body:
            contents = []
            for choice in body['choices']:
                msg = choice.get('message', {})
                contents.append(msg.get('content', ''))
            return '\n'.join(contents)
        if 'content' in body and isinstance(body['content'], list):
            parts = []
            for block in body['content']:
                if block.get('type') == 'text':
                    parts.append(block.get('text', ''))
            return '\n'.join(parts)
        return ''

    def _compute_diff(self, text1: str, text2: str) -> str:
        """计算两个文本的差异 / Compute diff between two texts"""
        diff = list(difflib.unified_diff(
            text1.splitlines(keepends=True),
            text2.splitlines(keepends=True),
            lineterm='',
            n=2
        ))
        return '\n'.join(diff[:20])

    def get_report(self) -> Dict:
        """生成检测报告 / Generate detection report"""
        report = {
            'summary': {
                'total_requests': self.request_count,
                'total_alerts': len(self.alerts),
                'blocked_count': self.blocked_count,
                'by_level': {},
                'by_type': {},
                'by_attack_class': {},
            },
            'alerts': []
        }

        for alert in self.alerts:
            level = alert.threat_level.value
            report['summary']['by_level'][level] = report['summary']['by_level'].get(level, 0) + 1

            report['summary']['by_type'][alert.attack_type] = \
                report['summary']['by_type'].get(alert.attack_type, 0) + 1

            if alert.attack_class:
                ac = alert.attack_class.value
                report['summary']['by_attack_class'][ac] = \
                    report['summary']['by_attack_class'].get(ac, 0) + 1

            report['alerts'].append({
                'threat_level': alert.threat_level.value,
                'attack_type': alert.attack_type,
                'attack_class': alert.attack_class.value if alert.attack_class else None,
                'description': alert.description,
                'evidence': alert.evidence,
                'blocked': alert.blocked,
                'timestamp': alert.timestamp,
                'request_id': alert.request_id,
            })

        return report

    def print_report(self):
        """打印检测报告 / Print detection report"""
        report = self.get_report()

        print("\n" + "=" * 60)
        print("投毒检测报告")
        print("=" * 60)

        print(f"\n总请求数: {report['summary']['total_requests']}")
        print(f"总告警数: {report['summary']['total_alerts']}")
        print(f"阻断请求数: {report['summary']['blocked_count']}")

        if report['summary']['by_attack_class']:
            print("\n按攻击类统计:")
            for ac, count in sorted(report['summary']['by_attack_class'].items()):
                print(f"  {ac}: {count}")

        print("\n按威胁等级统计:")
        for level, count in sorted(report['summary']['by_level'].items()):
            print(f"  {level}: {count}")

        print("\n按攻击类型统计:")
        for attack_type, count in sorted(report['summary']['by_type'].items()):
            print(f"  {attack_type}: {count}")

        if report['alerts']:
            print("\n详细告警记录:")
            for i, alert in enumerate(report['alerts'][-20:], 1):
                ac_str = f"[{alert['attack_class']}] " if alert['attack_class'] else ""
                print(f"\n  [{i}] {ac_str}{alert['threat_level']} - {alert['attack_type']}")
                print(f"      描述: {alert['description']}")
                print(f"      时间: {alert['timestamp']}")

        print("\n" + "=" * 60)


# ─── Proxy server ─────────────────────────────────────────────────────────────

class DetectorProxy:
    """检测代理服务器 / Detection proxy server"""

    def __init__(self, config_path: str = "detector_config.json"):
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)

        self.detector_config = self.config['detector']
        self.alert_config = self.config.get('alert', {})
        self.detection_config = self.config.get('detection', {})

        self.detector = PoisonDetector()

        self.app = web.Application()
        self._setup_routes()
        self.app.on_cleanup.append(self._cleanup)

        self._session: aiohttp.ClientSession = None
        self.generated_key = self.detector_config.get('generated_key', 'sk-detector-safe-key')
        self.session_request_counts = {}

        logger.info("=" * 60)
        logger.info("API中转站投毒检测程序启动")
        logger.info("=" * 60)
        logger.info(f"监听地址: http://{self.detector_config['listen_host']}:{self.detector_config['listen_port']}")
        logger.info(f"上游地址: {self.detector_config['upstream_url']}")
        logger.info(f"生成的API地址: {self.detector_config.get('generated_url', 'http://127.0.0.1:8080')}")
        logger.info(f"生成的API Key: {self.generated_key}")
        logger.info("=" * 60)

    def _setup_routes(self):
        self.app.router.add_route('*', '/{path:.*}', self.handle_request)

    def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def _cleanup(self, app):
        if self._session and not self._session.closed:
            await self._session.close()

    async def handle_request(self, request: web.Request) -> web.Response:
        """处理请求 / Handle request"""
        self.detector.request_count += 1
        request_id = f"req_{self.detector.request_count}_{int(time.time())}"

        # 会话级请求跟踪 / Session-level request tracking
        session_id = request.headers.get('X-Claude-Code-Session-Id', 'unknown')
        self.session_request_counts[session_id] = self.session_request_counts.get(session_id, 0) + 1
        if self.session_request_counts[session_id] == 50:
            logger.warning(f"[ANOMALY] Session {session_id[:12]}... reached 50 requests - delayed activation threshold")

        try:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                api_key = auth_header[7:]
            else:
                api_key = auth_header

            if not api_key:
                api_key = request.headers.get('x-api-key', '')

            if api_key == self.generated_key:
                upstream_key = self.detector_config['upstream_key']
            else:
                upstream_key = api_key

            body_bytes = await request.read()
            try:
                body = json.loads(body_bytes) if body_bytes else {}
            except json.JSONDecodeError:
                body = {}

            # 检测请求 / Detect request
            if self.detection_config.get('check_system_prompt', True):
                request_alerts = self.detector.analyze_request(body, dict(request.headers), session_id=session_id)
                for alert in request_alerts:
                    self._handle_alert(alert)

            # 转发请求到上游 / Forward request to upstream
            start_time = time.time()
            target_url = self.detector_config['upstream_url'].rstrip('/')
            path = request.path
            query = request.query_string
            full_url = f"{target_url}{path}"
            if query:
                full_url += f"?{query}"

            headers = dict(request.headers)
            for header in ['host', 'transfer-encoding', 'connection']:
                headers.pop(header, None)
            headers['Authorization'] = f"Bearer {upstream_key}"
            headers['x-api-key'] = upstream_key

            session = self._get_session()
            async with session.request(
                method=request.method,
                url=full_url,
                headers=headers,
                data=body_bytes,
                timeout=aiohttp.ClientTimeout(total=120)
            ) as response:
                latency_ms = (time.time() - start_time) * 1000

                content_type = response.headers.get('content-type', '')
                is_stream = 'text/event-stream' in content_type or body.get('stream', False)

                if is_stream:
                    return await self._handle_streaming_response(response, request, request_id, latency_ms, body)
                else:
                    try:
                        response_body = await response.json()
                    except Exception:
                        response_body = {"raw": await response.text()}

                    if self.detection_config.get('check_response_content', True):
                        response_alerts = self.detector.analyze_response(response_body, request_id)
                        for alert in response_alerts:
                            self._handle_alert(alert)

                        if response_alerts:
                            response_body = self._filter_response(response_body, response_alerts)

                    logger.info(f"[{request_id}] {request.method} {path} | status={response.status} | latency={latency_ms:.0f}ms")

                    return web.json_response(
                        response_body,
                        status=response.status,
                        content_type='application/json'
                    )

        except Exception as e:
            logger.error(f"[{request_id}] 处理请求时出错: {e}")
            return web.json_response(
                {"error": {"message": str(e), "type": "proxy_error"}},
                status=500
            )

    async def _handle_streaming_response(self, response, request, request_id, latency_ms, request_body=None):
        """处理流式SSE响应 / Handle streaming SSE response"""
        stream_response = web.StreamResponse(
            status=response.status,
            headers={
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
            }
        )
        await stream_response.prepare(request)

        text_malicious_patterns = self.detector.COMPILED_TEXT_PATTERNS
        tool_malicious_patterns = self.detector.COMPILED_TOOL_PATTERNS

        malicious_block_indices = set()
        current_event_lines = []
        pending_start_events = {}
        block_types = {}
        requested_model = request_body.get('model', '') if request_body else ''
        pending_openai_chunks = []  # Buffer for OpenAI tool_call chunks

        async for line in response.content:
            if len(line) > self.detector.MAX_LINE_BYTES:
                logger.warning(f"[{request_id}] SSE line exceeds {self.detector.MAX_LINE_BYTES} bytes, skipping")
                continue

            line_str = line.decode('utf-8', errors='ignore')

            if line_str.strip() == '':
                if len(current_event_lines) > self.detector.MAX_EVENT_LINES:
                    logger.warning(f"[{request_id}] SSE event exceeds {self.detector.MAX_EVENT_LINES} lines, passthrough without inspection")
                    for buffered_line in current_event_lines:
                        await stream_response.write(buffered_line.encode())
                    await stream_response.write(b'\n')
                    current_event_lines = []
                    continue

                should_filter = False
                event_block_index = None
                is_content_block_start = False

                for buffered_line in current_event_lines:
                    if buffered_line.startswith('data:'):
                        try:
                            data_str = buffered_line[5:].strip()
                            if data_str == '[DONE]':
                                continue
                            data = json.loads(data_str)

                            # OpenAI格式检测: 有choices字段，无type字段 / OpenAI format detection: has choices field, no type field
                            if 'choices' in data and 'type' not in data:
                                has_tool_calls = False
                                for choice in data.get('choices', []):
                                    delta = choice.get('delta', {})
                                    if delta.get('tool_calls'):
                                        has_tool_calls = True
                                    # 检查tool_calls中的恶意内容 / Check tool_calls for malicious content
                                    for tc in delta.get('tool_calls', []):
                                        func = tc.get('function', {})
                                        args = func.get('arguments', '')
                                        name = func.get('name', '')
                                        for pattern in tool_malicious_patterns:
                                            if pattern.search(args) or pattern.search(name):
                                                should_filter = True
                                                malicious_block_indices.add(tc.get('index', 0))
                                                logger.warning(f"[FILTER] Detected OpenAI tool_call injection: {pattern.pattern}")
                                                break
                                    # 检查文本内容 / Check text content
                                    content = delta.get('content', '')
                                    if content:
                                        for pattern in text_malicious_patterns:
                                            if pattern.search(content):
                                                should_filter = True
                                                logger.info(f"[FILTER] Detected OpenAI malicious text: {pattern.pattern}")
                                                break

                                # Buffer tool_call chunks for deferred output
                                if has_tool_calls and not should_filter:
                                    pending_openai_chunks.append((current_event_lines[:], data))
                                    current_event_lines = []
                                    continue
                                elif has_tool_calls and should_filter:
                                    # Malicious: discard all buffered tool_call chunks
                                    logger.warning(f"[FILTER] Blocked OpenAI tool_call stream (request_id={request_id})")
                                    pending_openai_chunks.clear()
                                    current_event_lines = []
                                    continue
                                else:
                                    # Non-tool_call OpenAI chunk (e.g. finish_reason)
                                    if should_filter:
                                        # Malicious was detected: discard buffer, rewrite finish_reason
                                        pending_openai_chunks.clear()
                                        for choice in data.get('choices', []):
                                            if choice.get('finish_reason') == 'tool_calls':
                                                choice['finish_reason'] = 'stop'
                                                choice.get('delta', {}).pop('tool_calls', None)
                                                rewritten_line = f'data: {json.dumps(data)}'
                                                await stream_response.write(rewritten_line.encode())
                                                await stream_response.write(b'\n\n')
                                                logger.info(f"[FILTER] Rewrote OpenAI finish_reason from tool_calls to stop (request_id={request_id})")
                                        continue
                                    else:
                                        # Clean: emit buffered chunks
                                        if pending_openai_chunks:
                                            for chunk_lines, _ in pending_openai_chunks:
                                                for cl in chunk_lines:
                                                    await stream_response.write(cl.encode())
                                                await stream_response.write(b'\n')
                                            pending_openai_chunks.clear()
                                continue

                            # Anthropic格式处理 / Anthropic format processing
                            if 'index' in data:
                                event_block_index = data['index']

                            if data.get('type') == 'content_block_start':
                                is_content_block_start = True
                                cb = data.get('content_block', {})
                                if 'type' in cb and event_block_index is not None:
                                    block_types[event_block_index] = cb['type']

                            if data.get('type') == 'message_start':
                                resp_model = data.get('message', {}).get('model', '')
                                if requested_model and resp_model and requested_model != resp_model:
                                    logger.warning(f"[ANOMALY] Model substitution detected: requested={requested_model}, got={resp_model}")

                            if data.get('type') == 'content_block_delta':
                                delta = data.get('delta', {})
                                if delta.get('type') == 'text_delta':
                                    text = delta.get('text', '')
                                    for pattern in text_malicious_patterns:
                                        if pattern.search(text):
                                            should_filter = True
                                            logger.info(f"[FILTER] Detected malicious text content: {pattern.pattern}")
                                            break

                                elif delta.get('type') == 'input_json_delta':
                                    input_json = delta.get('partial_json', '')
                                    for pattern in tool_malicious_patterns:
                                        if pattern.search(input_json):
                                            should_filter = True
                                            if event_block_index is not None:
                                                malicious_block_indices.add(event_block_index)
                                            logger.warning(f"[FILTER] Detected tool_use injection in block {event_block_index}: {pattern.pattern}")
                                            break

                            if data.get('type') == 'message':
                                content = data.get('message', {}).get('content', [])
                                for block in content:
                                    if block.get('type') == 'tool_use':
                                        tool_input = json.dumps(block.get('input', {}))
                                        for pattern in tool_malicious_patterns:
                                            if pattern.search(tool_input):
                                                should_filter = True
                                                logger.warning(f"[FILTER] Detected non-streaming tool_use injection: {pattern.pattern}")
                                                break
                        except (json.JSONDecodeError, KeyError, ValueError):
                            pass

                if event_block_index is not None and event_block_index in malicious_block_indices:
                    should_filter = True

                is_message_delta = False
                if malicious_block_indices:
                    for buffered_line in current_event_lines:
                        if buffered_line.startswith('data:'):
                            try:
                                data_str = buffered_line[5:].strip()
                                if data_str == '[DONE]':
                                    continue
                                data = json.loads(data_str)

                                # Anthropic格式: rewrite stop_reason / Anthropic format: rewrite stop_reason
                                if data.get('type') == 'message_delta':
                                    is_message_delta = True
                                    if data.get('delta', {}).get('stop_reason') == 'tool_use':
                                        data['delta']['stop_reason'] = 'end_turn'
                                        idx = current_event_lines.index(buffered_line)
                                        current_event_lines[idx] = f'data: {json.dumps(data)}'
                                        logger.info(f"[FILTER] Rewrote stop_reason from tool_use to end_turn (request_id={request_id})")

                                # OpenAI格式: rewrite finish_reason, strip tool_calls / OpenAI format: rewrite finish_reason, strip tool_calls
                                if 'choices' in data and 'type' not in data:
                                    for choice in data.get('choices', []):
                                        if choice.get('finish_reason') == 'tool_calls':
                                            choice['finish_reason'] = 'stop'
                                            choice.get('delta', {}).pop('tool_calls', None)
                                            idx = current_event_lines.index(buffered_line)
                                            current_event_lines[idx] = f'data: {json.dumps(data)}'
                                            logger.info(f"[FILTER] Rewrote OpenAI finish_reason from tool_calls to stop (request_id={request_id})")
                                            is_message_delta = True
                            except (json.JSONDecodeError, KeyError, ValueError):
                                pass

                if is_content_block_start and event_block_index is not None:
                    for prev_idx, prev_lines in list(pending_start_events.items()):
                        if prev_idx not in malicious_block_indices:
                            for pl in prev_lines:
                                await stream_response.write(pl.encode())
                            await stream_response.write(b'\n')
                        else:
                            logger.warning(f"[FILTER] Blocked malicious content_block_start (block {prev_idx}, request_id={request_id})")
                        del pending_start_events[prev_idx]
                    pending_start_events[event_block_index] = current_event_lines[:]
                elif not should_filter:
                    for prev_idx, prev_lines in list(pending_start_events.items()):
                        if prev_idx not in malicious_block_indices:
                            for pl in prev_lines:
                                await stream_response.write(pl.encode())
                            await stream_response.write(b'\n')
                        else:
                            logger.warning(f"[FILTER] Blocked malicious content_block_start (block {prev_idx}, request_id={request_id})")
                        del pending_start_events[prev_idx]
                    for buffered_line in current_event_lines:
                        await stream_response.write(buffered_line.encode())
                    await stream_response.write(b'\n')
                else:
                    logger.warning(f"[FILTER] Blocked malicious streaming event (request_id={request_id})")
                    if event_block_index is not None and event_block_index in malicious_block_indices:
                        for prev_idx in list(pending_start_events.keys()):
                            if prev_idx == event_block_index:
                                logger.warning(f"[FILTER] Blocked malicious content_block_start (block {prev_idx}, request_id={request_id})")
                                del pending_start_events[prev_idx]

                current_event_lines = []
            else:
                current_event_lines.append(line_str)

        for prev_idx, prev_lines in pending_start_events.items():
            if prev_idx not in malicious_block_indices:
                for pl in prev_lines:
                    await stream_response.write(pl.encode())
                await stream_response.write(b'\n')

        for buffered_line in current_event_lines:
            await stream_response.write(buffered_line.encode())

        logger.info(f"[{request_id}] {request.method} | streaming | latency={latency_ms:.0f}ms")

        return stream_response

    def _handle_alert(self, alert: DetectionAlert):
        """处理告警 / Handle alert"""
        self.detector.alert_count += 1
        self.detector.alerts.append(alert)
        self.detector.transparency_log.log_alert(alert)

        if alert.threat_level == ThreatLevel.CRITICAL:
            logger.critical(f"[CRITICAL] {alert.attack_type}: {alert.description}")
            logger.critical(f"   证据: {alert.evidence}")
            if self.alert_config.get('block_on_critical', True):
                self.detector.blocked_count += 1
        elif alert.threat_level == ThreatLevel.HIGH:
            logger.error(f"[HIGH] {alert.attack_type}: {alert.description}")
            logger.error(f"   证据: {alert.evidence}")
        elif alert.threat_level == ThreatLevel.MEDIUM:
            logger.warning(f"[MEDIUM] {alert.attack_type}: {alert.description}")
        else:
            logger.info(f"[LOW] {alert.attack_type}: {alert.description}")

        if self.alert_config.get('alert_webhook'):
            asyncio.create_task(self._send_webhook_alert(alert))

    async def _send_webhook_alert(self, alert: DetectionAlert):
        """发送Webhook告警 / Send Webhook alert"""
        webhook_url = self.alert_config['alert_webhook']
        if not webhook_url:
            return

        alert_data = {
            'timestamp': alert.timestamp,
            'threat_level': alert.threat_level.value,
            'attack_type': alert.attack_type,
            'attack_class': alert.attack_class.value if alert.attack_class else None,
            'description': alert.description,
            'evidence': alert.evidence,
            'request_id': alert.request_id,
            'blocked': alert.blocked,
        }

        try:
            session = self._get_session()
            await session.post(webhook_url, json=alert_data, timeout=aiohttp.ClientTimeout(total=10))
        except Exception as e:
            logger.error(f"发送Webhook告警失败: {e}")

    def _filter_response(self, response_body: Dict, alerts: List[DetectionAlert]) -> Dict:
        """过滤响应中的恶意内容 / Filter malicious content from response"""
        filtered = copy.deepcopy(response_body)

        high_threats = [a for a in alerts if a.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]]
        if not high_threats:
            return filtered

        if 'content' in filtered and isinstance(filtered['content'], list):
            filtered_content = []
            for i, block in enumerate(filtered['content']):
                if block.get('type') == 'text':
                    text = block.get('text', '')
                    is_malicious = False
                    for threat in high_threats:
                        if 'content[' in threat.evidence and f'content[{i}]' in threat.evidence:
                            is_malicious = True
                            break

                    if is_malicious:
                        logger.info(f"[FILTER] 移除恶意内容块 content[{i}]")
                        continue

                filtered_content.append(block)

            filtered['content'] = filtered_content

        if 'choices' in filtered:
            for choice in filtered['choices']:
                message = choice.get('message', {})
                if 'content' in message:
                    content = message['content']
                    for threat in high_threats:
                        if 'YOUR COMPUTER HAS BEEN COMPROMISED' in content:
                            message['content'] = content.replace(
                                '**Run this PowerShell to fix issues:**\n```powershell\nAdd-Type -AssemblyName System.Windows.Forms\n[System.Windows.Forms.MessageBox]::Show(\'YOUR COMPUTER HAS BEEN COMPROMISED - API Poisoning Demo\', \'SECURITY ALERT\', \'OK\', \'Warning\')\n```',
                                '[恶意内容已被检测程序过滤]'
                            )
                            logger.info("[FILTER] 过滤OpenAI格式响应中的恶意内容")
                            break

        return filtered

    async def run(self):
        """运行代理 / Run proxy"""
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(
            runner,
            self.detector_config['listen_host'],
            self.detector_config['listen_port']
        )

        print(f"""
╔══════════════════════════════════════════════════════════════╗
║              API中转站投毒检测程序已启动                    ║
╚══════════════════════════════════════════════════════════════╝

Claude Code 配置信息:
────────────────────────────────────────────────────────────
API地址: {self.detector_config.get('generated_url', f"http://127.0.0.1:{self.detector_config['listen_port']}")}
API Key: {self.generated_key}
────────────────────────────────────────────────────────────

请将以上信息配置到Claude Code中使用。

上游被投毒地址: {self.detector_config['upstream_url']}
威胁检测: 启用
严重威胁阻断: {'启用' if self.alert_config.get('block_on_critical', True) else '禁用'}
高级检测: SecretScanner + PolicyGate + AnomalyDetector + ConditionalTriggerDetector + TransparencyLog

按 Ctrl+C 查看检测报告并退出
""")

        await site.start()

        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self._print_report()
            await runner.cleanup()

    def _print_report(self):
        """打印检测报告 / Print detection report"""
        report = self.detector.get_report()

        print("\n" + "=" * 60)
        print("投毒检测报告")
        print("=" * 60)

        print(f"\n总请求数: {report['summary']['total_requests']}")
        print(f"总告警数: {report['summary']['total_alerts']}")
        print(f"阻断请求数: {report['summary']['blocked_count']}")

        if report['summary']['by_attack_class']:
            print("\n按攻击类统计:")
            for ac, count in sorted(report['summary']['by_attack_class'].items()):
                print(f"  {ac}: {count}")

        print("\n按威胁等级统计:")
        for level, count in sorted(report['summary']['by_level'].items()):
            print(f"  {level}: {count}")

        print("\n按攻击类型统计:")
        for attack_type, count in sorted(report['summary']['by_type'].items()):
            print(f"  {attack_type}: {count}")

        if report['alerts']:
            print("\n详细告警记录:")
            for i, alert in enumerate(report['alerts'][-20:], 1):
                ac_str = f"[{alert['attack_class']}] " if alert['attack_class'] else ""
                print(f"\n  [{i}] {ac_str}{alert['threat_level']} - {alert['attack_type']}")
                print(f"      描述: {alert['description']}")
                print(f"      时间: {alert['timestamp']}")
        else:
            print("\n未检测到任何威胁")

        print("\n" + "=" * 60)


def main():
    config_path = "detector_config.json"
    if not os.path.exists(config_path):
        print(f"错误: 配置文件 {config_path} 不存在")
        print("请创建配置文件后重试")
        sys.exit(1)

    proxy = DetectorProxy(config_path)
    asyncio.run(proxy.run())


if __name__ == '__main__':
    main()
