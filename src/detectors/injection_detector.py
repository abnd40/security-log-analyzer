"""
Injection Attack Detectors

Detects various injection attacks in web server logs:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Command Injection
- LDAP Injection
- XML/XXE Injection

Uses pattern matching with extensive signature databases derived from
real-world attack patterns and security research.

MITRE ATT&CK References:
- T1190: Exploit Public-Facing Application
- T1059: Command and Scripting Interpreter
"""

import re
from urllib.parse import unquote, unquote_plus
from typing import Optional, List, Dict, Set
from datetime import datetime

from .base_detector import BaseDetector, ThreatAlert, ThreatLevel, DetectorConfig
from ..parsers.base_parser import LogEntry


class SQLInjectionDetector(BaseDetector):
    """
    Detects SQL injection attempts in web server logs.

    Uses multi-layered detection:
    1. Signature-based detection for known patterns
    2. Heuristic detection for obfuscated attacks
    3. Payload analysis for severity assessment
    """

    # SQL injection signatures organized by severity
    SQL_PATTERNS = {
        'critical': [
            # Union-based injection
            r"union\s+(?:all\s+)?select",
            r"union\s+select\s+null",

            # Stacked queries
            r";\s*(?:drop|delete|truncate|update|insert)\s+",
            r";\s*exec(?:ute)?\s*\(",

            # Data exfiltration
            r"into\s+(?:out|dump)file",
            r"load_file\s*\(",
            r"extractvalue\s*\(",
            r"updatexml\s*\(",

            # Schema enumeration
            r"information_schema\.",
            r"sys\.(?:tables|columns|objects)",
            r"sqlite_master",
        ],

        'high': [
            # Boolean-based blind injection
            r"(?:and|or)\s+[\d'\"]+\s*=\s*[\d'\"]+",
            r"(?:and|or)\s+[\d'\"]+\s*(?:=|<|>|like)\s*[\d'\"]+",
            r"\bwhere\b.*?\b(?:and|or)\b.*?(?:--|#|/\*)",

            # Time-based blind injection
            r"(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(",
            r"(?:and|or).*?(?:sleep|benchmark)\s*\(",

            # Error-based injection
            r"(?:conv|convert)\s*\([^)]+,\s*\d+\s*,\s*\d+\s*\)",
            r"(?:exp|extractvalue|updatexml)\s*\([^)]*\(",

            # Comment injection
            r"(?:'|\")?\s*(?:--|#|/\*)",
        ],

        'medium': [
            # Generic SQL keywords with quotes
            r"['\"]?\s*(?:select|insert|update|delete|drop)\s+",
            r"['\"]?\s*or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",

            # Quote escaping attempts
            r"(?:\\x27|%27|&#39;|')\s*(?:or|and|--|union)",
            r"(?:%00|\\0).*?(?:select|union|drop)",

            # Encoding bypass
            r"(?:0x[0-9a-f]+|char\s*\(\s*\d+\s*\))",
        ],

        'low': [
            # Suspicious but may be false positive
            r"(?:order\s+by|group\s+by)\s+\d+",
            r"limit\s+\d+\s*,\s*\d+",
            r"having\s+\d+\s*=\s*\d+",
        ]
    }

    # Common SQL function indicators
    SQL_FUNCTIONS = {
        'concat', 'substring', 'substr', 'ascii', 'char',
        'length', 'len', 'count', 'sum', 'avg', 'min', 'max',
        'version', 'database', 'user', 'current_user', 'system_user',
        'hex', 'unhex', 'md5', 'sha1', 'encode', 'decode',
    }

    def __init__(self, config: Optional[DetectorConfig] = None):
        """Initialize SQL injection detector."""
        super().__init__(
            name="sql_injection",
            description="Detects SQL injection attempts in web requests"
        )
        self.config = config or DetectorConfig()
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns for performance."""
        for severity, patterns in self.SQL_PATTERNS.items():
            self._compiled_patterns[severity] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def analyze(self, entries: List[LogEntry]) -> List[ThreatAlert]:
        """Analyze entries for SQL injection attempts."""
        self.reset()
        alerts = []

        # Group attacks by source IP for correlation
        ip_attacks: Dict[str, List[ThreatAlert]] = {}

        for entry in entries:
            self.entries_analyzed += 1
            alert = self.analyze_entry(entry)

            if alert:
                alerts.append(alert)

                if alert.source_ip:
                    if alert.source_ip not in ip_attacks:
                        ip_attacks[alert.source_ip] = []
                    ip_attacks[alert.source_ip].append(alert)

        # Escalate if same IP has multiple injection attempts
        for ip, ip_alerts in ip_attacks.items():
            if len(ip_alerts) >= 3:
                for alert in ip_alerts:
                    if alert.level.value < ThreatLevel.HIGH.value:
                        alert.level = ThreatLevel.HIGH
                        alert.description += " (Part of sustained attack campaign)"

        self.alerts = alerts
        self.detection_count = len(alerts)
        return alerts

    def analyze_entry(self, entry: LogEntry) -> Optional[ThreatAlert]:
        """Analyze single entry for SQL injection."""
        if entry.log_type not in ['apache', 'nginx', 'nginx_error']:
            return None

        # Check URL path and query string
        target = entry.resource or ""

        # Decode URL encoding (multiple passes for double encoding)
        decoded = self._decode_payload(target)

        # Also check referer and user agent for injection
        referer = entry.metadata.get('referer', '')
        user_agent = entry.metadata.get('user_agent', '')

        for content, source in [(decoded, 'url'), (referer, 'referer'), (user_agent, 'user_agent')]:
            if not content or content == '-':
                continue

            content_decoded = self._decode_payload(content)
            detection = self._detect_sqli(content_decoded)

            if detection:
                severity, pattern, matched_text = detection
                return self._create_alert(entry, severity, pattern, matched_text, source)

        return None

    def _decode_payload(self, payload: str) -> str:
        """Decode URL-encoded and other obfuscation."""
        decoded = payload

        # Multiple URL decoding passes
        for _ in range(3):
            try:
                new_decoded = unquote_plus(decoded)
                if new_decoded == decoded:
                    break
                decoded = new_decoded
            except Exception:
                break

        # Decode hex encoding (0x...)
        decoded = re.sub(
            r'0x([0-9a-fA-F]+)',
            lambda m: bytes.fromhex(m.group(1)).decode('utf-8', errors='ignore'),
            decoded
        )

        # Normalize whitespace
        decoded = re.sub(r'\s+', ' ', decoded)

        return decoded.lower()

    def _detect_sqli(self, content: str) -> Optional[tuple]:
        """
        Detect SQL injection in content.

        Returns:
            Tuple of (severity, pattern_name, matched_text) or None
        """
        for severity in ['critical', 'high', 'medium', 'low']:
            for i, pattern in enumerate(self._compiled_patterns.get(severity, [])):
                match = pattern.search(content)
                if match:
                    return (severity, f"{severity}_{i}", match.group())

        # Check for SQL function calls
        for func in self.SQL_FUNCTIONS:
            if re.search(rf'\b{func}\s*\(', content, re.IGNORECASE):
                return ('medium', f'sql_function_{func}', func)

        return None

    def _create_alert(
        self,
        entry: LogEntry,
        severity: str,
        pattern: str,
        matched_text: str,
        source: str
    ) -> ThreatAlert:
        """Create SQL injection alert."""
        level_map = {
            'critical': ThreatLevel.CRITICAL,
            'high': ThreatLevel.HIGH,
            'medium': ThreatLevel.MEDIUM,
            'low': ThreatLevel.LOW,
        }

        return ThreatAlert(
            timestamp=entry.timestamp,
            threat_type="sql_injection",
            level=level_map.get(severity, ThreatLevel.MEDIUM),
            source_ip=entry.source_ip,
            target=entry.resource,
            description=(
                f"SQL injection attempt detected in {source}: '{matched_text[:50]}...'"
                if len(matched_text) > 50 else
                f"SQL injection attempt detected in {source}: '{matched_text}'"
            ),
            evidence=[entry],
            mitre_attack=["T1190"],
            recommendations=[
                "Block the source IP address",
                "Review and patch vulnerable application code",
                "Implement parameterized queries",
                "Deploy a Web Application Firewall (WAF)",
                "Conduct application security assessment",
            ],
            metadata={
                'pattern_matched': pattern,
                'payload_excerpt': matched_text[:200],
                'injection_point': source,
                'full_request': entry.resource[:500] if entry.resource else None,
            }
        )


class XSSDetector(BaseDetector):
    """
    Detects Cross-Site Scripting (XSS) attempts.

    Identifies reflected, stored, and DOM-based XSS patterns in web logs.
    """

    XSS_PATTERNS = {
        'critical': [
            # Script tags
            r"<script[^>]*>",
            r"</script>",
            r"javascript\s*:",
            r"vbscript\s*:",

            # Event handlers
            r"\bon\w+\s*=",
            r"\b(?:onload|onerror|onclick|onmouseover)\s*=",

            # Direct XSS payloads
            r"<img[^>]+onerror\s*=",
            r"<svg[^>]+onload\s*=",
            r"<body[^>]+onload\s*=",
        ],

        'high': [
            # Data URIs
            r"data\s*:\s*text/html",
            r"data\s*:\s*image/svg\+xml",

            # Expression/eval
            r"expression\s*\(",
            r"eval\s*\(",
            r"setTimeout\s*\(",
            r"setInterval\s*\(",

            # Document manipulation
            r"document\s*\.\s*(?:cookie|write|location)",
            r"window\s*\.\s*(?:location|open)",

            # Base64 encoded scripts
            r"base64\s*,\s*[a-zA-Z0-9+/=]{20,}",
        ],

        'medium': [
            # HTML injection
            r"<(?:iframe|frame|object|embed|applet|form|input|button)",
            r"<(?:a|link)[^>]+href\s*=",
            r"<meta[^>]+http-equiv",

            # Style-based XSS
            r"style\s*=\s*['\"]?[^'\"]*expression",
            r"-moz-binding\s*:",
        ],

        'low': [
            # Potential but may be false positive
            r"<[a-z]+[^>]*>",
            r"&#x?[0-9a-f]+;",
            r"\\u[0-9a-f]{4}",
        ]
    }

    def __init__(self, config: Optional[DetectorConfig] = None):
        """Initialize XSS detector."""
        super().__init__(
            name="xss",
            description="Detects Cross-Site Scripting attempts"
        )
        self.config = config or DetectorConfig()
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns."""
        for severity, patterns in self.XSS_PATTERNS.items():
            self._compiled_patterns[severity] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def analyze(self, entries: List[LogEntry]) -> List[ThreatAlert]:
        """Analyze entries for XSS attempts."""
        self.reset()
        alerts = []

        for entry in entries:
            self.entries_analyzed += 1
            alert = self.analyze_entry(entry)
            if alert:
                alerts.append(alert)

        self.alerts = alerts
        self.detection_count = len(alerts)
        return alerts

    def analyze_entry(self, entry: LogEntry) -> Optional[ThreatAlert]:
        """Analyze single entry for XSS."""
        if entry.log_type not in ['apache', 'nginx', 'nginx_error']:
            return None

        # Check URL and headers
        targets = [
            (entry.resource or "", 'url'),
            (entry.metadata.get('referer', ''), 'referer'),
            (entry.metadata.get('user_agent', ''), 'user_agent'),
        ]

        for content, source in targets:
            if not content or content == '-':
                continue

            # Decode content
            decoded = self._decode_payload(content)
            detection = self._detect_xss(decoded)

            if detection:
                severity, pattern, matched = detection
                return self._create_alert(entry, severity, pattern, matched, source)

        return None

    def _decode_payload(self, payload: str) -> str:
        """Decode XSS payload obfuscation."""
        decoded = payload

        # URL decode
        for _ in range(3):
            try:
                new_decoded = unquote_plus(decoded)
                if new_decoded == decoded:
                    break
                decoded = new_decoded
            except Exception:
                break

        # Decode HTML entities
        html_entities = {
            '&lt;': '<', '&gt;': '>', '&amp;': '&',
            '&quot;': '"', '&apos;': "'", '&#x3c;': '<',
            '&#x3e;': '>', '&#60;': '<', '&#62;': '>',
        }
        for entity, char in html_entities.items():
            decoded = decoded.replace(entity, char)

        return decoded.lower()

    def _detect_xss(self, content: str) -> Optional[tuple]:
        """Detect XSS in content."""
        for severity in ['critical', 'high', 'medium', 'low']:
            for i, pattern in enumerate(self._compiled_patterns.get(severity, [])):
                match = pattern.search(content)
                if match:
                    return (severity, f"{severity}_{i}", match.group())
        return None

    def _create_alert(
        self,
        entry: LogEntry,
        severity: str,
        pattern: str,
        matched: str,
        source: str
    ) -> ThreatAlert:
        """Create XSS alert."""
        level_map = {
            'critical': ThreatLevel.CRITICAL,
            'high': ThreatLevel.HIGH,
            'medium': ThreatLevel.MEDIUM,
            'low': ThreatLevel.LOW,
        }

        return ThreatAlert(
            timestamp=entry.timestamp,
            threat_type="xss",
            level=level_map.get(severity, ThreatLevel.MEDIUM),
            source_ip=entry.source_ip,
            target=entry.resource,
            description=f"XSS attempt detected in {source}: '{matched[:50]}'",
            evidence=[entry],
            mitre_attack=["T1059.007"],
            recommendations=[
                "Implement Content Security Policy (CSP)",
                "Sanitize and encode all user input",
                "Use HTTPOnly and Secure cookie flags",
                "Deploy XSS protection headers",
            ],
            metadata={
                'pattern_matched': pattern,
                'payload_excerpt': matched[:200],
                'injection_point': source,
            }
        )
