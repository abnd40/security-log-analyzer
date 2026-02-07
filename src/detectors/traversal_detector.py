"""
Directory Traversal Attack Detector

Detects path traversal and local file inclusion (LFI) attempts
that aim to access files outside the web root.

Attack Vectors Detected:
- Classic traversal (../, ..\)
- URL encoded traversal (%2e%2e%2f)
- Double encoding
- Unicode/UTF-8 encoding bypass
- Null byte injection
- Sensitive file access attempts

MITRE ATT&CK References:
- T1083: File and Directory Discovery
- T1005: Data from Local System
"""

import re
from urllib.parse import unquote, unquote_plus
from typing import Optional, List, Dict
from datetime import datetime

from .base_detector import BaseDetector, ThreatAlert, ThreatLevel, DetectorConfig
from ..parsers.base_parser import LogEntry


class DirectoryTraversalDetector(BaseDetector):
    """
    Detects directory traversal and LFI attacks.

    Identifies attempts to escape web root and access sensitive
    system files through various encoding techniques.
    """

    # Traversal patterns with various encodings
    TRAVERSAL_PATTERNS = [
        # Basic traversal
        r'\.\.[/\\]',
        r'\.\.%2[fF]',
        r'\.\.%5[cC]',

        # Double encoding
        r'%252[eE]%252[eE]%252[fF]',
        r'%252[eE]%252[eE]%255[cC]',

        # Mixed encoding
        r'\.%2[eE][/\\]',
        r'%2[eE]\.[/\\]',
        r'%2[eE]%2[eE][/\\%]',

        # Unicode encoding
        r'%c0%ae%c0%ae[/\\]',
        r'%c0%2f',
        r'%c1%1c',
        r'%c1%9c',

        # Null byte injection (for bypassing extension checks)
        r'%00',
        r'\\x00',
        r'\0',

        # Overlong UTF-8
        r'%c0%ae',
        r'%e0%80%ae',
        r'%f0%80%80%ae',
    ]

    # Sensitive files commonly targeted
    SENSITIVE_FILES = {
        'critical': [
            # Unix password/shadow files
            r'/etc/passwd',
            r'/etc/shadow',
            r'/etc/master\.passwd',

            # SSH keys
            r'\.ssh/(?:id_rsa|id_dsa|authorized_keys)',
            r'/root/\.ssh/',

            # Application secrets
            r'\.env$',
            r'config\.(?:php|ini|yml|yaml|json)',
            r'database\.yml',
            r'secrets\.yml',
            r'credentials',
            r'\.git/config',
            r'\.htpasswd',

            # Windows sensitive
            r'windows/system32/config/sam',
            r'boot\.ini',
            r'win\.ini',
        ],

        'high': [
            # Web server configs
            r'apache2?/(?:conf|sites)',
            r'nginx/(?:conf|sites)',
            r'httpd\.conf',
            r'nginx\.conf',

            # Application configs
            r'wp-config\.php',
            r'configuration\.php',
            r'settings\.php',
            r'config\.php',
            r'LocalSettings\.php',

            # Log files
            r'/var/log/',
            r'access\.log',
            r'error\.log',
            r'auth\.log',

            # Proc filesystem
            r'/proc/self/',
            r'/proc/\d+/',
        ],

        'medium': [
            # System info
            r'/etc/hosts',
            r'/etc/hostname',
            r'/etc/resolv\.conf',
            r'/etc/issue',
            r'/etc/motd',

            # Web application files
            r'\.htaccess',
            r'web\.config',
            r'crossdomain\.xml',
            r'robots\.txt',
            r'sitemap\.xml',
        ]
    }

    # Response codes that indicate successful traversal
    SUCCESS_CODES = {200, 206, 304}

    def __init__(self, config: Optional[DetectorConfig] = None):
        """Initialize traversal detector."""
        super().__init__(
            name="directory_traversal",
            description="Detects directory traversal and LFI attacks"
        )
        self.config = config or DetectorConfig()

        # Compile patterns
        self._traversal_patterns = [re.compile(p, re.IGNORECASE) for p in self.TRAVERSAL_PATTERNS]
        self._sensitive_patterns: Dict[str, List[re.Pattern]] = {}
        for level, patterns in self.SENSITIVE_FILES.items():
            self._sensitive_patterns[level] = [re.compile(p, re.IGNORECASE) for p in patterns]

    def analyze(self, entries: List[LogEntry]) -> List[ThreatAlert]:
        """Analyze entries for traversal attacks."""
        self.reset()
        alerts = []

        # Track IPs for escalation
        ip_attempts: Dict[str, int] = {}

        for entry in entries:
            self.entries_analyzed += 1
            alert = self.analyze_entry(entry)

            if alert:
                alerts.append(alert)
                if entry.source_ip:
                    ip_attempts[entry.source_ip] = ip_attempts.get(entry.source_ip, 0) + 1

        # Escalate alerts for repeat offenders
        for alert in alerts:
            if alert.source_ip and ip_attempts.get(alert.source_ip, 0) >= 5:
                if alert.level.value < ThreatLevel.HIGH.value:
                    alert.level = ThreatLevel.HIGH
                    alert.description += " (Multiple traversal attempts from same IP)"

        self.alerts = alerts
        self.detection_count = len(alerts)
        return alerts

    def analyze_entry(self, entry: LogEntry) -> Optional[ThreatAlert]:
        """Analyze single entry for traversal."""
        if entry.log_type not in ['apache', 'nginx', 'nginx_error']:
            return None

        resource = entry.resource or ""
        if not resource:
            return None

        # Decode multiple layers
        decoded = self._decode_path(resource)

        # Check for traversal patterns
        traversal_match = self._detect_traversal(decoded)

        # Check for sensitive file access
        sensitive_match = self._detect_sensitive_file(decoded)

        if traversal_match or sensitive_match:
            # Determine severity
            is_successful = entry.status_code in self.SUCCESS_CODES

            if sensitive_match:
                severity = sensitive_match[0]
                target_file = sensitive_match[1]
            else:
                severity = 'medium'
                target_file = decoded

            # Escalate if successful
            if is_successful and severity != 'critical':
                severity = 'critical' if severity == 'high' else 'high'

            return self._create_alert(
                entry=entry,
                severity=severity,
                target_file=target_file,
                traversal_detected=bool(traversal_match),
                successful=is_successful
            )

        return None

    def _decode_path(self, path: str) -> str:
        """Decode path with multiple encoding layers."""
        decoded = path

        # Multiple URL decode passes
        for _ in range(5):
            try:
                new_decoded = unquote(decoded)
                if new_decoded == decoded:
                    break
                decoded = new_decoded
            except Exception:
                break

        # Normalize slashes
        decoded = decoded.replace('\\', '/')

        # Remove null bytes
        decoded = decoded.replace('\x00', '')

        return decoded

    def _detect_traversal(self, path: str) -> bool:
        """Check for traversal sequences."""
        # Simple check first
        if '../' in path or '..\\' in path:
            return True

        # Check encoded patterns
        for pattern in self._traversal_patterns:
            if pattern.search(path):
                return True

        return False

    def _detect_sensitive_file(self, path: str) -> Optional[tuple]:
        """
        Check for sensitive file access.

        Returns:
            Tuple of (severity, matched_file) or None
        """
        for level in ['critical', 'high', 'medium']:
            for pattern in self._sensitive_patterns[level]:
                match = pattern.search(path)
                if match:
                    return (level, match.group())
        return None

    def _create_alert(
        self,
        entry: LogEntry,
        severity: str,
        target_file: str,
        traversal_detected: bool,
        successful: bool
    ) -> ThreatAlert:
        """Create traversal alert."""
        level_map = {
            'critical': ThreatLevel.CRITICAL,
            'high': ThreatLevel.HIGH,
            'medium': ThreatLevel.MEDIUM,
            'low': ThreatLevel.LOW,
        }

        attack_type = "Directory traversal" if traversal_detected else "Sensitive file access"

        description = f"{attack_type} attempt: {target_file[:100]}"
        if successful:
            description = f"SUCCESSFUL {description}"

        recommendations = [
            "Validate and sanitize all file path inputs",
            "Implement proper access controls",
            "Use chroot or containerization",
            "Configure web server to deny access to sensitive files",
        ]

        if successful:
            recommendations.insert(0, "URGENT: Review accessed file for data exposure")
            recommendations.insert(1, "Check for lateral movement from this access")

        return ThreatAlert(
            timestamp=entry.timestamp,
            threat_type="directory_traversal",
            level=level_map.get(severity, ThreatLevel.MEDIUM),
            source_ip=entry.source_ip,
            target=entry.resource,
            description=description,
            evidence=[entry],
            mitre_attack=["T1083", "T1005"],
            recommendations=recommendations,
            metadata={
                'target_file': target_file,
                'traversal_detected': traversal_detected,
                'successful': successful,
                'status_code': entry.status_code,
                'decoded_path': self._decode_path(entry.resource or ''),
            }
        )
