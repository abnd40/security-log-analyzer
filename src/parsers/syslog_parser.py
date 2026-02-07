"""
Syslog Parser

Parses standard syslog format (RFC 3164 and RFC 5424) entries.

RFC 3164 (BSD syslog):
    <priority>timestamp hostname process[pid]: message

RFC 5424:
    <priority>version timestamp hostname app-name procid msgid structured-data msg

Examples:
    Jan 15 10:23:45 webserver sshd[12345]: Accepted publickey for user from 192.168.1.50
    <34>1 2024-01-15T10:23:45.003Z webserver sshd 12345 - - Accepted publickey for user
"""

import re
from datetime import datetime
from typing import Optional, List, Dict, Any

from .base_parser import BaseParser, LogEntry


class SyslogParser(BaseParser):
    """
    Parser for syslog format logs.

    Handles both RFC 3164 (traditional BSD syslog) and RFC 5424
    (modern syslog protocol) formats. Extracts facility, severity,
    and structured data when available.
    """

    # Syslog facility codes
    FACILITIES = {
        0: 'kern', 1: 'user', 2: 'mail', 3: 'daemon',
        4: 'auth', 5: 'syslog', 6: 'lpr', 7: 'news',
        8: 'uucp', 9: 'cron', 10: 'authpriv', 11: 'ftp',
        12: 'ntp', 13: 'security', 14: 'console', 15: 'solaris-cron',
        16: 'local0', 17: 'local1', 18: 'local2', 19: 'local3',
        20: 'local4', 21: 'local5', 22: 'local6', 23: 'local7',
    }

    # Syslog severity levels
    SEVERITIES = {
        0: 'emergency', 1: 'alert', 2: 'critical', 3: 'error',
        4: 'warning', 5: 'notice', 6: 'info', 7: 'debug',
    }

    # RFC 3164 pattern (traditional BSD syslog)
    RFC3164_PATTERN = re.compile(
        r'^(?:<(?P<priority>\d{1,3})>)?'                    # Optional priority
        r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # Timestamp
        r'(?P<hostname>\S+)\s+'                              # Hostname
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'       # Process[pid]:
        r'(?P<message>.*)$'                                  # Message
    )

    # RFC 5424 pattern (modern syslog)
    RFC5424_PATTERN = re.compile(
        r'^<(?P<priority>\d{1,3})>'                         # Priority
        r'(?P<version>\d+)\s+'                              # Version
        r'(?P<timestamp>\S+)\s+'                            # ISO timestamp
        r'(?P<hostname>\S+)\s+'                             # Hostname
        r'(?P<appname>\S+)\s+'                              # App name
        r'(?P<procid>\S+)\s+'                               # Process ID
        r'(?P<msgid>\S+)\s+'                                # Message ID
        r'(?P<structured>(?:\[.*?\])*|-)\s*'                # Structured data
        r'(?P<message>.*)$'                                  # Message
    )

    # Alternative simple pattern for minimal syslog
    SIMPLE_PATTERN = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<message>.*)$'
    )

    def __init__(self):
        """Initialize syslog parser."""
        super().__init__("syslog")

    def _decode_priority(self, priority: int) -> Dict[str, Any]:
        """
        Decode syslog priority into facility and severity.

        Priority = Facility * 8 + Severity

        Args:
            priority: Syslog priority value

        Returns:
            Dictionary with facility and severity information
        """
        facility_code = priority // 8
        severity_code = priority % 8

        return {
            'facility_code': facility_code,
            'facility': self.FACILITIES.get(facility_code, 'unknown'),
            'severity_code': severity_code,
            'severity': self.SEVERITIES.get(severity_code, 'unknown'),
        }

    def _parse_rfc3164_timestamp(self, ts_str: str) -> datetime:
        """Parse RFC 3164 timestamp (Jan 15 10:23:45)."""
        current_year = datetime.now().year
        try:
            # Add current year since RFC 3164 doesn't include it
            timestamp = datetime.strptime(
                f"{current_year} {ts_str}",
                "%Y %b %d %H:%M:%S"
            )
            return timestamp
        except ValueError:
            return datetime.now()

    def _parse_rfc5424_timestamp(self, ts_str: str) -> datetime:
        """Parse RFC 5424 ISO timestamp."""
        # Handle various ISO 8601 formats
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue

        return datetime.now()

    def _extract_ip(self, message: str) -> Optional[str]:
        """Extract IP address from syslog message."""
        # Common patterns for IP in syslog messages
        patterns = [
            r'from\s+([\d.]+)',
            r'src=([\d.]+)',
            r'SRC=([\d.]+)',
            r'client\s+([\d.]+)',
            r'rhost=([\d.]+)',
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
        ]

        for pattern in patterns:
            match = re.search(pattern, message)
            if match:
                return match.group(1)

        return None

    def _extract_user(self, message: str) -> Optional[str]:
        """Extract username from syslog message."""
        patterns = [
            r'user[=:\s]+(\S+)',
            r'for\s+(?:user\s+)?(\w+)',
            r'USER=(\S+)',
            r'by\s+(\w+)',
            r'session\s+(?:opened|closed)\s+for\s+(?:user\s+)?(\w+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                user = match.group(1)
                # Filter out common false positives
                if user.lower() not in ['root', 'unknown', 'invalid', '(unknown)']:
                    return user
                elif user.lower() == 'root':
                    return user

        return None

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single syslog line.

        Attempts RFC 5424 first, then RFC 3164, then simple format.

        Args:
            line: Raw syslog line

        Returns:
            LogEntry if parsing successful, None otherwise
        """
        # Try RFC 5424 first
        match = self.RFC5424_PATTERN.match(line)
        if match:
            return self._parse_rfc5424(match, line)

        # Try RFC 3164
        match = self.RFC3164_PATTERN.match(line)
        if match:
            return self._parse_rfc3164(match, line)

        # Try simple format
        match = self.SIMPLE_PATTERN.match(line)
        if match:
            return self._parse_simple(match, line)

        return None

    def _parse_rfc5424(self, match: re.Match, raw_line: str) -> LogEntry:
        """Parse RFC 5424 format match."""
        groups = match.groupdict()

        priority = int(groups.get('priority', 13))
        priority_info = self._decode_priority(priority)

        timestamp = self._parse_rfc5424_timestamp(groups['timestamp'])
        message = groups.get('message', '')

        return LogEntry(
            timestamp=timestamp,
            source_ip=self._extract_ip(message),
            user=self._extract_user(message),
            action=groups.get('appname', 'syslog'),
            message=message,
            log_type=self.log_type,
            raw_line=raw_line,
            metadata={
                'hostname': groups.get('hostname'),
                'process': groups.get('appname'),
                'pid': groups.get('procid'),
                'msgid': groups.get('msgid'),
                'structured_data': groups.get('structured'),
                **priority_info,
            }
        )

    def _parse_rfc3164(self, match: re.Match, raw_line: str) -> LogEntry:
        """Parse RFC 3164 format match."""
        groups = match.groupdict()

        priority = int(groups.get('priority', 13)) if groups.get('priority') else 13
        priority_info = self._decode_priority(priority)

        timestamp = self._parse_rfc3164_timestamp(groups['timestamp'])
        message = groups.get('message', '')

        return LogEntry(
            timestamp=timestamp,
            source_ip=self._extract_ip(message),
            user=self._extract_user(message),
            action=groups.get('process', 'syslog'),
            message=message,
            log_type=self.log_type,
            raw_line=raw_line,
            metadata={
                'hostname': groups.get('hostname'),
                'process': groups.get('process'),
                'pid': groups.get('pid'),
                **priority_info,
            }
        )

    def _parse_simple(self, match: re.Match, raw_line: str) -> LogEntry:
        """Parse simple syslog format match."""
        groups = match.groupdict()

        timestamp = self._parse_rfc3164_timestamp(groups['timestamp'])
        message = groups.get('message', '')

        return LogEntry(
            timestamp=timestamp,
            source_ip=self._extract_ip(message),
            user=self._extract_user(message),
            action='syslog',
            message=message,
            log_type=self.log_type,
            raw_line=raw_line,
            metadata={
                'hostname': groups.get('hostname'),
            }
        )

    def detect_format(self, sample_lines: List[str]) -> bool:
        """
        Detect if sample lines match syslog format.

        Args:
            sample_lines: Sample log lines to analyze

        Returns:
            True if format appears to be syslog
        """
        if not sample_lines:
            return False

        matches = 0
        for line in sample_lines[:10]:
            line = line.strip()
            if not line:
                continue
            if (self.RFC5424_PATTERN.match(line) or
                self.RFC3164_PATTERN.match(line) or
                self.SIMPLE_PATTERN.match(line)):
                matches += 1

        valid_lines = len([l for l in sample_lines[:10] if l.strip()])
        return matches >= valid_lines * 0.5 if valid_lines > 0 else False
