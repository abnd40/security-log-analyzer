"""
Apache Access Log Parser

Parses Apache Combined Log Format and Common Log Format entries.

Combined Log Format:
    %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"

Example:
    192.168.1.100 - admin [10/Oct/2023:13:55:36 -0700] "GET /admin HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
"""

import re
from datetime import datetime
from typing import Optional, List

from .base_parser import BaseParser, LogEntry


class ApacheParser(BaseParser):
    """
    Parser for Apache access logs in Combined and Common formats.

    Handles both standard Apache log formats and extracts all relevant
    fields for security analysis including IP, user, request details,
    and response information.
    """

    # Regex pattern for Apache Combined Log Format
    COMBINED_PATTERN = re.compile(
        r'^(?P<ip>[\d.]+|[\da-fA-F:]+)\s+'           # Client IP (IPv4 or IPv6)
        r'(?P<ident>\S+)\s+'                          # Ident (usually -)
        r'(?P<user>\S+)\s+'                           # User (or -)
        r'\[(?P<timestamp>[^\]]+)\]\s+'               # Timestamp [dd/Mon/yyyy:HH:MM:SS zone]
        r'"(?P<method>\w+)\s+'                        # HTTP Method
        r'(?P<path>\S+)\s*'                           # Request path
        r'(?P<protocol>[^"]*)?"\s+'                   # Protocol
        r'(?P<status>\d{3})\s+'                       # Status code
        r'(?P<size>\S+)'                              # Response size
        r'(?:\s+"(?P<referer>[^"]*)"\s+'              # Referer (optional)
        r'"(?P<useragent>[^"]*)")?'                   # User-Agent (optional)
    )

    # Timestamp format in Apache logs
    TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

    def __init__(self):
        """Initialize Apache log parser."""
        super().__init__("apache")

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single Apache access log line.

        Args:
            line: Raw Apache log line

        Returns:
            LogEntry if parsing successful, None otherwise
        """
        match = self.COMBINED_PATTERN.match(line)
        if not match:
            return None

        groups = match.groupdict()

        # Parse timestamp
        try:
            timestamp = datetime.strptime(
                groups['timestamp'],
                self.TIMESTAMP_FORMAT
            )
        except ValueError:
            # Try without timezone
            try:
                timestamp = datetime.strptime(
                    groups['timestamp'].rsplit(' ', 1)[0],
                    "%d/%b/%Y:%H:%M:%S"
                )
            except ValueError:
                timestamp = datetime.now()

        # Parse response size
        size = groups.get('size', '-')
        response_size = int(size) if size.isdigit() else 0

        # Extract user (- means anonymous)
        user = groups.get('user')
        if user == '-':
            user = None

        return LogEntry(
            timestamp=timestamp,
            source_ip=groups['ip'],
            user=user,
            action=groups.get('method', 'GET'),
            resource=groups.get('path', '/'),
            status_code=int(groups['status']),
            message=f"{groups.get('method', 'GET')} {groups.get('path', '/')}",
            log_type=self.log_type,
            raw_line=line,
            metadata={
                'protocol': groups.get('protocol', 'HTTP/1.1'),
                'referer': groups.get('referer', '-'),
                'user_agent': groups.get('useragent', '-'),
                'response_size': response_size,
                'ident': groups.get('ident', '-'),
            }
        )

    def detect_format(self, sample_lines: List[str]) -> bool:
        """
        Detect if sample lines match Apache log format.

        Args:
            sample_lines: Sample log lines to analyze

        Returns:
            True if format appears to be Apache access log
        """
        if not sample_lines:
            return False

        matches = 0
        for line in sample_lines[:10]:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if self.COMBINED_PATTERN.match(line):
                matches += 1

        # Require at least 50% match rate
        return matches >= len([l for l in sample_lines[:10] if l.strip()]) * 0.5
