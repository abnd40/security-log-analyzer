"""
Nginx Access Log Parser

Parses Nginx access logs in the default combined format.

Default Nginx Combined Format:
    $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"

Example:
    10.0.0.1 - - [01/Jan/2024:12:00:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "curl/7.68.0"
"""

import re
from datetime import datetime
from typing import Optional, List

from .base_parser import BaseParser, LogEntry


class NginxParser(BaseParser):
    """
    Parser for Nginx access logs.

    Similar to Apache Combined format but handles Nginx-specific variations
    and additional fields commonly logged by Nginx.
    """

    # Regex pattern for Nginx combined log format
    NGINX_PATTERN = re.compile(
        r'^(?P<ip>[\d.]+|[\da-fA-F:]+)\s+'           # Remote address
        r'-\s+'                                        # Separator
        r'(?P<user>\S+)\s+'                           # Remote user
        r'\[(?P<timestamp>[^\]]+)\]\s+'               # Time local
        r'"(?P<request>[^"]*)"\s+'                    # Request line
        r'(?P<status>\d{3})\s+'                       # Status code
        r'(?P<bytes>\d+|-)\s*'                        # Body bytes sent
        r'(?:"(?P<referer>[^"]*)"\s*)?'               # HTTP referer
        r'(?:"(?P<useragent>[^"]*)")?'                # HTTP user agent
        r'(?:\s+"(?P<forwarded>[^"]*)")?'             # X-Forwarded-For (optional)
    )

    # Alternative pattern for error log format
    ERROR_PATTERN = re.compile(
        r'^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'\[(?P<level>\w+)\]\s+'
        r'(?P<pid>\d+)#(?P<tid>\d+):\s*'
        r'(?:\*(?P<cid>\d+)\s+)?'
        r'(?P<message>.+)$'
    )

    TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
    ERROR_TIMESTAMP_FORMAT = "%Y/%m/%d %H:%M:%S"

    def __init__(self):
        """Initialize Nginx log parser."""
        super().__init__("nginx")

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single Nginx log line.

        Attempts to parse as access log first, then falls back to error log.

        Args:
            line: Raw Nginx log line

        Returns:
            LogEntry if parsing successful, None otherwise
        """
        # Try access log format first
        match = self.NGINX_PATTERN.match(line)
        if match:
            return self._parse_access_log(match, line)

        # Try error log format
        match = self.ERROR_PATTERN.match(line)
        if match:
            return self._parse_error_log(match, line)

        return None

    def _parse_access_log(self, match: re.Match, raw_line: str) -> LogEntry:
        """Parse access log format match."""
        groups = match.groupdict()

        # Parse timestamp
        try:
            timestamp = datetime.strptime(
                groups['timestamp'],
                self.TIMESTAMP_FORMAT
            )
        except ValueError:
            timestamp = datetime.now()

        # Parse request line
        request = groups.get('request', '')
        request_parts = request.split()
        method = request_parts[0] if request_parts else 'GET'
        path = request_parts[1] if len(request_parts) > 1 else '/'
        protocol = request_parts[2] if len(request_parts) > 2 else 'HTTP/1.1'

        # Parse bytes
        bytes_sent = groups.get('bytes', '0')
        response_size = int(bytes_sent) if bytes_sent.isdigit() else 0

        # Handle user
        user = groups.get('user')
        if user == '-':
            user = None

        # Handle X-Forwarded-For for real client IP behind proxies
        real_ip = groups.get('ip')
        forwarded = groups.get('forwarded')
        if forwarded and forwarded != '-':
            # First IP in X-Forwarded-For is the original client
            real_ip = forwarded.split(',')[0].strip()

        return LogEntry(
            timestamp=timestamp,
            source_ip=real_ip,
            user=user,
            action=method,
            resource=path,
            status_code=int(groups['status']),
            message=request,
            log_type=self.log_type,
            raw_line=raw_line,
            metadata={
                'protocol': protocol,
                'referer': groups.get('referer', '-'),
                'user_agent': groups.get('useragent', '-'),
                'response_size': response_size,
                'original_ip': groups.get('ip'),
                'x_forwarded_for': forwarded,
            }
        )

    def _parse_error_log(self, match: re.Match, raw_line: str) -> LogEntry:
        """Parse error log format match."""
        groups = match.groupdict()

        try:
            timestamp = datetime.strptime(
                groups['timestamp'],
                self.ERROR_TIMESTAMP_FORMAT
            )
        except ValueError:
            timestamp = datetime.now()

        # Extract IP from error message if present
        ip_match = re.search(r'client:\s*([\d.]+)', groups.get('message', ''))
        source_ip = ip_match.group(1) if ip_match else None

        return LogEntry(
            timestamp=timestamp,
            source_ip=source_ip,
            action='ERROR',
            message=groups.get('message', ''),
            log_type=f"{self.log_type}_error",
            raw_line=raw_line,
            metadata={
                'level': groups.get('level', 'error'),
                'pid': groups.get('pid'),
                'tid': groups.get('tid'),
                'connection_id': groups.get('cid'),
            }
        )

    def detect_format(self, sample_lines: List[str]) -> bool:
        """
        Detect if sample lines match Nginx log format.

        Args:
            sample_lines: Sample log lines to analyze

        Returns:
            True if format appears to be Nginx log
        """
        if not sample_lines:
            return False

        matches = 0
        for line in sample_lines[:10]:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if self.NGINX_PATTERN.match(line) or self.ERROR_PATTERN.match(line):
                matches += 1

        valid_lines = len([l for l in sample_lines[:10] if l.strip()])
        return matches >= valid_lines * 0.5 if valid_lines > 0 else False
