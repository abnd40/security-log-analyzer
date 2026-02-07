"""
Log Parsers Module

Provides parsers for common log formats including:
- Apache/Nginx access logs
- Syslog format
- Authentication logs (auth.log)
- Windows Event logs
"""

from .base_parser import BaseParser, LogEntry
from .apache_parser import ApacheParser
from .nginx_parser import NginxParser
from .syslog_parser import SyslogParser
from .auth_parser import AuthLogParser
from .windows_parser import WindowsEventParser

__all__ = [
    'BaseParser',
    'LogEntry',
    'ApacheParser',
    'NginxParser',
    'SyslogParser',
    'AuthLogParser',
    'WindowsEventParser',
]
