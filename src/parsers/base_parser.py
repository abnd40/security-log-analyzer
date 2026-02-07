"""
Base Parser Module

Provides the abstract base class for all log parsers and the standardized
LogEntry dataclass for consistent log representation across formats.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any, Iterator
from pathlib import Path
import hashlib


@dataclass
class LogEntry:
    """
    Standardized log entry representation.

    This dataclass provides a unified structure for log entries across
    different log formats, enabling consistent threat analysis.

    Attributes:
        timestamp: When the event occurred
        source_ip: Origin IP address (if applicable)
        destination_ip: Target IP address (if applicable)
        user: Username associated with the event
        action: The action performed (GET, POST, LOGIN, etc.)
        resource: The resource accessed (URL path, file, etc.)
        status_code: HTTP status code or event result code
        message: Raw or processed log message
        log_type: Type of log (apache, nginx, syslog, auth, windows)
        raw_line: Original unparsed log line
        metadata: Additional format-specific fields
        entry_hash: SHA-256 hash for deduplication
    """
    timestamp: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    status_code: Optional[int] = None
    message: str = ""
    log_type: str = "unknown"
    raw_line: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    entry_hash: str = field(default="", init=False)

    def __post_init__(self):
        """Generate unique hash for the log entry."""
        hash_content = f"{self.timestamp}{self.source_ip}{self.message}{self.raw_line}"
        self.entry_hash = hashlib.sha256(hash_content.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary for serialization."""
        return {
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'user': self.user,
            'action': self.action,
            'resource': self.resource,
            'status_code': self.status_code,
            'message': self.message,
            'log_type': self.log_type,
            'metadata': self.metadata,
            'entry_hash': self.entry_hash,
        }


class BaseParser(ABC):
    """
    Abstract base class for log parsers.

    All log format parsers must inherit from this class and implement
    the required abstract methods for consistent parsing behavior.
    """

    def __init__(self, log_type: str):
        """
        Initialize the parser.

        Args:
            log_type: Identifier for the log format (e.g., 'apache', 'nginx')
        """
        self.log_type = log_type
        self.parse_errors: List[Dict[str, Any]] = []
        self.lines_processed = 0
        self.lines_parsed = 0

    @abstractmethod
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single log line into a LogEntry.

        Args:
            line: Raw log line to parse

        Returns:
            LogEntry if parsing successful, None otherwise
        """
        pass

    @abstractmethod
    def detect_format(self, sample_lines: List[str]) -> bool:
        """
        Detect if the given log lines match this parser's format.

        Args:
            sample_lines: Sample of log lines to analyze

        Returns:
            True if the format matches, False otherwise
        """
        pass

    def parse_file(self, file_path: Path) -> Iterator[LogEntry]:
        """
        Parse an entire log file.

        Args:
            file_path: Path to the log file

        Yields:
            LogEntry objects for each successfully parsed line
        """
        self.parse_errors = []
        self.lines_processed = 0
        self.lines_parsed = 0

        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line_num, line in enumerate(f, 1):
                self.lines_processed += 1
                line = line.strip()

                if not line or line.startswith('#'):
                    continue

                try:
                    entry = self.parse_line(line)
                    if entry:
                        self.lines_parsed += 1
                        yield entry
                except Exception as e:
                    self.parse_errors.append({
                        'line_number': line_num,
                        'line': line[:200],
                        'error': str(e)
                    })

    def get_stats(self) -> Dict[str, Any]:
        """
        Get parsing statistics.

        Returns:
            Dictionary containing parsing metrics
        """
        return {
            'log_type': self.log_type,
            'lines_processed': self.lines_processed,
            'lines_parsed': self.lines_parsed,
            'parse_errors': len(self.parse_errors),
            'success_rate': (self.lines_parsed / self.lines_processed * 100)
                           if self.lines_processed > 0 else 0
        }
