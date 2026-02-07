"""
Authentication Log Parser

Parses Linux authentication logs (auth.log, secure) for security events.

Common auth.log entries:
- SSH login attempts (success/failure)
- sudo usage
- PAM authentication events
- su command usage
- systemd-logind sessions

Example entries:
    Jan 15 10:23:45 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
    Jan 15 10:24:00 server sshd[12346]: Accepted publickey for ubuntu from 10.0.0.5 port 52341 ssh2
"""

import re
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

from .base_parser import BaseParser, LogEntry


class AuthEventType(Enum):
    """Types of authentication events."""
    SSH_SUCCESS = "ssh_success"
    SSH_FAILURE = "ssh_failure"
    SSH_INVALID_USER = "ssh_invalid_user"
    SUDO_SUCCESS = "sudo_success"
    SUDO_FAILURE = "sudo_failure"
    SU_SUCCESS = "su_success"
    SU_FAILURE = "su_failure"
    SESSION_OPEN = "session_open"
    SESSION_CLOSE = "session_close"
    PAM_AUTH = "pam_auth"
    OTHER = "other"


class AuthLogParser(BaseParser):
    """
    Parser for Linux authentication logs.

    Specifically designed to extract security-relevant information from
    auth.log and secure log files, with emphasis on detecting authentication
    attacks and anomalies.
    """

    # Base syslog pattern for auth logs
    BASE_PATTERN = re.compile(
        r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'
        r'(?P<message>.*)$'
    )

    # SSH-specific patterns
    SSH_PATTERNS = {
        'accepted_password': re.compile(
            r'Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
        ),
        'accepted_publickey': re.compile(
            r'Accepted publickey for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
        ),
        'failed_password': re.compile(
            r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
        ),
        'invalid_user': re.compile(
            r'Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)'
        ),
        'connection_closed': re.compile(
            r'Connection closed by (?:authenticating user (?P<user>\S+) )?(?P<ip>[\d.]+) port (?P<port>\d+)'
        ),
        'disconnect': re.compile(
            r'Disconnected from (?:authenticating user (?P<user>\S+) )?(?P<ip>[\d.]+) port (?P<port>\d+)'
        ),
        'too_many_failures': re.compile(
            r'Disconnecting.*: Too many authentication failures'
        ),
        'break_in_attempt': re.compile(
            r'reverse mapping checking.*POSSIBLE BREAK-IN ATTEMPT'
        ),
    }

    # Sudo patterns
    SUDO_PATTERNS = {
        'sudo_command': re.compile(
            r'(?P<user>\S+)\s+:\s+TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>\S+)\s+;\s+'
            r'USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.+)$'
        ),
        'sudo_failure': re.compile(
            r'(?P<user>\S+)\s+:\s+.*authentication failure'
        ),
        'sudo_incorrect': re.compile(
            r'(?P<user>\S+)\s+:\s+\d+ incorrect password attempts?'
        ),
    }

    # PAM patterns
    PAM_PATTERNS = {
        'session_opened': re.compile(
            r'pam_unix\([^)]+\):\s+session opened for user (?P<user>\S+)'
        ),
        'session_closed': re.compile(
            r'pam_unix\([^)]+\):\s+session closed for user (?P<user>\S+)'
        ),
        'auth_failure': re.compile(
            r'pam_unix\([^)]+\):\s+authentication failure.*user=(?P<user>\S+)'
        ),
    }

    def __init__(self):
        """Initialize authentication log parser."""
        super().__init__("auth")

    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Parse auth.log timestamp."""
        current_year = datetime.now().year
        try:
            timestamp = datetime.strptime(
                f"{current_year} {ts_str}",
                "%Y %b %d %H:%M:%S"
            )
            return timestamp
        except ValueError:
            return datetime.now()

    def _classify_event(self, process: str, message: str) -> Dict[str, Any]:
        """
        Classify the authentication event type and extract details.

        Returns:
            Dictionary with event_type and extracted details
        """
        result = {
            'event_type': AuthEventType.OTHER,
            'user': None,
            'source_ip': None,
            'port': None,
            'success': None,
            'details': {}
        }

        # Check SSH events
        if 'sshd' in process.lower():
            for event_name, pattern in self.SSH_PATTERNS.items():
                match = pattern.search(message)
                if match:
                    groups = match.groupdict()
                    result['user'] = groups.get('user')
                    result['source_ip'] = groups.get('ip')
                    result['port'] = groups.get('port')

                    if 'accepted' in event_name:
                        result['event_type'] = AuthEventType.SSH_SUCCESS
                        result['success'] = True
                        result['details']['auth_method'] = (
                            'publickey' if 'publickey' in event_name else 'password'
                        )
                    elif 'failed' in event_name:
                        result['event_type'] = AuthEventType.SSH_FAILURE
                        result['success'] = False
                    elif 'invalid_user' in event_name:
                        result['event_type'] = AuthEventType.SSH_INVALID_USER
                        result['success'] = False
                    elif 'too_many' in event_name or 'break_in' in event_name:
                        result['event_type'] = AuthEventType.SSH_FAILURE
                        result['success'] = False
                        result['details']['critical'] = True

                    break

        # Check sudo events
        elif 'sudo' in process.lower():
            for event_name, pattern in self.SUDO_PATTERNS.items():
                match = pattern.search(message)
                if match:
                    groups = match.groupdict()
                    result['user'] = groups.get('user')

                    if 'failure' in event_name or 'incorrect' in event_name:
                        result['event_type'] = AuthEventType.SUDO_FAILURE
                        result['success'] = False
                    else:
                        result['event_type'] = AuthEventType.SUDO_SUCCESS
                        result['success'] = True
                        result['details']['target_user'] = groups.get('target_user')
                        result['details']['command'] = groups.get('command')

                    break

        # Check PAM events
        for event_name, pattern in self.PAM_PATTERNS.items():
            match = pattern.search(message)
            if match:
                groups = match.groupdict()
                result['user'] = groups.get('user')

                if 'opened' in event_name:
                    result['event_type'] = AuthEventType.SESSION_OPEN
                    result['success'] = True
                elif 'closed' in event_name:
                    result['event_type'] = AuthEventType.SESSION_CLOSE
                elif 'failure' in event_name:
                    result['event_type'] = AuthEventType.PAM_AUTH
                    result['success'] = False

                break

        return result

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single authentication log line.

        Args:
            line: Raw auth.log line

        Returns:
            LogEntry if parsing successful, None otherwise
        """
        match = self.BASE_PATTERN.match(line)
        if not match:
            return None

        groups = match.groupdict()
        timestamp = self._parse_timestamp(groups['timestamp'])
        message = groups.get('message', '')
        process = groups.get('process', '')

        # Classify the event
        event_info = self._classify_event(process, message)

        return LogEntry(
            timestamp=timestamp,
            source_ip=event_info['source_ip'],
            user=event_info['user'],
            action=event_info['event_type'].value,
            message=message,
            log_type=self.log_type,
            raw_line=line,
            status_code=1 if event_info['success'] else 0 if event_info['success'] is False else None,
            metadata={
                'hostname': groups.get('hostname'),
                'process': process,
                'pid': groups.get('pid'),
                'event_type': event_info['event_type'].value,
                'success': event_info['success'],
                'port': event_info['port'],
                **event_info['details'],
            }
        )

    def detect_format(self, sample_lines: List[str]) -> bool:
        """
        Detect if sample lines match auth.log format.

        Args:
            sample_lines: Sample log lines to analyze

        Returns:
            True if format appears to be auth.log
        """
        if not sample_lines:
            return False

        auth_indicators = ['sshd', 'sudo', 'su', 'pam_', 'session', 'auth']
        matches = 0

        for line in sample_lines[:10]:
            line = line.strip()
            if not line:
                continue

            base_match = self.BASE_PATTERN.match(line)
            if base_match:
                message = base_match.group('message').lower()
                process = base_match.group('process').lower()

                if any(ind in message or ind in process for ind in auth_indicators):
                    matches += 1

        valid_lines = len([l for l in sample_lines[:10] if l.strip()])
        return matches >= valid_lines * 0.3 if valid_lines > 0 else False
