"""
Windows Event Log Parser

Parses Windows Event logs exported in various formats:
- XML export format
- CSV export format
- EVTX parsed format (text representation)

Common Security Event IDs:
- 4624: Successful logon
- 4625: Failed logon
- 4634: Logoff
- 4648: Explicit credential logon
- 4720: User account created
- 4722: User account enabled
- 4723: Password change attempt
- 4724: Password reset attempt
- 4725: User account disabled
- 4726: User account deleted
- 4728: Member added to security-enabled global group
- 4732: Member added to security-enabled local group
- 4756: Member added to security-enabled universal group
"""

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

from .base_parser import BaseParser, LogEntry


class WindowsEventType(Enum):
    """Windows Security Event categories."""
    LOGON_SUCCESS = "logon_success"
    LOGON_FAILURE = "logon_failure"
    LOGOFF = "logoff"
    PRIVILEGE_USE = "privilege_use"
    ACCOUNT_MANAGEMENT = "account_management"
    POLICY_CHANGE = "policy_change"
    SYSTEM = "system"
    PROCESS = "process"
    OTHER = "other"


class WindowsEventParser(BaseParser):
    """
    Parser for Windows Event logs.

    Handles multiple export formats and focuses on security-relevant events.
    Provides detailed extraction of logon types, authentication methods,
    and account management activities.
    """

    # Event ID to type mapping
    EVENT_CATEGORIES = {
        # Logon events
        4624: WindowsEventType.LOGON_SUCCESS,
        4625: WindowsEventType.LOGON_FAILURE,
        4634: WindowsEventType.LOGOFF,
        4647: WindowsEventType.LOGOFF,
        4648: WindowsEventType.LOGON_SUCCESS,
        4672: WindowsEventType.PRIVILEGE_USE,

        # Account management
        4720: WindowsEventType.ACCOUNT_MANAGEMENT,
        4722: WindowsEventType.ACCOUNT_MANAGEMENT,
        4723: WindowsEventType.ACCOUNT_MANAGEMENT,
        4724: WindowsEventType.ACCOUNT_MANAGEMENT,
        4725: WindowsEventType.ACCOUNT_MANAGEMENT,
        4726: WindowsEventType.ACCOUNT_MANAGEMENT,
        4728: WindowsEventType.ACCOUNT_MANAGEMENT,
        4732: WindowsEventType.ACCOUNT_MANAGEMENT,
        4756: WindowsEventType.ACCOUNT_MANAGEMENT,

        # Process events
        4688: WindowsEventType.PROCESS,
        4689: WindowsEventType.PROCESS,
    }

    # Logon type descriptions
    LOGON_TYPES = {
        2: "Interactive (local keyboard)",
        3: "Network (SMB, shared folders)",
        4: "Batch (scheduled task)",
        5: "Service",
        7: "Unlock",
        8: "NetworkCleartext",
        9: "NewCredentials",
        10: "RemoteInteractive (RDP)",
        11: "CachedInteractive",
    }

    # Failure reason codes for 4625
    FAILURE_REASONS = {
        "0xc0000064": "User does not exist",
        "0xc000006a": "Incorrect password",
        "0xc000006d": "Bad username or password",
        "0xc000006e": "Account restriction",
        "0xc000006f": "Logon outside allowed hours",
        "0xc0000070": "Logon from unauthorized workstation",
        "0xc0000071": "Expired password",
        "0xc0000072": "Account disabled",
        "0xc00000dc": "Server in wrong state",
        "0xc0000133": "Clocks out of sync",
        "0xc000015b": "Logon type not granted",
        "0xc000018c": "Trust relationship failed",
        "0xc0000192": "NetLogon service not started",
        "0xc0000193": "Account expired",
        "0xc0000224": "Password must change",
        "0xc0000225": "Windows bug",
        "0xc0000234": "Account locked out",
    }

    # XML namespace for Windows events
    XML_NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    # Pattern for text/CSV format
    TEXT_PATTERN = re.compile(
        r'(?P<date>\d{1,2}/\d{1,2}/\d{4})\s+'
        r'(?P<time>\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?)\s+'
        r'(?P<level>\w+)\s+'
        r'(?P<source>\S+)\s+'
        r'(?P<event_id>\d+)\s+'
        r'(?P<task_category>[^,\t]+)?'
    )

    # Alternative CSV pattern
    CSV_PATTERN = re.compile(
        r'"?(?P<level>\w+)"?\s*,\s*'
        r'"?(?P<date_time>[^",]+)"?\s*,\s*'
        r'"?(?P<source>[^",]+)"?\s*,\s*'
        r'"?(?P<event_id>\d+)"?'
    )

    def __init__(self):
        """Initialize Windows Event log parser."""
        super().__init__("windows")
        self._current_format = None

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """
        Parse a single Windows Event log line.

        Args:
            line: Raw log line (text/CSV format)

        Returns:
            LogEntry if parsing successful, None otherwise
        """
        # Try text format
        match = self.TEXT_PATTERN.match(line)
        if match:
            return self._parse_text_format(match, line)

        # Try CSV format
        match = self.CSV_PATTERN.match(line)
        if match:
            return self._parse_csv_format(match, line)

        return None

    def parse_xml(self, xml_content: str) -> List[LogEntry]:
        """
        Parse Windows Event log XML export.

        Args:
            xml_content: XML content string

        Returns:
            List of LogEntry objects
        """
        entries = []

        try:
            # Wrap in root element if needed
            if not xml_content.strip().startswith('<?xml'):
                xml_content = f'<Events>{xml_content}</Events>'

            root = ET.fromstring(xml_content)

            # Handle both single events and event collections
            events = root.findall('.//Event', self.XML_NS)
            if not events:
                events = root.findall('.//e:Event', self.XML_NS)
            if not events:
                events = [root] if root.tag.endswith('Event') else []

            for event in events:
                entry = self._parse_xml_event(event)
                if entry:
                    entries.append(entry)

        except ET.ParseError:
            pass

        return entries

    def _parse_xml_event(self, event: ET.Element) -> Optional[LogEntry]:
        """Parse a single XML event element."""
        try:
            # Get System info
            system = event.find('System', self.XML_NS) or event.find('e:System', self.XML_NS)
            if system is None:
                system = event.find('.//System') or event.find('.//{*}System')

            if system is None:
                return None

            # Extract event ID
            event_id_elem = system.find('EventID', self.XML_NS) or system.find('.//EventID') or system.find('.//{*}EventID')
            event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else 0

            # Extract timestamp
            time_created = system.find('TimeCreated', self.XML_NS) or system.find('.//TimeCreated') or system.find('.//{*}TimeCreated')
            timestamp_str = time_created.get('SystemTime') if time_created is not None else None
            timestamp = self._parse_xml_timestamp(timestamp_str) if timestamp_str else datetime.now()

            # Extract computer name
            computer = system.find('Computer', self.XML_NS) or system.find('.//Computer') or system.find('.//{*}Computer')
            hostname = computer.text if computer is not None else "unknown"

            # Get EventData
            event_data = event.find('EventData', self.XML_NS) or event.find('.//EventData') or event.find('.//{*}EventData')
            data_dict = {}

            if event_data is not None:
                for data in event_data:
                    name = data.get('Name', '')
                    value = data.text or ''
                    if name:
                        data_dict[name] = value

            # Classify event
            event_type = self.EVENT_CATEGORIES.get(event_id, WindowsEventType.OTHER)

            # Extract relevant fields based on event type
            source_ip = data_dict.get('IpAddress', data_dict.get('SourceNetworkAddress'))
            user = data_dict.get('TargetUserName', data_dict.get('SubjectUserName'))
            logon_type = data_dict.get('LogonType')

            # Build message
            message = f"Event {event_id}: {event_type.value}"
            if user:
                message += f" - User: {user}"
            if source_ip and source_ip != '-':
                message += f" from {source_ip}"

            return LogEntry(
                timestamp=timestamp,
                source_ip=source_ip if source_ip and source_ip != '-' else None,
                user=user,
                action=event_type.value,
                status_code=event_id,
                message=message,
                log_type=self.log_type,
                raw_line=ET.tostring(event, encoding='unicode')[:500],
                metadata={
                    'event_id': event_id,
                    'hostname': hostname,
                    'event_type': event_type.value,
                    'logon_type': self.LOGON_TYPES.get(int(logon_type), logon_type) if logon_type else None,
                    'failure_reason': self._get_failure_reason(data_dict),
                    **{k: v for k, v in data_dict.items() if k not in ['IpAddress', 'TargetUserName']}
                }
            )

        except Exception:
            return None

    def _parse_text_format(self, match: re.Match, raw_line: str) -> LogEntry:
        """Parse text format Windows event."""
        groups = match.groupdict()

        # Parse timestamp
        try:
            date_str = groups['date']
            time_str = groups['time'].strip()
            timestamp = datetime.strptime(f"{date_str} {time_str}", "%m/%d/%Y %I:%M:%S %p")
        except ValueError:
            try:
                timestamp = datetime.strptime(f"{date_str} {time_str}", "%m/%d/%Y %H:%M:%S")
            except ValueError:
                timestamp = datetime.now()

        event_id = int(groups.get('event_id', 0))
        event_type = self.EVENT_CATEGORIES.get(event_id, WindowsEventType.OTHER)

        return LogEntry(
            timestamp=timestamp,
            action=event_type.value,
            status_code=event_id,
            message=raw_line,
            log_type=self.log_type,
            raw_line=raw_line,
            metadata={
                'event_id': event_id,
                'level': groups.get('level'),
                'source': groups.get('source'),
                'task_category': groups.get('task_category'),
                'event_type': event_type.value,
            }
        )

    def _parse_csv_format(self, match: re.Match, raw_line: str) -> LogEntry:
        """Parse CSV format Windows event."""
        groups = match.groupdict()

        # Parse timestamp
        try:
            timestamp = datetime.strptime(groups['date_time'], "%m/%d/%Y %I:%M:%S %p")
        except ValueError:
            timestamp = datetime.now()

        event_id = int(groups.get('event_id', 0))
        event_type = self.EVENT_CATEGORIES.get(event_id, WindowsEventType.OTHER)

        return LogEntry(
            timestamp=timestamp,
            action=event_type.value,
            status_code=event_id,
            message=raw_line,
            log_type=self.log_type,
            raw_line=raw_line,
            metadata={
                'event_id': event_id,
                'level': groups.get('level'),
                'source': groups.get('source'),
                'event_type': event_type.value,
            }
        )

    def _parse_xml_timestamp(self, ts_str: str) -> datetime:
        """Parse XML timestamp format."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue

        return datetime.now()

    def _get_failure_reason(self, data_dict: Dict[str, Any]) -> Optional[str]:
        """Get human-readable failure reason from status code."""
        status = data_dict.get('Status', '').lower()
        sub_status = data_dict.get('SubStatus', '').lower()

        reason = self.FAILURE_REASONS.get(status)
        if not reason:
            reason = self.FAILURE_REASONS.get(sub_status)

        return reason

    def detect_format(self, sample_lines: List[str]) -> bool:
        """
        Detect if sample lines match Windows Event log format.

        Args:
            sample_lines: Sample log lines to analyze

        Returns:
            True if format appears to be Windows Event log
        """
        if not sample_lines:
            return False

        indicators = [
            'Security', 'Microsoft-Windows', 'EventID',
            'Event ID', 'Audit Success', 'Audit Failure',
            'Information', 'Warning', 'Error', 'Critical',
            '<Event', '</Event>'
        ]

        matches = 0
        for line in sample_lines[:10]:
            line_lower = line.lower()
            if any(ind.lower() in line_lower for ind in indicators):
                matches += 1
            elif self.TEXT_PATTERN.match(line) or self.CSV_PATTERN.match(line):
                matches += 1

        valid_lines = len([l for l in sample_lines[:10] if l.strip()])
        return matches >= valid_lines * 0.3 if valid_lines > 0 else False
