"""
Detection Engine

Orchestrates all threat detectors and provides unified analysis interface.
Handles detector registration, log routing, alert aggregation, and correlation.
"""

from typing import List, Dict, Any, Optional, Type
from pathlib import Path
from datetime import datetime
import json

from .base_detector import BaseDetector, ThreatAlert, ThreatLevel
from .brute_force_detector import BruteForceDetector
from .injection_detector import SQLInjectionDetector, XSSDetector
from .traversal_detector import DirectoryTraversalDetector
from .anomaly_detector import TemporalAnomalyDetector, GeoAnomalyDetector
from ..parsers.base_parser import BaseParser, LogEntry
from ..parsers import (
    ApacheParser, NginxParser, SyslogParser,
    AuthLogParser, WindowsEventParser
)


class DetectionEngine:
    """
    Central detection engine that coordinates all analysis.

    Provides:
    - Automatic log format detection
    - Multi-parser support
    - Parallel detector execution
    - Alert correlation and deduplication
    - Comprehensive statistics
    """

    def __init__(self, enable_all: bool = True):
        """
        Initialize detection engine.

        Args:
            enable_all: Enable all detectors by default
        """
        self.parsers: Dict[str, BaseParser] = {}
        self.detectors: Dict[str, BaseDetector] = {}

        # Initialize default parsers
        self._register_default_parsers()

        # Initialize default detectors
        if enable_all:
            self._register_default_detectors()

        # Analysis state
        self.entries: List[LogEntry] = []
        self.alerts: List[ThreatAlert] = []
        self.stats: Dict[str, Any] = {}
        self._analysis_start: Optional[datetime] = None
        self._analysis_end: Optional[datetime] = None

    def _register_default_parsers(self):
        """Register built-in log parsers."""
        self.parsers = {
            'apache': ApacheParser(),
            'nginx': NginxParser(),
            'syslog': SyslogParser(),
            'auth': AuthLogParser(),
            'windows': WindowsEventParser(),
        }

    def _register_default_detectors(self):
        """Register built-in threat detectors."""
        self.detectors = {
            'brute_force': BruteForceDetector(),
            'sql_injection': SQLInjectionDetector(),
            'xss': XSSDetector(),
            'directory_traversal': DirectoryTraversalDetector(),
            'temporal_anomaly': TemporalAnomalyDetector(),
            'geo_anomaly': GeoAnomalyDetector(),
        }

    def register_parser(self, name: str, parser: BaseParser):
        """Register a custom parser."""
        self.parsers[name] = parser

    def register_detector(self, name: str, detector: BaseDetector):
        """Register a custom detector."""
        self.detectors[name] = detector

    def enable_detector(self, name: str, enabled: bool = True):
        """Enable or disable a specific detector."""
        if name in self.detectors:
            self.detectors[name].enabled = enabled

    def detect_format(self, file_path: Path) -> Optional[str]:
        """
        Detect the format of a log file.

        Args:
            file_path: Path to the log file

        Returns:
            Parser name if detected, None otherwise
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                sample_lines = [line.strip() for line in f.readlines()[:20]]
        except Exception:
            return None

        # Try each parser
        for name, parser in self.parsers.items():
            if parser.detect_format(sample_lines):
                return name

        return None

    def parse_file(self, file_path: Path, format_hint: Optional[str] = None) -> List[LogEntry]:
        """
        Parse a log file.

        Args:
            file_path: Path to the log file
            format_hint: Optional parser name to use

        Returns:
            List of parsed log entries
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        # Detect or use hinted format
        parser_name = format_hint or self.detect_format(file_path)

        if not parser_name or parser_name not in self.parsers:
            raise ValueError(f"Unable to detect log format for: {file_path}")

        parser = self.parsers[parser_name]
        entries = list(parser.parse_file(file_path))

        return entries

    def analyze(
        self,
        entries: Optional[List[LogEntry]] = None,
        file_paths: Optional[List[Path]] = None,
        format_hints: Optional[Dict[str, str]] = None
    ) -> List[ThreatAlert]:
        """
        Run all enabled detectors on log entries.

        Args:
            entries: Pre-parsed log entries
            file_paths: Paths to log files to parse and analyze
            format_hints: Optional format hints for each file

        Returns:
            List of all detected threats
        """
        self._analysis_start = datetime.now()
        self.entries = entries or []
        self.alerts = []
        format_hints = format_hints or {}

        # Parse files if provided
        if file_paths:
            for file_path in file_paths:
                file_path = Path(file_path)
                hint = format_hints.get(str(file_path))
                try:
                    parsed = self.parse_file(file_path, hint)
                    self.entries.extend(parsed)
                except Exception as e:
                    print(f"Warning: Failed to parse {file_path}: {e}")

        # Sort entries by timestamp
        self.entries.sort(key=lambda e: e.timestamp if e.timestamp else datetime.min)

        # Run each enabled detector
        for name, detector in self.detectors.items():
            if detector.enabled:
                try:
                    detector_alerts = detector.analyze(self.entries)
                    self.alerts.extend(detector_alerts)
                except Exception as e:
                    print(f"Warning: Detector {name} failed: {e}")

        # Correlate and deduplicate alerts
        self.alerts = self._correlate_alerts(self.alerts)

        # Sort by severity then timestamp
        self.alerts.sort(
            key=lambda a: (-a.level.value, a.timestamp if a.timestamp else datetime.min)
        )

        self._analysis_end = datetime.now()
        self._compute_stats()

        return self.alerts

    def _correlate_alerts(self, alerts: List[ThreatAlert]) -> List[ThreatAlert]:
        """
        Correlate and deduplicate alerts.

        Combines related alerts and identifies attack campaigns.
        """
        if not alerts:
            return []

        # Group by source IP and time window
        ip_groups: Dict[str, List[ThreatAlert]] = {}
        for alert in alerts:
            ip = alert.source_ip or 'unknown'
            if ip not in ip_groups:
                ip_groups[ip] = []
            ip_groups[ip].append(alert)

        # Identify multi-vector attacks
        for ip, ip_alerts in ip_groups.items():
            if ip == 'unknown':
                continue

            threat_types = set(a.threat_type for a in ip_alerts)

            # If same IP uses multiple attack types, it's likely coordinated
            if len(threat_types) >= 2:
                for alert in ip_alerts:
                    alert.metadata['coordinated_attack'] = True
                    alert.metadata['attack_vectors'] = list(threat_types)

                    if alert.level.value < ThreatLevel.HIGH.value:
                        alert.level = ThreatLevel.HIGH
                        alert.description += " (Part of multi-vector attack)"

        # Deduplicate very similar alerts
        seen = set()
        unique_alerts = []

        for alert in alerts:
            # Create dedup key
            key = (
                alert.threat_type,
                alert.source_ip,
                alert.target,
                alert.timestamp.strftime('%Y-%m-%d %H:%M') if alert.timestamp else ''
            )

            if key not in seen:
                seen.add(key)
                unique_alerts.append(alert)

        return unique_alerts

    def _compute_stats(self):
        """Compute analysis statistics."""
        self.stats = {
            'analysis_time': (
                (self._analysis_end - self._analysis_start).total_seconds()
                if self._analysis_start and self._analysis_end else 0
            ),
            'total_entries': len(self.entries),
            'total_alerts': len(self.alerts),
            'alerts_by_level': {},
            'alerts_by_type': {},
            'unique_source_ips': len(set(e.source_ip for e in self.entries if e.source_ip)),
            'unique_attackers': len(set(a.source_ip for a in self.alerts if a.source_ip)),
            'time_range': self._get_time_range(),
            'detector_stats': {
                name: detector.get_stats()
                for name, detector in self.detectors.items()
            },
        }

        # Count by level
        for alert in self.alerts:
            level_name = alert.level.name
            self.stats['alerts_by_level'][level_name] = \
                self.stats['alerts_by_level'].get(level_name, 0) + 1

        # Count by type
        for alert in self.alerts:
            self.stats['alerts_by_type'][alert.threat_type] = \
                self.stats['alerts_by_type'].get(alert.threat_type, 0) + 1

    def _get_time_range(self) -> Dict[str, str]:
        """Get the time range of analyzed entries."""
        timestamps = [e.timestamp for e in self.entries if e.timestamp]
        if not timestamps:
            return {'start': 'N/A', 'end': 'N/A'}

        return {
            'start': min(timestamps).isoformat(),
            'end': max(timestamps).isoformat(),
        }

    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary."""
        return {
            'total_alerts': len(self.alerts),
            'critical': self.stats.get('alerts_by_level', {}).get('CRITICAL', 0),
            'high': self.stats.get('alerts_by_level', {}).get('HIGH', 0),
            'medium': self.stats.get('alerts_by_level', {}).get('MEDIUM', 0),
            'low': self.stats.get('alerts_by_level', {}).get('LOW', 0),
            'info': self.stats.get('alerts_by_level', {}).get('INFO', 0),
            'unique_attackers': self.stats.get('unique_attackers', 0),
            'attack_types': list(self.stats.get('alerts_by_type', {}).keys()),
        }

    def export_alerts(self, format: str = 'json') -> str:
        """
        Export alerts in specified format.

        Args:
            format: Output format ('json' or 'csv')

        Returns:
            Formatted alert data
        """
        if format == 'json':
            return json.dumps(
                [alert.to_dict() for alert in self.alerts],
                indent=2,
                default=str
            )

        elif format == 'csv':
            if not self.alerts:
                return "No alerts to export"

            headers = [
                'alert_id', 'timestamp', 'level', 'threat_type',
                'source_ip', 'target', 'description'
            ]
            lines = [','.join(headers)]

            for alert in self.alerts:
                row = [
                    alert.alert_id,
                    alert.timestamp.isoformat() if alert.timestamp else '',
                    alert.level.name,
                    alert.threat_type,
                    alert.source_ip or '',
                    alert.target or '',
                    f'"{alert.description}"',
                ]
                lines.append(','.join(row))

            return '\n'.join(lines)

        else:
            raise ValueError(f"Unsupported format: {format}")
