"""
Base Reporter Module

Provides abstract base class for report generators.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from ..detectors.base_detector import ThreatAlert, ThreatLevel


class BaseReporter(ABC):
    """
    Abstract base class for report generators.

    All report formats must inherit from this class and implement
    the required abstract methods.
    """

    def __init__(self, title: str = "Security Log Analysis Report"):
        """
        Initialize reporter.

        Args:
            title: Report title
        """
        self.title = title
        self.generated_at = datetime.now()

    @abstractmethod
    def generate(
        self,
        alerts: List[ThreatAlert],
        stats: Dict[str, Any],
        output_path: Optional[Path] = None
    ) -> str:
        """
        Generate the report.

        Args:
            alerts: List of threat alerts
            stats: Analysis statistics
            output_path: Optional file path to save report

        Returns:
            Report content as string
        """
        pass

    def _get_severity_summary(self, alerts: List[ThreatAlert]) -> Dict[str, int]:
        """Get count of alerts by severity level."""
        summary = {level.name: 0 for level in ThreatLevel}
        for alert in alerts:
            summary[alert.level.name] += 1
        return summary

    def _get_type_summary(self, alerts: List[ThreatAlert]) -> Dict[str, int]:
        """Get count of alerts by threat type."""
        summary: Dict[str, int] = {}
        for alert in alerts:
            summary[alert.threat_type] = summary.get(alert.threat_type, 0) + 1
        return summary

    def _get_top_attackers(self, alerts: List[ThreatAlert], limit: int = 10) -> List[tuple]:
        """Get top attacking IPs by alert count."""
        ip_counts: Dict[str, int] = {}
        for alert in alerts:
            if alert.source_ip:
                ip_counts[alert.source_ip] = ip_counts.get(alert.source_ip, 0) + 1

        sorted_ips = sorted(ip_counts.items(), key=lambda x: -x[1])
        return sorted_ips[:limit]
