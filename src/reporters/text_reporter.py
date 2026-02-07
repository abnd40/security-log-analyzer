"""
Text Report Generator

Generates formatted text reports for terminal display with
ANSI color support for threat level highlighting.
"""

from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from .base_reporter import BaseReporter
from ..detectors.base_detector import ThreatAlert, ThreatLevel


class TextReporter(BaseReporter):
    """
    Generates text reports for terminal display.

    Features:
    - ANSI color coding for severity levels
    - ASCII art headers
    - Structured sections for easy reading
    - Summary statistics
    """

    # ANSI color codes
    COLORS = {
        'CRITICAL': '\033[91m',  # Red
        'HIGH': '\033[93m',      # Yellow
        'MEDIUM': '\033[94m',    # Blue
        'LOW': '\033[92m',       # Green
        'INFO': '\033[90m',      # Gray
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'HEADER': '\033[95m',    # Magenta
    }

    def __init__(self, title: str = "Security Log Analysis Report", use_colors: bool = True):
        """
        Initialize text reporter.

        Args:
            title: Report title
            use_colors: Enable ANSI color output
        """
        super().__init__(title)
        self.use_colors = use_colors

    def _color(self, text: str, color: str) -> str:
        """Apply color to text if colors enabled."""
        if not self.use_colors:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['RESET']}"

    def generate(
        self,
        alerts: List[ThreatAlert],
        stats: Dict[str, Any],
        output_path: Optional[Path] = None
    ) -> str:
        """Generate text report."""
        lines = []

        # Header
        lines.extend(self._generate_header())
        lines.append("")

        # Executive Summary
        lines.extend(self._generate_summary(alerts, stats))
        lines.append("")

        # Severity Breakdown
        lines.extend(self._generate_severity_section(alerts))
        lines.append("")

        # Top Threats
        lines.extend(self._generate_top_threats(alerts))
        lines.append("")

        # Top Attackers
        lines.extend(self._generate_top_attackers(alerts))
        lines.append("")

        # Detailed Alerts
        lines.extend(self._generate_alert_details(alerts))
        lines.append("")

        # Recommendations
        lines.extend(self._generate_recommendations(alerts))
        lines.append("")

        # Footer
        lines.extend(self._generate_footer(stats))

        report = '\n'.join(lines)

        if output_path:
            # Remove color codes for file output
            clean_report = self._strip_colors(report)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(clean_report)

        return report

    def _generate_header(self) -> List[str]:
        """Generate report header."""
        header = [
            self._color("=" * 80, 'HEADER'),
            self._color(r"""
   _____ ______ _____ _    _ _____  _____ _________     __
  / ____|  ____/ ____| |  | |  __ \|_   _|__   __\ \   / /
 | (___ | |__ | |    | |  | | |__) | | |    | |   \ \_/ /
  \___ \|  __|| |    | |  | |  _  /  | |    | |    \   /
  ____) | |___| |____| |__| | | \ \ _| |_   | |     | |
 |_____/|______\_____|\____/|_|  \_\_____|  |_|     |_|

  _      ____   _____            _   _          _  __     _______ ______ _____
 | |    / __ \ / ____|     /\   | \ | |   /\   | | \ \   / /___  |  ____|  __ \
 | |   | |  | | |  __     /  \  |  \| |  /  \  | |  \ \_/ /   / /| |__  | |__) |
 | |   | |  | | | |_ |   / /\ \ | . ` | / /\ \ | |   \   /   / / |  __| |  _  /
 | |___| |__| | |__| |  / ____ \| |\  |/ ____ \| |____| |   / /__| |____| | \ \
 |______\____/ \_____| /_/    \_\_| \_/_/    \_\______|_|  /_____|______|_|  \_\
""", 'HEADER'),
            self._color("=" * 80, 'HEADER'),
            "",
            self._color(f"  {self.title}", 'BOLD'),
            f"  Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}",
            self._color("=" * 80, 'HEADER'),
        ]
        return header

    def _generate_summary(self, alerts: List[ThreatAlert], stats: Dict[str, Any]) -> List[str]:
        """Generate executive summary."""
        severity = self._get_severity_summary(alerts)

        lines = [
            self._color("  EXECUTIVE SUMMARY", 'BOLD'),
            self._color("-" * 40, 'HEADER'),
            "",
            f"  Total Log Entries Analyzed: {stats.get('total_entries', 0):,}",
            f"  Analysis Duration: {stats.get('analysis_time', 0):.2f} seconds",
            f"  Unique Source IPs: {stats.get('unique_source_ips', 0):,}",
            f"  Time Range: {stats.get('time_range', {}).get('start', 'N/A')} to "
            f"{stats.get('time_range', {}).get('end', 'N/A')}",
            "",
            self._color("  THREAT OVERVIEW:", 'BOLD'),
            f"  {self._color(f'CRITICAL: {severity.get(\"CRITICAL\", 0)}', 'CRITICAL')}",
            f"  {self._color(f'HIGH: {severity.get(\"HIGH\", 0)}', 'HIGH')}",
            f"  {self._color(f'MEDIUM: {severity.get(\"MEDIUM\", 0)}', 'MEDIUM')}",
            f"  {self._color(f'LOW: {severity.get(\"LOW\", 0)}', 'LOW')}",
            f"  {self._color(f'INFO: {severity.get(\"INFO\", 0)}', 'INFO')}",
            "",
            f"  {self._color(f'TOTAL ALERTS: {len(alerts)}', 'BOLD')}",
        ]
        return lines

    def _generate_severity_section(self, alerts: List[ThreatAlert]) -> List[str]:
        """Generate severity breakdown with visual bar."""
        lines = [
            self._color("  SEVERITY DISTRIBUTION", 'BOLD'),
            self._color("-" * 40, 'HEADER'),
        ]

        severity = self._get_severity_summary(alerts)
        total = max(sum(severity.values()), 1)

        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity.get(level, 0)
            pct = count / total * 100
            bar_len = int(pct / 2)
            bar = '#' * bar_len

            lines.append(
                f"  {self._color(f'{level:10}', level)} "
                f"[{self._color(bar.ljust(50), level)}] "
                f"{count:4} ({pct:5.1f}%)"
            )

        return lines

    def _generate_top_threats(self, alerts: List[ThreatAlert]) -> List[str]:
        """Generate top threat types section."""
        lines = [
            self._color("  TOP THREAT TYPES", 'BOLD'),
            self._color("-" * 40, 'HEADER'),
        ]

        types = self._get_type_summary(alerts)
        sorted_types = sorted(types.items(), key=lambda x: -x[1])

        for threat_type, count in sorted_types[:10]:
            lines.append(f"  {threat_type:30} {count:5}")

        return lines

    def _generate_top_attackers(self, alerts: List[ThreatAlert]) -> List[str]:
        """Generate top attackers section."""
        lines = [
            self._color("  TOP ATTACKING IPs", 'BOLD'),
            self._color("-" * 40, 'HEADER'),
        ]

        attackers = self._get_top_attackers(alerts)

        for ip, count in attackers:
            lines.append(f"  {ip:20} {count:5} alerts")

        if not attackers:
            lines.append("  No attacking IPs identified")

        return lines

    def _generate_alert_details(self, alerts: List[ThreatAlert]) -> List[str]:
        """Generate detailed alert listing."""
        lines = [
            self._color("  DETAILED ALERTS", 'BOLD'),
            self._color("-" * 40, 'HEADER'),
        ]

        # Group by severity
        for level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.MEDIUM]:
            level_alerts = [a for a in alerts if a.level == level]

            if level_alerts:
                lines.append("")
                lines.append(self._color(f"  [{level.name}] ALERTS ({len(level_alerts)})", level.name))
                lines.append("")

                for alert in level_alerts[:15]:  # Limit to 15 per level
                    lines.append(self._format_alert(alert))
                    lines.append("")

                if len(level_alerts) > 15:
                    lines.append(f"  ... and {len(level_alerts) - 15} more {level.name} alerts")

        return lines

    def _format_alert(self, alert: ThreatAlert) -> str:
        """Format a single alert for display."""
        lines = [
            f"  {self._color('Alert ID:', 'BOLD')} {alert.alert_id}",
            f"  {self._color('Time:', 'BOLD')} {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S') if alert.timestamp else 'N/A'}",
            f"  {self._color('Type:', 'BOLD')} {alert.threat_type}",
            f"  {self._color('Source IP:', 'BOLD')} {alert.source_ip or 'N/A'}",
            f"  {self._color('Target:', 'BOLD')} {alert.target or 'N/A'}",
            f"  {self._color('Description:', 'BOLD')} {alert.description}",
        ]

        if alert.mitre_attack:
            lines.append(f"  {self._color('MITRE ATT&CK:', 'BOLD')} {', '.join(alert.mitre_attack)}")

        return '\n'.join(lines)

    def _generate_recommendations(self, alerts: List[ThreatAlert]) -> List[str]:
        """Generate recommendations section."""
        lines = [
            self._color("  RECOMMENDATIONS", 'BOLD'),
            self._color("-" * 40, 'HEADER'),
        ]

        # Collect unique recommendations
        all_recs = set()
        for alert in alerts:
            for rec in alert.recommendations:
                all_recs.add(rec)

        for i, rec in enumerate(list(all_recs)[:15], 1):
            lines.append(f"  {i}. {rec}")

        return lines

    def _generate_footer(self, stats: Dict[str, Any]) -> List[str]:
        """Generate report footer."""
        return [
            self._color("=" * 80, 'HEADER'),
            "  Report generated by Security Log Analyzer",
            f"  Analysis completed in {stats.get('analysis_time', 0):.2f} seconds",
            self._color("=" * 80, 'HEADER'),
        ]

    def _strip_colors(self, text: str) -> str:
        """Remove ANSI color codes from text."""
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
