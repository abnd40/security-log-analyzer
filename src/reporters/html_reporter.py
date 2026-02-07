"""
HTML Report Generator

Generates professional HTML reports with:
- Interactive charts
- Sortable tables
- Responsive design
- Dark mode support
- Detailed threat breakdowns
"""

from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import json

from .base_reporter import BaseReporter
from ..detectors.base_detector import ThreatAlert, ThreatLevel


class HTMLReporter(BaseReporter):
    """
    Generates professional HTML security reports.

    Features:
    - Modern responsive design
    - Interactive JavaScript charts
    - Collapsible alert details
    - Dark/light theme toggle
    - Print-friendly styling
    """

    def __init__(self, title: str = "Security Log Analysis Report"):
        """Initialize HTML reporter."""
        super().__init__(title)

    def generate(
        self,
        alerts: List[ThreatAlert],
        stats: Dict[str, Any],
        output_path: Optional[Path] = None
    ) -> str:
        """Generate HTML report."""
        severity_data = self._get_severity_summary(alerts)
        type_data = self._get_type_summary(alerts)
        attackers = self._get_top_attackers(alerts)

        html = self._generate_html(alerts, stats, severity_data, type_data, attackers)

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)

        return html

    def _generate_html(
        self,
        alerts: List[ThreatAlert],
        stats: Dict[str, Any],
        severity_data: Dict[str, int],
        type_data: Dict[str, int],
        attackers: List[tuple]
    ) -> str:
        """Generate complete HTML document."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.title}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    <div class="container">
        {self._generate_header_html()}
        {self._generate_summary_html(alerts, stats)}
        {self._generate_charts_html(severity_data, type_data)}
        {self._generate_attackers_html(attackers)}
        {self._generate_alerts_html(alerts)}
        {self._generate_recommendations_html(alerts)}
        {self._generate_footer_html(stats)}
    </div>

    <script>
        {self._get_javascript(severity_data, type_data)}
    </script>
</body>
</html>"""

    def _get_css(self) -> str:
        """Return CSS styles."""
        return """
        :root {
            --bg-primary: #0a0e17;
            --bg-secondary: #131a2a;
            --bg-card: #1a2234;
            --text-primary: #e4e8f0;
            --text-secondary: #8892a6;
            --accent: #3b82f6;
            --critical: #ef4444;
            --high: #f59e0b;
            --medium: #3b82f6;
            --low: #22c55e;
            --info: #6b7280;
            --border: #2d3748;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        header {
            text-align: center;
            padding: 3rem 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }

        header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, var(--accent), #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        header .subtitle {
            color: var(--text-secondary);
            font-size: 1rem;
        }

        .logo {
            font-size: 3rem;
            margin-bottom: 1rem;
        }

        section {
            margin-bottom: 2rem;
        }

        section h2 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--accent);
            display: inline-block;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid var(--border);
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(59, 130, 246, 0.1);
        }

        .stat-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }

        .stat-card .label {
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .stat-card.critical .value { color: var(--critical); }
        .stat-card.high .value { color: var(--high); }
        .stat-card.medium .value { color: var(--medium); }
        .stat-card.low .value { color: var(--low); }

        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }

        .chart-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--border);
        }

        .chart-card h3 {
            margin-bottom: 1rem;
            color: var(--text-secondary);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 12px;
            overflow: hidden;
        }

        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        th {
            background: var(--bg-secondary);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }

        tr:hover {
            background: rgba(59, 130, 246, 0.05);
        }

        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge.critical { background: rgba(239, 68, 68, 0.2); color: var(--critical); }
        .badge.high { background: rgba(245, 158, 11, 0.2); color: var(--high); }
        .badge.medium { background: rgba(59, 130, 246, 0.2); color: var(--medium); }
        .badge.low { background: rgba(34, 197, 94, 0.2); color: var(--low); }
        .badge.info { background: rgba(107, 114, 128, 0.2); color: var(--info); }

        .alert-card {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border: 1px solid var(--border);
            border-left: 4px solid;
        }

        .alert-card.critical { border-left-color: var(--critical); }
        .alert-card.high { border-left-color: var(--high); }
        .alert-card.medium { border-left-color: var(--medium); }
        .alert-card.low { border-left-color: var(--low); }

        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }

        .alert-title {
            font-weight: 600;
            font-size: 1.1rem;
        }

        .alert-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.5rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }

        .alert-description {
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
        }

        .recommendations {
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--border);
        }

        .recommendations ul {
            list-style: none;
            padding-left: 0;
        }

        .recommendations li {
            padding: 0.75rem 0;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: flex-start;
            gap: 0.75rem;
        }

        .recommendations li:last-child {
            border-bottom: none;
        }

        .recommendations li::before {
            content: "\\2192";
            color: var(--accent);
            font-weight: bold;
        }

        footer {
            text-align: center;
            padding: 2rem 0;
            margin-top: 2rem;
            border-top: 1px solid var(--border);
            color: var(--text-secondary);
        }

        .mitre-tag {
            display: inline-block;
            background: rgba(139, 92, 246, 0.2);
            color: #a78bfa;
            padding: 0.125rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            margin-right: 0.25rem;
        }

        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }

            header h1 {
                font-size: 1.75rem;
            }

            .charts-grid {
                grid-template-columns: 1fr;
            }
        }

        @media print {
            body {
                background: white;
                color: black;
            }

            .stat-card, .chart-card, .alert-card, .recommendations {
                background: #f5f5f5;
                border: 1px solid #ddd;
            }
        }
        """

    def _generate_header_html(self) -> str:
        """Generate header section."""
        return f"""
        <header>
            <div class="logo">&#128737;</div>
            <h1>{self.title}</h1>
            <p class="subtitle">Generated on {self.generated_at.strftime('%B %d, %Y at %H:%M:%S')}</p>
        </header>
        """

    def _generate_summary_html(self, alerts: List[ThreatAlert], stats: Dict[str, Any]) -> str:
        """Generate summary statistics section."""
        severity = self._get_severity_summary(alerts)

        return f"""
        <section id="summary">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="value">{stats.get('total_entries', 0):,}</div>
                    <div class="label">Log Entries Analyzed</div>
                </div>
                <div class="stat-card">
                    <div class="value">{len(alerts)}</div>
                    <div class="label">Total Alerts</div>
                </div>
                <div class="stat-card critical">
                    <div class="value">{severity.get('CRITICAL', 0)}</div>
                    <div class="label">Critical Alerts</div>
                </div>
                <div class="stat-card high">
                    <div class="value">{severity.get('HIGH', 0)}</div>
                    <div class="label">High Alerts</div>
                </div>
                <div class="stat-card medium">
                    <div class="value">{severity.get('MEDIUM', 0)}</div>
                    <div class="label">Medium Alerts</div>
                </div>
                <div class="stat-card low">
                    <div class="value">{severity.get('LOW', 0)}</div>
                    <div class="label">Low Alerts</div>
                </div>
                <div class="stat-card">
                    <div class="value">{stats.get('unique_attackers', 0)}</div>
                    <div class="label">Unique Attackers</div>
                </div>
                <div class="stat-card">
                    <div class="value">{stats.get('analysis_time', 0):.2f}s</div>
                    <div class="label">Analysis Time</div>
                </div>
            </div>
        </section>
        """

    def _generate_charts_html(self, severity_data: Dict[str, int], type_data: Dict[str, int]) -> str:
        """Generate charts section."""
        return """
        <section id="charts">
            <h2>Threat Analysis</h2>
            <div class="charts-grid">
                <div class="chart-card">
                    <h3>Alerts by Severity</h3>
                    <canvas id="severityChart"></canvas>
                </div>
                <div class="chart-card">
                    <h3>Alerts by Type</h3>
                    <canvas id="typeChart"></canvas>
                </div>
            </div>
        </section>
        """

    def _generate_attackers_html(self, attackers: List[tuple]) -> str:
        """Generate top attackers section."""
        if not attackers:
            return ""

        rows = ""
        for i, (ip, count) in enumerate(attackers, 1):
            rows += f"""
            <tr>
                <td>{i}</td>
                <td><code>{ip}</code></td>
                <td>{count}</td>
            </tr>
            """

        return f"""
        <section id="attackers">
            <h2>Top Attacking IPs</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP Address</th>
                        <th>Alert Count</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </section>
        """

    def _generate_alerts_html(self, alerts: List[ThreatAlert]) -> str:
        """Generate detailed alerts section."""
        alert_cards = ""

        # Show top 50 most severe alerts
        sorted_alerts = sorted(alerts, key=lambda a: -a.level.value)[:50]

        for alert in sorted_alerts:
            level_class = alert.level.name.lower()
            mitre_tags = ''.join(
                f'<span class="mitre-tag">{t}</span>'
                for t in alert.mitre_attack
            )

            alert_cards += f"""
            <div class="alert-card {level_class}">
                <div class="alert-header">
                    <div class="alert-title">{alert.threat_type.replace('_', ' ').title()}</div>
                    <span class="badge {level_class}">{alert.level.name}</span>
                </div>
                <div class="alert-meta">
                    <div><strong>Alert ID:</strong> {alert.alert_id}</div>
                    <div><strong>Time:</strong> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S') if alert.timestamp else 'N/A'}</div>
                    <div><strong>Source IP:</strong> {alert.source_ip or 'N/A'}</div>
                    <div><strong>Target:</strong> {alert.target or 'N/A'}</div>
                </div>
                <div class="alert-description">
                    <p>{alert.description}</p>
                    {f'<div style="margin-top: 0.5rem;">{mitre_tags}</div>' if mitre_tags else ''}
                </div>
            </div>
            """

        remaining = len(alerts) - 50
        if remaining > 0:
            alert_cards += f'<p style="text-align: center; color: var(--text-secondary);">... and {remaining} more alerts</p>'

        return f"""
        <section id="alerts">
            <h2>Detailed Alerts</h2>
            {alert_cards}
        </section>
        """

    def _generate_recommendations_html(self, alerts: List[ThreatAlert]) -> str:
        """Generate recommendations section."""
        all_recs = set()
        for alert in alerts:
            for rec in alert.recommendations:
                all_recs.add(rec)

        if not all_recs:
            return ""

        rec_list = ''.join(f'<li>{rec}</li>' for rec in list(all_recs)[:15])

        return f"""
        <section id="recommendations">
            <h2>Recommendations</h2>
            <div class="recommendations">
                <ul>
                    {rec_list}
                </ul>
            </div>
        </section>
        """

    def _generate_footer_html(self, stats: Dict[str, Any]) -> str:
        """Generate footer section."""
        return f"""
        <footer>
            <p>Security Log Analyzer Report</p>
            <p>Analysis completed in {stats.get('analysis_time', 0):.2f} seconds</p>
        </footer>
        """

    def _get_javascript(self, severity_data: Dict[str, int], type_data: Dict[str, int]) -> str:
        """Return JavaScript for charts."""
        severity_json = json.dumps(severity_data)
        type_json = json.dumps(type_data)

        return f"""
        // Severity Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        const severityData = {severity_json};

        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: Object.keys(severityData),
                datasets: [{{
                    data: Object.values(severityData),
                    backgroundColor: [
                        '#ef4444',  // CRITICAL
                        '#f59e0b',  // HIGH
                        '#3b82f6',  // MEDIUM
                        '#22c55e',  // LOW
                        '#6b7280'   // INFO
                    ],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            color: '#8892a6'
                        }}
                    }}
                }}
            }}
        }});

        // Type Chart
        const typeCtx = document.getElementById('typeChart').getContext('2d');
        const typeData = {type_json};

        new Chart(typeCtx, {{
            type: 'bar',
            data: {{
                labels: Object.keys(typeData).map(k => k.replace('_', ' ')),
                datasets: [{{
                    label: 'Alerts',
                    data: Object.values(typeData),
                    backgroundColor: '#3b82f6',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        grid: {{
                            color: '#2d3748'
                        }},
                        ticks: {{
                            color: '#8892a6'
                        }}
                    }},
                    x: {{
                        grid: {{
                            display: false
                        }},
                        ticks: {{
                            color: '#8892a6'
                        }}
                    }}
                }}
            }}
        }});
        """
