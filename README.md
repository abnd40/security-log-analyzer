# Security Log Analyzer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg" alt="Status">
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red.svg" alt="MITRE ATT&CK">
</p>

A comprehensive, modular security log analysis tool designed for threat detection and incident response. This tool demonstrates practical detection engineering skills by implementing signature-based and behavioral analysis across multiple log formats.

## Overview

Security Log Analyzer parses common log formats and applies a multi-layered detection engine to identify security threats, including:

- **Brute Force Attacks** - Password guessing, credential stuffing, password spraying
- **Injection Attacks** - SQL injection, Cross-Site Scripting (XSS)
- **Directory Traversal** - Path traversal, Local File Inclusion (LFI)
- **Behavioral Anomalies** - Unusual access times, geographic impossibilities

All detections are mapped to the [MITRE ATT&CK](https://attack.mitre.org/) framework for standardized threat classification.

## Features

### Multi-Format Log Parsing

| Format | Description | Supported Variants |
|--------|-------------|-------------------|
| **Apache** | Web server access logs | Combined, Common, Custom |
| **Nginx** | Web server access/error logs | Access, Error, JSON |
| **Syslog** | System logging | RFC 3164, RFC 5424 |
| **Auth.log** | Linux authentication | SSH, sudo, PAM |
| **Windows** | Security event logs | Text, CSV, XML |

### Detection Capabilities

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        DETECTION ENGINE                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐       │
│  │  Brute Force     │  │  SQL Injection   │  │  XSS Detection   │       │
│  │  Detector        │  │  Detector        │  │                  │       │
│  │                  │  │                  │  │  - Script tags   │       │
│  │  - Single IP     │  │  - Union-based   │  │  - Event handlers│       │
│  │  - Distributed   │  │  - Boolean-blind │  │  - Data URIs     │       │
│  │  - Credential    │  │  - Time-based    │  │  - DOM-based     │       │
│  │    stuffing      │  │  - Error-based   │  │                  │       │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘       │
│                                                                          │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐       │
│  │  Directory       │  │  Temporal        │  │  Geographic      │       │
│  │  Traversal       │  │  Anomaly         │  │  Anomaly         │       │
│  │                  │  │                  │  │                  │       │
│  │  - Path escape   │  │  - Off-hours     │  │  - Impossible    │       │
│  │  - Encoding      │  │  - Weekend       │  │    travel        │       │
│  │    bypass        │  │  - Baseline      │  │  - New location  │       │
│  │  - LFI/RFI       │  │    deviation     │  │  - VPN/Tor       │       │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘       │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### MITRE ATT&CK Mapping

| Detection | Technique ID | Technique Name |
|-----------|--------------|----------------|
| Brute Force | T1110.001 | Password Guessing |
| Credential Stuffing | T1110.004 | Credential Stuffing |
| Password Spraying | T1110.003 | Password Spraying |
| SQL Injection | T1190 | Exploit Public-Facing Application |
| XSS | T1059.007 | JavaScript |
| Directory Traversal | T1083, T1005 | File Discovery, Data from Local System |
| Account Anomalies | T1078 | Valid Accounts |

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/security-log-analyzer.git
cd security-log-analyzer

# No external dependencies required!
# Python 3.8+ with standard library is all you need

# Optional: Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Verify installation
python analyzer.py --version
```

## Quick Start

### Run Demo Analysis

```bash
# Analyze included sample logs with simulated attacks
python analyzer.py --demo
```

### Analyze Your Logs

```bash
# Single file analysis
python analyzer.py /var/log/auth.log

# Auto-detect format
python analyzer.py access.log

# Specify format explicitly
python analyzer.py webserver.log --format nginx

# Analyze entire directory
python analyzer.py /var/log/ --recursive
```

### Generate Reports

```bash
# HTML report with interactive charts
python analyzer.py auth.log --output report.html

# Text report to file
python analyzer.py auth.log --output report.txt --output-format text

# Filter by severity
python analyzer.py auth.log --severity high
```

## Usage Examples

### Basic Analysis

```bash
$ python analyzer.py sample_logs/apache_access.log

╔══════════════════════════════════════════════════════════════════════════════╗
║   SECURITY LOG ANALYZER                                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

  EXECUTIVE SUMMARY
----------------------------------------
  Total Log Entries Analyzed: 67
  Analysis Duration: 0.15 seconds
  Unique Source IPs: 12

  THREAT OVERVIEW:
  CRITICAL: 2
  HIGH: 8
  MEDIUM: 15
  LOW: 4
  INFO: 3

  TOTAL ALERTS: 32
```

### Detection Examples

#### SQL Injection Detection
```
Alert ID: a3f2b1c8d4e5
Time: 2024-01-15 09:15:22
Type: sql_injection
Source IP: 45.33.32.156
Target: /search?q=1'+UNION+SELECT+NULL,username,password+FROM+users--
Description: SQL injection attempt detected in url: 'union select null'
MITRE ATT&CK: T1190
```

#### Brute Force Detection
```
Alert ID: b7c9d2e6f1a3
Time: 2024-01-15 09:00:10
Type: brute_force
Source IP: 45.33.32.156
Target: admin
Description: Brute force attack detected: 10 failed login attempts
             from 45.33.32.156 targeting user 'admin'
MITRE ATT&CK: T1110.001
```

#### Directory Traversal Detection
```
Alert ID: c4e8f3a2b9d1
Time: 2024-01-15 11:45:37
Type: directory_traversal
Source IP: 185.220.101.45
Target: /read?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
Description: SUCCESSFUL Directory traversal attempt: /etc/passwd
MITRE ATT&CK: T1083, T1005
```

## Architecture

```
security-log-analyzer/
├── analyzer.py              # Main CLI entry point
├── requirements.txt         # Dependencies
├── README.md               # Documentation
│
├── src/
│   ├── parsers/            # Log format parsers
│   │   ├── base_parser.py      # Abstract base class
│   │   ├── apache_parser.py    # Apache log parser
│   │   ├── nginx_parser.py     # Nginx log parser
│   │   ├── syslog_parser.py    # Syslog parser
│   │   ├── auth_parser.py      # Auth.log parser
│   │   └── windows_parser.py   # Windows Event parser
│   │
│   ├── detectors/          # Threat detection modules
│   │   ├── base_detector.py        # Abstract base class
│   │   ├── brute_force_detector.py # Auth attack detection
│   │   ├── injection_detector.py   # SQLi/XSS detection
│   │   ├── traversal_detector.py   # Path traversal detection
│   │   ├── anomaly_detector.py     # Behavioral analysis
│   │   └── detection_engine.py     # Orchestration engine
│   │
│   └── reporters/          # Report generators
│       ├── base_reporter.py    # Abstract base class
│       ├── text_reporter.py    # Terminal output
│       └── html_reporter.py    # HTML reports
│
├── sample_logs/            # Demo log files
│   ├── apache_access.log
│   ├── auth.log
│   ├── nginx_access.log
│   └── windows_security.log
│
└── reports/                # Generated reports
```

## Detection Rules Explained

### Brute Force Detection

The brute force detector uses a multi-dimensional approach:

1. **Single-IP Attack**: Tracks failed authentication attempts per IP/user pair
   - Threshold: 5 failures in 10 minutes
   - Escalates if successful login follows (potential compromise)

2. **Credential Stuffing**: Detects single IP targeting multiple accounts
   - Threshold: 3+ different usernames from same IP
   - Indicates automated credential testing

3. **Distributed Attack**: Multiple IPs targeting single account
   - Threshold: 10+ unique IPs targeting same user
   - Indicates coordinated botnet attack

### Injection Detection

SQL Injection patterns are categorized by severity:

| Severity | Patterns | Risk |
|----------|----------|------|
| Critical | UNION SELECT, INTO OUTFILE, LOAD_FILE | Data exfiltration |
| High | SLEEP(), BENCHMARK(), Boolean blind | Active exploitation |
| Medium | OR 1=1, encoded payloads | Probing/testing |
| Low | ORDER BY, LIMIT manipulation | Reconnaissance |

XSS patterns include:
- Script tag injection
- Event handler injection (onload, onerror, etc.)
- JavaScript protocol handlers
- Data URI schemes
- DOM manipulation attempts

### Directory Traversal Detection

Detects various encoding bypass techniques:
- Standard: `../`, `..\`
- URL encoded: `%2e%2e%2f`
- Double encoded: `%252e%252e%252f`
- Unicode: `%c0%ae%c0%ae`
- Null byte: `%00`

Monitors access to sensitive files:
- `/etc/passwd`, `/etc/shadow`
- SSH keys, configuration files
- Application secrets (`.env`, `config.php`)
- Version control (`.git/config`)

## Extending the Analyzer

### Adding Custom Detectors

```python
from src.detectors.base_detector import BaseDetector, ThreatAlert, ThreatLevel

class CustomDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="custom_detector",
            description="Detects custom threat patterns"
        )

    def analyze(self, entries):
        alerts = []
        for entry in entries:
            alert = self.analyze_entry(entry)
            if alert:
                alerts.append(alert)
        return alerts

    def analyze_entry(self, entry):
        if self._detect_threat(entry):
            return ThreatAlert(
                timestamp=entry.timestamp,
                threat_type="custom_threat",
                level=ThreatLevel.HIGH,
                source_ip=entry.source_ip,
                target=entry.resource,
                description="Custom threat detected",
                evidence=[entry],
                mitre_attack=["T1xxx"],
                recommendations=["Take action"]
            )
        return None
```

### Adding Custom Parsers

```python
from src.parsers.base_parser import BaseParser, LogEntry

class CustomParser(BaseParser):
    def __init__(self):
        super().__init__("custom")

    def parse_line(self, line):
        # Implement parsing logic
        return LogEntry(
            timestamp=parsed_time,
            source_ip=parsed_ip,
            message=line,
            log_type=self.log_type,
            raw_line=line
        )

    def detect_format(self, sample_lines):
        # Return True if format matches
        return any("CUSTOM_MARKER" in line for line in sample_lines)
```

## Technologies Used

- **Python 3.8+** - Core implementation
- **Regular Expressions** - Pattern matching and parsing
- **Standard Library** - Zero external dependencies for core functionality
- **Chart.js** - Interactive HTML report visualizations

## Sample Output

### HTML Report Preview

The HTML reporter generates a professional, interactive report with:
- Executive summary dashboard
- Severity distribution charts
- Threat type breakdown
- Top attacker analysis
- Detailed alert cards
- Actionable recommendations

### Text Report Preview

```
================================================================================
   SECURITY LOG ANALYZER
================================================================================

  EXECUTIVE SUMMARY
----------------------------------------
  Total Log Entries Analyzed: 156
  Analysis Duration: 0.23 seconds
  Unique Source IPs: 18

  THREAT OVERVIEW:
  CRITICAL: 3
  HIGH: 12
  MEDIUM: 28
  LOW: 15
  INFO: 8

  SEVERITY DISTRIBUTION
----------------------------------------
  CRITICAL   [#####                                             ]    3 (  4.5%)
  HIGH       [############                                      ]   12 ( 18.2%)
  MEDIUM     [############################                      ]   28 ( 42.4%)
  LOW        [###############                                   ]   15 ( 22.7%)
  INFO       [########                                          ]    8 ( 12.1%)
```

## Contributing

Contributions are welcome! Areas for improvement:

- Additional log format parsers
- New detection signatures
- Machine learning-based anomaly detection
- Threat intelligence feed integration
- SIEM integration connectors

## License

MIT License - See LICENSE file for details.

## Author

Developed as a portfolio project demonstrating:
- Security operations and detection engineering
- Log analysis and parsing techniques
- MITRE ATT&CK framework knowledge
- Clean, modular Python architecture
- Professional documentation practices

---

<p align="center">
  <strong>Built for Security Operations and Threat Detection</strong>
</p>
