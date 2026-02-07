#!/usr/bin/env python3
"""
Security Log Analyzer - Main CLI Entry Point

A comprehensive security log analysis tool for threat detection and reporting.

Usage:
    python analyzer.py <log_file> [options]
    python analyzer.py --demo

Examples:
    python analyzer.py /var/log/auth.log --format auth
    python analyzer.py access.log --output report.html --format html
    python analyzer.py sample_logs/ --recursive
    python analyzer.py --demo --output demo_report.html
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from src.detectors.detection_engine import DetectionEngine
from src.reporters.text_reporter import TextReporter
from src.reporters.html_reporter import HTMLReporter


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer - Detect threats in log files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /var/log/auth.log                     Analyze auth log
  %(prog)s access.log --format apache            Analyze Apache log
  %(prog)s logs/ --recursive                     Analyze all logs in directory
  %(prog)s --demo                                Run demo with sample logs
  %(prog)s access.log --output report.html       Generate HTML report

Supported log formats:
  apache    - Apache access logs (Combined/Common format)
  nginx     - Nginx access and error logs
  syslog    - Standard syslog format (RFC 3164/5424)
  auth      - Linux authentication logs (auth.log, secure)
  windows   - Windows Security Event logs

Detection capabilities:
  - Brute force attacks (password guessing, credential stuffing)
  - SQL injection attempts
  - Cross-site scripting (XSS)
  - Directory traversal / Local File Inclusion
  - Temporal anomalies (unusual access times)
  - Geographic anomalies (impossible travel)
        """
    )

    parser.add_argument(
        'input',
        nargs='?',
        help='Log file or directory to analyze'
    )

    parser.add_argument(
        '--demo',
        action='store_true',
        help='Run demo analysis with sample log files'
    )

    parser.add_argument(
        '--format', '-f',
        choices=['apache', 'nginx', 'syslog', 'auth', 'windows', 'auto'],
        default='auto',
        help='Log format (default: auto-detect)'
    )

    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Output file path for report'
    )

    parser.add_argument(
        '--output-format',
        choices=['text', 'html', 'json', 'csv'],
        default='text',
        help='Report format (default: text)'
    )

    parser.add_argument(
        '--recursive', '-r',
        action='store_true',
        help='Recursively analyze logs in directory'
    )

    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )

    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress progress output'
    )

    parser.add_argument(
        '--detectors',
        type=str,
        help='Comma-separated list of detectors to enable (default: all)'
    )

    parser.add_argument(
        '--severity',
        choices=['critical', 'high', 'medium', 'low', 'info'],
        default='low',
        help='Minimum severity level to report (default: low)'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='Security Log Analyzer v1.0.0'
    )

    return parser.parse_args()


def print_banner():
    """Print application banner."""
    banner = """
\033[95m╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗            ║
║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝            ║
║   ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝             ║
║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝              ║
║   ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║               ║
║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝               ║
║                                                                              ║
║   ██╗      ██████╗  ██████╗      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗    ║
║   ██║     ██╔═══██╗██╔════╝     ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝    ║
║   ██║     ██║   ██║██║  ███╗    ███████║██╔██╗ ██║███████║██║   ╚████╔╝     ║
║   ██║     ██║   ██║██║   ██║    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝      ║
║   ███████╗╚██████╔╝╚██████╔╝    ██║  ██║██║ ╚████║██║  ██║███████╗██║YZER   ║
║   ╚══════╝ ╚═════╝  ╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝       ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝\033[0m
"""
    print(banner)


def get_log_files(path: Path, recursive: bool = False) -> List[Path]:
    """Get list of log files from path."""
    if path.is_file():
        return [path]

    if path.is_dir():
        pattern = '**/*' if recursive else '*'
        files = []
        for ext in ['*.log', '*.txt', '*.evtx']:
            files.extend(path.glob(f"{pattern}{ext}" if recursive else ext))
        # Also get files without extensions that might be logs
        for f in path.glob(pattern):
            if f.is_file() and f.suffix == '' and f.name in ['auth', 'secure', 'messages', 'syslog']:
                files.append(f)
        return sorted(set(files))

    return []


def run_demo(args: argparse.Namespace) -> int:
    """Run demo analysis with sample logs."""
    sample_dir = Path(__file__).parent / 'sample_logs'

    if not sample_dir.exists():
        print("\033[91mError: Sample logs directory not found.\033[0m")
        print("Please ensure sample_logs/ directory exists with sample log files.")
        return 1

    print("\n\033[94m[*] Running demo analysis with sample log files...\033[0m\n")

    log_files = get_log_files(sample_dir, recursive=False)

    if not log_files:
        print("\033[91mError: No sample log files found.\033[0m")
        return 1

    print(f"\033[92m[+] Found {len(log_files)} sample log files:\033[0m")
    for f in log_files:
        print(f"    - {f.name}")
    print()

    return run_analysis(log_files, args)


def run_analysis(log_files: List[Path], args: argparse.Namespace) -> int:
    """Run analysis on log files."""
    engine = DetectionEngine()

    # Configure detectors if specified
    if args.detectors:
        detector_names = [d.strip() for d in args.detectors.split(',')]
        for name, detector in engine.detectors.items():
            detector.enabled = name in detector_names

    # Determine format hint
    format_hints = {}
    if args.format != 'auto':
        for f in log_files:
            format_hints[str(f)] = args.format

    # Run analysis
    if not args.quiet:
        print(f"\033[94m[*] Analyzing {len(log_files)} log file(s)...\033[0m\n")

    try:
        alerts = engine.analyze(file_paths=log_files, format_hints=format_hints)
    except Exception as e:
        print(f"\033[91mError during analysis: {e}\033[0m")
        return 1

    # Filter by severity
    severity_map = {
        'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1
    }
    min_severity = severity_map.get(args.severity, 2)
    alerts = [a for a in alerts if a.level.value >= min_severity]

    # Generate report
    if args.output_format == 'html' or (args.output and args.output.endswith('.html')):
        reporter = HTMLReporter()
        output_path = Path(args.output) if args.output else Path('security_report.html')
    else:
        reporter = TextReporter(use_colors=not args.no_color)
        output_path = Path(args.output) if args.output else None

    report = reporter.generate(alerts, engine.stats, output_path)

    # Print to console unless output file specified with non-text format
    if args.output_format == 'text' or not args.output:
        print(report)

    # Print summary
    if not args.quiet:
        print(f"\n\033[94m[*] Analysis complete.\033[0m")
        print(f"    - Entries analyzed: {engine.stats.get('total_entries', 0):,}")
        print(f"    - Alerts generated: {len(alerts)}")

        if args.output:
            print(f"    - Report saved to: {output_path}")

    # Return non-zero if critical threats found
    critical_count = sum(1 for a in alerts if a.level.name == 'CRITICAL')
    return 1 if critical_count > 0 else 0


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Print banner unless quiet mode
    if not args.quiet:
        print_banner()

    # Run demo mode
    if args.demo:
        return run_demo(args)

    # Validate input
    if not args.input:
        print("\033[91mError: No input file specified. Use --demo for demo mode.\033[0m")
        print("Run with --help for usage information.")
        return 1

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"\033[91mError: Input path not found: {input_path}\033[0m")
        return 1

    # Get log files
    log_files = get_log_files(input_path, args.recursive)

    if not log_files:
        print(f"\033[91mError: No log files found in: {input_path}\033[0m")
        return 1

    return run_analysis(log_files, args)


if __name__ == '__main__':
    sys.exit(main())
