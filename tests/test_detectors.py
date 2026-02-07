"""
Unit tests for threat detectors.
"""

import unittest
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parsers.base_parser import LogEntry
from src.detectors.brute_force_detector import BruteForceDetector
from src.detectors.injection_detector import SQLInjectionDetector, XSSDetector
from src.detectors.traversal_detector import DirectoryTraversalDetector
from src.detectors.base_detector import ThreatLevel


class TestBruteForceDetector(unittest.TestCase):
    """Tests for brute force detector."""

    def setUp(self):
        self.detector = BruteForceDetector()

    def test_detect_brute_force(self):
        """Test detection of brute force attack."""
        entries = []
        base_time = datetime.now()

        # Create 10 failed login attempts from same IP
        for i in range(10):
            entries.append(LogEntry(
                timestamp=base_time + timedelta(seconds=i),
                source_ip="45.33.32.156",
                user="admin",
                action="ssh_failure",
                message="Failed password for admin from 45.33.32.156",
                log_type="auth",
                raw_line=f"Failed attempt {i}",
                status_code=0,
            ))

        alerts = self.detector.analyze(entries)

        self.assertGreater(len(alerts), 0)
        self.assertEqual(alerts[0].threat_type, "brute_force")
        self.assertEqual(alerts[0].source_ip, "45.33.32.156")

    def test_detect_credential_stuffing(self):
        """Test detection of credential stuffing."""
        entries = []
        base_time = datetime.now()

        # Same IP targeting multiple users
        users = ["john", "jane", "admin", "root", "test"]
        for i, user in enumerate(users):
            entries.append(LogEntry(
                timestamp=base_time + timedelta(seconds=i),
                source_ip="77.88.55.66",
                user=user,
                action="ssh_failure",
                message=f"Failed password for {user}",
                log_type="auth",
                raw_line=f"Failed attempt for {user}",
                status_code=0,
            ))

        alerts = self.detector.analyze(entries)

        # Should detect credential stuffing
        stuffing_alerts = [a for a in alerts if a.threat_type == "credential_stuffing"]
        self.assertGreater(len(stuffing_alerts), 0)


class TestSQLInjectionDetector(unittest.TestCase):
    """Tests for SQL injection detector."""

    def setUp(self):
        self.detector = SQLInjectionDetector()

    def test_detect_union_injection(self):
        """Test detection of UNION-based SQL injection."""
        entry = LogEntry(
            timestamp=datetime.now(),
            source_ip="45.33.32.156",
            action="GET",
            resource="/search?q=1'+UNION+SELECT+username,password+FROM+users--",
            message="GET /search?q=...",
            log_type="apache",
            raw_line="...",
        )

        alert = self.detector.analyze_entry(entry)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_type, "sql_injection")
        self.assertEqual(alert.level, ThreatLevel.CRITICAL)

    def test_detect_boolean_injection(self):
        """Test detection of boolean-based SQL injection."""
        entry = LogEntry(
            timestamp=datetime.now(),
            source_ip="45.33.32.156",
            action="GET",
            resource="/users?id=1'+OR+'1'='1",
            message="GET /users?id=...",
            log_type="apache",
            raw_line="...",
        )

        alert = self.detector.analyze_entry(entry)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_type, "sql_injection")

    def test_no_false_positive(self):
        """Test that normal requests don't trigger alerts."""
        entry = LogEntry(
            timestamp=datetime.now(),
            source_ip="192.168.1.50",
            action="GET",
            resource="/api/users?page=1&limit=10",
            message="GET /api/users",
            log_type="apache",
            raw_line="...",
        )

        alert = self.detector.analyze_entry(entry)
        self.assertIsNone(alert)


class TestXSSDetector(unittest.TestCase):
    """Tests for XSS detector."""

    def setUp(self):
        self.detector = XSSDetector()

    def test_detect_script_tag(self):
        """Test detection of script tag injection."""
        entry = LogEntry(
            timestamp=datetime.now(),
            source_ip="103.45.67.89",
            action="GET",
            resource="/search?q=<script>alert('XSS')</script>",
            message="GET /search...",
            log_type="apache",
            raw_line="...",
        )

        alert = self.detector.analyze_entry(entry)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_type, "xss")
        self.assertEqual(alert.level, ThreatLevel.CRITICAL)

    def test_detect_event_handler(self):
        """Test detection of event handler injection."""
        entry = LogEntry(
            timestamp=datetime.now(),
            source_ip="103.45.67.89",
            action="GET",
            resource="/profile?name=<img+src=x+onerror=alert(1)>",
            message="GET /profile...",
            log_type="apache",
            raw_line="...",
        )

        alert = self.detector.analyze_entry(entry)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_type, "xss")


class TestDirectoryTraversalDetector(unittest.TestCase):
    """Tests for directory traversal detector."""

    def setUp(self):
        self.detector = DirectoryTraversalDetector()

    def test_detect_basic_traversal(self):
        """Test detection of basic directory traversal."""
        entry = LogEntry(
            timestamp=datetime.now(),
            source_ip="185.220.101.45",
            action="GET",
            resource="/files/../../../etc/passwd",
            status_code=200,
            message="GET /files/...",
            log_type="apache",
            raw_line="...",
        )

        alert = self.detector.analyze_entry(entry)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_type, "directory_traversal")

    def test_detect_encoded_traversal(self):
        """Test detection of URL-encoded traversal."""
        entry = LogEntry(
            timestamp=datetime.now(),
            source_ip="185.220.101.45",
            action="GET",
            resource="/files?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            status_code=200,
            message="GET /files...",
            log_type="apache",
            raw_line="...",
        )

        alert = self.detector.analyze_entry(entry)

        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_type, "directory_traversal")

    def test_detect_sensitive_file(self):
        """Test detection of sensitive file access."""
        entry = LogEntry(
            timestamp=datetime.now(),
            source_ip="185.220.101.45",
            action="GET",
            resource="/.env",
            status_code=200,
            message="GET /.env",
            log_type="nginx",
            raw_line="...",
        )

        alert = self.detector.analyze_entry(entry)

        self.assertIsNotNone(alert)


if __name__ == '__main__':
    unittest.main()
