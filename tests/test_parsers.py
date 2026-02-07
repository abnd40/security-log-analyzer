"""
Unit tests for log parsers.
"""

import unittest
from datetime import datetime
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parsers.apache_parser import ApacheParser
from src.parsers.nginx_parser import NginxParser
from src.parsers.auth_parser import AuthLogParser
from src.parsers.syslog_parser import SyslogParser


class TestApacheParser(unittest.TestCase):
    """Tests for Apache log parser."""

    def setUp(self):
        self.parser = ApacheParser()

    def test_parse_combined_format(self):
        """Test parsing Apache combined log format."""
        line = '192.168.1.100 - admin [15/Jan/2024:13:55:36 -0700] "GET /admin HTTP/1.1" 200 2326 "-" "Mozilla/5.0"'
        entry = self.parser.parse_line(line)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.source_ip, "192.168.1.100")
        self.assertEqual(entry.user, "admin")
        self.assertEqual(entry.action, "GET")
        self.assertEqual(entry.resource, "/admin")
        self.assertEqual(entry.status_code, 200)
        self.assertEqual(entry.log_type, "apache")

    def test_parse_common_format(self):
        """Test parsing Apache common log format."""
        line = '10.0.0.1 - - [15/Jan/2024:10:00:00 -0500] "POST /api/login HTTP/1.1" 401 128'
        entry = self.parser.parse_line(line)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.source_ip, "10.0.0.1")
        self.assertIsNone(entry.user)
        self.assertEqual(entry.action, "POST")
        self.assertEqual(entry.status_code, 401)

    def test_detect_format(self):
        """Test format detection."""
        apache_lines = [
            '192.168.1.1 - - [15/Jan/2024:10:00:00 -0500] "GET / HTTP/1.1" 200 1024',
            '192.168.1.2 - user [15/Jan/2024:10:00:01 -0500] "POST /login HTTP/1.1" 302 0',
        ]
        self.assertTrue(self.parser.detect_format(apache_lines))

        non_apache_lines = [
            'Jan 15 10:00:00 server sshd[1234]: Accepted password for user',
        ]
        self.assertFalse(self.parser.detect_format(non_apache_lines))


class TestAuthLogParser(unittest.TestCase):
    """Tests for auth.log parser."""

    def setUp(self):
        self.parser = AuthLogParser()

    def test_parse_ssh_failed(self):
        """Test parsing SSH failed authentication."""
        line = 'Jan 15 09:00:01 webserver sshd[24001]: Failed password for invalid user admin from 45.33.32.156 port 54321 ssh2'
        entry = self.parser.parse_line(line)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.source_ip, "45.33.32.156")
        self.assertEqual(entry.user, "admin")
        self.assertEqual(entry.action, "ssh_invalid_user")
        self.assertFalse(entry.metadata.get('success'))

    def test_parse_ssh_success(self):
        """Test parsing SSH successful authentication."""
        line = 'Jan 15 08:15:22 webserver sshd[23456]: Accepted publickey for ubuntu from 192.168.1.100 port 52341 ssh2'
        entry = self.parser.parse_line(line)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.source_ip, "192.168.1.100")
        self.assertEqual(entry.user, "ubuntu")
        self.assertEqual(entry.action, "ssh_success")
        self.assertTrue(entry.metadata.get('success'))

    def test_parse_sudo(self):
        """Test parsing sudo command."""
        line = 'Jan 15 10:32:15 webserver sudo: developer : TTY=pts/1 ; PWD=/home/developer ; USER=root ; COMMAND=/bin/cat /etc/shadow'
        entry = self.parser.parse_line(line)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.user, "developer")
        self.assertEqual(entry.action, "sudo_success")


class TestNginxParser(unittest.TestCase):
    """Tests for Nginx log parser."""

    def setUp(self):
        self.parser = NginxParser()

    def test_parse_access_log(self):
        """Test parsing Nginx access log."""
        line = '10.0.0.1 - - [15/Jan/2024:12:00:00 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "curl/7.68.0"'
        entry = self.parser.parse_line(line)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.source_ip, "10.0.0.1")
        self.assertEqual(entry.action, "GET")
        self.assertEqual(entry.resource, "/api/users")
        self.assertEqual(entry.status_code, 200)


class TestSyslogParser(unittest.TestCase):
    """Tests for Syslog parser."""

    def setUp(self):
        self.parser = SyslogParser()

    def test_parse_rfc3164(self):
        """Test parsing RFC 3164 syslog format."""
        line = 'Jan 15 10:23:45 webserver sshd[12345]: Connection from 192.168.1.50'
        entry = self.parser.parse_line(line)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.metadata.get('hostname'), 'webserver')
        self.assertEqual(entry.metadata.get('process'), 'sshd')
        self.assertIn('Connection', entry.message)


if __name__ == '__main__':
    unittest.main()
