"""
Brute Force Attack Detector

Detects credential stuffing and brute force authentication attacks by
analyzing patterns of failed login attempts across multiple dimensions:
- Single IP targeting single account
- Single IP targeting multiple accounts (credential stuffing)
- Distributed attack from multiple IPs targeting single account
- Password spraying (few attempts per account from many IPs)

MITRE ATT&CK References:
- T1110.001: Brute Force - Password Guessing
- T1110.003: Brute Force - Password Spraying
- T1110.004: Brute Force - Credential Stuffing
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from .base_detector import BaseDetector, ThreatAlert, ThreatLevel, DetectorConfig
from ..parsers.base_parser import LogEntry


class BruteForceDetector(BaseDetector):
    """
    Detects brute force and credential stuffing attacks.

    Analyzes authentication failures to identify patterns indicative
    of automated credential attacks. Uses sliding window analysis
    and adaptive thresholds based on baseline behavior.
    """

    # Default detection thresholds
    DEFAULT_CONFIG = {
        'failed_attempts_threshold': 5,      # Failed attempts before alert
        'time_window_minutes': 10,            # Time window for counting attempts
        'credential_stuffing_threshold': 3,   # Different accounts from same IP
        'distributed_attack_threshold': 10,   # Different IPs targeting same account
        'spray_detection_threshold': 3,       # Same password across accounts
    }

    def __init__(self, config: Optional[DetectorConfig] = None):
        """
        Initialize brute force detector.

        Args:
            config: Optional configuration overrides
        """
        super().__init__(
            name="brute_force",
            description="Detects brute force and credential stuffing attacks"
        )

        self.config = config or DetectorConfig(**self.DEFAULT_CONFIG)

        # State tracking
        self._failed_attempts: Dict[str, List[LogEntry]] = defaultdict(list)
        self._ip_to_users: Dict[str, set] = defaultdict(set)
        self._user_to_ips: Dict[str, set] = defaultdict(set)
        self._successful_logins: Dict[str, datetime] = {}

    def reset(self):
        """Reset detector state."""
        super().reset()
        self._failed_attempts.clear()
        self._ip_to_users.clear()
        self._user_to_ips.clear()
        self._successful_logins.clear()

    def analyze(self, entries: List[LogEntry]) -> List[ThreatAlert]:
        """
        Analyze log entries for brute force patterns.

        Performs multi-pass analysis:
        1. Single IP -> Single account attacks
        2. Single IP -> Multiple accounts (credential stuffing)
        3. Multiple IPs -> Single account (distributed attack)

        Args:
            entries: List of parsed log entries

        Returns:
            List of ThreatAlert objects
        """
        self.reset()
        alerts = []

        # First pass: Build state from entries
        for entry in entries:
            self.entries_analyzed += 1
            self._process_entry(entry)

        # Second pass: Analyze patterns
        alerts.extend(self._detect_single_ip_attacks())
        alerts.extend(self._detect_credential_stuffing())
        alerts.extend(self._detect_distributed_attacks())

        self.alerts = alerts
        self.detection_count = len(alerts)

        return alerts

    def analyze_entry(self, entry: LogEntry) -> Optional[ThreatAlert]:
        """
        Analyze single entry (for streaming analysis).

        Args:
            entry: Single log entry

        Returns:
            ThreatAlert if threshold exceeded, None otherwise
        """
        self.entries_analyzed += 1
        self._process_entry(entry)

        # Check if this entry triggers an alert
        if self._is_failed_auth(entry) and entry.source_ip:
            key = f"{entry.source_ip}:{entry.user or 'unknown'}"
            attempts = self._failed_attempts.get(key, [])

            threshold = self.config.get('failed_attempts_threshold', 5)
            if len(attempts) >= threshold:
                return self._create_brute_force_alert(
                    entry.source_ip,
                    entry.user,
                    attempts
                )

        return None

    def _process_entry(self, entry: LogEntry) -> None:
        """Process a log entry and update state."""
        if not entry.source_ip:
            return

        # Check for authentication events
        if self._is_failed_auth(entry):
            key = f"{entry.source_ip}:{entry.user or 'unknown'}"

            # Clean old entries outside time window
            self._clean_old_entries(key, entry.timestamp)

            # Add to tracking
            self._failed_attempts[key].append(entry)

            if entry.user:
                self._ip_to_users[entry.source_ip].add(entry.user)
                self._user_to_ips[entry.user].add(entry.source_ip)

        elif self._is_successful_auth(entry):
            # Track successful logins to identify account compromise after brute force
            if entry.user:
                self._successful_logins[f"{entry.source_ip}:{entry.user}"] = entry.timestamp

    def _is_failed_auth(self, entry: LogEntry) -> bool:
        """Check if entry represents a failed authentication."""
        indicators = [
            'failed' in entry.message.lower(),
            'failure' in entry.message.lower(),
            'invalid' in entry.message.lower(),
            'denied' in entry.message.lower(),
            entry.action in ['ssh_failure', 'ssh_invalid_user', 'sudo_failure'],
            entry.status_code == 0 and entry.log_type == 'auth',
            entry.action == 'logon_failure',
            entry.metadata.get('event_id') == 4625,
        ]
        return any(indicators)

    def _is_successful_auth(self, entry: LogEntry) -> bool:
        """Check if entry represents successful authentication."""
        indicators = [
            'accepted' in entry.message.lower(),
            'succeeded' in entry.message.lower(),
            entry.action in ['ssh_success', 'sudo_success'],
            entry.status_code == 1 and entry.log_type == 'auth',
            entry.action == 'logon_success',
            entry.metadata.get('event_id') == 4624,
        ]
        return any(indicators)

    def _clean_old_entries(self, key: str, current_time: datetime) -> None:
        """Remove entries outside the time window."""
        window = timedelta(minutes=self.config.get('time_window_minutes', 10))
        cutoff = current_time - window

        if key in self._failed_attempts:
            self._failed_attempts[key] = [
                e for e in self._failed_attempts[key]
                if e.timestamp >= cutoff
            ]

    def _detect_single_ip_attacks(self) -> List[ThreatAlert]:
        """Detect single IP targeting single account."""
        alerts = []
        threshold = self.config.get('failed_attempts_threshold', 5)

        for key, attempts in self._failed_attempts.items():
            if len(attempts) >= threshold:
                ip, user = key.rsplit(':', 1)

                # Check if successful login followed (potential compromise)
                success_key = f"{ip}:{user}"
                compromised = success_key in self._successful_logins

                alert = self._create_brute_force_alert(ip, user, attempts, compromised)
                alerts.append(alert)

        return alerts

    def _detect_credential_stuffing(self) -> List[ThreatAlert]:
        """Detect single IP targeting multiple accounts."""
        alerts = []
        threshold = self.config.get('credential_stuffing_threshold', 3)

        for ip, users in self._ip_to_users.items():
            if len(users) >= threshold:
                # Gather all evidence
                evidence = []
                for user in users:
                    key = f"{ip}:{user}"
                    evidence.extend(self._failed_attempts.get(key, []))

                if evidence:
                    alerts.append(self._create_credential_stuffing_alert(
                        ip, list(users), evidence
                    ))

        return alerts

    def _detect_distributed_attacks(self) -> List[ThreatAlert]:
        """Detect multiple IPs targeting single account."""
        alerts = []
        threshold = self.config.get('distributed_attack_threshold', 10)

        for user, ips in self._user_to_ips.items():
            if len(ips) >= threshold:
                # Gather all evidence
                evidence = []
                for ip in ips:
                    key = f"{ip}:{user}"
                    evidence.extend(self._failed_attempts.get(key, []))

                if evidence:
                    alerts.append(self._create_distributed_attack_alert(
                        user, list(ips), evidence
                    ))

        return alerts

    def _create_brute_force_alert(
        self,
        source_ip: str,
        target_user: Optional[str],
        evidence: List[LogEntry],
        compromised: bool = False
    ) -> ThreatAlert:
        """Create alert for single IP brute force attack."""
        # Determine severity based on attempt count and compromise status
        attempt_count = len(evidence)
        if compromised:
            level = ThreatLevel.CRITICAL
        elif attempt_count >= 50:
            level = ThreatLevel.HIGH
        elif attempt_count >= 20:
            level = ThreatLevel.MEDIUM
        else:
            level = ThreatLevel.LOW

        description = (
            f"Brute force attack detected: {attempt_count} failed login attempts "
            f"from {source_ip} targeting user '{target_user or 'unknown'}'"
        )

        if compromised:
            description += " - SUCCESSFUL LOGIN DETECTED AFTER ATTACK"

        recommendations = [
            f"Block IP address {source_ip} at the firewall",
            f"Review account '{target_user}' for unauthorized access",
            "Implement rate limiting on authentication endpoints",
            "Consider implementing multi-factor authentication",
        ]

        if compromised:
            recommendations.insert(0, f"URGENT: Force password reset for user '{target_user}'")
            recommendations.insert(1, "Check for unauthorized activities from this account")

        return ThreatAlert(
            timestamp=evidence[-1].timestamp if evidence else datetime.now(),
            threat_type="brute_force",
            level=level,
            source_ip=source_ip,
            target=target_user,
            description=description,
            evidence=evidence[-10:],  # Keep last 10 entries
            mitre_attack=["T1110.001"],
            recommendations=recommendations,
            metadata={
                'attempt_count': attempt_count,
                'compromised': compromised,
                'time_span_minutes': self._calculate_time_span(evidence),
                'attempts_per_minute': attempt_count / max(1, self._calculate_time_span(evidence)),
            }
        )

    def _create_credential_stuffing_alert(
        self,
        source_ip: str,
        target_users: List[str],
        evidence: List[LogEntry]
    ) -> ThreatAlert:
        """Create alert for credential stuffing attack."""
        return ThreatAlert(
            timestamp=evidence[-1].timestamp if evidence else datetime.now(),
            threat_type="credential_stuffing",
            level=ThreatLevel.HIGH,
            source_ip=source_ip,
            target=f"{len(target_users)} accounts",
            description=(
                f"Credential stuffing attack detected: {source_ip} attempted to "
                f"authenticate to {len(target_users)} different accounts"
            ),
            evidence=evidence[-10:],
            mitre_attack=["T1110.004"],
            recommendations=[
                f"Block IP address {source_ip} immediately",
                "Review all targeted accounts for compromise",
                "Implement CAPTCHA on login pages",
                "Check if credentials appear in known breach databases",
            ],
            metadata={
                'targeted_users': target_users[:20],  # Limit for display
                'total_users_targeted': len(target_users),
                'total_attempts': len(evidence),
            }
        )

    def _create_distributed_attack_alert(
        self,
        target_user: str,
        source_ips: List[str],
        evidence: List[LogEntry]
    ) -> ThreatAlert:
        """Create alert for distributed brute force attack."""
        return ThreatAlert(
            timestamp=evidence[-1].timestamp if evidence else datetime.now(),
            threat_type="distributed_brute_force",
            level=ThreatLevel.HIGH,
            source_ip=f"{len(source_ips)} IPs",
            target=target_user,
            description=(
                f"Distributed brute force attack detected: {len(source_ips)} different IPs "
                f"targeting user '{target_user}'"
            ),
            evidence=evidence[-10:],
            mitre_attack=["T1110.003"],
            recommendations=[
                f"Force password reset for user '{target_user}'",
                "Enable multi-factor authentication for this account",
                "Review source IPs for botnet indicators",
                "Consider geo-blocking if IPs are from unusual locations",
            ],
            metadata={
                'source_ips': source_ips[:20],
                'total_ips': len(source_ips),
                'total_attempts': len(evidence),
            }
        )

    def _calculate_time_span(self, entries: List[LogEntry]) -> float:
        """Calculate time span in minutes for a list of entries."""
        if len(entries) < 2:
            return 1.0

        times = [e.timestamp for e in entries if e.timestamp]
        if not times:
            return 1.0

        span = (max(times) - min(times)).total_seconds() / 60
        return max(1.0, span)
