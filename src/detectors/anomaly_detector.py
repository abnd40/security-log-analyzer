"""
Anomaly Detection Module

Detects behavioral anomalies that may indicate compromise or attack:
- Temporal anomalies (unusual access times)
- Geographic anomalies (impossible travel, unusual locations)
- Statistical anomalies (unusual request patterns)

These detectors use behavioral baselines and statistical methods
to identify deviations that signature-based detection may miss.

MITRE ATT&CK References:
- T1078: Valid Accounts
- T1133: External Remote Services
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Set, Tuple
from dataclasses import dataclass
import math

from .base_detector import BaseDetector, ThreatAlert, ThreatLevel, DetectorConfig
from ..parsers.base_parser import LogEntry


@dataclass
class IPGeoInfo:
    """Geographic information for an IP address."""
    ip: str
    country: str
    country_code: str
    region: str
    city: str
    latitude: float
    longitude: float
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False


class TemporalAnomalyDetector(BaseDetector):
    """
    Detects access at unusual times.

    Builds a baseline of normal access patterns and flags
    significant deviations that may indicate:
    - Compromised credentials being used by attackers in different timezones
    - Automated attacks running outside business hours
    - Insider threats operating during off-hours
    """

    DEFAULT_CONFIG = {
        'business_hours_start': 6,    # 6 AM
        'business_hours_end': 22,     # 10 PM
        'weekend_threshold': 0.1,     # < 10% weekend activity triggers alert
        'night_threshold': 0.15,      # < 15% night activity triggers alert
        'baseline_days': 30,          # Days of baseline to establish
    }

    # Known high-risk hours (UTC) for automated attacks
    HIGH_RISK_HOURS = {0, 1, 2, 3, 4, 5, 23}

    def __init__(self, config: Optional[DetectorConfig] = None):
        """Initialize temporal anomaly detector."""
        super().__init__(
            name="temporal_anomaly",
            description="Detects access at unusual times"
        )
        self.config = config or DetectorConfig(**self.DEFAULT_CONFIG)

        # Baseline tracking
        self._user_baselines: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        self._user_weekend_activity: Dict[str, int] = defaultdict(int)
        self._user_total_activity: Dict[str, int] = defaultdict(int)

    def reset(self):
        """Reset detector state."""
        super().reset()
        self._user_baselines.clear()
        self._user_weekend_activity.clear()
        self._user_total_activity.clear()

    def analyze(self, entries: List[LogEntry]) -> List[ThreatAlert]:
        """Analyze entries for temporal anomalies."""
        self.reset()
        alerts = []

        # First pass: Build baselines
        for entry in entries:
            self.entries_analyzed += 1
            if entry.user and entry.timestamp:
                hour = entry.timestamp.hour
                self._user_baselines[entry.user][hour] += 1
                self._user_total_activity[entry.user] += 1

                if entry.timestamp.weekday() >= 5:  # Weekend
                    self._user_weekend_activity[entry.user] += 1

        # Second pass: Detect anomalies
        for entry in entries:
            alert = self._check_temporal_anomaly(entry)
            if alert:
                alerts.append(alert)

        self.alerts = alerts
        self.detection_count = len(alerts)
        return alerts

    def analyze_entry(self, entry: LogEntry) -> Optional[ThreatAlert]:
        """Analyze single entry for temporal anomaly."""
        self.entries_analyzed += 1

        if entry.user and entry.timestamp:
            hour = entry.timestamp.hour
            self._user_baselines[entry.user][hour] += 1
            self._user_total_activity[entry.user] += 1

            if entry.timestamp.weekday() >= 5:
                self._user_weekend_activity[entry.user] += 1

        return self._check_temporal_anomaly(entry)

    def _check_temporal_anomaly(self, entry: LogEntry) -> Optional[ThreatAlert]:
        """Check single entry for temporal anomalies."""
        if not entry.timestamp:
            return None

        hour = entry.timestamp.hour
        is_weekend = entry.timestamp.weekday() >= 5
        is_night = hour in self.HIGH_RISK_HOURS

        anomalies = []
        severity = 'low'

        # Check business hours
        bh_start = self.config.get('business_hours_start', 6)
        bh_end = self.config.get('business_hours_end', 22)

        if hour < bh_start or hour > bh_end:
            anomalies.append(f"Access outside business hours ({hour}:00)")
            severity = 'medium'

        # Check for high-risk hours
        if is_night:
            anomalies.append(f"Access during high-risk hour ({hour}:00 UTC)")
            severity = 'medium'

        # Check user baseline if we have history
        if entry.user and entry.user in self._user_baselines:
            baseline = self._user_baselines[entry.user]
            total = self._user_total_activity.get(entry.user, 0)

            if total >= 20:  # Minimum activity threshold
                hour_pct = baseline[hour] / total

                # Flag if this hour is unusual for this user
                if hour_pct < 0.02:  # Less than 2% of activity
                    anomalies.append(f"Unusual hour for user {entry.user}")
                    severity = 'high'

        # Check weekend access for users with no weekend history
        if is_weekend and entry.user:
            weekend_activity = self._user_weekend_activity.get(entry.user, 0)
            total_activity = self._user_total_activity.get(entry.user, 0)

            if total_activity >= 20:
                weekend_pct = weekend_activity / total_activity
                threshold = self.config.get('weekend_threshold', 0.1)

                if weekend_pct < threshold:
                    anomalies.append(f"Weekend access unusual for user {entry.user}")
                    severity = 'high' if severity != 'high' else severity

        if anomalies:
            return self._create_alert(entry, anomalies, severity)

        return None

    def _create_alert(
        self,
        entry: LogEntry,
        anomalies: List[str],
        severity: str
    ) -> ThreatAlert:
        """Create temporal anomaly alert."""
        level_map = {
            'high': ThreatLevel.MEDIUM,
            'medium': ThreatLevel.LOW,
            'low': ThreatLevel.INFO,
        }

        return ThreatAlert(
            timestamp=entry.timestamp,
            threat_type="temporal_anomaly",
            level=level_map.get(severity, ThreatLevel.LOW),
            source_ip=entry.source_ip,
            target=entry.user or entry.resource,
            description=f"Temporal anomaly detected: {'; '.join(anomalies)}",
            evidence=[entry],
            mitre_attack=["T1078"],
            recommendations=[
                "Verify the access was authorized",
                "Check for signs of account compromise",
                "Review recent activity for this user",
                "Consider implementing time-based access controls",
            ],
            metadata={
                'anomalies': anomalies,
                'access_hour': entry.timestamp.hour if entry.timestamp else None,
                'is_weekend': entry.timestamp.weekday() >= 5 if entry.timestamp else None,
                'user': entry.user,
            }
        )


class GeoAnomalyDetector(BaseDetector):
    """
    Detects geographic anomalies in access patterns.

    Identifies:
    - Impossible travel (access from distant locations in short time)
    - Access from unusual countries
    - Access from known malicious networks (VPN, Tor, proxies)
    - New location for user
    """

    DEFAULT_CONFIG = {
        'impossible_travel_speed_kmh': 1000,  # Max reasonable travel speed
        'high_risk_countries': ['KP', 'IR', 'RU', 'CN', 'BY'],
        'min_location_history': 5,  # Minimum logins before flagging new location
    }

    # Known suspicious IP ranges (examples - in production use threat intel feeds)
    SUSPICIOUS_RANGES = [
        # Tor exit nodes would be loaded from a feed
        # VPN providers would be loaded from a feed
        # Cloud provider IPs that shouldn't be used for user logins
    ]

    def __init__(self, config: Optional[DetectorConfig] = None, geo_db: Optional[Dict[str, IPGeoInfo]] = None):
        """
        Initialize geographic anomaly detector.

        Args:
            config: Detection configuration
            geo_db: Optional IP geolocation database
        """
        super().__init__(
            name="geo_anomaly",
            description="Detects geographic access anomalies"
        )
        self.config = config or DetectorConfig(**self.DEFAULT_CONFIG)
        self._geo_db = geo_db or {}

        # Track user locations
        self._user_locations: Dict[str, List[Tuple[datetime, IPGeoInfo]]] = defaultdict(list)
        self._user_countries: Dict[str, Set[str]] = defaultdict(set)

    def reset(self):
        """Reset detector state."""
        super().reset()
        self._user_locations.clear()
        self._user_countries.clear()

    def set_geo_db(self, geo_db: Dict[str, IPGeoInfo]):
        """Set the IP geolocation database."""
        self._geo_db = geo_db

    def add_geo_info(self, ip: str, info: IPGeoInfo):
        """Add geolocation info for an IP."""
        self._geo_db[ip] = info

    def analyze(self, entries: List[LogEntry]) -> List[ThreatAlert]:
        """Analyze entries for geographic anomalies."""
        self.reset()
        alerts = []

        # Sort entries by timestamp for impossible travel detection
        sorted_entries = sorted(
            [e for e in entries if e.timestamp],
            key=lambda x: x.timestamp
        )

        for entry in sorted_entries:
            self.entries_analyzed += 1
            alert = self.analyze_entry(entry)
            if alert:
                alerts.append(alert)

        self.alerts = alerts
        self.detection_count = len(alerts)
        return alerts

    def analyze_entry(self, entry: LogEntry) -> Optional[ThreatAlert]:
        """Analyze single entry for geographic anomalies."""
        self.entries_analyzed += 1

        if not entry.source_ip:
            return None

        # Look up geo info
        geo_info = self._geo_db.get(entry.source_ip)

        # If we have geo info, perform checks
        if geo_info:
            alerts = []

            # Check for VPN/Tor/Proxy
            if geo_info.is_tor:
                alerts.append(("Tor exit node detected", ThreatLevel.HIGH))
            elif geo_info.is_vpn:
                alerts.append(("VPN detected", ThreatLevel.LOW))
            elif geo_info.is_proxy:
                alerts.append(("Proxy detected", ThreatLevel.LOW))

            # Check for high-risk countries
            high_risk = self.config.get('high_risk_countries', [])
            if geo_info.country_code in high_risk:
                alerts.append((
                    f"Access from high-risk country: {geo_info.country}",
                    ThreatLevel.MEDIUM
                ))

            # Check for impossible travel
            if entry.user and entry.timestamp:
                travel_alert = self._check_impossible_travel(entry, geo_info)
                if travel_alert:
                    alerts.append(travel_alert)

                # Check for new location
                new_loc_alert = self._check_new_location(entry, geo_info)
                if new_loc_alert:
                    alerts.append(new_loc_alert)

                # Update user location history
                self._user_locations[entry.user].append((entry.timestamp, geo_info))
                self._user_countries[entry.user].add(geo_info.country_code)

            if alerts:
                # Use highest severity
                max_level = max(a[1].value for a in alerts)
                level = ThreatLevel(max_level)
                descriptions = [a[0] for a in alerts]

                return self._create_alert(entry, geo_info, descriptions, level)

        # Even without geo info, check for suspicious IP patterns
        return self._check_ip_reputation(entry)

    def _check_impossible_travel(
        self,
        entry: LogEntry,
        current_geo: IPGeoInfo
    ) -> Optional[Tuple[str, ThreatLevel]]:
        """Check for impossible travel scenario."""
        if not entry.user or entry.user not in self._user_locations:
            return None

        history = self._user_locations[entry.user]
        if not history:
            return None

        # Get last location
        last_time, last_geo = history[-1]

        if not entry.timestamp or last_time >= entry.timestamp:
            return None

        # Calculate distance
        distance = self._haversine_distance(
            last_geo.latitude, last_geo.longitude,
            current_geo.latitude, current_geo.longitude
        )

        # Calculate time difference in hours
        time_diff = (entry.timestamp - last_time).total_seconds() / 3600

        if time_diff <= 0:
            return None

        # Calculate required speed
        required_speed = distance / time_diff

        max_speed = self.config.get('impossible_travel_speed_kmh', 1000)

        if required_speed > max_speed:
            return (
                f"Impossible travel detected: {distance:.0f}km in {time_diff:.1f}h "
                f"({last_geo.city}, {last_geo.country} -> {current_geo.city}, {current_geo.country})",
                ThreatLevel.HIGH
            )

        return None

    def _check_new_location(
        self,
        entry: LogEntry,
        geo_info: IPGeoInfo
    ) -> Optional[Tuple[str, ThreatLevel]]:
        """Check if this is a new location for the user."""
        if not entry.user:
            return None

        known_countries = self._user_countries.get(entry.user, set())
        min_history = self.config.get('min_location_history', 5)

        if len(known_countries) >= min_history:
            if geo_info.country_code not in known_countries:
                return (
                    f"First access from new country: {geo_info.country}",
                    ThreatLevel.MEDIUM
                )

        return None

    def _check_ip_reputation(self, entry: LogEntry) -> Optional[ThreatAlert]:
        """Check IP against known bad ranges."""
        # In production, this would check threat intel feeds
        # For demo, return None (no reputation data)
        return None

    def _haversine_distance(
        self,
        lat1: float, lon1: float,
        lat2: float, lon2: float
    ) -> float:
        """Calculate distance between two points in kilometers."""
        R = 6371  # Earth radius in km

        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)

        a = (math.sin(delta_lat / 2) ** 2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) *
             math.sin(delta_lon / 2) ** 2)
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return R * c

    def _create_alert(
        self,
        entry: LogEntry,
        geo_info: Optional[IPGeoInfo],
        descriptions: List[str],
        level: ThreatLevel
    ) -> ThreatAlert:
        """Create geographic anomaly alert."""
        return ThreatAlert(
            timestamp=entry.timestamp,
            threat_type="geo_anomaly",
            level=level,
            source_ip=entry.source_ip,
            target=entry.user or entry.resource,
            description=f"Geographic anomaly: {'; '.join(descriptions)}",
            evidence=[entry],
            mitre_attack=["T1078", "T1133"],
            recommendations=[
                "Verify the access was from an authorized location",
                "Check for account compromise",
                "Consider implementing geo-blocking",
                "Review VPN/anonymizer usage policies",
            ],
            metadata={
                'anomalies': descriptions,
                'country': geo_info.country if geo_info else None,
                'city': geo_info.city if geo_info else None,
                'is_vpn': geo_info.is_vpn if geo_info else None,
                'is_tor': geo_info.is_tor if geo_info else None,
            }
        )
