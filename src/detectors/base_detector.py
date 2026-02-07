"""
Base Detector Module

Provides the abstract base class for all threat detectors and the
standardized ThreatAlert dataclass for consistent threat reporting.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
import hashlib

from ..parsers.base_parser import LogEntry


class ThreatLevel(Enum):
    """
    Threat severity levels following industry standards.

    Based on CVSS-like scoring with clear operational implications:
    - CRITICAL: Immediate action required, active exploitation
    - HIGH: Significant risk, requires prompt attention
    - MEDIUM: Moderate risk, should be addressed in near term
    - LOW: Minor risk, address during normal operations
    - INFO: Informational, no immediate action needed
    """
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

    def __str__(self):
        return self.name

    @property
    def color(self) -> str:
        """Return ANSI color code for threat level."""
        colors = {
            ThreatLevel.CRITICAL: "\033[91m",  # Red
            ThreatLevel.HIGH: "\033[93m",      # Yellow
            ThreatLevel.MEDIUM: "\033[94m",    # Blue
            ThreatLevel.LOW: "\033[92m",       # Green
            ThreatLevel.INFO: "\033[90m",      # Gray
        }
        return colors.get(self, "\033[0m")


@dataclass
class ThreatAlert:
    """
    Standardized threat alert representation.

    Provides comprehensive information about detected threats for
    analysis, reporting, and incident response.

    Attributes:
        timestamp: When the threat was detected
        threat_type: Category of threat (e.g., 'brute_force', 'sql_injection')
        level: Severity level of the threat
        source_ip: Origin IP address of the threat
        target: Target resource or system
        description: Human-readable description of the threat
        evidence: List of log entries supporting the alert
        mitre_attack: MITRE ATT&CK technique IDs if applicable
        recommendations: Suggested remediation actions
        metadata: Additional threat-specific data
        alert_id: Unique identifier for the alert
    """
    timestamp: datetime
    threat_type: str
    level: ThreatLevel
    source_ip: Optional[str]
    target: Optional[str]
    description: str
    evidence: List[LogEntry] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    alert_id: str = field(default="", init=False)

    def __post_init__(self):
        """Generate unique alert ID."""
        hash_content = f"{self.timestamp}{self.threat_type}{self.source_ip}{self.target}"
        self.alert_id = hashlib.sha256(hash_content.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for serialization."""
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'threat_type': self.threat_type,
            'level': self.level.name,
            'level_value': self.level.value,
            'source_ip': self.source_ip,
            'target': self.target,
            'description': self.description,
            'evidence_count': len(self.evidence),
            'mitre_attack': self.mitre_attack,
            'recommendations': self.recommendations,
            'metadata': self.metadata,
        }


class BaseDetector(ABC):
    """
    Abstract base class for threat detectors.

    All threat detection modules must inherit from this class and
    implement the required abstract methods for consistent detection
    behavior and reporting.
    """

    def __init__(self, name: str, description: str):
        """
        Initialize the detector.

        Args:
            name: Unique identifier for the detector
            description: Human-readable description of what the detector finds
        """
        self.name = name
        self.description = description
        self.enabled = True
        self.alerts: List[ThreatAlert] = []
        self.entries_analyzed = 0
        self.detection_count = 0

    @abstractmethod
    def analyze(self, entries: List[LogEntry]) -> List[ThreatAlert]:
        """
        Analyze log entries for threats.

        Args:
            entries: List of parsed log entries to analyze

        Returns:
            List of ThreatAlert objects for detected threats
        """
        pass

    @abstractmethod
    def analyze_entry(self, entry: LogEntry) -> Optional[ThreatAlert]:
        """
        Analyze a single log entry for threats.

        Args:
            entry: Single parsed log entry

        Returns:
            ThreatAlert if threat detected, None otherwise
        """
        pass

    def reset(self):
        """Reset detector state for new analysis."""
        self.alerts = []
        self.entries_analyzed = 0
        self.detection_count = 0

    def get_stats(self) -> Dict[str, Any]:
        """
        Get detection statistics.

        Returns:
            Dictionary containing detection metrics
        """
        level_counts = {}
        for alert in self.alerts:
            level_name = alert.level.name
            level_counts[level_name] = level_counts.get(level_name, 0) + 1

        return {
            'detector_name': self.name,
            'description': self.description,
            'enabled': self.enabled,
            'entries_analyzed': self.entries_analyzed,
            'total_alerts': len(self.alerts),
            'alerts_by_level': level_counts,
        }


class DetectorConfig:
    """
    Configuration container for detector parameters.

    Allows customization of detection thresholds and behavior
    without modifying detector code.
    """

    def __init__(self, **kwargs):
        """
        Initialize configuration with keyword arguments.

        All parameters are stored as attributes for easy access.
        """
        for key, value in kwargs.items():
            setattr(self, key, value)

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with default."""
        return getattr(self, key, default)

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}
