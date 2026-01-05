"""CloudTrail real-time threat detection."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Callable

logger = logging.getLogger(__name__)


class ThreatType(Enum):
    """Types of detected threats."""

    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    RESOURCE_HIJACKING = "resource_hijacking"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    CONFIGURATION_CHANGE = "configuration_change"
    ANOMALOUS_ACTIVITY = "anomalous_activity"


class ThreatSeverity(Enum):
    """Threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ThreatAlert:
    """A detected threat alert."""

    id: str
    threat_type: ThreatType
    severity: ThreatSeverity
    title: str
    description: str
    event_name: str
    source_ip: Optional[str] = None
    user_identity: Optional[str] = None
    aws_region: Optional[str] = None
    timestamp: Optional[datetime] = None
    raw_event: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


# Detection rules
DETECTION_RULES = {
    # Privilege Escalation
    "CreateUser": {
        "type": ThreatType.PRIVILEGE_ESCALATION,
        "severity": ThreatSeverity.MEDIUM,
        "title": "IAM User Created",
        "description": "A new IAM user was created",
        "recommendations": ["Verify the user creation was authorized", "Review user permissions"],
    },
    "CreateAccessKey": {
        "type": ThreatType.CREDENTIAL_COMPROMISE,
        "severity": ThreatSeverity.HIGH,
        "title": "Access Key Created",
        "description": "A new access key was created for an IAM user",
        "recommendations": ["Verify key creation was authorized", "Monitor key usage"],
    },
    "AttachUserPolicy": {
        "type": ThreatType.PRIVILEGE_ESCALATION,
        "severity": ThreatSeverity.HIGH,
        "title": "Policy Attached to User",
        "description": "A policy was attached to an IAM user",
        "recommendations": ["Review attached policy", "Verify least privilege"],
    },
    "AttachRolePolicy": {
        "type": ThreatType.PRIVILEGE_ESCALATION,
        "severity": ThreatSeverity.HIGH,
        "title": "Policy Attached to Role",
        "description": "A policy was attached to an IAM role",
        "recommendations": ["Review attached policy", "Verify least privilege"],
    },
    "PutUserPolicy": {
        "type": ThreatType.PRIVILEGE_ESCALATION,
        "severity": ThreatSeverity.HIGH,
        "title": "Inline Policy Added to User",
        "description": "An inline policy was added to an IAM user",
        "recommendations": ["Review inline policy", "Consider using managed policies"],
    },
    # Configuration Changes
    "DeleteTrail": {
        "type": ThreatType.CONFIGURATION_CHANGE,
        "severity": ThreatSeverity.CRITICAL,
        "title": "CloudTrail Deleted",
        "description": "A CloudTrail trail was deleted - this may indicate an attacker covering tracks",
        "recommendations": ["Investigate immediately", "Restore CloudTrail", "Check for other signs of compromise"],
    },
    "StopLogging": {
        "type": ThreatType.CONFIGURATION_CHANGE,
        "severity": ThreatSeverity.CRITICAL,
        "title": "CloudTrail Logging Stopped",
        "description": "CloudTrail logging was stopped - possible attempt to hide malicious activity",
        "recommendations": ["Restart logging immediately", "Investigate who stopped logging"],
    },
    "DeleteBucket": {
        "type": ThreatType.DATA_EXFILTRATION,
        "severity": ThreatSeverity.HIGH,
        "title": "S3 Bucket Deleted",
        "description": "An S3 bucket was deleted",
        "recommendations": ["Verify deletion was authorized", "Check if data was backed up"],
    },
    "PutBucketPolicy": {
        "type": ThreatType.CONFIGURATION_CHANGE,
        "severity": ThreatSeverity.MEDIUM,
        "title": "S3 Bucket Policy Changed",
        "description": "An S3 bucket policy was modified",
        "recommendations": ["Review new policy", "Check for public access"],
    },
    "PutBucketAcl": {
        "type": ThreatType.CONFIGURATION_CHANGE,
        "severity": ThreatSeverity.MEDIUM,
        "title": "S3 Bucket ACL Changed",
        "description": "An S3 bucket ACL was modified",
        "recommendations": ["Review new ACL", "Check for public access"],
    },
    # Unauthorized Access
    "ConsoleLogin": {
        "type": ThreatType.UNAUTHORIZED_ACCESS,
        "severity": ThreatSeverity.MEDIUM,
        "title": "Console Login",
        "description": "A console login was detected",
        "recommendations": ["Verify login was authorized", "Check source IP"],
        "check_error": True,  # Only alert on failed logins
    },
    "GetSecretValue": {
        "type": ThreatType.CREDENTIAL_COMPROMISE,
        "severity": ThreatSeverity.MEDIUM,
        "title": "Secret Retrieved",
        "description": "A secret was retrieved from Secrets Manager",
        "recommendations": ["Verify access was authorized", "Review secret usage"],
    },
    # Resource Hijacking
    "RunInstances": {
        "type": ThreatType.RESOURCE_HIJACKING,
        "severity": ThreatSeverity.MEDIUM,
        "title": "EC2 Instance Launched",
        "description": "An EC2 instance was launched",
        "recommendations": ["Verify instance type and purpose", "Check for crypto mining"],
    },
    "AuthorizeSecurityGroupIngress": {
        "type": ThreatType.CONFIGURATION_CHANGE,
        "severity": ThreatSeverity.HIGH,
        "title": "Security Group Rule Added",
        "description": "An inbound rule was added to a security group",
        "recommendations": ["Review new rule", "Check for overly permissive access"],
    },
}


class CloudTrailDetector:
    """Real-time threat detection from CloudTrail events."""

    def __init__(self, alert_callback: Optional[Callable[[ThreatAlert], None]] = None):
        """Initialize the detector.

        Args:
            alert_callback: Optional callback function for alerts
        """
        self.alert_callback = alert_callback
        self.alerts: List[ThreatAlert] = []
        self._boto3 = None
        self._alert_counter = 0

    @property
    def boto3(self):
        """Lazy load boto3."""
        if self._boto3 is None:
            try:
                import boto3
                self._boto3 = boto3
            except ImportError:
                raise ImportError(
                    "boto3 is required for CloudTrail detection. "
                    "Install with: pip install secureagent[aws]"
                )
        return self._boto3

    def process_event(self, event: Dict[str, Any]) -> Optional[ThreatAlert]:
        """Process a CloudTrail event and check for threats.

        Args:
            event: CloudTrail event dictionary

        Returns:
            ThreatAlert if threat detected, None otherwise
        """
        event_name = event.get("eventName", "")
        error_code = event.get("errorCode")

        # Check if event matches a detection rule
        rule = DETECTION_RULES.get(event_name)
        if not rule:
            return None

        # Some rules only trigger on errors (e.g., failed logins)
        if rule.get("check_error") and not error_code:
            return None

        # Generate alert
        self._alert_counter += 1
        alert = ThreatAlert(
            id=f"CT-{self._alert_counter:06d}",
            threat_type=rule["type"],
            severity=rule["severity"],
            title=rule["title"],
            description=rule["description"],
            event_name=event_name,
            source_ip=event.get("sourceIPAddress"),
            user_identity=self._extract_user_identity(event),
            aws_region=event.get("awsRegion"),
            timestamp=self._parse_timestamp(event.get("eventTime")),
            raw_event=event,
            recommendations=rule.get("recommendations", []),
        )

        self.alerts.append(alert)

        # Call callback if provided
        if self.alert_callback:
            self.alert_callback(alert)

        return alert

    def process_events(self, events: List[Dict[str, Any]]) -> List[ThreatAlert]:
        """Process multiple CloudTrail events.

        Args:
            events: List of CloudTrail events

        Returns:
            List of detected alerts
        """
        alerts = []
        for event in events:
            alert = self.process_event(event)
            if alert:
                alerts.append(alert)
        return alerts

    def _extract_user_identity(self, event: Dict[str, Any]) -> Optional[str]:
        """Extract user identity from event."""
        user_identity = event.get("userIdentity", {})

        if user_identity.get("type") == "Root":
            return "ROOT"

        arn = user_identity.get("arn", "")
        user_name = user_identity.get("userName")

        if user_name:
            return user_name
        elif arn:
            # Extract from ARN
            parts = arn.split("/")
            return parts[-1] if len(parts) > 1 else arn

        return None

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse CloudTrail timestamp."""
        if not timestamp_str:
            return None

        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None

    def get_alerts_by_severity(self, severity: ThreatSeverity) -> List[ThreatAlert]:
        """Get alerts filtered by severity."""
        return [a for a in self.alerts if a.severity == severity]

    def get_alerts_by_type(self, threat_type: ThreatType) -> List[ThreatAlert]:
        """Get alerts filtered by threat type."""
        return [a for a in self.alerts if a.threat_type == threat_type]

    def get_summary(self) -> Dict[str, Any]:
        """Get alert summary."""
        return {
            "total_alerts": len(self.alerts),
            "by_severity": {
                s.value: len([a for a in self.alerts if a.severity == s])
                for s in ThreatSeverity
            },
            "by_type": {
                t.value: len([a for a in self.alerts if a.threat_type == t])
                for t in ThreatType
            },
            "critical_alerts": len(self.get_alerts_by_severity(ThreatSeverity.CRITICAL)),
        }

    def clear_alerts(self) -> None:
        """Clear all alerts."""
        self.alerts = []
