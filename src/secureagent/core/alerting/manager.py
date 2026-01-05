"""Alert manager for SecureAgent."""

import logging
from typing import List, Optional, Dict, Any, Protocol
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ..models.finding import Finding
from ..models.severity import Severity

logger = logging.getLogger(__name__)


def _get_severity_value(severity) -> str:
    """Get string value from severity, handling both enum and string."""
    if hasattr(severity, 'value'):
        return severity.value
    return str(severity)


def _get_severity_enum(severity) -> Severity:
    """Get Severity enum from severity, handling both enum and string."""
    if isinstance(severity, Severity):
        return severity
    return Severity(severity)


class AlertChannel(str, Enum):
    """Alert channel types."""

    SNS = "sns"
    SLACK = "slack"
    WEBHOOK = "webhook"
    EMAIL = "email"
    PAGERDUTY = "pagerduty"


class AlertPriority(str, Enum):
    """Alert priority levels."""

    P1 = "P1"  # Critical - immediate response required
    P2 = "P2"  # High - response within 1 hour
    P3 = "P3"  # Medium - response within 24 hours
    P4 = "P4"  # Low - informational


@dataclass
class Alert:
    """Alert to be sent."""

    id: str
    title: str
    message: str
    priority: AlertPriority
    severity: Severity
    source: str
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


class Alerter(Protocol):
    """Protocol for alerter implementations."""

    def send(self, alert: Alert) -> bool:
        """Send an alert. Returns True if successful."""
        ...


@dataclass
class AlertRule:
    """Rule for triggering alerts."""

    name: str
    min_severity: Severity
    channels: List[AlertChannel]
    min_findings: int = 1
    enabled: bool = True
    dedupe_window_minutes: int = 60


class AlertManager:
    """Manage and dispatch security alerts."""

    SEVERITY_TO_PRIORITY = {
        Severity.CRITICAL: AlertPriority.P1,
        Severity.HIGH: AlertPriority.P2,
        Severity.MEDIUM: AlertPriority.P3,
        Severity.LOW: AlertPriority.P4,
        Severity.INFO: AlertPriority.P4,
    }

    def __init__(self):
        """Initialize alert manager."""
        self.alerters: Dict[AlertChannel, Alerter] = {}
        self.rules: List[AlertRule] = []
        self.sent_alerts: Dict[str, datetime] = {}  # For deduplication

    def register_alerter(self, channel: AlertChannel, alerter: Alerter) -> None:
        """Register an alerter for a channel."""
        self.alerters[channel] = alerter

    def add_rule(self, rule: AlertRule) -> None:
        """Add an alert rule."""
        self.rules.append(rule)

    def remove_rule(self, name: str) -> None:
        """Remove a rule by name."""
        self.rules = [r for r in self.rules if r.name != name]

    def process_findings(
        self,
        findings: List[Finding],
        source: str = "security-scan",
    ) -> List[Alert]:
        """Process findings and send alerts based on rules."""
        sent_alerts = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            # Filter findings by severity
            matching_findings = [
                f
                for f in findings
                if list(Severity).index(_get_severity_enum(f.severity))
                <= list(Severity).index(rule.min_severity)
            ]

            if len(matching_findings) < rule.min_findings:
                continue

            # Check deduplication
            dedupe_key = f"{rule.name}:{source}"
            if self._is_deduplicated(dedupe_key, rule.dedupe_window_minutes):
                logger.debug(f"Alert deduplicated: {dedupe_key}")
                continue

            # Create and send alert
            alert = self._create_alert(matching_findings, rule, source)
            success = self._send_alert(alert, rule.channels)

            if success:
                self.sent_alerts[dedupe_key] = datetime.utcnow()
                sent_alerts.append(alert)

        return sent_alerts

    def send_immediate_alert(
        self,
        title: str,
        message: str,
        priority: AlertPriority,
        channels: Optional[List[AlertChannel]] = None,
        findings: Optional[List[Finding]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Send an immediate alert without rule processing."""
        import uuid

        alert = Alert(
            id=str(uuid.uuid4()),
            title=title,
            message=message,
            priority=priority,
            severity=self._priority_to_severity(priority),
            source="immediate",
            findings=findings or [],
            metadata=metadata or {},
        )

        target_channels = channels or list(self.alerters.keys())
        return self._send_alert(alert, target_channels)

    def _create_alert(
        self,
        findings: List[Finding],
        rule: AlertRule,
        source: str,
    ) -> Alert:
        """Create an alert from findings."""
        import uuid

        # Determine highest severity
        highest_severity = Severity.INFO
        for finding in findings:
            finding_severity = _get_severity_enum(finding.severity)
            if list(Severity).index(finding_severity) < list(Severity).index(
                highest_severity
            ):
                highest_severity = finding_severity

        # Build title and message
        severity_counts: Dict[Severity, int] = {}
        for f in findings:
            severity_enum = _get_severity_enum(f.severity)
            severity_counts[severity_enum] = severity_counts.get(severity_enum, 0) + 1

        title = f"Security Alert: {len(findings)} findings detected"
        message = self._build_alert_message(findings, severity_counts)

        return Alert(
            id=str(uuid.uuid4()),
            title=title,
            message=message,
            priority=self.SEVERITY_TO_PRIORITY.get(highest_severity, AlertPriority.P4),
            severity=highest_severity,
            source=source,
            findings=findings,
            metadata={
                "rule_name": rule.name,
                "severity_counts": {_get_severity_value(k): v for k, v in severity_counts.items()},
            },
        )

    def _build_alert_message(
        self,
        findings: List[Finding],
        severity_counts: Dict[Severity, int],
    ) -> str:
        """Build alert message."""
        lines = [
            f"Detected {len(findings)} security findings:\n",
        ]

        # Severity breakdown
        for severity in Severity:
            count = severity_counts.get(severity, 0)
            if count > 0:
                lines.append(f"  - {severity.value}: {count}")

        lines.append("")

        # Top findings
        critical_high = [
            f for f in findings if _get_severity_enum(f.severity) in (Severity.CRITICAL, Severity.HIGH)
        ]
        if critical_high:
            lines.append("Critical/High findings:")
            for finding in critical_high[:5]:
                lines.append(f"  * {finding.title}")

        return "\n".join(lines)

    def _send_alert(
        self,
        alert: Alert,
        channels: List[AlertChannel],
    ) -> bool:
        """Send alert to specified channels."""
        success = False

        for channel in channels:
            alerter = self.alerters.get(channel)
            if not alerter:
                logger.warning(f"No alerter registered for channel: {channel}")
                continue

            try:
                if alerter.send(alert):
                    logger.info(f"Alert sent via {channel.value}: {alert.title}")
                    success = True
                else:
                    logger.warning(f"Failed to send alert via {channel.value}")
            except Exception as e:
                logger.error(f"Error sending alert via {channel.value}: {e}")

        return success

    def _is_deduplicated(self, key: str, window_minutes: int) -> bool:
        """Check if alert was recently sent."""
        if key not in self.sent_alerts:
            return False

        last_sent = self.sent_alerts[key]
        elapsed = (datetime.utcnow() - last_sent).total_seconds() / 60
        return elapsed < window_minutes

    def _priority_to_severity(self, priority: AlertPriority) -> Severity:
        """Convert priority to severity."""
        mapping = {
            AlertPriority.P1: Severity.CRITICAL,
            AlertPriority.P2: Severity.HIGH,
            AlertPriority.P3: Severity.MEDIUM,
            AlertPriority.P4: Severity.LOW,
        }
        return mapping.get(priority, Severity.INFO)

    def get_default_rules(self) -> List[AlertRule]:
        """Get default alerting rules."""
        return [
            AlertRule(
                name="critical-immediate",
                min_severity=Severity.CRITICAL,
                channels=[AlertChannel.SLACK, AlertChannel.SNS],
                min_findings=1,
                dedupe_window_minutes=30,
            ),
            AlertRule(
                name="high-severity",
                min_severity=Severity.HIGH,
                channels=[AlertChannel.SLACK],
                min_findings=1,
                dedupe_window_minutes=60,
            ),
            AlertRule(
                name="medium-batch",
                min_severity=Severity.MEDIUM,
                channels=[AlertChannel.WEBHOOK],
                min_findings=5,
                dedupe_window_minutes=120,
            ),
        ]
