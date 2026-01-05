"""Tests for alert manager."""

import pytest
from unittest.mock import MagicMock, patch

from secureagent.core.alerting.manager import (
    AlertManager,
    AlertRule,
    AlertPriority,
    AlertChannel,
    Alert,
)
from secureagent.core.models.finding import Finding, FindingDomain, Location
from secureagent.core.models.severity import Severity


class TestAlertManager:
    """Tests for AlertManager."""

    def test_manager_initialization(self):
        """Test manager initialization."""
        manager = AlertManager()
        assert manager is not None
        assert len(manager.rules) == 0
        assert len(manager.alerters) == 0

    def test_add_alert_rule(self):
        """Test adding alert rules."""
        manager = AlertManager()

        rule = AlertRule(
            name="critical-findings",
            min_severity=Severity.CRITICAL,
            channels=[AlertChannel.SLACK],
        )
        manager.add_rule(rule)

        assert len(manager.rules) == 1

    def test_remove_alert_rule(self):
        """Test removing alert rules."""
        manager = AlertManager()

        rule = AlertRule(
            name="test-rule",
            min_severity=Severity.HIGH,
            channels=[AlertChannel.SLACK],
        )
        manager.add_rule(rule)
        manager.remove_rule("test-rule")

        assert len(manager.rules) == 0

    def test_process_findings_with_matching_rule(self, sample_finding):
        """Test that findings trigger alerts based on rules."""
        manager = AlertManager()

        # Add rule for high severity
        rule = AlertRule(
            name="high-findings",
            min_severity=Severity.HIGH,
            channels=[AlertChannel.WEBHOOK],
        )
        manager.add_rule(rule)

        # Register a mock alerter
        mock_alerter = MagicMock()
        mock_alerter.send.return_value = True
        manager.register_alerter(AlertChannel.WEBHOOK, mock_alerter)

        alerts = manager.process_findings([sample_finding])

        # Sample finding is HIGH severity, should match
        assert len(alerts) > 0
        mock_alerter.send.assert_called()

    def test_process_findings_no_match(self, sample_finding):
        """Test that non-matching findings don't trigger alerts."""
        manager = AlertManager()

        # Add rule for CRITICAL only
        rule = AlertRule(
            name="critical-only",
            min_severity=Severity.CRITICAL,
            channels=[AlertChannel.SLACK],
        )
        manager.add_rule(rule)

        # Register mock alerter
        mock_alerter = MagicMock()
        mock_alerter.send.return_value = True
        manager.register_alerter(AlertChannel.SLACK, mock_alerter)

        # Sample finding is HIGH, not CRITICAL
        alerts = manager.process_findings([sample_finding])

        # Should not trigger (HIGH doesn't meet CRITICAL minimum)
        assert len(alerts) == 0

    def test_alert_deduplication(self, sample_finding):
        """Test that duplicate alerts are deduplicated."""
        manager = AlertManager()

        rule = AlertRule(
            name="high-findings",
            min_severity=Severity.HIGH,
            channels=[AlertChannel.WEBHOOK],
            dedupe_window_minutes=60,
        )
        manager.add_rule(rule)

        # Register mock alerter
        mock_alerter = MagicMock()
        mock_alerter.send.return_value = True
        manager.register_alerter(AlertChannel.WEBHOOK, mock_alerter)

        # Process same finding twice
        alerts1 = manager.process_findings([sample_finding])
        alerts2 = manager.process_findings([sample_finding])

        # First should trigger, second should be deduplicated
        assert len(alerts1) == 1
        assert len(alerts2) == 0

    def test_multiple_rules(self):
        """Test multiple rules processing."""
        manager = AlertManager()

        manager.add_rule(AlertRule(
            name="critical",
            min_severity=Severity.CRITICAL,
            channels=[AlertChannel.SNS],
        ))
        manager.add_rule(AlertRule(
            name="high",
            min_severity=Severity.HIGH,
            channels=[AlertChannel.SLACK],
        ))

        # Register mock alerters
        mock_sns = MagicMock()
        mock_sns.send.return_value = True
        mock_slack = MagicMock()
        mock_slack.send.return_value = True
        manager.register_alerter(AlertChannel.SNS, mock_sns)
        manager.register_alerter(AlertChannel.SLACK, mock_slack)

        findings = [
            Finding(
                id="f1",
                rule_id="R1",
                domain=FindingDomain.MCP,
                title="Critical",
                description="Test",
                severity=Severity.CRITICAL,
                location=Location(file_path="/test"),
                remediation="Fix",
            ),
        ]

        alerts = manager.process_findings(findings)

        # Critical finding should trigger both rules (critical meets both thresholds)
        assert len(alerts) == 2

    def test_send_immediate_alert(self):
        """Test sending immediate alerts."""
        manager = AlertManager()

        mock_alerter = MagicMock()
        mock_alerter.send.return_value = True
        manager.register_alerter(AlertChannel.SLACK, mock_alerter)

        result = manager.send_immediate_alert(
            title="Immediate Alert",
            message="This is urgent",
            priority=AlertPriority.P1,
            channels=[AlertChannel.SLACK],
        )

        assert result is True
        mock_alerter.send.assert_called_once()

    def test_get_default_rules(self):
        """Test getting default alert rules."""
        manager = AlertManager()
        rules = manager.get_default_rules()

        assert len(rules) == 3
        assert any(r.name == "critical-immediate" for r in rules)
        assert any(r.name == "high-severity" for r in rules)

    def test_severity_to_priority_mapping(self):
        """Test severity to priority mapping."""
        manager = AlertManager()

        assert manager.SEVERITY_TO_PRIORITY[Severity.CRITICAL] == AlertPriority.P1
        assert manager.SEVERITY_TO_PRIORITY[Severity.HIGH] == AlertPriority.P2
        assert manager.SEVERITY_TO_PRIORITY[Severity.MEDIUM] == AlertPriority.P3
        assert manager.SEVERITY_TO_PRIORITY[Severity.LOW] == AlertPriority.P4


class TestAlertRule:
    """Tests for AlertRule."""

    def test_rule_creation(self):
        """Test rule creation."""
        rule = AlertRule(
            name="test-rule",
            min_severity=Severity.HIGH,
            channels=[AlertChannel.SLACK],
        )

        assert rule.name == "test-rule"
        assert rule.min_severity == Severity.HIGH
        assert rule.enabled is True
        assert rule.min_findings == 1

    def test_rule_with_options(self):
        """Test rule with additional options."""
        rule = AlertRule(
            name="custom-rule",
            min_severity=Severity.MEDIUM,
            channels=[AlertChannel.SLACK, AlertChannel.WEBHOOK],
            min_findings=3,
            enabled=True,
            dedupe_window_minutes=120,
        )

        assert rule.min_findings == 3
        assert rule.dedupe_window_minutes == 120
        assert len(rule.channels) == 2


class TestAlert:
    """Tests for Alert dataclass."""

    def test_alert_creation(self, sample_finding):
        """Test alert creation."""
        alert = Alert(
            id="alert-001",
            title="Test Alert",
            message="Test message",
            priority=AlertPriority.P2,
            severity=Severity.HIGH,
            source="test",
            findings=[sample_finding],
        )

        assert alert.id == "alert-001"
        assert alert.priority == AlertPriority.P2
        assert len(alert.findings) == 1

    def test_alert_with_metadata(self, sample_finding):
        """Test alert with metadata."""
        alert = Alert(
            id="alert-002",
            title="Alert with Metadata",
            message="Test",
            priority=AlertPriority.P1,
            severity=Severity.CRITICAL,
            source="test",
            metadata={"team": "security", "runbook": "https://wiki/runbook"},
        )

        assert alert.metadata["team"] == "security"
