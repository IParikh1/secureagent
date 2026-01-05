"""Slack bot for SecureAgent."""

import os
import logging
from typing import List, Optional, Dict, Any, Callable
from dataclasses import dataclass
from enum import Enum

from ...core.models.finding import Finding
from ...core.models.severity import Severity

logger = logging.getLogger(__name__)


class MessageType(str, Enum):
    """Slack message types."""

    ALERT = "alert"
    REPORT = "report"
    STATUS = "status"


@dataclass
class SlackMessage:
    """Slack message to send."""

    channel: str
    text: str
    blocks: Optional[List[Dict]] = None
    attachments: Optional[List[Dict]] = None
    thread_ts: Optional[str] = None


class SlackBot:
    """Slack bot for security alerts and commands."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: "#dc3545",
        Severity.HIGH: "#fd7e14",
        Severity.MEDIUM: "#ffc107",
        Severity.LOW: "#17a2b8",
        Severity.INFO: "#6c757d",
    }

    SEVERITY_EMOJIS = {
        Severity.CRITICAL: ":rotating_light:",
        Severity.HIGH: ":warning:",
        Severity.MEDIUM: ":large_yellow_circle:",
        Severity.LOW: ":information_source:",
        Severity.INFO: ":memo:",
    }

    def __init__(
        self,
        token: Optional[str] = None,
        signing_secret: Optional[str] = None,
        default_channel: Optional[str] = None,
    ):
        """Initialize Slack bot."""
        self.token = token or os.environ.get("SLACK_BOT_TOKEN")
        self.signing_secret = signing_secret or os.environ.get("SLACK_SIGNING_SECRET")
        self.default_channel = default_channel or os.environ.get(
            "SLACK_DEFAULT_CHANNEL", "#security-alerts"
        )
        self._client = None
        self._app = None
        self.command_handlers: Dict[str, Callable] = {}

    @property
    def client(self):
        """Lazy-load Slack client."""
        if self._client is None:
            try:
                from slack_sdk import WebClient

                self._client = WebClient(token=self.token)
            except ImportError:
                raise ImportError(
                    "slack-sdk is required for Slack integration. "
                    "Install with: pip install secureagent[slack]"
                )
        return self._client

    def send_message(self, message: SlackMessage) -> str:
        """Send a message to Slack."""
        response = self.client.chat_postMessage(
            channel=message.channel,
            text=message.text,
            blocks=message.blocks,
            attachments=message.attachments,
            thread_ts=message.thread_ts,
        )
        return response["ts"]

    def send_alert(
        self,
        findings: List[Finding],
        channel: Optional[str] = None,
        title: str = "Security Alert",
        include_details: bool = True,
    ) -> str:
        """Send security alert for findings."""
        channel = channel or self.default_channel

        blocks = self._build_alert_blocks(findings, title, include_details)
        text = f"{title}: Found {len(findings)} security issues"

        message = SlackMessage(
            channel=channel,
            text=text,
            blocks=blocks,
        )

        return self.send_message(message)

    def send_scan_report(
        self,
        findings: List[Finding],
        scan_target: str,
        channel: Optional[str] = None,
        scan_duration: Optional[float] = None,
    ) -> str:
        """Send a scan report to Slack."""
        channel = channel or self.default_channel

        blocks = self._build_report_blocks(findings, scan_target, scan_duration)
        text = f"Scan complete for {scan_target}: {len(findings)} findings"

        message = SlackMessage(
            channel=channel,
            text=text,
            blocks=blocks,
        )

        return self.send_message(message)

    def send_finding_detail(
        self,
        finding: Finding,
        channel: Optional[str] = None,
        thread_ts: Optional[str] = None,
    ) -> str:
        """Send detailed finding information."""
        channel = channel or self.default_channel
        blocks = self._build_finding_blocks(finding)

        message = SlackMessage(
            channel=channel,
            text=f"Finding: {finding.title}",
            blocks=blocks,
            thread_ts=thread_ts,
        )

        return self.send_message(message)

    def _build_alert_blocks(
        self,
        findings: List[Finding],
        title: str,
        include_details: bool,
    ) -> List[Dict]:
        """Build Slack blocks for alert."""
        # Count by severity
        severity_counts: Dict[Severity, int] = {}
        for finding in findings:
            severity_counts[finding.severity] = (
                severity_counts.get(finding.severity, 0) + 1
            )

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f":shield: {title}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Found *{len(findings)}* security issues",
                },
            },
            {"type": "divider"},
        ]

        # Severity summary
        summary_parts = []
        for severity in Severity:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = self.SEVERITY_EMOJIS.get(severity, "")
                summary_parts.append(f"{emoji} *{severity.value}:* {count}")

        if summary_parts:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": " | ".join(summary_parts),
                    },
                }
            )

        # Critical/High findings details
        if include_details:
            critical_high = [
                f
                for f in findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH)
            ]
            if critical_high:
                blocks.append({"type": "divider"})
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Critical/High Severity Issues:*",
                        },
                    }
                )

                for finding in critical_high[:5]:
                    emoji = self.SEVERITY_EMOJIS.get(finding.severity, "")
                    location = ""
                    if finding.location and finding.location.file_path:
                        location = f"\n`{finding.location.file_path}`"
                    blocks.append(
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"{emoji} *{finding.title}*{location}",
                            },
                        }
                    )

                if len(critical_high) > 5:
                    blocks.append(
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"_...and {len(critical_high) - 5} more_",
                                }
                            ],
                        }
                    )

        # Footer
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "_SecureAgent Security Scanner_",
                    }
                ],
            }
        )

        return blocks

    def _build_report_blocks(
        self,
        findings: List[Finding],
        scan_target: str,
        scan_duration: Optional[float],
    ) -> List[Dict]:
        """Build Slack blocks for scan report."""
        severity_counts: Dict[Severity, int] = {}
        for finding in findings:
            severity_counts[finding.severity] = (
                severity_counts.get(finding.severity, 0) + 1
            )

        # Status emoji
        critical_high = severity_counts.get(Severity.CRITICAL, 0) + severity_counts.get(
            Severity.HIGH, 0
        )
        status_emoji = ":white_check_mark:" if critical_high == 0 else ":x:"

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} Security Scan Complete",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n{scan_target}"},
                    {"type": "mrkdwn", "text": f"*Total Findings:*\n{len(findings)}"},
                ],
            },
        ]

        if scan_duration:
            blocks[1]["fields"].append(
                {"type": "mrkdwn", "text": f"*Duration:*\n{scan_duration:.2f}s"}
            )

        blocks.append({"type": "divider"})

        # Severity breakdown
        breakdown = []
        for severity in Severity:
            count = severity_counts.get(severity, 0)
            emoji = self.SEVERITY_EMOJIS.get(severity, "")
            breakdown.append(f"{emoji} {severity.value}: *{count}*")

        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "\n".join(breakdown)},
            }
        )

        return blocks

    def _build_finding_blocks(self, finding: Finding) -> List[Dict]:
        """Build Slack blocks for single finding."""
        emoji = self.SEVERITY_EMOJIS.get(finding.severity, "")
        color = self.SEVERITY_COLORS.get(finding.severity, "#6c757d")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {finding.title}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{finding.severity.value}",
                    },
                    {"type": "mrkdwn", "text": f"*Rule:*\n{finding.rule_id}"},
                ],
            },
        ]

        if finding.location and finding.location.file_path:
            location = finding.location.file_path
            if finding.location.line_number:
                location += f":{finding.location.line_number}"
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Location:*\n`{location}`"},
                }
            )

        blocks.append({"type": "divider"})
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Description:*\n{finding.description}"},
            }
        )

        if finding.remediation:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Remediation:*\n{finding.remediation}",
                    },
                }
            )

        refs = []
        if finding.cwe_id:
            refs.append(finding.cwe_id)
        if finding.owasp_id:
            refs.append(finding.owasp_id)
        if refs:
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"References: {', '.join(refs)}"}
                    ],
                }
            )

        return blocks

    def register_command(self, command: str, handler: Callable) -> None:
        """Register a slash command handler."""
        self.command_handlers[command] = handler

    def handle_command(
        self, command: str, args: str, user_id: str, channel_id: str
    ) -> Dict[str, Any]:
        """Handle incoming slash command."""
        if command in self.command_handlers:
            return self.command_handlers[command](args, user_id, channel_id)
        return {"text": f"Unknown command: {command}"}
