"""Slack alerter for SecureAgent."""

import os
import logging
from typing import Optional, List, Dict, Any

from .manager import Alert, AlertPriority
from ..models.severity import Severity

logger = logging.getLogger(__name__)


class SlackAlerter:
    """Send alerts via Slack webhook."""

    PRIORITY_COLORS = {
        AlertPriority.P1: "#dc3545",  # Red
        AlertPriority.P2: "#fd7e14",  # Orange
        AlertPriority.P3: "#ffc107",  # Yellow
        AlertPriority.P4: "#17a2b8",  # Cyan
    }

    PRIORITY_EMOJIS = {
        AlertPriority.P1: ":rotating_light:",
        AlertPriority.P2: ":warning:",
        AlertPriority.P3: ":large_yellow_circle:",
        AlertPriority.P4: ":information_source:",
    }

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        channel: Optional[str] = None,
    ):
        """Initialize Slack alerter."""
        self.webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
        self.channel = channel or os.environ.get("SLACK_ALERT_CHANNEL")
        self._http_client = None

    @property
    def http_client(self):
        """Lazy-load HTTP client."""
        if self._http_client is None:
            try:
                import httpx

                self._http_client = httpx.Client(timeout=30)
            except ImportError:
                raise ImportError(
                    "httpx is required for Slack alerting. "
                    "Install with: pip install httpx"
                )
        return self._http_client

    def send(self, alert: Alert) -> bool:
        """Send alert via Slack webhook."""
        if not self.webhook_url:
            logger.error("Slack webhook URL not configured")
            return False

        try:
            payload = self._build_payload(alert)

            response = self.http_client.post(
                self.webhook_url,
                json=payload,
            )

            if response.status_code == 200:
                logger.info(f"Slack alert sent: {alert.title}")
                return True
            else:
                logger.warning(
                    f"Slack webhook returned {response.status_code}: {response.text}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False

    def _build_payload(self, alert: Alert) -> Dict[str, Any]:
        """Build Slack webhook payload."""
        emoji = self.PRIORITY_EMOJIS.get(alert.priority, ":bell:")
        color = self.PRIORITY_COLORS.get(alert.priority, "#6c757d")

        payload: Dict[str, Any] = {
            "attachments": [
                {
                    "color": color,
                    "blocks": self._build_blocks(alert, emoji),
                }
            ],
        }

        if self.channel:
            payload["channel"] = self.channel

        return payload

    def _build_blocks(self, alert: Alert, emoji: str) -> List[Dict[str, Any]]:
        """Build Slack Block Kit blocks."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {alert.title}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Priority:*\n{alert.priority.value}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{alert.severity.value}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Source:*\n{alert.source}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Findings:*\n{len(alert.findings)}",
                    },
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"```{alert.message}```",
                },
            },
        ]

        # Add top findings
        critical_high = [
            f
            for f in alert.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        if critical_high:
            findings_text = "*Critical/High Findings:*\n"
            for finding in critical_high[:5]:
                severity_emoji = {
                    Severity.CRITICAL: ":rotating_light:",
                    Severity.HIGH: ":warning:",
                }.get(finding.severity, ":question:")
                findings_text += f"{severity_emoji} {finding.title}\n"

            if len(critical_high) > 5:
                findings_text += f"_...and {len(critical_high) - 5} more_"

            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": findings_text,
                    },
                }
            )

        # Footer
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"SecureAgent | {alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                    }
                ],
            }
        )

        return blocks

    def send_simple(
        self,
        title: str,
        message: str,
        color: str = "#36a64f",
    ) -> bool:
        """Send a simple Slack message."""
        if not self.webhook_url:
            return False

        try:
            payload = {
                "attachments": [
                    {
                        "color": color,
                        "title": title,
                        "text": message,
                        "footer": "SecureAgent",
                    }
                ],
            }

            if self.channel:
                payload["channel"] = self.channel

            response = self.http_client.post(self.webhook_url, json=payload)
            return response.status_code == 200

        except Exception as e:
            logger.error(f"Failed to send simple Slack message: {e}")
            return False
