"""Slack slash commands for SecureAgent."""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from ...core.models.finding import Finding
from ...core.models.severity import Severity


@dataclass
class CommandResponse:
    """Response to a slash command."""

    text: str
    response_type: str = "ephemeral"  # or "in_channel"
    blocks: Optional[List[Dict]] = None
    attachments: Optional[List[Dict]] = None


class SlackCommands:
    """Slack slash command handlers."""

    def __init__(self, bot):
        """Initialize commands with bot reference."""
        self.bot = bot
        self._register_commands()

    def _register_commands(self) -> None:
        """Register all commands."""
        self.bot.register_command("/secureagent", self.handle_main_command)
        self.bot.register_command("/scan", self.handle_scan_command)
        self.bot.register_command("/security-status", self.handle_status_command)

    def handle_main_command(
        self, args: str, user_id: str, channel_id: str
    ) -> Dict[str, Any]:
        """Handle main /secureagent command."""
        parts = args.strip().split() if args else []
        subcommand = parts[0] if parts else "help"
        sub_args = parts[1:] if len(parts) > 1 else []

        handlers = {
            "help": self._handle_help,
            "scan": self._handle_scan_subcommand,
            "status": self._handle_status_subcommand,
            "findings": self._handle_findings_subcommand,
            "config": self._handle_config_subcommand,
        }

        handler = handlers.get(subcommand, self._handle_help)
        return handler(sub_args, user_id, channel_id)

    def _handle_help(
        self, args: List[str], user_id: str, channel_id: str
    ) -> Dict[str, Any]:
        """Handle help subcommand."""
        help_text = """
*SecureAgent Commands*

`/secureagent help` - Show this help message
`/secureagent scan <target>` - Scan a target (path, repo, or URL)
`/secureagent status` - Show current security status
`/secureagent findings [severity]` - Show recent findings
`/secureagent config` - Show current configuration

*Quick Commands*
`/scan <target>` - Quick scan shortcut
`/security-status` - Quick status check
"""
        return {
            "response_type": "ephemeral",
            "text": help_text,
        }

    def _handle_scan_subcommand(
        self, args: List[str], user_id: str, channel_id: str
    ) -> Dict[str, Any]:
        """Handle scan subcommand."""
        if not args:
            return {
                "response_type": "ephemeral",
                "text": "Please specify a target to scan. Usage: `/secureagent scan <path|repo|url>`",
            }

        target = args[0]
        return {
            "response_type": "in_channel",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f":mag: Starting security scan of `{target}`...",
                    },
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"Requested by <@{user_id}>"}
                    ],
                },
            ],
        }

    def _handle_status_subcommand(
        self, args: List[str], user_id: str, channel_id: str
    ) -> Dict[str, Any]:
        """Handle status subcommand."""
        # This would typically fetch real data
        return {
            "response_type": "ephemeral",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": ":shield: Security Status",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": "*Last Scan:*\nToday, 10:30 AM"},
                        {"type": "mrkdwn", "text": "*Open Findings:*\n12"},
                        {"type": "mrkdwn", "text": "*Critical:*\n0"},
                        {"type": "mrkdwn", "text": "*High:*\n3"},
                    ],
                },
            ],
        }

    def _handle_findings_subcommand(
        self, args: List[str], user_id: str, channel_id: str
    ) -> Dict[str, Any]:
        """Handle findings subcommand."""
        severity_filter = args[0].upper() if args else None

        if severity_filter and severity_filter not in [s.value for s in Severity]:
            return {
                "response_type": "ephemeral",
                "text": f"Invalid severity. Use: {', '.join(s.value for s in Severity)}",
            }

        # This would typically fetch real findings
        return {
            "response_type": "ephemeral",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": ":page_facing_up: Recent Findings",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "No recent findings to display.",
                    },
                },
            ],
        }

    def _handle_config_subcommand(
        self, args: List[str], user_id: str, channel_id: str
    ) -> Dict[str, Any]:
        """Handle config subcommand."""
        return {
            "response_type": "ephemeral",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": ":gear: Current Configuration",
                        "emoji": True,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": "*Alert Channel:*\n#security-alerts"},
                        {"type": "mrkdwn", "text": "*Min Severity:*\nMEDIUM"},
                        {"type": "mrkdwn", "text": "*Auto-scan:*\nEnabled"},
                        {"type": "mrkdwn", "text": "*Scanners:*\nmcp, langchain, aws"},
                    ],
                },
            ],
        }

    def handle_scan_command(
        self, args: str, user_id: str, channel_id: str
    ) -> Dict[str, Any]:
        """Handle /scan shortcut command."""
        return self._handle_scan_subcommand(
            args.split() if args else [], user_id, channel_id
        )

    def handle_status_command(
        self, args: str, user_id: str, channel_id: str
    ) -> Dict[str, Any]:
        """Handle /security-status shortcut command."""
        return self._handle_status_subcommand([], user_id, channel_id)

    def format_findings_response(
        self, findings: List[Finding], limit: int = 10
    ) -> Dict[str, Any]:
        """Format findings as Slack response."""
        if not findings:
            return {
                "response_type": "ephemeral",
                "text": "No findings to display.",
            }

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f":shield: Security Findings ({len(findings)} total)",
                    "emoji": True,
                },
            },
            {"type": "divider"},
        ]

        for finding in findings[:limit]:
            severity_emoji = {
                Severity.CRITICAL: ":rotating_light:",
                Severity.HIGH: ":warning:",
                Severity.MEDIUM: ":large_yellow_circle:",
                Severity.LOW: ":information_source:",
                Severity.INFO: ":memo:",
            }.get(finding.severity, ":question:")

            location = ""
            if finding.location and finding.location.file_path:
                location = f"\n`{finding.location.file_path}`"

            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{severity_emoji} *{finding.title}* [{finding.severity.value}]{location}",
                    },
                }
            )

        if len(findings) > limit:
            blocks.append(
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"_Showing {limit} of {len(findings)} findings_",
                        }
                    ],
                }
            )

        return {"response_type": "ephemeral", "blocks": blocks}
