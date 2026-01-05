"""AWS SNS alerter for SecureAgent."""

import os
import json
import logging
from typing import Optional, Dict, Any

from .manager import Alert, AlertPriority

logger = logging.getLogger(__name__)


class SNSAlerter:
    """Send alerts via AWS SNS."""

    def __init__(
        self,
        topic_arn: Optional[str] = None,
        region: Optional[str] = None,
    ):
        """Initialize SNS alerter."""
        self.topic_arn = topic_arn or os.environ.get("SECUREAGENT_SNS_TOPIC_ARN")
        self.region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self._client = None

    @property
    def client(self):
        """Lazy-load SNS client."""
        if self._client is None:
            try:
                import boto3

                self._client = boto3.client("sns", region_name=self.region)
            except ImportError:
                raise ImportError(
                    "boto3 is required for SNS alerting. "
                    "Install with: pip install secureagent[aws]"
                )
        return self._client

    def send(self, alert: Alert) -> bool:
        """Send alert via SNS."""
        if not self.topic_arn:
            logger.error("SNS topic ARN not configured")
            return False

        try:
            # Build message
            message = self._build_message(alert)
            subject = self._build_subject(alert)

            # Publish to SNS
            response = self.client.publish(
                TopicArn=self.topic_arn,
                Message=message,
                Subject=subject[:100],  # SNS subject limit
                MessageAttributes=self._build_attributes(alert),
            )

            logger.info(f"SNS alert published: {response['MessageId']}")
            return True

        except Exception as e:
            logger.error(f"Failed to publish SNS alert: {e}")
            return False

    def _build_subject(self, alert: Alert) -> str:
        """Build SNS subject line."""
        priority_emoji = {
            AlertPriority.P1: "[P1-CRITICAL]",
            AlertPriority.P2: "[P2-HIGH]",
            AlertPriority.P3: "[P3-MEDIUM]",
            AlertPriority.P4: "[P4-LOW]",
        }
        prefix = priority_emoji.get(alert.priority, "[ALERT]")
        return f"{prefix} {alert.title}"

    def _build_message(self, alert: Alert) -> str:
        """Build SNS message body."""
        lines = [
            f"Security Alert: {alert.title}",
            f"Priority: {alert.priority.value}",
            f"Severity: {alert.severity.value}",
            f"Source: {alert.source}",
            f"Time: {alert.created_at.isoformat()}",
            "",
            "Details:",
            alert.message,
        ]

        if alert.findings:
            lines.extend(
                [
                    "",
                    f"Total Findings: {len(alert.findings)}",
                    "",
                    "Top Findings:",
                ]
            )
            for finding in alert.findings[:5]:
                lines.append(f"  - [{finding.severity.value}] {finding.title}")

        lines.extend(
            [
                "",
                "---",
                "SecureAgent Security Scanner",
            ]
        )

        return "\n".join(lines)

    def _build_attributes(self, alert: Alert) -> Dict[str, Dict[str, str]]:
        """Build SNS message attributes."""
        return {
            "priority": {
                "DataType": "String",
                "StringValue": alert.priority.value,
            },
            "severity": {
                "DataType": "String",
                "StringValue": alert.severity.value,
            },
            "source": {
                "DataType": "String",
                "StringValue": alert.source,
            },
            "finding_count": {
                "DataType": "Number",
                "StringValue": str(len(alert.findings)),
            },
        }

    def send_json(self, alert: Alert) -> bool:
        """Send alert as JSON (for Lambda/SQS subscribers)."""
        if not self.topic_arn:
            logger.error("SNS topic ARN not configured")
            return False

        try:
            # Build JSON payload
            payload = {
                "id": alert.id,
                "title": alert.title,
                "message": alert.message,
                "priority": alert.priority.value,
                "severity": alert.severity.value,
                "source": alert.source,
                "created_at": alert.created_at.isoformat(),
                "findings": [
                    {
                        "id": f.id,
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "description": f.description,
                    }
                    for f in alert.findings
                ],
                "metadata": alert.metadata,
            }

            response = self.client.publish(
                TopicArn=self.topic_arn,
                Message=json.dumps(payload),
                MessageAttributes={
                    "content_type": {
                        "DataType": "String",
                        "StringValue": "application/json",
                    },
                    **self._build_attributes(alert),
                },
            )

            logger.info(f"SNS JSON alert published: {response['MessageId']}")
            return True

        except Exception as e:
            logger.error(f"Failed to publish SNS JSON alert: {e}")
            return False
