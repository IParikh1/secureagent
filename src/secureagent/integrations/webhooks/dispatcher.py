"""Webhook dispatcher for SecureAgent."""

import hashlib
import hmac
import json
import logging
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ...core.models.finding import Finding
from ...core.models.severity import Severity

logger = logging.getLogger(__name__)


class WebhookEvent(str, Enum):
    """Webhook event types."""

    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    FINDING_DETECTED = "finding.detected"
    CRITICAL_ALERT = "critical.alert"
    COMPLIANCE_VIOLATION = "compliance.violation"


@dataclass
class WebhookConfig:
    """Webhook configuration."""

    url: str
    events: List[WebhookEvent] = field(default_factory=lambda: list(WebhookEvent))
    secret: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    retry_count: int = 3
    timeout: int = 30


@dataclass
class WebhookPayload:
    """Webhook payload."""

    event: WebhookEvent
    timestamp: str
    data: Dict[str, Any]


class WebhookDispatcher:
    """Dispatch events to configured webhooks."""

    def __init__(self):
        """Initialize webhook dispatcher."""
        self.webhooks: List[WebhookConfig] = []
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
                    "httpx is required for webhook integration. "
                    "Install with: pip install httpx"
                )
        return self._http_client

    def add_webhook(self, config: WebhookConfig) -> None:
        """Add a webhook configuration."""
        self.webhooks.append(config)

    def remove_webhook(self, url: str) -> None:
        """Remove a webhook by URL."""
        self.webhooks = [w for w in self.webhooks if w.url != url]

    def dispatch(self, event: WebhookEvent, data: Dict[str, Any]) -> List[bool]:
        """Dispatch event to all matching webhooks."""
        results = []

        payload = WebhookPayload(
            event=event,
            timestamp=datetime.utcnow().isoformat() + "Z",
            data=data,
        )

        for webhook in self.webhooks:
            if not webhook.enabled:
                continue

            if event not in webhook.events:
                continue

            success = self._send_webhook(webhook, payload)
            results.append(success)

        return results

    def _send_webhook(self, config: WebhookConfig, payload: WebhookPayload) -> bool:
        """Send payload to a webhook."""
        json_payload = {
            "event": payload.event.value,
            "timestamp": payload.timestamp,
            "data": payload.data,
        }

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SecureAgent/1.0",
            **config.headers,
        }

        # Add signature if secret configured
        if config.secret:
            signature = self._generate_signature(json_payload, config.secret)
            headers["X-SecureAgent-Signature"] = signature

        for attempt in range(config.retry_count):
            try:
                response = self.http_client.post(
                    config.url,
                    json=json_payload,
                    headers=headers,
                    timeout=config.timeout,
                )

                if response.status_code >= 200 and response.status_code < 300:
                    logger.info(f"Webhook delivered to {config.url}")
                    return True

                logger.warning(
                    f"Webhook failed with status {response.status_code}: {config.url}"
                )

            except Exception as e:
                logger.error(f"Webhook error (attempt {attempt + 1}): {e}")

        return False

    def _generate_signature(self, payload: Dict, secret: str) -> str:
        """Generate HMAC signature for payload."""
        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        signature = hmac.new(
            secret.encode(),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()
        return f"sha256={signature}"

    def dispatch_scan_started(
        self,
        scan_id: str,
        target: str,
        scanners: List[str],
    ) -> List[bool]:
        """Dispatch scan started event."""
        return self.dispatch(
            WebhookEvent.SCAN_STARTED,
            {
                "scan_id": scan_id,
                "target": target,
                "scanners": scanners,
            },
        )

    def dispatch_scan_completed(
        self,
        scan_id: str,
        target: str,
        findings: List[Finding],
        duration: float,
    ) -> List[bool]:
        """Dispatch scan completed event."""
        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity.value] = (
                severity_counts.get(finding.severity.value, 0) + 1
            )

        return self.dispatch(
            WebhookEvent.SCAN_COMPLETED,
            {
                "scan_id": scan_id,
                "target": target,
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "duration_seconds": duration,
            },
        )

    def dispatch_finding(self, finding: Finding) -> List[bool]:
        """Dispatch finding detected event."""
        return self.dispatch(
            WebhookEvent.FINDING_DETECTED,
            {
                "finding_id": finding.id,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "description": finding.description,
                "location": (
                    {
                        "file_path": finding.location.file_path,
                        "line_number": finding.location.line_number,
                    }
                    if finding.location
                    else None
                ),
            },
        )

    def dispatch_critical_alert(
        self,
        findings: List[Finding],
        scan_target: str,
    ) -> List[bool]:
        """Dispatch critical security alert."""
        critical_findings = [
            f for f in findings if f.severity == Severity.CRITICAL
        ]

        if not critical_findings:
            return []

        return self.dispatch(
            WebhookEvent.CRITICAL_ALERT,
            {
                "target": scan_target,
                "critical_count": len(critical_findings),
                "findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "rule_id": f.rule_id,
                    }
                    for f in critical_findings
                ],
            },
        )

    def dispatch_compliance_violation(
        self,
        framework: str,
        control_id: str,
        findings: List[Finding],
    ) -> List[bool]:
        """Dispatch compliance violation event."""
        return self.dispatch(
            WebhookEvent.COMPLIANCE_VIOLATION,
            {
                "framework": framework,
                "control_id": control_id,
                "finding_count": len(findings),
                "findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity.value,
                    }
                    for f in findings
                ],
            },
        )

    @staticmethod
    def verify_signature(
        payload: bytes,
        signature: str,
        secret: str,
    ) -> bool:
        """Verify incoming webhook signature."""
        if not signature.startswith("sha256="):
            return False

        expected_sig = signature[7:]
        computed_sig = hmac.new(
            secret.encode(),
            payload,
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(expected_sig, computed_sig)
