"""Generic webhook alerter for SecureAgent."""

import os
import json
import hashlib
import hmac
import logging
from typing import Optional, Dict, Any

from .manager import Alert

logger = logging.getLogger(__name__)


class WebhookAlerter:
    """Send alerts via generic webhooks."""

    def __init__(
        self,
        url: Optional[str] = None,
        secret: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        """Initialize webhook alerter."""
        self.url = url or os.environ.get("SECUREAGENT_WEBHOOK_URL")
        self.secret = secret or os.environ.get("SECUREAGENT_WEBHOOK_SECRET")
        self.headers = headers or {}
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
                    "httpx is required for webhook alerting. "
                    "Install with: pip install httpx"
                )
        return self._http_client

    def send(self, alert: Alert) -> bool:
        """Send alert via webhook."""
        if not self.url:
            logger.error("Webhook URL not configured")
            return False

        try:
            payload = self._build_payload(alert)
            headers = self._build_headers(payload)

            response = self.http_client.post(
                self.url,
                json=payload,
                headers=headers,
            )

            if response.status_code >= 200 and response.status_code < 300:
                logger.info(f"Webhook alert sent: {alert.title}")
                return True
            else:
                logger.warning(
                    f"Webhook returned {response.status_code}: {response.text}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False

    def _build_payload(self, alert: Alert) -> Dict[str, Any]:
        """Build webhook payload."""
        return {
            "event": "security_alert",
            "timestamp": alert.created_at.isoformat(),
            "alert": {
                "id": alert.id,
                "title": alert.title,
                "message": alert.message,
                "priority": alert.priority.value,
                "severity": alert.severity.value,
                "source": alert.source,
            },
            "summary": {
                "total_findings": len(alert.findings),
                "findings_by_severity": self._count_by_severity(alert),
            },
            "findings": [
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "description": f.description,
                    "location": (
                        {
                            "file_path": f.location.file_path,
                            "line_number": f.location.line_number,
                        }
                        if f.location
                        else None
                    ),
                    "cwe_id": f.cwe_id,
                    "owasp_id": f.owasp_id,
                }
                for f in alert.findings
            ],
            "metadata": alert.metadata,
        }

    def _count_by_severity(self, alert: Alert) -> Dict[str, int]:
        """Count findings by severity."""
        counts: Dict[str, int] = {}
        for finding in alert.findings:
            severity = finding.severity.value
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _build_headers(self, payload: Dict[str, Any]) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SecureAgent/1.0",
            **self.headers,
        }

        # Add signature if secret configured
        if self.secret:
            payload_bytes = json.dumps(payload, sort_keys=True).encode()
            signature = hmac.new(
                self.secret.encode(),
                payload_bytes,
                hashlib.sha256,
            ).hexdigest()
            headers["X-SecureAgent-Signature"] = f"sha256={signature}"

        return headers

    def send_raw(
        self,
        payload: Dict[str, Any],
        method: str = "POST",
    ) -> bool:
        """Send raw payload to webhook."""
        if not self.url:
            return False

        try:
            headers = self._build_headers(payload)

            if method.upper() == "POST":
                response = self.http_client.post(self.url, json=payload, headers=headers)
            elif method.upper() == "PUT":
                response = self.http_client.put(self.url, json=payload, headers=headers)
            else:
                raise ValueError(f"Unsupported method: {method}")

            return response.status_code >= 200 and response.status_code < 300

        except Exception as e:
            logger.error(f"Failed to send raw webhook: {e}")
            return False

    @staticmethod
    def verify_signature(
        payload_bytes: bytes,
        signature: str,
        secret: str,
    ) -> bool:
        """Verify incoming webhook signature."""
        if not signature.startswith("sha256="):
            return False

        expected_sig = signature[7:]
        computed_sig = hmac.new(
            secret.encode(),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(expected_sig, computed_sig)
