"""Telemetry tracker for SecureAgent.

This module provides async, non-blocking telemetry tracking with:
- Anonymous session IDs (SHA256 hashed)
- 2 second timeout for HTTP requests
- Silent failure (never blocks user operations)
- Event tracking for CLI usage analytics
"""

import asyncio
import hashlib
import platform
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

from secureagent import __version__
from secureagent.telemetry.config import TelemetryConfig, get_telemetry_config


class Telemetry:
    """Opt-in anonymous usage telemetry.

    Collects anonymous usage data to improve SecureAgent. All data is:
    - Anonymous (hashed session IDs, no personal info)
    - Non-blocking (async with timeout)
    - Opt-out capable (env var or config file)
    """

    ENDPOINT = "https://api.secureagent.dev/telemetry"
    TIMEOUT = 2.0  # seconds

    # Standard event types
    EVENT_CLI_START = "cli_start"
    EVENT_SCAN_COMPLETE = "scan_complete"
    EVENT_SCAN_ERROR = "scan_error"
    EVENT_FEATURE_USED = "feature_used"

    def __init__(
        self,
        enabled: Optional[bool] = None,
        config: Optional[TelemetryConfig] = None,
    ):
        """Initialize telemetry tracker.

        Args:
            enabled: Explicitly enable/disable telemetry. If None, uses config.
            config: TelemetryConfig instance. If None, uses singleton.
        """
        self._config = config or get_telemetry_config()

        # Determine if telemetry is enabled
        if enabled is not None:
            self._enabled = enabled
        else:
            self._enabled = self._config.is_enabled()

        # Check if httpx is available
        if not HTTPX_AVAILABLE:
            self._enabled = False

        self._session_id = self._generate_session_id()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @property
    def enabled(self) -> bool:
        """Check if telemetry is enabled."""
        return self._enabled

    @property
    def session_id(self) -> str:
        """Get the anonymous session ID."""
        return self._session_id

    def _generate_session_id(self) -> str:
        """Generate anonymous session ID (hashed machine ID).

        Creates a unique but anonymous identifier based on machine
        characteristics. The hash ensures no personally identifiable
        information is transmitted.

        Returns:
            str: 16-character hex string derived from SHA256 hash.
        """
        # Combine machine-specific info for a stable session ID
        machine_info = f"{platform.node()}-{platform.machine()}-{platform.system()}"
        return hashlib.sha256(machine_info.encode()).hexdigest()[:16]

    def _build_payload(
        self,
        event: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build the telemetry event payload.

        Args:
            event: Event name (e.g., 'cli_start', 'scan_complete').
            properties: Optional event-specific properties.

        Returns:
            dict: The complete payload to send.
        """
        return {
            "event": event,
            "session_id": self._session_id,
            "properties": properties or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": __version__,
            "os": platform.system(),
            "os_version": platform.release(),
            "python_version": platform.python_version(),
            "machine": platform.machine(),
        }

    async def track_async(
        self,
        event: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Track an event asynchronously.

        Args:
            event: Event name (e.g., 'cli_start', 'scan_complete').
            properties: Optional event-specific properties.

        Returns:
            bool: True if event was sent successfully, False otherwise.
        """
        if not self._enabled:
            return False

        payload = self._build_payload(event, properties)

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.ENDPOINT,
                    json=payload,
                    timeout=self.TIMEOUT,
                )
                return response.status_code == 200
        except Exception:
            # Silent fail - never block user operations
            return False

    def track(
        self,
        event: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Track an event (fire and forget).

        This method is non-blocking. It schedules the telemetry request
        to run in the background and returns immediately.

        Args:
            event: Event name (e.g., 'cli_start', 'scan_complete').
            properties: Optional event-specific properties.
        """
        if not self._enabled:
            return

        # Try to get or create an event loop
        try:
            loop = asyncio.get_running_loop()
            # We're in an async context, create a task
            loop.create_task(self._track_with_timeout(event, properties))
        except RuntimeError:
            # No running loop, use run() in a thread or skip
            # For CLI apps, we use fire-and-forget approach
            try:
                asyncio.run(self._track_with_timeout(event, properties))
            except Exception:
                # Silent fail
                pass

    async def _track_with_timeout(
        self,
        event: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Track with enforced timeout.

        Args:
            event: Event name.
            properties: Optional event properties.

        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            return await asyncio.wait_for(
                self.track_async(event, properties),
                timeout=self.TIMEOUT,
            )
        except asyncio.TimeoutError:
            return False
        except Exception:
            return False

    def track_cli_start(self, command: Optional[str] = None) -> None:
        """Track CLI start event.

        Args:
            command: The CLI command being executed (optional).
        """
        properties = {}
        if command:
            properties["command"] = command
        self.track(self.EVENT_CLI_START, properties)

    def track_scan_complete(
        self,
        scanner: str,
        findings_count: int,
        duration_ms: int,
        severity_counts: Optional[Dict[str, int]] = None,
    ) -> None:
        """Track scan completion event.

        Args:
            scanner: Name of the scanner used.
            findings_count: Total number of findings.
            duration_ms: Scan duration in milliseconds.
            severity_counts: Count of findings by severity (optional).
        """
        properties = {
            "scanner": scanner,
            "findings_count": findings_count,
            "duration_ms": duration_ms,
        }
        if severity_counts:
            properties["severity_counts"] = severity_counts
        self.track(self.EVENT_SCAN_COMPLETE, properties)

    def track_scan_error(
        self,
        scanner: str,
        error_type: str,
        error_message: Optional[str] = None,
    ) -> None:
        """Track scan error event.

        Args:
            scanner: Name of the scanner that encountered the error.
            error_type: Type of error (e.g., 'FileNotFound', 'ParseError').
            error_message: Error message (optional, truncated for privacy).
        """
        properties = {
            "scanner": scanner,
            "error_type": error_type,
        }
        if error_message:
            # Truncate error message to avoid sending sensitive data
            properties["error_message"] = error_message[:100]
        self.track(self.EVENT_SCAN_ERROR, properties)

    def track_feature_used(self, feature: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Track feature usage event.

        Args:
            feature: Name of the feature used.
            details: Additional details about the feature usage (optional).
        """
        properties = {"feature": feature}
        if details:
            properties.update(details)
        self.track(self.EVENT_FEATURE_USED, properties)


# Singleton instance
_telemetry_instance: Optional[Telemetry] = None


def get_telemetry() -> Telemetry:
    """Get the singleton telemetry instance.

    Returns:
        Telemetry: The telemetry tracker instance.
    """
    global _telemetry_instance
    if _telemetry_instance is None:
        _telemetry_instance = Telemetry()
    return _telemetry_instance


def reset_telemetry() -> None:
    """Reset the telemetry singleton (useful for testing)."""
    global _telemetry_instance
    _telemetry_instance = None
