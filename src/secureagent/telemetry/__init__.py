"""SecureAgent Telemetry Module.

This module provides anonymous, opt-in usage telemetry for SecureAgent.
All telemetry is:
- Anonymous (hashed session IDs, no personal information)
- Non-blocking (async with 2s timeout)
- Opt-out capable (environment variable or config file)

Example usage:
    from secureagent.telemetry import get_telemetry

    telemetry = get_telemetry()
    telemetry.track_cli_start(command="scan")
    telemetry.track_scan_complete(
        scanner="mcp",
        findings_count=5,
        duration_ms=1234,
    )

To disable telemetry:
    - Set SECUREAGENT_TELEMETRY=false environment variable
    - Or add to ~/.secureagent/config.yaml:
        telemetry:
          enabled: false
"""

from secureagent.telemetry.config import (
    TelemetryConfig,
    get_telemetry_config,
)
from secureagent.telemetry.tracker import (
    Telemetry,
    get_telemetry,
    reset_telemetry,
)

__all__ = [
    "Telemetry",
    "TelemetryConfig",
    "get_telemetry",
    "get_telemetry_config",
    "reset_telemetry",
]
