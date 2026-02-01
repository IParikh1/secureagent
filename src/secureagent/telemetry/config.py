"""Telemetry configuration management for SecureAgent.

This module handles telemetry opt-in/opt-out settings, including:
- Environment variable checks (SECUREAGENT_TELEMETRY=false)
- Config file settings (~/.secureagent/config.yaml)
- First-run notice display
"""

import os
from pathlib import Path
from typing import Optional

import yaml


class TelemetryConfig:
    """Manages telemetry configuration and opt-in/opt-out settings."""

    CONFIG_DIR = Path.home() / ".secureagent"
    CONFIG_FILE = CONFIG_DIR / "config.yaml"
    FIRST_RUN_FILE = CONFIG_DIR / ".telemetry_notice_shown"
    ENV_VAR = "SECUREAGENT_TELEMETRY"

    def __init__(self):
        """Initialize telemetry configuration."""
        self._config: Optional[dict] = None

    def _ensure_config_dir(self) -> None:
        """Ensure the config directory exists."""
        self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    def _load_config(self) -> dict:
        """Load configuration from config file."""
        if self._config is not None:
            return self._config

        self._config = {}
        if self.CONFIG_FILE.exists():
            try:
                with open(self.CONFIG_FILE, "r") as f:
                    self._config = yaml.safe_load(f) or {}
            except Exception:
                self._config = {}

        return self._config

    def is_enabled(self) -> bool:
        """Check if telemetry is enabled.

        Telemetry can be disabled by:
        1. Setting SECUREAGENT_TELEMETRY=false environment variable
        2. Setting telemetry: false in ~/.secureagent/config.yaml

        Returns:
            bool: True if telemetry is enabled, False otherwise.
        """
        # Check environment variable first (highest priority)
        env_value = os.environ.get(self.ENV_VAR, "").lower()
        if env_value in ("false", "0", "no", "off", "disabled"):
            return False

        # Check config file
        config = self._load_config()
        telemetry_setting = config.get("telemetry", {})

        # Handle both formats: telemetry: false and telemetry: {enabled: false}
        if isinstance(telemetry_setting, bool):
            return telemetry_setting
        elif isinstance(telemetry_setting, dict):
            return telemetry_setting.get("enabled", True)

        # Default: enabled
        return True

    def is_first_run(self) -> bool:
        """Check if this is the first run (telemetry notice not yet shown).

        Returns:
            bool: True if first run, False otherwise.
        """
        return not self.FIRST_RUN_FILE.exists()

    def mark_notice_shown(self) -> None:
        """Mark that the telemetry notice has been shown."""
        self._ensure_config_dir()
        self.FIRST_RUN_FILE.touch()

    def disable_telemetry(self) -> None:
        """Disable telemetry by updating the config file."""
        self._ensure_config_dir()

        config = self._load_config()
        config["telemetry"] = {"enabled": False}

        with open(self.CONFIG_FILE, "w") as f:
            yaml.dump(config, f, default_flow_style=False)

        # Reset cached config
        self._config = None

    def enable_telemetry(self) -> None:
        """Enable telemetry by updating the config file."""
        self._ensure_config_dir()

        config = self._load_config()
        config["telemetry"] = {"enabled": True}

        with open(self.CONFIG_FILE, "w") as f:
            yaml.dump(config, f, default_flow_style=False)

        # Reset cached config
        self._config = None

    def get_first_run_notice(self) -> str:
        """Get the first-run telemetry notice text.

        Returns:
            str: The notice text to display to users.
        """
        return """
[dim]SecureAgent collects anonymous usage data to improve the product.
This includes command usage, scan statistics, and error rates.
No personal information, file contents, or scan results are collected.

To disable telemetry:
  - Set environment variable: export SECUREAGENT_TELEMETRY=false
  - Or add to ~/.secureagent/config.yaml:
      telemetry:
        enabled: false

Learn more: https://secureagent.dev/telemetry[/dim]
"""


# Singleton instance
_config_instance: Optional[TelemetryConfig] = None


def get_telemetry_config() -> TelemetryConfig:
    """Get the singleton telemetry configuration instance.

    Returns:
        TelemetryConfig: The telemetry configuration instance.
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = TelemetryConfig()
    return _config_instance
