"""Tests for SecureAgent telemetry module.

This module tests:
- Telemetry configuration (opt-in/opt-out)
- Session ID generation
- Event tracking with mocked HTTP
- First-run notice logic
"""

import asyncio
import hashlib
import os
import platform
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from secureagent.telemetry.config import TelemetryConfig, get_telemetry_config
from secureagent.telemetry.tracker import (
    Telemetry,
    get_telemetry,
    reset_telemetry,
)


class TestTelemetryConfig:
    """Tests for TelemetryConfig class."""

    @pytest.fixture(autouse=True)
    def setup_temp_config(self, tmp_path):
        """Set up temporary config directory for each test."""
        self.config_dir = tmp_path / ".secureagent"
        self.config_dir.mkdir(parents=True)
        self.config_file = self.config_dir / "config.yaml"
        self.first_run_file = self.config_dir / ".telemetry_notice_shown"

        # Patch the config paths
        with patch.object(TelemetryConfig, "CONFIG_DIR", self.config_dir):
            with patch.object(TelemetryConfig, "CONFIG_FILE", self.config_file):
                with patch.object(
                    TelemetryConfig, "FIRST_RUN_FILE", self.first_run_file
                ):
                    self.config = TelemetryConfig()
                    yield

    def test_is_enabled_default(self):
        """Test that telemetry is enabled by default."""
        assert self.config.is_enabled() is True

    def test_is_enabled_env_var_false(self):
        """Test that SECUREAGENT_TELEMETRY=false disables telemetry."""
        with patch.dict(os.environ, {"SECUREAGENT_TELEMETRY": "false"}):
            config = TelemetryConfig()
            # Re-patch the config paths for the new instance
            with patch.object(TelemetryConfig, "CONFIG_DIR", self.config_dir):
                with patch.object(TelemetryConfig, "CONFIG_FILE", self.config_file):
                    assert config.is_enabled() is False

    def test_is_enabled_env_var_variants(self):
        """Test various env var values that should disable telemetry."""
        disable_values = ["false", "0", "no", "off", "disabled", "FALSE", "No"]

        for value in disable_values:
            with patch.dict(os.environ, {"SECUREAGENT_TELEMETRY": value}):
                config = TelemetryConfig()
                assert config.is_enabled() is False, f"Failed for value: {value}"

    def test_is_enabled_env_var_true(self):
        """Test that SECUREAGENT_TELEMETRY=true keeps telemetry enabled."""
        with patch.dict(os.environ, {"SECUREAGENT_TELEMETRY": "true"}):
            config = TelemetryConfig()
            with patch.object(TelemetryConfig, "CONFIG_DIR", self.config_dir):
                with patch.object(TelemetryConfig, "CONFIG_FILE", self.config_file):
                    assert config.is_enabled() is True

    def test_is_enabled_config_file_false(self):
        """Test that config file can disable telemetry."""
        self.config_file.write_text("telemetry:\n  enabled: false\n")

        with patch.object(TelemetryConfig, "CONFIG_DIR", self.config_dir):
            with patch.object(TelemetryConfig, "CONFIG_FILE", self.config_file):
                config = TelemetryConfig()
                assert config.is_enabled() is False

    def test_is_enabled_config_file_simple_false(self):
        """Test that simple 'telemetry: false' format works."""
        self.config_file.write_text("telemetry: false\n")

        with patch.object(TelemetryConfig, "CONFIG_DIR", self.config_dir):
            with patch.object(TelemetryConfig, "CONFIG_FILE", self.config_file):
                config = TelemetryConfig()
                assert config.is_enabled() is False

    def test_env_var_takes_precedence_over_config(self):
        """Test that environment variable takes precedence over config file."""
        # Config file says enabled
        self.config_file.write_text("telemetry:\n  enabled: true\n")

        # But env var says disabled
        with patch.dict(os.environ, {"SECUREAGENT_TELEMETRY": "false"}):
            config = TelemetryConfig()
            assert config.is_enabled() is False

    def test_is_first_run_true_when_no_file(self):
        """Test that is_first_run returns True when notice file doesn't exist."""
        assert not self.first_run_file.exists()
        with patch.object(TelemetryConfig, "FIRST_RUN_FILE", self.first_run_file):
            config = TelemetryConfig()
            assert config.is_first_run() is True

    def test_is_first_run_false_after_mark(self):
        """Test that is_first_run returns False after marking notice shown."""
        with patch.object(TelemetryConfig, "CONFIG_DIR", self.config_dir):
            with patch.object(TelemetryConfig, "FIRST_RUN_FILE", self.first_run_file):
                config = TelemetryConfig()
                assert config.is_first_run() is True
                config.mark_notice_shown()
                assert config.is_first_run() is False

    def test_disable_telemetry(self):
        """Test disabling telemetry updates config file."""
        with patch.object(TelemetryConfig, "CONFIG_DIR", self.config_dir):
            with patch.object(TelemetryConfig, "CONFIG_FILE", self.config_file):
                config = TelemetryConfig()
                config.disable_telemetry()

                assert self.config_file.exists()
                content = self.config_file.read_text()
                assert "enabled: false" in content

    def test_enable_telemetry(self):
        """Test enabling telemetry updates config file."""
        # First disable
        self.config_file.write_text("telemetry:\n  enabled: false\n")

        with patch.object(TelemetryConfig, "CONFIG_DIR", self.config_dir):
            with patch.object(TelemetryConfig, "CONFIG_FILE", self.config_file):
                config = TelemetryConfig()
                config.enable_telemetry()

                content = self.config_file.read_text()
                assert "enabled: true" in content

    def test_get_first_run_notice(self):
        """Test that first run notice contains expected information."""
        notice = self.config.get_first_run_notice()

        assert "anonymous" in notice.lower() or "usage data" in notice.lower()
        assert "SECUREAGENT_TELEMETRY=false" in notice
        assert "~/.secureagent/config.yaml" in notice


class TestTelemetry:
    """Tests for Telemetry tracker class."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Reset telemetry singleton before each test."""
        reset_telemetry()

        # Set up temp config
        self.config_dir = tmp_path / ".secureagent"
        self.config_dir.mkdir(parents=True)

        yield

        reset_telemetry()

    def test_session_id_generation(self):
        """Test that session ID is generated correctly."""
        telemetry = Telemetry(enabled=True)

        # Session ID should be 16 characters (first 16 of SHA256 hex)
        assert len(telemetry.session_id) == 16

        # Should be hex characters only
        assert all(c in "0123456789abcdef" for c in telemetry.session_id)

    def test_session_id_deterministic(self):
        """Test that session ID is deterministic for same machine."""
        telemetry1 = Telemetry(enabled=True)
        telemetry2 = Telemetry(enabled=True)

        # Same machine should generate same session ID
        assert telemetry1.session_id == telemetry2.session_id

    def test_session_id_format(self):
        """Test that session ID matches expected format."""
        machine_info = f"{platform.node()}-{platform.machine()}-{platform.system()}"
        expected = hashlib.sha256(machine_info.encode()).hexdigest()[:16]

        telemetry = Telemetry(enabled=True)
        assert telemetry.session_id == expected

    def test_telemetry_disabled_explicit(self):
        """Test that telemetry can be explicitly disabled."""
        telemetry = Telemetry(enabled=False)
        assert telemetry.enabled is False

    def test_telemetry_enabled_explicit(self):
        """Test that telemetry can be explicitly enabled."""
        telemetry = Telemetry(enabled=True)
        assert telemetry.enabled is True

    def test_telemetry_uses_config_when_not_explicit(self):
        """Test that telemetry uses config when not explicitly set."""
        mock_config = MagicMock()
        mock_config.is_enabled.return_value = False

        telemetry = Telemetry(config=mock_config)
        assert telemetry.enabled is False

        mock_config.is_enabled.return_value = True
        telemetry = Telemetry(config=mock_config)
        assert telemetry.enabled is True

    def test_build_payload(self):
        """Test that event payload is built correctly."""
        telemetry = Telemetry(enabled=True)

        payload = telemetry._build_payload("test_event", {"key": "value"})

        assert payload["event"] == "test_event"
        assert payload["session_id"] == telemetry.session_id
        assert payload["properties"] == {"key": "value"}
        assert "timestamp" in payload
        assert "version" in payload
        assert payload["os"] == platform.system()
        assert payload["python_version"] == platform.python_version()

    def test_build_payload_empty_properties(self):
        """Test payload with no properties."""
        telemetry = Telemetry(enabled=True)
        payload = telemetry._build_payload("test_event")

        assert payload["properties"] == {}

    @pytest.mark.asyncio
    async def test_track_async_disabled(self):
        """Test that track_async returns False when disabled."""
        telemetry = Telemetry(enabled=False)
        result = await telemetry.track_async("test_event")
        assert result is False

    @pytest.mark.asyncio
    async def test_track_async_success(self):
        """Test successful async tracking."""
        telemetry = Telemetry(enabled=True)

        with patch("secureagent.telemetry.tracker.httpx") as mock_httpx:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.post.return_value = mock_response
            mock_httpx.AsyncClient.return_value.__aenter__.return_value = mock_client

            result = await telemetry.track_async("test_event", {"key": "value"})

            assert result is True
            mock_client.post.assert_called_once()

            call_kwargs = mock_client.post.call_args
            assert call_kwargs[0][0] == telemetry.ENDPOINT
            assert call_kwargs[1]["timeout"] == 2.0

    @pytest.mark.asyncio
    async def test_track_async_network_error(self):
        """Test that network errors are handled silently."""
        telemetry = Telemetry(enabled=True)

        with patch("secureagent.telemetry.tracker.httpx") as mock_httpx:
            mock_client = AsyncMock()
            mock_client.post.side_effect = Exception("Network error")
            mock_httpx.AsyncClient.return_value.__aenter__.return_value = mock_client

            # Should not raise, should return False
            result = await telemetry.track_async("test_event")
            assert result is False

    @pytest.mark.asyncio
    async def test_track_async_timeout(self):
        """Test that timeouts are handled properly."""
        telemetry = Telemetry(enabled=True)

        async def slow_post(*args, **kwargs):
            await asyncio.sleep(5)
            return MagicMock(status_code=200)

        with patch("secureagent.telemetry.tracker.httpx") as mock_httpx:
            mock_client = AsyncMock()
            mock_client.post = slow_post
            mock_httpx.AsyncClient.return_value.__aenter__.return_value = mock_client

            result = await telemetry._track_with_timeout("test_event")
            assert result is False

    def test_track_cli_start(self):
        """Test track_cli_start convenience method."""
        telemetry = Telemetry(enabled=True)

        with patch.object(telemetry, "track") as mock_track:
            telemetry.track_cli_start(command="scan")

            mock_track.assert_called_once_with(
                Telemetry.EVENT_CLI_START, {"command": "scan"}
            )

    def test_track_cli_start_no_command(self):
        """Test track_cli_start without command."""
        telemetry = Telemetry(enabled=True)

        with patch.object(telemetry, "track") as mock_track:
            telemetry.track_cli_start()

            mock_track.assert_called_once_with(Telemetry.EVENT_CLI_START, {})

    def test_track_scan_complete(self):
        """Test track_scan_complete convenience method."""
        telemetry = Telemetry(enabled=True)

        with patch.object(telemetry, "track") as mock_track:
            telemetry.track_scan_complete(
                scanner="mcp",
                findings_count=5,
                duration_ms=1234,
                severity_counts={"high": 2, "medium": 3},
            )

            mock_track.assert_called_once()
            call_args = mock_track.call_args
            assert call_args[0][0] == Telemetry.EVENT_SCAN_COMPLETE
            assert call_args[0][1]["scanner"] == "mcp"
            assert call_args[0][1]["findings_count"] == 5
            assert call_args[0][1]["duration_ms"] == 1234
            assert call_args[0][1]["severity_counts"] == {"high": 2, "medium": 3}

    def test_track_scan_error(self):
        """Test track_scan_error convenience method."""
        telemetry = Telemetry(enabled=True)

        with patch.object(telemetry, "track") as mock_track:
            telemetry.track_scan_error(
                scanner="mcp",
                error_type="FileNotFoundError",
                error_message="Config file not found",
            )

            mock_track.assert_called_once()
            call_args = mock_track.call_args
            assert call_args[0][0] == Telemetry.EVENT_SCAN_ERROR
            assert call_args[0][1]["scanner"] == "mcp"
            assert call_args[0][1]["error_type"] == "FileNotFoundError"
            assert call_args[0][1]["error_message"] == "Config file not found"

    def test_track_scan_error_truncates_message(self):
        """Test that long error messages are truncated."""
        telemetry = Telemetry(enabled=True)

        long_message = "x" * 200

        with patch.object(telemetry, "track") as mock_track:
            telemetry.track_scan_error(
                scanner="mcp",
                error_type="Error",
                error_message=long_message,
            )

            call_args = mock_track.call_args
            assert len(call_args[0][1]["error_message"]) == 100

    def test_track_feature_used(self):
        """Test track_feature_used convenience method."""
        telemetry = Telemetry(enabled=True)

        with patch.object(telemetry, "track") as mock_track:
            telemetry.track_feature_used(
                feature="compliance_report",
                details={"framework": "soc2"},
            )

            mock_track.assert_called_once()
            call_args = mock_track.call_args
            assert call_args[0][0] == Telemetry.EVENT_FEATURE_USED
            assert call_args[0][1]["feature"] == "compliance_report"
            assert call_args[0][1]["framework"] == "soc2"

    def test_track_disabled_does_nothing(self):
        """Test that track() does nothing when disabled."""
        telemetry = Telemetry(enabled=False)

        # This should not raise or make any HTTP calls
        with patch("secureagent.telemetry.tracker.asyncio") as mock_asyncio:
            telemetry.track("test_event")
            mock_asyncio.run.assert_not_called()


class TestTelemetrySingleton:
    """Tests for telemetry singleton functions."""

    @pytest.fixture(autouse=True)
    def reset(self):
        """Reset singleton before and after each test."""
        reset_telemetry()
        yield
        reset_telemetry()

    def test_get_telemetry_returns_same_instance(self):
        """Test that get_telemetry returns the same instance."""
        telemetry1 = get_telemetry()
        telemetry2 = get_telemetry()

        assert telemetry1 is telemetry2

    def test_reset_telemetry(self):
        """Test that reset_telemetry creates a new instance."""
        telemetry1 = get_telemetry()
        reset_telemetry()
        telemetry2 = get_telemetry()

        assert telemetry1 is not telemetry2


class TestTelemetryIntegration:
    """Integration tests for telemetry module."""

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        """Set up test environment."""
        reset_telemetry()
        self.config_dir = tmp_path / ".secureagent"
        self.config_dir.mkdir(parents=True)
        yield
        reset_telemetry()

    def test_full_opt_out_flow(self, tmp_path):
        """Test complete opt-out flow via environment variable."""
        with patch.dict(os.environ, {"SECUREAGENT_TELEMETRY": "false"}):
            telemetry = Telemetry()
            assert telemetry.enabled is False

            # Tracking should be a no-op
            with patch("secureagent.telemetry.tracker.httpx") as mock_httpx:
                telemetry.track_cli_start()
                # httpx should never be called
                mock_httpx.AsyncClient.assert_not_called()

    def test_config_file_opt_out_flow(self, tmp_path):
        """Test opt-out via config file."""
        config_file = tmp_path / ".secureagent" / "config.yaml"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text("telemetry:\n  enabled: false\n")

        with patch.object(TelemetryConfig, "CONFIG_DIR", tmp_path / ".secureagent"):
            with patch.object(TelemetryConfig, "CONFIG_FILE", config_file):
                config = TelemetryConfig()
                telemetry = Telemetry(config=config)

                assert telemetry.enabled is False
