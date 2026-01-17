"""Performance tests for CLI operations."""

import json
import time
import pytest
from pathlib import Path
from typer.testing import CliRunner

from secureagent.cli.app import app


runner = CliRunner()


class TestCLIStartupPerformance:
    """Performance tests for CLI startup time."""

    def test_help_command_startup(self):
        """Test CLI help command startup time."""
        start_time = time.perf_counter()
        result = runner.invoke(app, ["--help"])
        elapsed = time.perf_counter() - start_time

        # Help should display in under 2 seconds
        assert elapsed < 2.0, f"Help command too slow: {elapsed:.2f}s"
        assert result.exit_code == 0

    def test_version_command_startup(self):
        """Test CLI version command startup time."""
        start_time = time.perf_counter()
        result = runner.invoke(app, ["--version"])
        elapsed = time.perf_counter() - start_time

        # Version should display in under 1 second
        assert elapsed < 1.0, f"Version command too slow: {elapsed:.2f}s"
        assert result.exit_code == 0

    def test_info_command_startup(self):
        """Test CLI info command startup time."""
        start_time = time.perf_counter()
        result = runner.invoke(app, ["info"])
        elapsed = time.perf_counter() - start_time

        # Info should display in under 2 seconds
        assert elapsed < 2.0, f"Info command too slow: {elapsed:.2f}s"
        assert result.exit_code == 0


class TestScanCLIPerformance:
    """Performance tests for scan CLI commands."""

    @pytest.fixture
    def config_file(self, tmp_path) -> Path:
        """Create a sample config file."""
        config = {
            "mcpServers": {
                "test-server": {
                    "command": "npx",
                    "args": ["-y", "@test/mcp-server"],
                    "env": {"API_KEY": "sk-test-key"}
                }
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config))
        return config_path

    @pytest.fixture
    def large_config_file(self, tmp_path) -> Path:
        """Create a large config file."""
        config = {"mcpServers": {}}
        for i in range(50):
            config["mcpServers"][f"server-{i}"] = {
                "command": "node",
                "args": [f"server{i}.js"],
                "env": {
                    "API_KEY": f"sk-test-{'x' * 40}",
                    "DEBUG": "true",
                },
            }
        config_path = tmp_path / "large_config.json"
        config_path.write_text(json.dumps(config, indent=2))
        return config_path

    def test_mcp_scan_cli_performance(self, config_file):
        """Test MCP scan CLI performance."""
        start_time = time.perf_counter()
        result = runner.invoke(app, ["mcp", "scan", str(config_file)])
        elapsed = time.perf_counter() - start_time

        # Scan should complete in under 5 seconds
        assert elapsed < 5.0, f"MCP scan CLI too slow: {elapsed:.2f}s"
        assert result.exit_code in [0, 1]

    def test_scan_with_json_output_performance(self, config_file, tmp_path):
        """Test scan with JSON output performance."""
        output_file = tmp_path / "results.json"

        start_time = time.perf_counter()
        result = runner.invoke(app, [
            "scan", str(config_file),
            "--format", "json",
            "--output", str(output_file),
        ])
        elapsed = time.perf_counter() - start_time

        # Scan with output should complete in under 5 seconds
        assert elapsed < 5.0, f"Scan with output too slow: {elapsed:.2f}s"
        assert result.exit_code in [0, 1, 2]

    def test_large_scan_cli_performance(self, large_config_file):
        """Test scan CLI performance on large config."""
        start_time = time.perf_counter()
        result = runner.invoke(app, ["mcp", "scan", str(large_config_file)])
        elapsed = time.perf_counter() - start_time

        # Large scan should complete in under 10 seconds
        assert elapsed < 10.0, f"Large scan CLI too slow: {elapsed:.2f}s"
        assert result.exit_code in [0, 1]


class TestRemediationCLIPerformance:
    """Performance tests for remediation CLI commands."""

    @pytest.fixture
    def config_with_issues(self, tmp_path) -> Path:
        """Create config with security issues."""
        config = {
            "mcpServers": {
                "server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "OPENAI_API_KEY": "sk-proj-1234567890abcdef",
                        "PASSWORD": "secret123",
                    }
                }
            }
        }
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config, indent=2))
        return config_path

    def test_fix_dry_run_cli_performance(self, config_with_issues):
        """Test fix dry-run CLI performance."""
        start_time = time.perf_counter()
        result = runner.invoke(app, [
            "mcp", "fix", str(config_with_issues),
            "--no-preview",
        ])
        elapsed = time.perf_counter() - start_time

        # Dry run should complete in under 5 seconds
        assert elapsed < 5.0, f"Fix dry-run too slow: {elapsed:.2f}s"
        assert result.exit_code in [0, 1, 2]


class TestInventoryCLIPerformance:
    """Performance tests for inventory CLI commands."""

    def test_inventory_list_cli_performance(self):
        """Test inventory list CLI performance."""
        start_time = time.perf_counter()
        result = runner.invoke(app, ["inventory", "list"])
        elapsed = time.perf_counter() - start_time

        # List should complete in under 2 seconds
        assert elapsed < 2.0, f"Inventory list too slow: {elapsed:.2f}s"
        assert result.exit_code in [0, 1, 2]

    def test_inventory_discover_cli_performance(self, tmp_path):
        """Test inventory discover CLI performance."""
        # Create some discoverable configs
        for i in range(10):
            config = {"mcpServers": {"server": {"command": "test"}}}
            (tmp_path / f"config{i}").mkdir()
            (tmp_path / f"config{i}" / ".mcp.json").write_text(json.dumps(config))

        start_time = time.perf_counter()
        result = runner.invoke(app, ["inventory", "discover", "--path", str(tmp_path)])
        elapsed = time.perf_counter() - start_time

        # Discovery should complete in under 5 seconds
        assert elapsed < 5.0, f"Inventory discover too slow: {elapsed:.2f}s"
        assert result.exit_code in [0, 1, 2]


class TestComplianceCLIPerformance:
    """Performance tests for compliance CLI commands."""

    def test_compliance_frameworks_cli_performance(self):
        """Test compliance frameworks list CLI performance."""
        start_time = time.perf_counter()
        result = runner.invoke(app, ["compliance", "frameworks"])
        elapsed = time.perf_counter() - start_time

        # Framework list should be instant
        assert elapsed < 2.0, f"Compliance frameworks too slow: {elapsed:.2f}s"
        assert result.exit_code in [0, 1, 2]

    def test_compliance_report_cli_performance(self):
        """Test compliance report CLI performance."""
        start_time = time.perf_counter()
        result = runner.invoke(app, ["compliance", "report", "owasp-llm"])
        elapsed = time.perf_counter() - start_time

        # Report generation should complete in under 5 seconds
        assert elapsed < 5.0, f"Compliance report too slow: {elapsed:.2f}s"
        assert result.exit_code in [0, 1, 2]


class TestMLCLIPerformance:
    """Performance tests for ML CLI commands."""

    def test_ml_info_cli_performance(self):
        """Test ML info CLI performance."""
        start_time = time.perf_counter()
        result = runner.invoke(app, ["ml", "info"])
        elapsed = time.perf_counter() - start_time

        # Info should be fast
        assert elapsed < 3.0, f"ML info too slow: {elapsed:.2f}s"
        assert result.exit_code in [0, 1, 2]

    def test_ml_generate_data_cli_performance(self, tmp_path):
        """Test ML data generation CLI performance."""
        output_file = tmp_path / "training_data.json"

        start_time = time.perf_counter()
        result = runner.invoke(app, [
            "ml", "generate-data", str(output_file),
            "--samples", "500",
        ])
        elapsed = time.perf_counter() - start_time

        # Data generation should complete in under 10 seconds
        assert elapsed < 10.0, f"ML data generation too slow: {elapsed:.2f}s"
        assert result.exit_code in [0, 1, 2]


class TestConcurrentCLIPerformance:
    """Performance tests for concurrent CLI operations."""

    def test_repeated_scan_performance(self, tmp_path):
        """Test repeated scan operations."""
        config = {"mcpServers": {"server": {"command": "test"}}}
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config))

        times = []
        for _ in range(5):
            start_time = time.perf_counter()
            runner.invoke(app, ["mcp", "scan", str(config_path)])
            times.append(time.perf_counter() - start_time)

        avg_time = sum(times) / len(times)

        # Average scan time should be under 3 seconds
        assert avg_time < 3.0, f"Average scan time too slow: {avg_time:.2f}s"

        # No significant degradation between runs
        max_variation = max(times) - min(times)
        assert max_variation < 2.0, f"Too much variation between runs: {max_variation:.2f}s"
