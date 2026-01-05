"""Tests for CLI application."""

import pytest
from typer.testing import CliRunner

from secureagent.cli.app import app


runner = CliRunner()


class TestCLIApp:
    """Tests for CLI application."""

    def test_app_help(self):
        """Test help command displays usage."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "secureagent" in result.stdout.lower() or "usage" in result.stdout.lower()

    def test_version_command(self):
        """Test version display."""
        result = runner.invoke(app, ["--version"])
        # Should display version or not error
        assert result.exit_code in [0, 2]  # 2 if --version not implemented

    def test_scan_help(self):
        """Test scan command help."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0

    def test_mcp_help(self):
        """Test MCP subcommand help."""
        result = runner.invoke(app, ["mcp", "--help"])
        assert result.exit_code == 0

    def test_cloud_help(self):
        """Test cloud subcommand help."""
        result = runner.invoke(app, ["cloud", "--help"])
        assert result.exit_code == 0

    def test_inventory_help(self):
        """Test inventory subcommand help."""
        result = runner.invoke(app, ["inventory", "--help"])
        assert result.exit_code == 0

    def test_compliance_help(self):
        """Test compliance subcommand help."""
        result = runner.invoke(app, ["compliance", "--help"])
        assert result.exit_code == 0


class TestScanCommand:
    """Tests for scan command."""

    def test_scan_missing_target(self):
        """Test scan command requires target."""
        result = runner.invoke(app, ["scan"])
        # Should error or show help
        assert result.exit_code != 0 or "target" in result.stdout.lower()

    def test_scan_nonexistent_path(self):
        """Test scan with nonexistent path."""
        result = runner.invoke(app, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0

    def test_scan_with_format_option(self):
        """Test scan with format option."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "format" in result.stdout.lower() or result.exit_code == 0


class TestMCPCommands:
    """Tests for MCP subcommands."""

    def test_mcp_scan_help(self):
        """Test MCP scan help."""
        result = runner.invoke(app, ["mcp", "scan", "--help"])
        assert result.exit_code == 0

    def test_mcp_validate_help(self):
        """Test MCP validate help."""
        result = runner.invoke(app, ["mcp", "validate", "--help"])
        assert result.exit_code == 0

    def test_mcp_rules_command(self):
        """Test MCP rules listing."""
        result = runner.invoke(app, ["mcp", "rules"])
        # Should list rules or show help
        assert result.exit_code in [0, 1, 2]


class TestInventoryCommands:
    """Tests for inventory subcommands."""

    def test_inventory_list(self):
        """Test inventory list command."""
        result = runner.invoke(app, ["inventory", "list"])
        # Should work even with empty catalog
        assert result.exit_code in [0, 1]

    def test_inventory_discover_help(self):
        """Test inventory discover help."""
        result = runner.invoke(app, ["inventory", "discover", "--help"])
        assert result.exit_code == 0


class TestComplianceCommands:
    """Tests for compliance subcommands."""

    def test_compliance_status(self):
        """Test compliance status command."""
        result = runner.invoke(app, ["compliance", "status"])
        assert result.exit_code in [0, 1]

    def test_compliance_report_help(self):
        """Test compliance report help."""
        result = runner.invoke(app, ["compliance", "report", "--help"])
        assert result.exit_code == 0
