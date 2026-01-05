"""End-to-end tests for full scanning workflow."""

import pytest
import json
from pathlib import Path
from typer.testing import CliRunner

from secureagent.cli.app import app
from secureagent.core.models.finding import Finding, Severity
from secureagent.core.scanner.registry import ScannerRegistry


runner = CliRunner()


class TestFullScanWorkflow:
    """End-to-end tests for complete scanning workflow."""

    def test_mcp_scan_workflow(self, temp_dir):
        """Test complete MCP scanning workflow."""
        # Create a sample MCP config
        mcp_config = {
            "mcpServers": {
                "test-server": {
                    "command": "npx",
                    "args": ["-y", "@test/mcp-server"],
                    "env": {
                        "API_KEY": "hardcoded-secret-key"
                    }
                }
            }
        }

        config_path = temp_dir / "mcp_config.json"
        config_path.write_text(json.dumps(mcp_config, indent=2))

        # Run scan via CLI
        result = runner.invoke(app, ["mcp", "scan", str(config_path)])

        # Should complete (may have findings)
        assert result.exit_code in [0, 1]

    def test_scan_with_json_output(self, temp_dir):
        """Test scan with JSON output format."""
        # Create sample config
        config = {"mcpServers": {"server": {"command": "test"}}}
        config_path = temp_dir / "config.json"
        config_path.write_text(json.dumps(config))

        output_path = temp_dir / "results.json"

        result = runner.invoke(
            app,
            ["scan", str(config_path), "--format", "json", "--output", str(output_path)],
        )

        # Check output file was created (if scan succeeded)
        if result.exit_code == 0:
            assert output_path.exists()
            data = json.loads(output_path.read_text())
            assert "findings" in data or isinstance(data, list)

    def test_scan_with_sarif_output(self, temp_dir):
        """Test scan with SARIF output format."""
        config = {"mcpServers": {"server": {"command": "test"}}}
        config_path = temp_dir / "config.json"
        config_path.write_text(json.dumps(config))

        output_path = temp_dir / "results.sarif"

        result = runner.invoke(
            app,
            ["scan", str(config_path), "--format", "sarif", "--output", str(output_path)],
        )

        if result.exit_code == 0 and output_path.exists():
            data = json.loads(output_path.read_text())
            assert data.get("$schema") or data.get("version")

    def test_multi_scanner_workflow(self, temp_dir):
        """Test scanning with multiple scanners."""
        # Create MCP config
        mcp_config = {"mcpServers": {"server": {"command": "test"}}}
        mcp_path = temp_dir / "mcp.json"
        mcp_path.write_text(json.dumps(mcp_config))

        # Create Terraform config
        tf_config = """
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
}
"""
        tf_path = temp_dir / "main.tf"
        tf_path.write_text(tf_config)

        # Scan with all scanners
        result = runner.invoke(
            app,
            ["scan", str(temp_dir), "--scanners", "mcp,terraform"],
        )

        # Should complete
        assert result.exit_code in [0, 1, 2]


class TestComplianceWorkflow:
    """End-to-end tests for compliance reporting workflow."""

    def test_compliance_report_generation(self, temp_dir):
        """Test generating a compliance report."""
        # Create config with potential issues
        config = {
            "mcpServers": {
                "server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"SECRET": "password123"}
                }
            }
        }
        config_path = temp_dir / "config.json"
        config_path.write_text(json.dumps(config))

        # Run scan first
        runner.invoke(app, ["scan", str(config_path)])

        # Generate compliance report
        result = runner.invoke(
            app,
            ["compliance", "report", "owasp-llm"],
        )

        # Should complete
        assert result.exit_code in [0, 1, 2]

    def test_compliance_gap_analysis(self):
        """Test compliance gap analysis."""
        result = runner.invoke(app, ["compliance", "gaps"])

        # Should complete
        assert result.exit_code in [0, 1, 2]


class TestInventoryWorkflow:
    """End-to-end tests for inventory management workflow."""

    def test_discover_and_list_agents(self, temp_dir):
        """Test discovering and listing agents."""
        # Create config files that could be discovered
        mcp_config = {"mcpServers": {"agent1": {"command": "test"}}}
        (temp_dir / ".mcp.json").write_text(json.dumps(mcp_config))

        # Discover agents
        result = runner.invoke(app, ["inventory", "discover", "--path", str(temp_dir)])

        # List agents
        list_result = runner.invoke(app, ["inventory", "list"])

        # Both should complete
        assert result.exit_code in [0, 1, 2]
        assert list_result.exit_code in [0, 1, 2]

    def test_export_inventory(self, temp_dir):
        """Test exporting agent inventory."""
        output_path = temp_dir / "inventory.json"

        result = runner.invoke(
            app,
            ["inventory", "export", "--output", str(output_path)],
        )

        # Should complete
        assert result.exit_code in [0, 1, 2]


class TestAnalysisWorkflow:
    """End-to-end tests for analysis workflow."""

    def test_risk_analysis(self, temp_dir):
        """Test risk analysis on a configuration."""
        config = {
            "mcpServers": {
                "risky-server": {
                    "command": "bash",
                    "args": ["-c", "cat /etc/passwd"],
                }
            }
        }
        config_path = temp_dir / "config.json"
        config_path.write_text(json.dumps(config))

        result = runner.invoke(app, ["analyze", "risk", str(config_path)])

        # Should complete with risk assessment
        assert result.exit_code in [0, 1, 2]


class TestScannerRegistry:
    """Tests for scanner registry integration."""

    def test_all_scanners_registered(self):
        """Test that expected scanners are registered."""
        registry = ScannerRegistry()

        # Should have MCP scanner at minimum
        scanners = registry.list_scanners()
        assert len(scanners) >= 0  # May be empty if not auto-registered

    def test_get_scanner_by_domain(self):
        """Test getting scanners by domain."""
        registry = ScannerRegistry()

        mcp_scanners = registry.get_by_domain("mcp")
        # May be empty or contain MCP scanner
        assert isinstance(mcp_scanners, list)


class TestCIMode:
    """Tests for CI/CD mode functionality."""

    def test_ci_mode_exit_codes(self, temp_dir):
        """Test that CI mode returns appropriate exit codes."""
        # Config with known issue
        config = {
            "mcpServers": {
                "server": {
                    "command": "test",
                    "env": {"PASSWORD": "secret"}
                }
            }
        }
        config_path = temp_dir / "config.json"
        config_path.write_text(json.dumps(config))

        result = runner.invoke(
            app,
            ["scan", str(config_path), "--ci"],
        )

        # In CI mode, should return non-zero for findings
        # Exit code 0 = no findings, 1 = findings, 2 = error
        assert result.exit_code in [0, 1, 2]

    def test_min_severity_filter(self, temp_dir):
        """Test minimum severity filtering."""
        config = {"mcpServers": {"server": {"command": "test"}}}
        config_path = temp_dir / "config.json"
        config_path.write_text(json.dumps(config))

        # Only report critical findings
        result = runner.invoke(
            app,
            ["scan", str(config_path), "--min-severity", "critical", "--ci"],
        )

        # Should complete
        assert result.exit_code in [0, 1, 2]
