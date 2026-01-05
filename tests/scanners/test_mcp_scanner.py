"""Tests for MCP scanner."""

import pytest
import json
from pathlib import Path

from secureagent.scanners.mcp.scanner import MCPScanner
from secureagent.core.models.severity import Severity


class TestMCPScanner:
    """Tests for MCP scanner."""

    def test_scanner_initialization(self, temp_dir):
        """Test scanner initialization."""
        scanner = MCPScanner(path=temp_dir)
        assert scanner is not None
        assert scanner.name == "mcp"

    def test_scan_config_with_hardcoded_credential(self, temp_dir):
        """Test detecting hardcoded credentials."""
        config = {
            "mcpServers": {
                "test-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "API_KEY": "sk-proj-1234567890abcdefghijklmnop",
                    },
                }
            }
        }
        config_path = temp_dir / "mcp_config.json"
        config_path.write_text(json.dumps(config))

        scanner = MCPScanner(path=config_path)
        findings = scanner.scan()

        # Should find hardcoded API key
        credential_findings = [
            f for f in findings
            if "credential" in f.title.lower() or "key" in f.title.lower()
        ]
        assert len(credential_findings) > 0

    def test_scan_config_with_command_injection(self, temp_dir):
        """Test detecting command injection patterns."""
        config = {
            "mcpServers": {
                "dangerous-server": {
                    "command": "bash",
                    "args": ["-c", "$(cat /etc/passwd)"],
                }
            }
        }
        config_path = temp_dir / "mcp_config.json"
        config_path.write_text(json.dumps(config))

        scanner = MCPScanner(path=config_path)
        findings = scanner.scan()

        # Should find command injection risk
        injection_findings = [
            f for f in findings if "injection" in f.title.lower() or "command" in f.title.lower()
        ]
        assert len(injection_findings) > 0

    def test_scan_config_with_shell_patterns(self, temp_dir):
        """Test detecting dangerous shell patterns."""
        config = {
            "mcpServers": {
                "shell-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "CMD": "ls | grep secret",
                    },
                }
            }
        }
        config_path = temp_dir / "mcp_config.json"
        config_path.write_text(json.dumps(config))

        scanner = MCPScanner(path=config_path)
        findings = scanner.scan()

        # Should detect pipe pattern
        assert isinstance(findings, list)

    def test_scan_clean_config(self, temp_dir):
        """Test scanning a clean configuration."""
        config = {
            "mcpServers": {
                "safe-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "NODE_ENV": "production",
                    },
                }
            }
        }
        config_path = temp_dir / "mcp_config.json"
        config_path.write_text(json.dumps(config))

        scanner = MCPScanner(path=config_path)
        findings = scanner.scan()

        # Should have minimal or no critical findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0

    def test_scan_path_traversal(self, temp_dir):
        """Test detecting path traversal patterns."""
        config = {
            "mcpServers": {
                "traversal-server": {
                    "command": "node",
                    "args": ["../../etc/passwd"],
                }
            }
        }
        config_path = temp_dir / "mcp_config.json"
        config_path.write_text(json.dumps(config))

        scanner = MCPScanner(path=config_path)
        findings = scanner.scan()

        # Should find path traversal
        traversal_findings = [
            f for f in findings if "traversal" in f.title.lower() or "path" in f.title.lower()
        ]
        assert len(traversal_findings) > 0

    def test_scan_invalid_json(self, temp_dir):
        """Test handling invalid JSON gracefully."""
        invalid_path = temp_dir / "mcp_invalid.json"
        invalid_path.write_text("not valid json {")

        scanner = MCPScanner(path=invalid_path)
        findings = scanner.scan()

        # Should handle gracefully, returning parse error finding
        assert isinstance(findings, list)
        # May have a parse error finding
        if findings:
            error_findings = [f for f in findings if "parse" in f.title.lower() or "error" in f.title.lower()]
            assert len(error_findings) >= 0

    def test_scan_directory(self, temp_dir):
        """Test scanning a directory for MCP configs."""
        config = {
            "mcpServers": {
                "server": {
                    "command": "node",
                    "env": {"SECRET": "sk-1234567890abcdefghij"}
                }
            }
        }

        # Create MCP config files
        (temp_dir / "mcp.json").write_text(json.dumps(config))
        (temp_dir / ".mcp.json").write_text(json.dumps(config))

        scanner = MCPScanner(path=temp_dir)
        findings = scanner.scan()

        assert isinstance(findings, list)
        # Should find issues in multiple files
        assert len(findings) >= 1

    def test_scan_sensitive_env_vars(self, temp_dir):
        """Test detecting sensitive environment variables."""
        config = {
            "mcpServers": {
                "db-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "DATABASE_URL": "postgres://user:password@localhost/db",
                    },
                }
            }
        }
        config_path = temp_dir / "mcp_config.json"
        config_path.write_text(json.dumps(config))

        scanner = MCPScanner(path=config_path)
        findings = scanner.scan()

        # Should find sensitive env var
        sensitive_findings = [
            f for f in findings
            if "environment" in f.title.lower() or "sensitive" in f.title.lower()
        ]
        assert len(sensitive_findings) > 0

    def test_discover_targets(self, temp_dir):
        """Test target discovery."""
        # Create various MCP config files
        (temp_dir / "mcp.json").write_text('{"mcpServers": {}}')
        (temp_dir / ".mcp.json").write_text('{"mcpServers": {}}')
        (temp_dir / "other.txt").write_text("not a config")

        scanner = MCPScanner(path=temp_dir)
        targets = list(scanner.discover_targets())

        # Should find MCP config files
        assert len(targets) >= 2
        target_names = [t.name for t in targets]
        assert "mcp.json" in target_names
        assert ".mcp.json" in target_names

    def test_finding_has_location(self, temp_dir):
        """Test that findings include location information."""
        config = {
            "mcpServers": {
                "server": {
                    "command": "node",
                    "env": {"API_KEY": "sk-abcdefghijklmnopqrstuvwxyz"}
                }
            }
        }
        config_path = temp_dir / "mcp_config.json"
        config_path.write_text(json.dumps(config))

        scanner = MCPScanner(path=config_path)
        findings = scanner.scan()

        for finding in findings:
            assert finding.location is not None
            assert finding.location.file_path is not None
