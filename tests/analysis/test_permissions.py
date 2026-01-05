"""Tests for permission analyzer."""

import pytest

from secureagent.analysis.permissions import (
    PermissionAnalyzer,
    PermissionCategory,
    PermissionRisk,
    PermissionReport,
)
from secureagent.core.models.agent import AgentInventoryItem, AgentFramework, ToolReference, Permission
from secureagent.core.models.severity import Severity


class TestPermissionAnalyzer:
    """Tests for permission analyzer."""

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = PermissionAnalyzer()
        assert analyzer is not None

    def test_analyze_shell_permission(self):
        """Test analyzing shell permissions."""
        analyzer = PermissionAnalyzer()

        agent = AgentInventoryItem(
            id="test-001",
            name="Test Agent",
            framework=AgentFramework.MCP,
            tools=[
                ToolReference(name="ShellTool", type="function"),
                ToolReference(name="BashTool", type="function"),
            ],
        )
        report = analyzer.analyze_agent(agent)

        # Should identify shell execution permission
        shell_perms = [
            p for p in report.permission_risks if p.category == PermissionCategory.SHELL_EXECUTION
        ]
        assert len(shell_perms) > 0
        assert shell_perms[0].severity in (Severity.HIGH, Severity.CRITICAL)

    def test_analyze_file_permission(self):
        """Test analyzing file permissions."""
        analyzer = PermissionAnalyzer()

        agent = AgentInventoryItem(
            id="test-002",
            name="File Agent",
            framework=AgentFramework.LANGCHAIN,
            tools=[
                ToolReference(name="read_file_tool", type="function"),
                ToolReference(name="write_file_tool", type="function"),
            ],
        )
        report = analyzer.analyze_agent(agent)

        # Should identify file access permissions
        file_read_perms = [
            p for p in report.permission_risks if p.category == PermissionCategory.FILE_READ
        ]
        file_write_perms = [
            p for p in report.permission_risks if p.category == PermissionCategory.FILE_WRITE
        ]
        assert len(file_read_perms) > 0 or len(file_write_perms) > 0

    def test_analyze_network_permission(self):
        """Test analyzing network permissions."""
        analyzer = PermissionAnalyzer()

        agent = AgentInventoryItem(
            id="test-003",
            name="Network Agent",
            framework=AgentFramework.MCP,
            tools=[
                ToolReference(name="http_get_tool", type="function"),
                ToolReference(name="http_post_tool", type="function"),
            ],
        )
        report = analyzer.analyze_agent(agent)

        # Should identify network access permission
        network_perms = [
            p for p in report.permission_risks
            if p.category in (PermissionCategory.NETWORK_READ, PermissionCategory.NETWORK_WRITE)
        ]
        assert len(network_perms) > 0

    def test_analyze_safe_tools(self):
        """Test analyzing safe tools."""
        analyzer = PermissionAnalyzer()

        agent = AgentInventoryItem(
            id="test-004",
            name="Safe Agent",
            framework=AgentFramework.MCP,
            tools=[
                ToolReference(name="Calculator", type="function"),
                ToolReference(name="DateTool", type="function"),
            ],
        )
        report = analyzer.analyze_agent(agent)

        # Should have no high or critical risk permissions
        high_risk = [
            p for p in report.permission_risks
            if p.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
        assert len(high_risk) == 0

    def test_calculate_permission_score(self):
        """Test calculating overall permission score from analyze_agent."""
        analyzer = PermissionAnalyzer()

        agent = AgentInventoryItem(
            id="test-005",
            name="Mixed Agent",
            framework=AgentFramework.MCP,
            tools=[
                ToolReference(name="ShellTool", type="function"),
                ToolReference(name="write_file_tool", type="function"),
                ToolReference(name="Calculator", type="function"),
            ],
        )
        report = analyzer.analyze_agent(agent)

        # Should have elevated risk score due to shell and file tools
        assert 0.0 <= report.overall_risk_score <= 1.0
        assert report.overall_risk_score > 0.3
        assert report.over_privileged is True  # Has critical shell permission


class TestPermissionReport:
    """Tests for PermissionReport."""

    def test_critical_risks_property(self):
        """Test critical_risks property."""
        agent = AgentInventoryItem(
            id="test-006",
            name="Test Agent",
            framework=AgentFramework.MCP,
            tools=[
                ToolReference(name="ShellTool", type="function"),
            ],
        )
        analyzer = PermissionAnalyzer()
        report = analyzer.analyze_agent(agent)

        assert len(report.critical_risks) > 0
        for risk in report.critical_risks:
            assert risk.severity == Severity.CRITICAL

    def test_high_risks_property(self):
        """Test high_risks property."""
        agent = AgentInventoryItem(
            id="test-007",
            name="Test Agent",
            framework=AgentFramework.MCP,
            tools=[
                ToolReference(name="write_file_tool", type="function"),
                ToolReference(name="delete_file_tool", type="function"),
            ],
        )
        analyzer = PermissionAnalyzer()
        report = analyzer.analyze_agent(agent)

        # May have high risks from file operations
        for risk in report.high_risks:
            assert risk.severity == Severity.HIGH


class TestPermissionCategory:
    """Tests for PermissionCategory enum."""

    def test_all_categories_defined(self):
        """Test that all expected categories are defined."""
        expected = [
            "SHELL_EXECUTION", "CODE_EXECUTION",
            "FILE_READ", "FILE_WRITE", "FILE_DELETE",
            "NETWORK_READ", "NETWORK_WRITE",
            "DATABASE_READ", "DATABASE_WRITE",
            "MEMORY_ACCESS", "EXTERNAL_API",
            "SYSTEM_ADMIN", "USER_DATA",
            "CREDENTIALS", "DELEGATION",
        ]
        for category in expected:
            assert hasattr(PermissionCategory, category)
