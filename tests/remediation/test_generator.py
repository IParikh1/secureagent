"""Tests for the remediation generator."""

import pytest
from secureagent.remediation.generator import (
    RemediationGenerator,
    RemediationOption,
    GeneratedFix,
    FixType,
    FixComplexity,
)
from secureagent.core.models.finding import Finding, FindingDomain, Location
from secureagent.core.models.severity import Severity


@pytest.fixture
def generator():
    """Create a remediation generator instance."""
    return RemediationGenerator()


@pytest.fixture
def hardcoded_credential_finding():
    """Create a finding for hardcoded credentials."""
    return Finding(
        rule_id="MCP-002",
        domain=FindingDomain.MCP,
        title="Hardcoded Credentials",
        description="Found OpenAI API key in configuration file",
        severity=Severity.CRITICAL,
        location=Location(
            file_path="/tmp/test/mcp.json",
            line_number=5,
            snippet='sk-proj-abc123xyz456',
        ),
        remediation="Use environment variables instead of hardcoding credentials.",
    )


@pytest.fixture
def no_auth_finding():
    """Create a finding for no authentication."""
    return Finding(
        rule_id="MCP-001",
        domain=FindingDomain.MCP,
        title="No Authentication Configured",
        description="Remote MCP server 'api-server' appears to have no authentication configured.",
        severity=Severity.CRITICAL,
        location=Location(
            file_path="/tmp/test/mcp.json",
            line_number=10,
            snippet='url: https://api.example.com',
        ),
        remediation="Configure authentication for the MCP server.",
    )


@pytest.fixture
def path_traversal_finding():
    """Create a finding for path traversal."""
    return Finding(
        rule_id="MCP-005",
        domain=FindingDomain.MCP,
        title="Path Traversal",
        description="Server 'file-server' references absolute paths.",
        severity=Severity.MEDIUM,
        location=Location(
            file_path="/tmp/test/mcp.json",
            line_number=15,
            snippet='/etc/passwd',
        ),
        remediation="Use relative paths within allowed directories.",
    )


class TestRemediationGenerator:
    """Tests for RemediationGenerator."""

    def test_generator_creation(self, generator):
        """Test generator can be created."""
        assert generator is not None
        assert len(generator.get_supported_rules()) > 0

    def test_supported_rules(self, generator):
        """Test supported rules list."""
        rules = generator.get_supported_rules()
        assert "MCP-001" in rules
        assert "MCP-002" in rules
        assert "MCP-003" in rules
        assert "MCP-004" in rules
        assert "MCP-005" in rules
        assert "MCP-006" in rules
        assert "MCP-007" in rules

    def test_has_automatic_fix(self, generator):
        """Test checking for automatic fix support."""
        assert generator.has_automatic_fix("MCP-002") is True
        assert generator.has_automatic_fix("UNKNOWN-001") is False

    def test_generate_fix_hardcoded_credentials(
        self, generator, hardcoded_credential_finding
    ):
        """Test generating fix for hardcoded credentials."""
        fix = generator.generate_fix(hardcoded_credential_finding)

        assert fix is not None
        assert fix.rule_id == "MCP-002"
        assert fix.finding_id == hardcoded_credential_finding.id
        assert len(fix.options) >= 1

        # Check first option
        option = fix.options[0]
        assert option.title == "Use Environment Variable"
        assert option.fix_type == FixType.REPLACE
        assert "OPENAI_API_KEY" in option.replacement
        assert option.complexity == FixComplexity.TRIVIAL

    def test_generate_fix_no_auth(self, generator, no_auth_finding):
        """Test generating fix for no authentication."""
        fix = generator.generate_fix(no_auth_finding)

        assert fix is not None
        assert fix.rule_id == "MCP-001"
        assert len(fix.options) >= 2

        # Check options
        titles = [opt.title for opt in fix.options]
        assert "Add API Key Authentication" in titles
        assert "Add Bearer Token Authentication" in titles

    def test_generate_fix_path_traversal(self, generator, path_traversal_finding):
        """Test generating fix for path traversal."""
        fix = generator.generate_fix(path_traversal_finding)

        assert fix is not None
        assert fix.rule_id == "MCP-005"
        assert len(fix.options) >= 1
        assert fix.requires_review is True

    def test_generate_fixes_batch(self, generator, hardcoded_credential_finding, no_auth_finding):
        """Test generating fixes for multiple findings."""
        findings = [hardcoded_credential_finding, no_auth_finding]
        fixes = generator.generate_fixes(findings)

        assert len(fixes) == 2
        assert fixes[0].rule_id == "MCP-002"
        assert fixes[1].rule_id == "MCP-001"

    def test_generate_manual_fix_for_unknown_rule(self, generator):
        """Test generating manual fix for unknown rule."""
        finding = Finding(
            rule_id="UNKNOWN-001",
            domain=FindingDomain.MCP,
            title="Unknown Issue",
            description="Some unknown security issue",
            severity=Severity.MEDIUM,
            location=Location(file_path="/tmp/test.json"),
            remediation="Fix the issue manually",
        )

        fix = generator.generate_fix(finding, include_manual=True)

        assert fix is not None
        assert fix.requires_review is True
        assert len(fix.options) == 1
        assert fix.options[0].fix_type == FixType.MANUAL

    def test_no_fix_when_manual_disabled(self, generator):
        """Test no fix returned when manual is disabled for unknown rule."""
        finding = Finding(
            rule_id="UNKNOWN-001",
            domain=FindingDomain.MCP,
            title="Unknown Issue",
            description="Some unknown security issue",
            severity=Severity.MEDIUM,
            location=Location(file_path="/tmp/test.json"),
            remediation="Fix the issue manually",
        )

        fix = generator.generate_fix(finding, include_manual=False)

        assert fix is None


class TestRemediationOption:
    """Tests for RemediationOption."""

    def test_option_to_dict(self):
        """Test converting option to dictionary."""
        option = RemediationOption(
            title="Test Fix",
            description="A test fix",
            fix_type=FixType.REPLACE,
            complexity=FixComplexity.SIMPLE,
            original="old",
            replacement="new",
            security_impact="Improves security",
            usability_impact="None",
        )

        d = option.to_dict()

        assert d["title"] == "Test Fix"
        assert d["fix_type"] == "replace"
        assert d["complexity"] == "simple"
        assert d["original"] == "old"
        assert d["replacement"] == "new"


class TestGeneratedFix:
    """Tests for GeneratedFix."""

    def test_fix_to_dict(self):
        """Test converting fix to dictionary."""
        fix = GeneratedFix(
            finding_id="finding-123",
            rule_id="MCP-002",
            file_path="/tmp/test.json",
            line_number=10,
            options=[
                RemediationOption(
                    title="Option 1",
                    fix_type=FixType.REPLACE,
                )
            ],
            confidence=0.9,
        )

        d = fix.to_dict()

        assert d["finding_id"] == "finding-123"
        assert d["rule_id"] == "MCP-002"
        assert d["file_path"] == "/tmp/test.json"
        assert d["confidence"] == 0.9
        assert len(d["options"]) == 1

    def test_primary_fix(self):
        """Test getting primary fix option."""
        options = [
            RemediationOption(title="Option 1"),
            RemediationOption(title="Option 2"),
        ]

        fix = GeneratedFix(
            finding_id="123",
            rule_id="MCP-001",
            file_path="/tmp/test.json",
            options=options,
            recommended_option=1,
        )

        assert fix.primary_fix == options[1]
        assert fix.primary_fix.title == "Option 2"

    def test_primary_fix_empty_options(self):
        """Test primary fix with no options."""
        fix = GeneratedFix(
            finding_id="123",
            rule_id="MCP-001",
            file_path="/tmp/test.json",
            options=[],
        )

        assert fix.primary_fix is None
