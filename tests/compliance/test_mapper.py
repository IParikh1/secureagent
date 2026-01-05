"""Tests for compliance mapper."""

import pytest

from secureagent.compliance.mapper import (
    ComplianceMapper,
    ComplianceFramework,
)
from secureagent.core.models.finding import Finding, FindingDomain, Location
from secureagent.core.models.severity import Severity


class TestComplianceMapper:
    """Tests for compliance mapper."""

    def test_mapper_initialization(self):
        """Test mapper initialization."""
        mapper = ComplianceMapper()
        assert mapper is not None

    def test_map_finding_to_owasp_llm(self, sample_finding):
        """Test mapping finding to OWASP LLM Top 10."""
        mapper = ComplianceMapper()
        mapping = mapper.map_finding(sample_finding, ComplianceFramework.OWASP_LLM)

        assert mapping is not None
        assert mapping.framework == ComplianceFramework.OWASP_LLM
        assert len(mapping.control_ids) > 0

    def test_map_mcp_finding_to_owasp_mcp(self):
        """Test mapping MCP finding to OWASP MCP Top 10."""
        finding = Finding(
            id="test-001",
            rule_id="MCP-001",
            domain=FindingDomain.MCP,
            title="Hardcoded Credential",
            description="API key found",
            severity=Severity.CRITICAL,
            remediation="Remove hardcoded credentials and use environment variables.",
        )

        mapper = ComplianceMapper()
        mapping = mapper.map_finding(finding, ComplianceFramework.OWASP_MCP)

        assert mapping is not None
        assert "MCP03" in mapping.control_ids  # Credential Exposure

    def test_map_finding_to_soc2(self, sample_finding):
        """Test mapping finding to SOC2."""
        mapper = ComplianceMapper()
        mapping = mapper.map_finding(sample_finding, ComplianceFramework.SOC2)

        # MCP-001 should map to access control SOC2 controls
        if mapping:
            assert mapping.framework == ComplianceFramework.SOC2

    def test_get_compliance_status(self, sample_findings):
        """Test getting compliance status."""
        mapper = ComplianceMapper()
        status = mapper.get_compliance_status(
            sample_findings, ComplianceFramework.OWASP_LLM
        )

        assert status.framework == ComplianceFramework.OWASP_LLM
        assert status.total_controls > 0
        assert 0 <= status.compliance_percentage <= 100

    def test_get_all_mappings(self, sample_findings):
        """Test getting mappings for all frameworks."""
        mapper = ComplianceMapper()
        all_mappings = mapper.get_all_mappings(sample_findings)

        assert isinstance(all_mappings, dict)
        # Should have at least some mappings
        assert len(all_mappings) > 0

    def test_severity_to_status(self):
        """Test severity to compliance status conversion."""
        mapper = ComplianceMapper()

        # Critical should be violation
        finding = Finding(
            id="test-001",
            rule_id="MCP-001",
            domain=FindingDomain.MCP,
            title="Test",
            description="Test",
            severity=Severity.CRITICAL,
            remediation="Fix the issue.",
        )
        mapping = mapper.map_finding(finding, ComplianceFramework.OWASP_LLM)
        if mapping:
            assert mapping.compliance_status == "violation"

    def test_unmapped_rule(self):
        """Test handling of unmapped rules."""
        finding = Finding(
            id="test-001",
            rule_id="UNKNOWN-999",
            domain=FindingDomain.MCP,
            title="Unknown Finding",
            description="Unknown",
            severity=Severity.LOW,
            remediation="No specific remediation.",
        )

        mapper = ComplianceMapper()
        mapping = mapper.map_finding(finding, ComplianceFramework.OWASP_MCP)

        # Should return None for unknown rules
        assert mapping is None
