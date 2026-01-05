"""Tests for core data models."""

import pytest
from datetime import datetime

from secureagent.core.models.finding import Finding, Location, FindingDomain
from secureagent.core.models.severity import Severity
from secureagent.core.models.agent import AgentInventoryItem, AgentFramework, ToolReference
from secureagent.core.models.data_flow import DataFlow, DataEndpoint, FlowType, DataType


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_ordering(self):
        """Test severity ordering."""
        severities = list(Severity)
        assert severities[0] == Severity.CRITICAL
        assert severities[-1] == Severity.INFO

    def test_severity_comparison(self):
        """Test severity comparison."""
        assert Severity.CRITICAL < Severity.HIGH
        assert Severity.HIGH < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.LOW
        assert Severity.LOW < Severity.INFO

    def test_severity_sarif_level(self):
        """Test severity to SARIF level mapping."""
        assert Severity.CRITICAL.sarif_level == "error"
        assert Severity.HIGH.sarif_level == "error"
        assert Severity.MEDIUM.sarif_level == "warning"
        assert Severity.LOW.sarif_level == "note"
        assert Severity.INFO.sarif_level == "none"


class TestLocation:
    """Tests for Location model."""

    def test_location_with_file(self):
        """Test location with file path."""
        loc = Location(file_path="/path/to/file.py", line_number=10)
        assert loc.file_path == "/path/to/file.py"
        assert loc.line_number == 10

    def test_location_with_resource(self):
        """Test location with cloud resource."""
        loc = Location(
            resource_type="aws_s3_bucket",
            resource_id="my-bucket",
            region="us-east-1",
        )
        assert loc.resource_type == "aws_s3_bucket"
        assert loc.resource_id == "my-bucket"
        assert loc.region == "us-east-1"

    def test_location_to_string_file(self):
        """Test location to_string with file path."""
        loc = Location(file_path="/path/to/file.py", line_number=10)
        assert loc.to_string() == "/path/to/file.py:10"

    def test_location_to_string_resource(self):
        """Test location to_string with resource."""
        loc = Location(resource_type="AWS::S3::Bucket", resource_id="my-bucket")
        assert "my-bucket" in loc.to_string()


class TestFinding:
    """Tests for Finding model."""

    def test_finding_creation(self, sample_finding):
        """Test finding creation."""
        assert sample_finding.id == "test-001"
        assert sample_finding.rule_id == "MCP-001"
        assert sample_finding.severity == Severity.HIGH

    def test_finding_with_location(self):
        """Test finding with location."""
        finding = Finding(
            id="test-001",
            rule_id="TEST-001",
            domain=FindingDomain.MCP,
            title="Test",
            description="Test description",
            severity=Severity.MEDIUM,
            location=Location(file_path="/test.py", line_number=5),
            remediation="Fix the issue.",
        )
        assert finding.location.file_path == "/test.py"
        assert finding.location.line_number == 5

    def test_finding_domain(self):
        """Test finding domain assignment."""
        finding = Finding(
            id="test-001",
            rule_id="MCP-001",
            domain=FindingDomain.MCP,
            title="Test",
            description="Test",
            severity=Severity.LOW,
            remediation="Fix the issue.",
        )
        assert finding.domain == FindingDomain.MCP

    def test_finding_metadata(self):
        """Test finding metadata."""
        finding = Finding(
            id="test-001",
            rule_id="TEST-001",
            domain=FindingDomain.MCP,
            title="Test",
            description="Test",
            severity=Severity.INFO,
            remediation="Fix the issue.",
            metadata={"custom": "value"},
        )
        assert finding.metadata["custom"] == "value"

    def test_finding_all_domains(self):
        """Test all finding domains are valid."""
        for domain in FindingDomain:
            finding = Finding(
                rule_id="TEST-001",
                domain=domain,
                title="Test",
                description="Test",
                severity=Severity.INFO,
                remediation="Fix the issue.",
            )
            assert finding.domain == domain


class TestAgentInventoryItem:
    """Tests for AgentInventoryItem model."""

    def test_agent_creation(self, sample_agent):
        """Test agent creation."""
        assert sample_agent.id == "agent-001"
        assert sample_agent.name == "Test Agent"
        assert sample_agent.framework == AgentFramework.LANGCHAIN

    def test_agent_with_tools(self):
        """Test agent with tools."""
        tool1 = ToolReference(name="tool1", type="function")
        tool2 = ToolReference(name="tool2", type="api")
        tool3 = ToolReference(name="tool3", type="file_access")

        agent = AgentInventoryItem(
            id="test-001",
            name="Test Agent",
            framework=AgentFramework.MCP,
            tools=[tool1, tool2, tool3],
        )
        assert len(agent.tools) == 3
        assert agent.tools[0].name == "tool1"

    def test_agent_frameworks(self):
        """Test all agent frameworks."""
        for framework in AgentFramework:
            agent = AgentInventoryItem(
                name="Test Agent",
                framework=framework,
            )
            assert agent.framework == framework

    def test_agent_risk_score(self):
        """Test agent risk score."""
        agent = AgentInventoryItem(
            name="Test Agent",
            framework=AgentFramework.LANGCHAIN,
            risk_score=0.75,
        )
        assert agent.risk_score == 0.75

    def test_agent_to_dict(self):
        """Test agent serialization."""
        agent = AgentInventoryItem(
            id="test-001",
            name="Test Agent",
            framework=AgentFramework.MCP,
        )
        data = agent.to_dict()
        assert data["id"] == "test-001"
        assert data["name"] == "Test Agent"


class TestDataFlow:
    """Tests for DataFlow model."""

    def test_data_flow_creation(self):
        """Test data flow creation."""
        flow = DataFlow(
            source=DataEndpoint(
                name="user_input",
                type="input",
            ),
            destination=DataEndpoint(
                name="database",
                type="storage",
            ),
            flow_type=FlowType.PROMPT_INPUT,
            data_types=[DataType.PII],
        )
        assert flow.source.name == "user_input"
        assert flow.destination.name == "database"
        assert flow.flow_type == FlowType.PROMPT_INPUT
        assert DataType.PII in flow.data_types

    def test_data_flow_sensitive_data(self):
        """Test data flow sensitive data detection."""
        flow = DataFlow(
            source=DataEndpoint(name="input", type="user"),
            destination=DataEndpoint(name="output", type="api"),
            flow_type=FlowType.API_REQUEST,
            data_types=[DataType.CREDENTIALS],
        )
        assert flow.contains_sensitive_data

    def test_data_flow_external_egress(self):
        """Test data flow external egress detection."""
        flow = DataFlow(
            source=DataEndpoint(name="input", type="agent", is_internal=True),
            destination=DataEndpoint(name="output", type="api", is_internal=False),
            flow_type=FlowType.EXTERNAL_EGRESS,
        )
        assert flow.is_external_egress

    def test_data_flow_types(self):
        """Test all flow types are valid."""
        for flow_type in FlowType:
            flow = DataFlow(
                source=DataEndpoint(name="src", type="agent"),
                destination=DataEndpoint(name="dst", type="api"),
                flow_type=flow_type,
            )
            assert flow.flow_type == flow_type
