"""Unified Finding model for all security scanners."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from secureagent.core.models.severity import Severity


class FindingDomain(str, Enum):
    """Domain/source of a security finding."""

    MCP = "mcp"
    LANGCHAIN = "langchain"
    OPENAI = "openai"
    AUTOGPT = "autogpt"
    CREWAI = "crewai"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    TERRAFORM = "terraform"
    CLOUDTRAIL = "cloudtrail"
    GRAPH = "graph"
    INVENTORY = "inventory"
    CLOUD = "cloud"  # Generic cloud domain for cross-provider findings


class Location(BaseModel):
    """Location of a finding - supports both file-based and cloud resources."""

    # File-based location (MCP, Terraform, LangChain configs)
    file_path: Optional[str] = Field(None, description="Path to the file")
    line_number: Optional[int] = Field(None, description="Line number (1-indexed)")
    column: Optional[int] = Field(None, description="Column number")
    snippet: Optional[str] = Field(None, description="Code snippet around the finding")

    # Cloud resource location (AWS, Azure, GCP)
    resource_type: Optional[str] = Field(
        None, description="Cloud resource type (e.g., AWS::S3::Bucket)"
    )
    resource_id: Optional[str] = Field(
        None, description="Resource identifier (ARN, ID, name)"
    )
    resource_name: Optional[str] = Field(
        None, description="Human-readable resource name"
    )
    region: Optional[str] = Field(None, description="Cloud region")
    account_id: Optional[str] = Field(None, description="Cloud account ID")

    # Agent location (for AI agent findings)
    agent_id: Optional[str] = Field(None, description="AI agent identifier")
    agent_name: Optional[str] = Field(None, description="AI agent name")
    tool_name: Optional[str] = Field(None, description="Tool or function name")

    def to_string(self) -> str:
        """Get human-readable location string."""
        if self.file_path:
            loc = self.file_path
            if self.line_number:
                loc += f":{self.line_number}"
            return loc
        elif self.resource_id:
            return f"{self.resource_type or 'Resource'}: {self.resource_id}"
        elif self.agent_id:
            return f"Agent: {self.agent_name or self.agent_id}"
        return "Unknown location"


class Finding(BaseModel):
    """Unified security finding model for all scanner types."""

    # Core identification
    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique finding ID")
    rule_id: str = Field(..., description="Rule identifier (e.g., MCP-001, AWS-S3-001, LC-001)")
    domain: FindingDomain = Field(..., description="Source domain of the finding")

    # Finding details
    title: str = Field(..., description="Short, descriptive title")
    description: str = Field(..., description="Detailed description of the finding")
    severity: Severity = Field(..., description="Severity level")
    location: Location = Field(default_factory=Location, description="Location of the finding")

    # Remediation guidance
    remediation: str = Field(..., description="How to fix the issue")
    remediation_effort: Optional[str] = Field(
        None, description="Estimated effort: low, medium, high"
    )

    # Standards mapping
    cwe_id: Optional[str] = Field(None, description="CWE identifier (e.g., CWE-798)")
    owasp_id: Optional[str] = Field(
        None, description="OWASP mapping (e.g., LLM01, MCP02)"
    )
    mitre_attack_id: Optional[str] = Field(
        None, description="MITRE ATT&CK technique ID"
    )
    compliance_mappings: List[str] = Field(
        default_factory=list,
        description="Compliance framework mappings (e.g., SOC2-CC6.1, PCI-DSS-6.5.1)",
    )

    # ML risk scoring
    risk_score: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="ML-calculated risk score (0.0-1.0)"
    )
    confidence: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Model confidence in the finding"
    )

    # Additional context
    references: List[str] = Field(
        default_factory=list, description="Reference URLs for documentation"
    )
    tags: List[str] = Field(default_factory=list, description="Finding tags for filtering")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Domain-specific metadata"
    )

    # Timestamps
    detected_at: datetime = Field(default_factory=datetime.utcnow)

    # Status tracking
    suppressed: bool = Field(default=False, description="Whether finding is suppressed")
    false_positive: bool = Field(default=False, description="Marked as false positive")

    class Config:
        use_enum_values = True

    def to_sarif_result(self) -> Dict[str, Any]:
        """Convert finding to SARIF result format."""
        result = {
            "ruleId": self.rule_id,
            "level": self.severity.sarif_level if isinstance(self.severity, Severity) else "warning",
            "message": {"text": self.description},
            "locations": [],
        }

        if self.location.file_path:
            result["locations"].append({
                "physicalLocation": {
                    "artifactLocation": {"uri": self.location.file_path},
                    "region": {
                        "startLine": self.location.line_number or 1,
                        "startColumn": self.location.column or 1,
                    },
                }
            })

        if self.remediation:
            result["fixes"] = [{"description": {"text": self.remediation}}]

        return result

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "domain": self.domain,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "location": {
                "file_path": self.location.file_path,
                "line_number": self.location.line_number,
                "resource_type": self.location.resource_type,
                "resource_id": self.location.resource_id,
                "agent_id": self.location.agent_id,
            },
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "owasp_id": self.owasp_id,
            "compliance_mappings": self.compliance_mappings,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "references": self.references,
            "tags": self.tags,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }


class ScanResult(BaseModel):
    """Container for scan results."""

    findings: List[Finding] = Field(default_factory=list)
    scan_path: Optional[str] = None
    scanner_name: str = ""
    scan_duration_ms: Optional[int] = None
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        """Count of critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of high findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Count of medium findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Count of low findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def has_critical_or_high(self) -> bool:
        """Check if there are any critical or high severity findings."""
        return self.critical_count > 0 or self.high_count > 0

    def by_severity(self) -> Dict[Severity, List[Finding]]:
        """Group findings by severity."""
        result: Dict[Severity, List[Finding]] = {s: [] for s in Severity}
        for finding in self.findings:
            sev = finding.severity if isinstance(finding.severity, Severity) else Severity(finding.severity)
            result[sev].append(finding)
        return result

    def by_rule(self) -> Dict[str, List[Finding]]:
        """Group findings by rule ID."""
        result: Dict[str, List[Finding]] = {}
        for finding in self.findings:
            if finding.rule_id not in result:
                result[finding.rule_id] = []
            result[finding.rule_id].append(finding)
        return result
