"""Data flow models for tracking data movement through AI agents."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from secureagent.core.models.severity import Severity


class FlowType(str, Enum):
    """Type of data flow."""

    PROMPT_INPUT = "prompt_input"
    PROMPT_OUTPUT = "prompt_output"
    TOOL_CALL = "tool_call"
    TOOL_RESPONSE = "tool_response"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    API_REQUEST = "api_request"
    API_RESPONSE = "api_response"
    DATABASE_QUERY = "database_query"
    DATABASE_RESULT = "database_result"
    VECTOR_STORE_QUERY = "vector_store_query"
    VECTOR_STORE_RESULT = "vector_store_result"
    EXTERNAL_EGRESS = "external_egress"


class DataType(str, Enum):
    """Classification of data types."""

    # Sensitivity levels
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    # Specific data types
    PII = "pii"
    PHI = "phi"  # Protected Health Information
    PCI = "pci"  # Payment Card Information
    CREDENTIALS = "credentials"
    API_KEYS = "api_keys"
    SOURCE_CODE = "source_code"
    FINANCIAL = "financial"
    LEGAL = "legal"

    # Content types
    USER_INPUT = "user_input"
    SYSTEM_PROMPT = "system_prompt"
    MODEL_OUTPUT = "model_output"
    TOOL_OUTPUT = "tool_output"
    ERROR_MESSAGE = "error_message"
    LOG_DATA = "log_data"


class DataEndpoint(BaseModel):
    """Endpoint in a data flow (source or destination)."""

    name: str = Field(..., description="Endpoint name")
    type: str = Field(..., description="Endpoint type (agent, tool, api, database, file, user)")
    location: Optional[str] = Field(None, description="Location/path/URL")

    # Context
    agent_id: Optional[str] = Field(None, description="Associated agent ID")
    tool_name: Optional[str] = Field(None, description="Associated tool name")

    # Security properties
    is_internal: bool = Field(default=True, description="Internal vs external endpoint")
    is_trusted: bool = Field(default=False, description="Trusted endpoint")
    requires_auth: bool = Field(default=False, description="Requires authentication")
    is_encrypted: bool = Field(default=False, description="Connection is encrypted")

    def to_string(self) -> str:
        """Get human-readable endpoint string."""
        if self.location:
            return f"{self.type}:{self.location}"
        return f"{self.type}:{self.name}"


class DataFlow(BaseModel):
    """Represents a data flow between endpoints."""

    id: str = Field(default_factory=lambda: str(uuid4()))

    # Flow endpoints
    source: DataEndpoint = Field(..., description="Where data comes from")
    destination: DataEndpoint = Field(..., description="Where data goes to")

    # Flow characteristics
    flow_type: FlowType = Field(..., description="Type of data flow")
    data_types: List[DataType] = Field(
        default_factory=list, description="Types of data in this flow"
    )

    # Security controls
    guardrails: List[str] = Field(
        default_factory=list, description="Guardrails protecting this flow"
    )
    is_filtered: bool = Field(default=False, description="Data is filtered/sanitized")
    is_logged: bool = Field(default=False, description="Flow is audit logged")
    is_rate_limited: bool = Field(default=False, description="Flow is rate limited")

    # Risk assessment
    risk_level: Severity = Field(default=Severity.INFO)
    risk_factors: List[str] = Field(default_factory=list)

    # Compliance
    compliance_violations: List[str] = Field(
        default_factory=list, description="Compliance violations identified"
    )

    # Metadata
    volume_estimate: Optional[str] = Field(
        None, description="Estimated data volume (low, medium, high)"
    )
    frequency: Optional[str] = Field(
        None, description="Flow frequency (rare, occasional, frequent, continuous)"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Timestamps
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        use_enum_values = True

    @property
    def is_external_egress(self) -> bool:
        """Check if this is an external egress flow."""
        return not self.destination.is_internal

    @property
    def contains_sensitive_data(self) -> bool:
        """Check if flow contains sensitive data types."""
        sensitive_types = {
            DataType.PII, DataType.PHI, DataType.PCI,
            DataType.CREDENTIALS, DataType.API_KEYS,
            DataType.CONFIDENTIAL, DataType.RESTRICTED
        }
        return bool(set(self.data_types) & sensitive_types)

    @property
    def is_unprotected(self) -> bool:
        """Check if flow lacks security controls."""
        return (
            not self.guardrails
            and not self.is_filtered
            and not self.is_logged
        )

    def calculate_risk(self) -> Severity:
        """Calculate risk level based on flow properties."""
        risk_score = 0
        factors = []

        # External egress is risky
        if self.is_external_egress:
            risk_score += 3
            factors.append("external_egress")

        # Sensitive data increases risk
        if self.contains_sensitive_data:
            risk_score += 3
            factors.append("sensitive_data")

        # Lack of controls increases risk
        if self.is_unprotected:
            risk_score += 2
            factors.append("no_security_controls")

        # Untrusted source/destination
        if not self.source.is_trusted:
            risk_score += 1
            factors.append("untrusted_source")
        if not self.destination.is_trusted:
            risk_score += 1
            factors.append("untrusted_destination")

        # No encryption
        if not self.source.is_encrypted and not self.destination.is_encrypted:
            risk_score += 1
            factors.append("unencrypted")

        # High volume/frequency
        if self.volume_estimate == "high" or self.frequency == "continuous":
            risk_score += 1
            factors.append("high_volume")

        self.risk_factors = factors

        # Map score to severity
        if risk_score >= 7:
            return Severity.CRITICAL
        elif risk_score >= 5:
            return Severity.HIGH
        elif risk_score >= 3:
            return Severity.MEDIUM
        elif risk_score >= 1:
            return Severity.LOW
        return Severity.INFO

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "source": self.source.model_dump(),
            "destination": self.destination.model_dump(),
            "flow_type": self.flow_type,
            "data_types": self.data_types,
            "guardrails": self.guardrails,
            "is_filtered": self.is_filtered,
            "is_logged": self.is_logged,
            "risk_level": self.risk_level,
            "risk_factors": self.risk_factors,
            "compliance_violations": self.compliance_violations,
            "discovered_at": self.discovered_at.isoformat(),
        }


class DataFlowGraph(BaseModel):
    """Collection of data flows forming a graph."""

    agent_id: str = Field(..., description="Agent these flows belong to")
    flows: List[DataFlow] = Field(default_factory=list)
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def external_egress_flows(self) -> List[DataFlow]:
        """Get all external egress flows."""
        return [f for f in self.flows if f.is_external_egress]

    @property
    def sensitive_data_flows(self) -> List[DataFlow]:
        """Get all flows containing sensitive data."""
        return [f for f in self.flows if f.contains_sensitive_data]

    @property
    def unprotected_flows(self) -> List[DataFlow]:
        """Get all unprotected flows."""
        return [f for f in self.flows if f.is_unprotected]

    @property
    def high_risk_flows(self) -> List[DataFlow]:
        """Get all high or critical risk flows."""
        return [
            f for f in self.flows
            if f.risk_level in [Severity.HIGH, Severity.CRITICAL]
        ]

    def get_flows_by_type(self, flow_type: FlowType) -> List[DataFlow]:
        """Get flows by type."""
        return [f for f in self.flows if f.flow_type == flow_type]

    def get_egress_destinations(self) -> List[str]:
        """Get unique external egress destinations."""
        return list(set(
            f.destination.to_string()
            for f in self.external_egress_flows
        ))

    def summary(self) -> Dict[str, Any]:
        """Get summary of data flows."""
        return {
            "total_flows": len(self.flows),
            "external_egress_count": len(self.external_egress_flows),
            "sensitive_data_count": len(self.sensitive_data_flows),
            "unprotected_count": len(self.unprotected_flows),
            "high_risk_count": len(self.high_risk_flows),
            "egress_destinations": self.get_egress_destinations(),
            "flow_types": list(set(f.flow_type for f in self.flows)),
        }
