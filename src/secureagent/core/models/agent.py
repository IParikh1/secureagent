"""Agent inventory models for AI agent discovery and tracking."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from secureagent.core.models.severity import Severity


class AgentFramework(str, Enum):
    """Supported AI agent frameworks."""

    MCP = "mcp"
    LANGCHAIN = "langchain"
    OPENAI_ASSISTANTS = "openai_assistants"
    AUTOGPT = "autogpt"
    CREWAI = "crewai"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class ModelReference(BaseModel):
    """Reference to an LLM model used by an agent."""

    provider: str = Field(..., description="Model provider (openai, anthropic, etc.)")
    model_id: str = Field(..., description="Model identifier (gpt-4, claude-3, etc.)")
    version: Optional[str] = Field(None, description="Model version if applicable")
    endpoint: Optional[str] = Field(None, description="Custom endpoint URL")
    parameters: Dict[str, Any] = Field(
        default_factory=dict, description="Model parameters (temperature, max_tokens, etc.)"
    )

    def to_string(self) -> str:
        """Get human-readable model string."""
        return f"{self.provider}/{self.model_id}"


class ToolReference(BaseModel):
    """Reference to a tool or connector available to an agent."""

    name: str = Field(..., description="Tool name")
    type: str = Field(..., description="Tool type (function, api, file_access, etc.)")
    description: Optional[str] = Field(None, description="Tool description")
    permissions: List[str] = Field(
        default_factory=list, description="Permissions required/granted"
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict, description="Tool parameters schema"
    )
    risk_level: Severity = Field(
        default=Severity.INFO, description="Risk level of this tool"
    )

    # Capability flags
    can_read_files: bool = Field(default=False)
    can_write_files: bool = Field(default=False)
    can_execute_code: bool = Field(default=False)
    can_make_network_requests: bool = Field(default=False)
    can_access_secrets: bool = Field(default=False)


class DataSource(BaseModel):
    """Data source that an agent can read from or write to."""

    name: str = Field(..., description="Data source name")
    type: str = Field(..., description="Type (database, file, api, memory, etc.)")
    location: Optional[str] = Field(None, description="Location/connection string")
    access_mode: str = Field(default="read", description="Access mode: read, write, read_write")
    data_classification: Optional[str] = Field(
        None, description="Data classification (public, internal, confidential, restricted)"
    )
    contains_pii: bool = Field(default=False, description="Contains personally identifiable information")
    contains_secrets: bool = Field(default=False, description="Contains secrets or credentials")
    encryption_at_rest: bool = Field(default=False)
    encryption_in_transit: bool = Field(default=False)


class Permission(BaseModel):
    """Permission or action that an agent can execute."""

    action: str = Field(..., description="Action name (read_file, execute_code, etc.)")
    resource: Optional[str] = Field(None, description="Resource the action applies to")
    scope: str = Field(default="*", description="Scope of the permission")
    risk_level: Severity = Field(default=Severity.INFO)
    requires_approval: bool = Field(default=False, description="Requires human approval")
    audit_logged: bool = Field(default=False, description="Action is audit logged")

    # Risk indicators
    is_destructive: bool = Field(default=False, description="Can cause data loss")
    is_privileged: bool = Field(default=False, description="Requires elevated privileges")
    exposes_data: bool = Field(default=False, description="Can expose sensitive data")


class Guardrail(BaseModel):
    """Guardrail protecting an agent."""

    name: str = Field(..., description="Guardrail name")
    type: str = Field(..., description="Type (input_filter, output_filter, rate_limit, etc.)")
    description: Optional[str] = Field(None)
    enabled: bool = Field(default=True)
    configuration: Dict[str, Any] = Field(default_factory=dict)

    # Coverage indicators
    covers_prompt_injection: bool = Field(default=False)
    covers_jailbreak: bool = Field(default=False)
    covers_data_leakage: bool = Field(default=False)
    covers_pii: bool = Field(default=False)
    covers_harmful_content: bool = Field(default=False)


class EgressPath(BaseModel):
    """Egress path where data can flow out from an agent."""

    destination: str = Field(..., description="Destination (URL, service name, etc.)")
    type: str = Field(..., description="Type (http, database, file, email, etc.)")
    protocol: Optional[str] = Field(None, description="Protocol used")
    port: Optional[int] = Field(None)
    data_types: List[str] = Field(
        default_factory=list, description="Types of data that can flow through"
    )
    is_encrypted: bool = Field(default=False)
    is_authenticated: bool = Field(default=False)
    risk_level: Severity = Field(default=Severity.INFO)

    # Compliance
    allowed_by_policy: bool = Field(default=True)
    requires_approval: bool = Field(default=False)


class AgentInventoryItem(BaseModel):
    """Complete inventory item for a discovered AI agent."""

    # Identification
    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique agent ID")
    name: str = Field(..., description="Agent name")
    description: Optional[str] = Field(None, description="Agent description")
    framework: AgentFramework = Field(..., description="AI framework used")
    version: Optional[str] = Field(None, description="Agent version")

    # Configuration
    config_path: Optional[str] = Field(None, description="Path to configuration file")
    config_hash: Optional[str] = Field(None, description="Hash of configuration for change detection")

    # Components
    models: List[ModelReference] = Field(
        default_factory=list, description="LLM models this agent calls"
    )
    tools: List[ToolReference] = Field(
        default_factory=list, description="Tools/connectors available"
    )
    data_sources: List[DataSource] = Field(
        default_factory=list, description="Data sources accessed"
    )
    permissions: List[Permission] = Field(
        default_factory=list, description="Actions agent can execute"
    )
    guardrails: List[Guardrail] = Field(
        default_factory=list, description="Configured guardrails"
    )
    egress_paths: List[EgressPath] = Field(
        default_factory=list, description="Egress paths for data"
    )

    # Risk assessment
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Overall risk score")
    risk_factors: List[str] = Field(default_factory=list, description="Contributing risk factors")
    compliance_status: Dict[str, bool] = Field(
        default_factory=dict, description="Compliance status by framework"
    )

    # Metadata
    owner: Optional[str] = Field(None, description="Owner/team responsible")
    environment: Optional[str] = Field(None, description="Environment (dev, staging, prod)")
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Timestamps
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    last_scanned_at: Optional[datetime] = Field(None)
    last_modified_at: Optional[datetime] = Field(None)

    # Status
    is_active: bool = Field(default=True)
    is_approved: bool = Field(default=False, description="Approved for production use")

    class Config:
        use_enum_values = True

    @property
    def total_tools(self) -> int:
        """Total number of tools available."""
        return len(self.tools)

    @property
    def dangerous_tools(self) -> List[ToolReference]:
        """Tools with high or critical risk level."""
        return [t for t in self.tools if t.risk_level in [Severity.HIGH, Severity.CRITICAL]]

    @property
    def has_code_execution(self) -> bool:
        """Check if agent can execute code."""
        return any(t.can_execute_code for t in self.tools)

    @property
    def has_file_write(self) -> bool:
        """Check if agent can write files."""
        return any(t.can_write_files for t in self.tools)

    @property
    def has_network_access(self) -> bool:
        """Check if agent can make network requests."""
        return any(t.can_make_network_requests for t in self.tools)

    @property
    def pii_exposure_risk(self) -> bool:
        """Check if agent has access to PII data."""
        return any(ds.contains_pii for ds in self.data_sources)

    @property
    def guardrail_coverage(self) -> Dict[str, bool]:
        """Get guardrail coverage summary."""
        return {
            "prompt_injection": any(g.covers_prompt_injection for g in self.guardrails),
            "jailbreak": any(g.covers_jailbreak for g in self.guardrails),
            "data_leakage": any(g.covers_data_leakage for g in self.guardrails),
            "pii": any(g.covers_pii for g in self.guardrails),
            "harmful_content": any(g.covers_harmful_content for g in self.guardrails),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "framework": self.framework,
            "version": self.version,
            "config_path": self.config_path,
            "models": [m.model_dump() for m in self.models],
            "tools": [t.model_dump() for t in self.tools],
            "data_sources": [ds.model_dump() for ds in self.data_sources],
            "permissions": [p.model_dump() for p in self.permissions],
            "guardrails": [g.model_dump() for g in self.guardrails],
            "egress_paths": [e.model_dump() for e in self.egress_paths],
            "risk_score": self.risk_score,
            "risk_factors": self.risk_factors,
            "compliance_status": self.compliance_status,
            "owner": self.owner,
            "environment": self.environment,
            "tags": self.tags,
            "discovered_at": self.discovered_at.isoformat(),
            "is_active": self.is_active,
            "is_approved": self.is_approved,
        }
