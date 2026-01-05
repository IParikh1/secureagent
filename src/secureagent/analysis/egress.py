"""Egress path detection and analysis for AI agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from secureagent.core.models.agent import AgentInventoryItem
from secureagent.core.models.severity import Severity


class EgressType(Enum):
    """Types of egress paths."""

    HTTP_API = "http_api"
    EMAIL = "email"
    FILE_UPLOAD = "file_upload"
    DATABASE_WRITE = "database_write"
    MESSAGE_QUEUE = "message_queue"
    WEBHOOK = "webhook"
    CLOUD_STORAGE = "cloud_storage"
    EXTERNAL_SERVICE = "external_service"
    LLM_API = "llm_api"
    LOGGING = "logging"


class EgressRisk(Enum):
    """Egress risk levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class EgressPath:
    """Represents a data egress path."""

    name: str
    egress_type: EgressType
    destination: str
    risk: EgressRisk
    data_types: List[str] = field(default_factory=list)
    is_external: bool = True
    requires_auth: bool = False
    rate_limited: bool = False
    monitored: bool = False
    description: str = ""


@dataclass
class EgressReport:
    """Egress analysis report for an agent."""

    agent_id: str
    agent_name: str
    egress_paths: List[EgressPath] = field(default_factory=list)
    total_paths: int = 0
    external_paths: int = 0
    unmonitored_paths: int = 0
    high_risk_paths: int = 0
    recommendations: List[str] = field(default_factory=list)

    @property
    def critical_paths(self) -> List[EgressPath]:
        """Get critical risk egress paths."""
        return [p for p in self.egress_paths if p.risk == EgressRisk.CRITICAL]

    @property
    def has_uncontrolled_egress(self) -> bool:
        """Check if there are uncontrolled egress paths."""
        return any(
            p.is_external and not p.rate_limited and not p.monitored
            for p in self.egress_paths
        )


class EgressAnalyzer:
    """Analyzes data egress paths for AI agents."""

    # Tool patterns indicating egress capability
    EGRESS_PATTERNS = {
        EgressType.HTTP_API: ["http", "request", "api", "rest", "fetch"],
        EgressType.EMAIL: ["email", "smtp", "mail", "send_email"],
        EgressType.FILE_UPLOAD: ["upload", "s3", "blob", "file_write"],
        EgressType.DATABASE_WRITE: ["database", "sql", "db", "insert", "update"],
        EgressType.MESSAGE_QUEUE: ["queue", "kafka", "rabbitmq", "sqs", "pubsub"],
        EgressType.WEBHOOK: ["webhook", "callback", "notify"],
        EgressType.CLOUD_STORAGE: ["s3", "gcs", "azure_blob", "storage"],
        EgressType.EXTERNAL_SERVICE: ["slack", "discord", "teams", "twilio"],
        EgressType.LLM_API: ["openai", "anthropic", "llm", "gpt", "claude"],
        EgressType.LOGGING: ["log", "trace", "telemetry", "metrics"],
    }

    # Risk levels by egress type
    RISK_BY_TYPE = {
        EgressType.HTTP_API: EgressRisk.HIGH,
        EgressType.EMAIL: EgressRisk.HIGH,
        EgressType.FILE_UPLOAD: EgressRisk.HIGH,
        EgressType.DATABASE_WRITE: EgressRisk.MEDIUM,
        EgressType.MESSAGE_QUEUE: EgressRisk.MEDIUM,
        EgressType.WEBHOOK: EgressRisk.HIGH,
        EgressType.CLOUD_STORAGE: EgressRisk.HIGH,
        EgressType.EXTERNAL_SERVICE: EgressRisk.MEDIUM,
        EgressType.LLM_API: EgressRisk.MEDIUM,
        EgressType.LOGGING: EgressRisk.LOW,
    }

    def __init__(self):
        """Initialize the analyzer."""
        self._reports: Dict[str, EgressReport] = {}

    def analyze(self, agent: AgentInventoryItem) -> EgressReport:
        """Analyze egress paths for an agent.

        Args:
            agent: Agent to analyze

        Returns:
            EgressReport with analysis results
        """
        report = EgressReport(
            agent_id=agent.id,
            agent_name=agent.name,
        )

        # Find egress paths from tools
        for tool in agent.tools:
            paths = self._analyze_tool_egress(tool.name, tool.tool_type)
            report.egress_paths.extend(paths)

        # Find egress paths from permissions
        for perm in agent.permissions:
            if perm.granted:
                paths = self._analyze_permission_egress(perm.action, perm.resource)
                report.egress_paths.extend(paths)

        # Find egress from data sources with write access
        for source in agent.data_sources:
            if source.access_type in ["write", "read_write"]:
                path = self._create_data_source_egress(source)
                if path:
                    report.egress_paths.append(path)

        # Deduplicate paths
        report.egress_paths = self._deduplicate_paths(report.egress_paths)

        # Calculate statistics
        report.total_paths = len(report.egress_paths)
        report.external_paths = len([p for p in report.egress_paths if p.is_external])
        report.unmonitored_paths = len([p for p in report.egress_paths if not p.monitored])
        report.high_risk_paths = len(
            [p for p in report.egress_paths if p.risk in [EgressRisk.CRITICAL, EgressRisk.HIGH]]
        )

        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)

        self._reports[agent.id] = report
        return report

    def _analyze_tool_egress(
        self, tool_name: str, tool_type: str
    ) -> List[EgressPath]:
        """Analyze egress capabilities of a tool."""
        paths = []
        tool_lower = tool_name.lower()

        for egress_type, patterns in self.EGRESS_PATTERNS.items():
            if any(p in tool_lower for p in patterns):
                risk = self.RISK_BY_TYPE.get(egress_type, EgressRisk.MEDIUM)

                # Elevate risk for certain combinations
                if egress_type in [EgressType.HTTP_API, EgressType.WEBHOOK]:
                    # Check if it's POST-like (higher risk)
                    if any(p in tool_lower for p in ["post", "send", "write"]):
                        risk = EgressRisk.CRITICAL

                path = EgressPath(
                    name=f"{tool_name}_egress",
                    egress_type=egress_type,
                    destination=f"via {tool_name}",
                    risk=risk,
                    is_external=egress_type
                    not in [EgressType.DATABASE_WRITE, EgressType.LOGGING],
                    description=f"Egress via tool: {tool_name}",
                )
                paths.append(path)

        return paths

    def _analyze_permission_egress(
        self, action: str, resource: str
    ) -> List[EgressPath]:
        """Analyze egress capabilities from permissions."""
        paths = []
        action_lower = action.lower()
        resource_lower = resource.lower()

        for egress_type, patterns in self.EGRESS_PATTERNS.items():
            if any(p in action_lower or p in resource_lower for p in patterns):
                risk = self.RISK_BY_TYPE.get(egress_type, EgressRisk.MEDIUM)

                path = EgressPath(
                    name=f"permission_{action}",
                    egress_type=egress_type,
                    destination=resource,
                    risk=risk,
                    is_external=True,
                    description=f"Egress via permission: {action} on {resource}",
                )
                paths.append(path)

        return paths

    def _create_data_source_egress(self, source) -> Optional[EgressPath]:
        """Create egress path from writable data source."""
        source_lower = source.name.lower()

        # Determine egress type
        egress_type = EgressType.DATABASE_WRITE
        if any(p in source_lower for p in ["s3", "blob", "storage"]):
            egress_type = EgressType.CLOUD_STORAGE
        elif any(p in source_lower for p in ["api", "http"]):
            egress_type = EgressType.HTTP_API

        risk = self.RISK_BY_TYPE.get(egress_type, EgressRisk.MEDIUM)

        return EgressPath(
            name=f"datasource_{source.name}",
            egress_type=egress_type,
            destination=source.name,
            risk=risk,
            is_external=egress_type != EgressType.DATABASE_WRITE,
            description=f"Write access to: {source.name}",
        )

    def _deduplicate_paths(self, paths: List[EgressPath]) -> List[EgressPath]:
        """Remove duplicate egress paths."""
        seen = set()
        unique = []

        for path in paths:
            key = (path.egress_type, path.destination)
            if key not in seen:
                seen.add(key)
                unique.append(path)

        return unique

    def _generate_recommendations(self, report: EgressReport) -> List[str]:
        """Generate recommendations based on egress analysis."""
        recommendations = []

        # Critical paths
        if report.critical_paths:
            recommendations.append(
                f"CRITICAL: {len(report.critical_paths)} critical egress paths require immediate review"
            )

        # Unmonitored external paths
        unmonitored_external = [
            p for p in report.egress_paths if p.is_external and not p.monitored
        ]
        if unmonitored_external:
            recommendations.append(
                f"Implement monitoring for {len(unmonitored_external)} unmonitored external egress paths"
            )

        # No rate limiting
        no_rate_limit = [
            p for p in report.egress_paths if p.is_external and not p.rate_limited
        ]
        if no_rate_limit:
            recommendations.append(
                f"Add rate limiting to {len(no_rate_limit)} external egress paths"
            )

        # High-risk egress types
        http_paths = [p for p in report.egress_paths if p.egress_type == EgressType.HTTP_API]
        if http_paths:
            recommendations.append(
                "Implement URL allowlists for HTTP API egress paths"
            )

        email_paths = [p for p in report.egress_paths if p.egress_type == EgressType.EMAIL]
        if email_paths:
            recommendations.append(
                "Review email egress paths - potential data exfiltration vector"
            )

        return recommendations

    def get_egress_summary(
        self, agents: List[AgentInventoryItem]
    ) -> Dict[str, any]:
        """Get egress summary across multiple agents.

        Args:
            agents: List of agents

        Returns:
            Summary statistics
        """
        reports = [self.analyze(a) for a in agents]

        all_paths = []
        for r in reports:
            all_paths.extend(r.egress_paths)

        by_type: Dict[str, int] = {}
        for path in all_paths:
            etype = path.egress_type.value
            by_type[etype] = by_type.get(etype, 0) + 1

        return {
            "total_agents": len(agents),
            "total_egress_paths": len(all_paths),
            "agents_with_external_egress": len([r for r in reports if r.external_paths > 0]),
            "agents_with_uncontrolled_egress": len(
                [r for r in reports if r.has_uncontrolled_egress]
            ),
            "egress_by_type": by_type,
            "high_risk_paths": sum(r.high_risk_paths for r in reports),
        }
