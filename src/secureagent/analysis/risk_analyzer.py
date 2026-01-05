"""Risk analysis engine for AI agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple

from secureagent.core.models.agent import AgentInventoryItem
from secureagent.core.models.severity import Severity
from secureagent.core.models.finding import Finding


class RiskFactor(Enum):
    """Risk factors for agents."""

    SHELL_ACCESS = "shell_access"
    CODE_EXECUTION = "code_execution"
    FILE_SYSTEM_ACCESS = "file_system_access"
    NETWORK_ACCESS = "network_access"
    DATABASE_ACCESS = "database_access"
    CREDENTIAL_ACCESS = "credential_access"
    PII_ACCESS = "pii_access"
    NO_ITERATION_LIMITS = "no_iteration_limits"
    NO_HUMAN_OVERSIGHT = "no_human_oversight"
    DELEGATION_ENABLED = "delegation_enabled"
    MULTIPLE_DANGEROUS_TOOLS = "multiple_dangerous_tools"
    NO_GUARDRAILS = "no_guardrails"
    EXTERNAL_API_ACCESS = "external_api_access"
    MEMORY_PERSISTENCE = "memory_persistence"


@dataclass
class RiskFactorAssessment:
    """Assessment of a single risk factor."""

    factor: RiskFactor
    present: bool
    weight: float
    description: str
    evidence: List[str] = field(default_factory=list)
    mitigation: Optional[str] = None


@dataclass
class BlastRadius:
    """Estimated blast radius if agent is compromised."""

    affected_systems: List[str] = field(default_factory=list)
    affected_data: List[str] = field(default_factory=list)
    affected_users: str = "unknown"
    potential_damage: str = ""
    recovery_difficulty: str = "medium"


@dataclass
class RiskReport:
    """Comprehensive risk report for an agent."""

    agent_id: str
    agent_name: str
    overall_risk_score: float
    risk_level: Severity
    factor_assessments: List[RiskFactorAssessment] = field(default_factory=list)
    blast_radius: Optional[BlastRadius] = None
    key_risks: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    analyzed_at: datetime = field(default_factory=datetime.now)

    @property
    def critical_factors(self) -> List[RiskFactorAssessment]:
        """Get factors with highest weights."""
        return [f for f in self.factor_assessments if f.present and f.weight >= 0.8]


# Risk factor weights
RISK_WEIGHTS: Dict[RiskFactor, Tuple[float, str]] = {
    RiskFactor.SHELL_ACCESS: (0.95, "Can execute arbitrary shell commands"),
    RiskFactor.CODE_EXECUTION: (0.90, "Can execute arbitrary code"),
    RiskFactor.CREDENTIAL_ACCESS: (0.85, "Has access to credentials or secrets"),
    RiskFactor.NO_HUMAN_OVERSIGHT: (0.80, "Operates without human approval"),
    RiskFactor.FILE_SYSTEM_ACCESS: (0.70, "Can read/write files"),
    RiskFactor.DATABASE_ACCESS: (0.70, "Has database access"),
    RiskFactor.PII_ACCESS: (0.75, "Can access personal data"),
    RiskFactor.NETWORK_ACCESS: (0.65, "Can make network requests"),
    RiskFactor.DELEGATION_ENABLED: (0.60, "Can delegate tasks to other agents"),
    RiskFactor.NO_ITERATION_LIMITS: (0.55, "No iteration or time limits set"),
    RiskFactor.MULTIPLE_DANGEROUS_TOOLS: (0.70, "Has multiple dangerous tools"),
    RiskFactor.NO_GUARDRAILS: (0.65, "No guardrails configured"),
    RiskFactor.EXTERNAL_API_ACCESS: (0.50, "Can call external APIs"),
    RiskFactor.MEMORY_PERSISTENCE: (0.40, "Has persistent memory"),
}


class RiskAnalyzer:
    """Analyzes overall risk for AI agents."""

    def __init__(self):
        """Initialize the analyzer."""
        self._reports: Dict[str, RiskReport] = {}

    def analyze(self, agent: AgentInventoryItem) -> RiskReport:
        """Perform comprehensive risk analysis on an agent.

        Args:
            agent: Agent to analyze

        Returns:
            RiskReport with analysis results
        """
        report = RiskReport(
            agent_id=agent.id,
            agent_name=agent.name,
            overall_risk_score=0.0,
            risk_level=Severity.LOW,
        )

        # Assess each risk factor
        self._assess_shell_access(agent, report)
        self._assess_code_execution(agent, report)
        self._assess_credential_access(agent, report)
        self._assess_file_access(agent, report)
        self._assess_database_access(agent, report)
        self._assess_pii_access(agent, report)
        self._assess_network_access(agent, report)
        self._assess_delegation(agent, report)
        self._assess_iteration_limits(agent, report)
        self._assess_human_oversight(agent, report)
        self._assess_guardrails(agent, report)
        self._assess_tool_count(agent, report)

        # Calculate overall score
        self._calculate_overall_score(report)

        # Estimate blast radius
        report.blast_radius = self._estimate_blast_radius(agent, report)

        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)

        # Generate key risks summary
        report.key_risks = [
            f.description for f in report.factor_assessments if f.present and f.weight >= 0.6
        ]

        self._reports[agent.id] = report
        return report

    def _assess_shell_access(
        self, agent: AgentInventoryItem, report: RiskReport
    ) -> None:
        """Assess shell access risk."""
        factor = RiskFactor.SHELL_ACCESS
        weight, desc = RISK_WEIGHTS[factor]

        shell_patterns = ["shell", "bash", "terminal", "cmd", "exec"]
        evidence = []

        for tool in agent.tools:
            if any(p in tool.name.lower() for p in shell_patterns):
                evidence.append(f"Tool: {tool.name}")

        for perm in agent.permissions:
            if perm.granted and any(p in perm.action.lower() for p in shell_patterns):
                evidence.append(f"Permission: {perm.action}")

        report.factor_assessments.append(
            RiskFactorAssessment(
                factor=factor,
                present=len(evidence) > 0,
                weight=weight,
                description=desc,
                evidence=evidence,
                mitigation="Remove shell access or implement strict sandboxing",
            )
        )

    def _assess_code_execution(
        self, agent: AgentInventoryItem, report: RiskReport
    ) -> None:
        """Assess code execution risk."""
        factor = RiskFactor.CODE_EXECUTION
        weight, desc = RISK_WEIGHTS[factor]

        code_patterns = ["code_interpreter", "python", "repl", "eval", "execute"]
        evidence = []

        for tool in agent.tools:
            if any(p in tool.name.lower() for p in code_patterns):
                evidence.append(f"Tool: {tool.name}")

        report.factor_assessments.append(
            RiskFactorAssessment(
                factor=factor,
                present=len(evidence) > 0,
                weight=weight,
                description=desc,
                evidence=evidence,
                mitigation="Use sandboxed execution environment",
            )
        )

    def _assess_credential_access(
        self, agent: AgentInventoryItem, report: RiskReport
    ) -> None:
        """Assess credential access risk."""
        factor = RiskFactor.CREDENTIAL_ACCESS
        weight, desc = RISK_WEIGHTS[factor]

        cred_patterns = ["credential", "secret", "password", "token", "key", "auth"]
        evidence = []

        for source in agent.data_sources:
            if any(p in source.name.lower() for p in cred_patterns):
                evidence.append(f"Data source: {source.name}")

        for perm in agent.permissions:
            if perm.granted and any(p in perm.resource.lower() for p in cred_patterns):
                evidence.append(f"Permission on: {perm.resource}")

        report.factor_assessments.append(
            RiskFactorAssessment(
                factor=factor,
                present=len(evidence) > 0,
                weight=weight,
                description=desc,
                evidence=evidence,
                mitigation="Use secure secret management, implement just-in-time access",
            )
        )

    def _assess_file_access(
        self, agent: AgentInventoryItem, report: RiskReport
    ) -> None:
        """Assess file system access risk."""
        factor = RiskFactor.FILE_SYSTEM_ACCESS
        weight, desc = RISK_WEIGHTS[factor]

        file_patterns = ["file", "read", "write", "delete", "directory", "path"]
        evidence = []

        for tool in agent.tools:
            if any(p in tool.name.lower() for p in file_patterns):
                evidence.append(f"Tool: {tool.name}")

        report.factor_assessments.append(
            RiskFactorAssessment(
                factor=factor,
                present=len(evidence) > 0,
                weight=weight,
                description=desc,
                evidence=evidence,
                mitigation="Restrict access to specific directories",
            )
        )

    def _assess_database_access(
        self, agent: AgentInventoryItem, report: RiskReport
    ) -> None:
        """Assess database access risk."""
        factor = RiskFactor.DATABASE_ACCESS
        weight, desc = RISK_WEIGHTS[factor]

        db_patterns = ["database", "sql", "query", "db", "postgres", "mysql", "mongo"]
        evidence = []

        for tool in agent.tools:
            if any(p in tool.name.lower() for p in db_patterns):
                evidence.append(f"Tool: {tool.name}")

        for source in agent.data_sources:
            if any(p in source.name.lower() for p in db_patterns):
                evidence.append(f"Data source: {source.name}")

        report.factor_assessments.append(
            RiskFactorAssessment(
                factor=factor,
                present=len(evidence) > 0,
                weight=weight,
                description=desc,
                evidence=evidence,
                mitigation="Use read-only access where possible, parameterized queries",
            )
        )

    def _assess_pii_access(
        self, agent: AgentInventoryItem, report: RiskReport
    ) -> None:
        """Assess PII access risk."""
        factor = RiskFactor.PII_ACCESS
        weight, desc = RISK_WEIGHTS[factor]

        pii_patterns = ["user", "customer", "personal", "email", "phone", "address", "name"]
        evidence = []

        for source in agent.data_sources:
            if any(p in source.name.lower() for p in pii_patterns):
                evidence.append(f"Data source: {source.name}")

        report.factor_assessments.append(
            RiskFactorAssessment(
                factor=factor,
                present=len(evidence) > 0,
                weight=weight,
                description=desc,
                evidence=evidence,
                mitigation="Implement data minimization, anonymization",
            )
        )

    def _assess_network_access(
        self, agent: AgentInventoryItem, report: RiskReport
    ) -> None:
        """Assess network access risk."""
        factor = RiskFactor.NETWORK_ACCESS
        weight, desc = RISK_WEIGHTS[factor]

        net_patterns = ["http", "request", "api", "web", "browser", "fetch"]
        evidence = []

        for tool in agent.tools:
            if any(p in tool.name.lower() for p in net_patterns):
                evidence.append(f"Tool: {tool.name}")

        report.factor_assessments.append(
            RiskFactorAssessment(
                factor=factor,
                present=len(evidence) > 0,
                weight=weight,
                description=desc,
                evidence=evidence,
                mitigation="Implement URL allowlists, monitor outbound traffic",
            )
        )

    def _assess_delegation(
        self, agent: AgentInventoryItem, report: RiskReport
    ) -> None:
        """Assess delegation risk."""
        factor = RiskFactor.DELEGATION_ENABLED
        weight, desc = RISK_WEIGHTS[factor]

        # Check raw config for delegation settings
        has_delegation = False
        evidence = []

        for perm in agent.permissions:
            if "delegate" in perm.action.lower() and perm.granted:
                has_delegation = True
                evidence.append(f"Permission: {perm.action}")

        report.factor_assessments.append(
            RiskFactorAssessment(
                factor=factor,
                present=has_delegation,
                weight=weight,
                description=desc,
                evidence=evidence,
                mitigation="Implement delegation policies and approval workflows",
            )
        )

    def _assess_iteration_limits(
        self, agent: AgentInventoryItem, report: RiskReport
    ) -> None:
        """Assess iteration limits."""
        factor = RiskFactor.NO_ITERATION_LIMITS
        weight, desc = RISK_WEIGHTS[factor]

        # Assume no limits unless we find evidence of limits
        has_limits = False  # Would be detected during scanning

        report.factor_assessments.append(
            RiskFactorAssessment(
                factor=factor,
                present=not has_limits,
                weight=weight,
                description=desc,
                evidence=["No iteration limits detected"] if not has_limits else [],
                mitigation="Set max_iterations and max_execution_time",
            )
        )

    def _assess_human_oversight(
        self, agent: AgentInventoryItem, report: RiskReport
    ) -> None:
        """Assess human oversight."""
        factor = RiskFactor.NO_HUMAN_OVERSIGHT
        weight, desc = RISK_WEIGHTS[factor]

        # Check for human-in-the-loop indicators
        has_oversight = False

        for perm in agent.permissions:
            if "approval" in perm.action.lower() or "human" in perm.action.lower():
                has_oversight = True

        report.factor_assessments.append(
            RiskFactorAssessment(
                factor=factor,
                present=not has_oversight,
                weight=weight,
                description=desc,
                evidence=["No human approval workflow detected"] if not has_oversight else [],
                mitigation="Implement human-in-the-loop for critical actions",
            )
        )

    def _assess_guardrails(
        self, agent: AgentInventoryItem, report: RiskReport
    ) -> None:
        """Assess guardrail coverage."""
        factor = RiskFactor.NO_GUARDRAILS
        weight, desc = RISK_WEIGHTS[factor]

        has_guardrails = len(agent.guardrails) > 0

        report.factor_assessments.append(
            RiskFactorAssessment(
                factor=factor,
                present=not has_guardrails,
                weight=weight,
                description=desc,
                evidence=["No guardrails configured"] if not has_guardrails else [],
                mitigation="Implement input/output guardrails",
            )
        )

    def _assess_tool_count(
        self, agent: AgentInventoryItem, report: RiskReport
    ) -> None:
        """Assess dangerous tool count."""
        factor = RiskFactor.MULTIPLE_DANGEROUS_TOOLS
        weight, desc = RISK_WEIGHTS[factor]

        dangerous_patterns = ["shell", "exec", "write", "delete", "sql", "code"]
        dangerous_count = 0
        evidence = []

        for tool in agent.tools:
            if any(p in tool.name.lower() for p in dangerous_patterns):
                dangerous_count += 1
                evidence.append(f"Dangerous tool: {tool.name}")

        report.factor_assessments.append(
            RiskFactorAssessment(
                factor=factor,
                present=dangerous_count >= 2,
                weight=weight,
                description=desc,
                evidence=evidence,
                mitigation="Reduce number of dangerous tools, implement principle of least privilege",
            )
        )

    def _calculate_overall_score(self, report: RiskReport) -> None:
        """Calculate overall risk score."""
        present_factors = [f for f in report.factor_assessments if f.present]

        if not present_factors:
            report.overall_risk_score = 0.1
            report.risk_level = Severity.LOW
            return

        # Weighted average with emphasis on highest risks
        weights = sorted([f.weight for f in present_factors], reverse=True)

        # Give more weight to top risks
        weighted_sum = sum(w * (1.1 ** i) for i, w in enumerate(reversed(weights[:5])))
        max_possible = sum((1.1 ** i) for i in range(min(5, len(weights))))

        report.overall_risk_score = min(1.0, weighted_sum / max_possible)

        # Determine risk level
        if report.overall_risk_score >= 0.8:
            report.risk_level = Severity.CRITICAL
        elif report.overall_risk_score >= 0.6:
            report.risk_level = Severity.HIGH
        elif report.overall_risk_score >= 0.4:
            report.risk_level = Severity.MEDIUM
        elif report.overall_risk_score >= 0.2:
            report.risk_level = Severity.LOW
        else:
            report.risk_level = Severity.INFO

    def _estimate_blast_radius(
        self, agent: AgentInventoryItem, report: RiskReport
    ) -> BlastRadius:
        """Estimate blast radius if agent is compromised."""
        blast = BlastRadius()

        # Affected systems based on tools
        for tool in agent.tools:
            if "shell" in tool.name.lower() or "exec" in tool.name.lower():
                blast.affected_systems.append("Operating System")
            if "file" in tool.name.lower():
                blast.affected_systems.append("File System")
            if "database" in tool.name.lower() or "sql" in tool.name.lower():
                blast.affected_systems.append("Database")
            if "http" in tool.name.lower() or "api" in tool.name.lower():
                blast.affected_systems.append("External APIs")

        # Affected data
        for source in agent.data_sources:
            blast.affected_data.append(source.name)

        # Assess damage potential
        if report.overall_risk_score >= 0.8:
            blast.potential_damage = "Severe: Full system compromise possible"
            blast.recovery_difficulty = "hard"
        elif report.overall_risk_score >= 0.6:
            blast.potential_damage = "High: Significant data exposure and modification possible"
            blast.recovery_difficulty = "hard"
        elif report.overall_risk_score >= 0.4:
            blast.potential_damage = "Moderate: Limited data exposure possible"
            blast.recovery_difficulty = "medium"
        else:
            blast.potential_damage = "Low: Limited impact expected"
            blast.recovery_difficulty = "easy"

        return blast

    def _generate_recommendations(self, report: RiskReport) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []

        # Sort factors by weight
        sorted_factors = sorted(
            [f for f in report.factor_assessments if f.present],
            key=lambda x: x.weight,
            reverse=True,
        )

        for factor in sorted_factors[:5]:  # Top 5 recommendations
            if factor.mitigation:
                recommendations.append(factor.mitigation)

        return recommendations

    def analyze_multiple(
        self, agents: List[AgentInventoryItem]
    ) -> Dict[str, RiskReport]:
        """Analyze multiple agents.

        Args:
            agents: List of agents

        Returns:
            Dictionary mapping agent IDs to reports
        """
        return {agent.id: self.analyze(agent) for agent in agents}

    def get_high_risk_agents(
        self, agents: List[AgentInventoryItem], threshold: float = 0.6
    ) -> List[RiskReport]:
        """Find high-risk agents.

        Args:
            agents: List of agents
            threshold: Risk score threshold

        Returns:
            List of high-risk reports
        """
        reports = self.analyze_multiple(agents)
        return [r for r in reports.values() if r.overall_risk_score >= threshold]
