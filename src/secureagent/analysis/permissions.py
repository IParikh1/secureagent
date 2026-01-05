"""Permission mapping and analysis for AI agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from secureagent.core.models.agent import AgentInventoryItem, Permission
from secureagent.core.models.severity import Severity


class PermissionCategory(Enum):
    """Categories of permissions."""

    SHELL_EXECUTION = "shell_execution"
    CODE_EXECUTION = "code_execution"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    NETWORK_READ = "network_read"
    NETWORK_WRITE = "network_write"
    DATABASE_READ = "database_read"
    DATABASE_WRITE = "database_write"
    MEMORY_ACCESS = "memory_access"
    EXTERNAL_API = "external_api"
    SYSTEM_ADMIN = "system_admin"
    USER_DATA = "user_data"
    CREDENTIALS = "credentials"
    DELEGATION = "delegation"


@dataclass
class PermissionRisk:
    """Risk assessment for a permission."""

    permission: Permission
    category: PermissionCategory
    severity: Severity
    risk_score: float
    justification: str
    recommendations: List[str] = field(default_factory=list)


@dataclass
class PermissionReport:
    """Permission analysis report for an agent."""

    agent_id: str
    agent_name: str
    total_permissions: int
    granted_permissions: int
    denied_permissions: int
    permission_risks: List[PermissionRisk] = field(default_factory=list)
    over_privileged: bool = False
    risk_summary: str = ""
    overall_risk_score: float = 0.0

    @property
    def critical_risks(self) -> List[PermissionRisk]:
        """Get critical permission risks."""
        return [r for r in self.permission_risks if r.severity == Severity.CRITICAL]

    @property
    def high_risks(self) -> List[PermissionRisk]:
        """Get high permission risks."""
        return [r for r in self.permission_risks if r.severity == Severity.HIGH]


class PermissionAnalyzer:
    """Analyzes agent permissions and identifies risks."""

    # Permission patterns and their risk levels
    PERMISSION_PATTERNS = {
        # Critical permissions
        "shell": (PermissionCategory.SHELL_EXECUTION, Severity.CRITICAL, 0.9),
        "bash": (PermissionCategory.SHELL_EXECUTION, Severity.CRITICAL, 0.9),
        "exec": (PermissionCategory.CODE_EXECUTION, Severity.CRITICAL, 0.85),
        "execute_command": (PermissionCategory.SHELL_EXECUTION, Severity.CRITICAL, 0.9),
        "system": (PermissionCategory.SYSTEM_ADMIN, Severity.CRITICAL, 0.95),
        "sudo": (PermissionCategory.SYSTEM_ADMIN, Severity.CRITICAL, 1.0),
        "admin": (PermissionCategory.SYSTEM_ADMIN, Severity.CRITICAL, 0.95),
        # High risk permissions
        "write_file": (PermissionCategory.FILE_WRITE, Severity.HIGH, 0.7),
        "delete_file": (PermissionCategory.FILE_DELETE, Severity.HIGH, 0.75),
        "database_write": (PermissionCategory.DATABASE_WRITE, Severity.HIGH, 0.7),
        "send_email": (PermissionCategory.NETWORK_WRITE, Severity.HIGH, 0.65),
        "http_post": (PermissionCategory.NETWORK_WRITE, Severity.HIGH, 0.7),
        "api_call": (PermissionCategory.EXTERNAL_API, Severity.HIGH, 0.6),
        "credentials": (PermissionCategory.CREDENTIALS, Severity.HIGH, 0.8),
        "delegate": (PermissionCategory.DELEGATION, Severity.HIGH, 0.65),
        # Medium risk permissions
        "read_file": (PermissionCategory.FILE_READ, Severity.MEDIUM, 0.4),
        "database_read": (PermissionCategory.DATABASE_READ, Severity.MEDIUM, 0.45),
        "http_get": (PermissionCategory.NETWORK_READ, Severity.MEDIUM, 0.35),
        "memory": (PermissionCategory.MEMORY_ACCESS, Severity.MEDIUM, 0.4),
        "user_data": (PermissionCategory.USER_DATA, Severity.MEDIUM, 0.5),
        # Low risk permissions
        "search": (PermissionCategory.FILE_READ, Severity.LOW, 0.2),
        "list": (PermissionCategory.FILE_READ, Severity.LOW, 0.15),
    }

    def __init__(self):
        """Initialize the analyzer."""
        self._reports: Dict[str, PermissionReport] = {}

    def analyze_agent(self, agent: AgentInventoryItem) -> PermissionReport:
        """Analyze permissions for a single agent.

        Args:
            agent: Agent to analyze

        Returns:
            PermissionReport with analysis results
        """
        report = PermissionReport(
            agent_id=agent.id,
            agent_name=agent.name,
            total_permissions=len(agent.permissions),
            granted_permissions=len([p for p in agent.permissions if p.granted]),
            denied_permissions=len([p for p in agent.permissions if not p.granted]),
        )

        # Analyze each permission
        for permission in agent.permissions:
            if permission.granted:
                risk = self._analyze_permission(permission)
                if risk:
                    report.permission_risks.append(risk)

        # Also analyze tools as implied permissions
        for tool in agent.tools:
            implied_risk = self._analyze_tool_permission(tool.name)
            if implied_risk:
                report.permission_risks.append(implied_risk)

        # Calculate overall risk
        if report.permission_risks:
            report.overall_risk_score = sum(
                r.risk_score for r in report.permission_risks
            ) / len(report.permission_risks)

            # Check if over-privileged
            critical_count = len(report.critical_risks)
            high_count = len(report.high_risks)
            report.over_privileged = critical_count > 0 or high_count > 2

            # Generate summary
            report.risk_summary = self._generate_summary(report)

        self._reports[agent.id] = report
        return report

    def _analyze_permission(self, permission: Permission) -> Optional[PermissionRisk]:
        """Analyze a single permission."""
        action_lower = permission.action.lower()

        for pattern, (category, severity, base_score) in self.PERMISSION_PATTERNS.items():
            if pattern in action_lower:
                return PermissionRisk(
                    permission=permission,
                    category=category,
                    severity=severity,
                    risk_score=base_score,
                    justification=f"Permission '{permission.action}' grants {category.value} capability",
                    recommendations=self._get_recommendations(category),
                )

        return None

    def _analyze_tool_permission(self, tool_name: str) -> Optional[PermissionRisk]:
        """Analyze implied permissions from a tool."""
        tool_lower = tool_name.lower()

        for pattern, (category, severity, base_score) in self.PERMISSION_PATTERNS.items():
            if pattern in tool_lower:
                permission = Permission(
                    action=f"use_{tool_name}",
                    resource=tool_name,
                    granted=True,
                )
                return PermissionRisk(
                    permission=permission,
                    category=category,
                    severity=severity,
                    risk_score=base_score,
                    justification=f"Tool '{tool_name}' implies {category.value} capability",
                    recommendations=self._get_recommendations(category),
                )

        return None

    def _get_recommendations(self, category: PermissionCategory) -> List[str]:
        """Get security recommendations for a permission category."""
        recommendations = {
            PermissionCategory.SHELL_EXECUTION: [
                "Implement strict command allowlists",
                "Use sandboxed execution environment",
                "Require human approval for shell commands",
            ],
            PermissionCategory.CODE_EXECUTION: [
                "Use sandboxed code execution",
                "Implement code review before execution",
                "Limit execution time and resources",
            ],
            PermissionCategory.FILE_WRITE: [
                "Restrict write access to specific directories",
                "Implement file type validation",
                "Log all file write operations",
            ],
            PermissionCategory.FILE_DELETE: [
                "Require confirmation for delete operations",
                "Implement soft-delete with recovery",
                "Restrict deletion to non-critical paths",
            ],
            PermissionCategory.DATABASE_WRITE: [
                "Use parameterized queries",
                "Implement transaction rollback capability",
                "Restrict to specific tables/schemas",
            ],
            PermissionCategory.NETWORK_WRITE: [
                "Implement URL allowlists",
                "Monitor outbound data for sensitive information",
                "Use rate limiting",
            ],
            PermissionCategory.CREDENTIALS: [
                "Use secure credential management",
                "Implement just-in-time access",
                "Audit all credential access",
            ],
            PermissionCategory.DELEGATION: [
                "Implement delegation policies",
                "Require approval for task delegation",
                "Limit delegation depth",
            ],
            PermissionCategory.SYSTEM_ADMIN: [
                "Remove admin privileges if not required",
                "Implement principle of least privilege",
                "Require multi-factor approval",
            ],
        }

        return recommendations.get(category, ["Review and restrict permissions"])

    def _generate_summary(self, report: PermissionReport) -> str:
        """Generate a risk summary."""
        critical = len(report.critical_risks)
        high = len(report.high_risks)
        total = len(report.permission_risks)

        if critical > 0:
            return f"CRITICAL: {critical} critical and {high} high-risk permissions. Immediate review required."
        elif high > 2:
            return f"HIGH RISK: {high} high-risk permissions out of {total} total. Review recommended."
        elif high > 0:
            return f"MODERATE: {high} high-risk permissions. Monitor closely."
        else:
            return f"LOW RISK: {total} permissions analyzed. Normal risk profile."

    def analyze_multiple(
        self, agents: List[AgentInventoryItem]
    ) -> Dict[str, PermissionReport]:
        """Analyze permissions for multiple agents.

        Args:
            agents: List of agents to analyze

        Returns:
            Dictionary mapping agent IDs to reports
        """
        return {agent.id: self.analyze_agent(agent) for agent in agents}

    def get_over_privileged_agents(
        self, agents: List[AgentInventoryItem]
    ) -> List[PermissionReport]:
        """Find over-privileged agents.

        Args:
            agents: List of agents to analyze

        Returns:
            List of reports for over-privileged agents
        """
        reports = self.analyze_multiple(agents)
        return [r for r in reports.values() if r.over_privileged]

    def get_agents_with_permission(
        self, agents: List[AgentInventoryItem], category: PermissionCategory
    ) -> List[AgentInventoryItem]:
        """Find agents with a specific permission category.

        Args:
            agents: List of agents
            category: Permission category to find

        Returns:
            List of agents with the permission
        """
        result = []
        for agent in agents:
            report = self.analyze_agent(agent)
            if any(r.category == category for r in report.permission_risks):
                result.append(agent)
        return result
