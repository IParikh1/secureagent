"""Main multi-agent security scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

from secureagent.core.models.finding import Finding, Location, ScanResult
from secureagent.core.models.severity import Severity
from secureagent.core.scanner.base import BaseScanner
from secureagent.core.scanner.registry import register_scanner

from .orchestration import OrchestrationAnalyzer, AgentWorkflow
from .communication import CommunicationAnalyzer, CommunicationThreat
from .delegation import DelegationAnalyzer, DelegationChain
from .frameworks import (
    FrameworkDetector,
    LangGraphAnalyzer,
    AutoGenAnalyzer,
    MultiAgentFramework,
    FrameworkConfig,
)


@dataclass
class MultiAgentSecurityReport:
    """Comprehensive multi-agent security report."""
    target_path: str
    frameworks_detected: List[MultiAgentFramework] = field(default_factory=list)
    orchestration_findings: List[Finding] = field(default_factory=list)
    communication_findings: List[Finding] = field(default_factory=list)
    delegation_findings: List[Finding] = field(default_factory=list)
    framework_findings: List[Finding] = field(default_factory=list)
    workflows: List[AgentWorkflow] = field(default_factory=list)
    delegation_chains: List[DelegationChain] = field(default_factory=list)
    total_agents_found: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def all_findings(self) -> List[Finding]:
        """Get all findings combined."""
        return (
            self.orchestration_findings +
            self.communication_findings +
            self.delegation_findings +
            self.framework_findings
        )

    @property
    def critical_count(self) -> int:
        """Count of critical findings."""
        return sum(1 for f in self.all_findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        """Count of high severity findings."""
        return sum(1 for f in self.all_findings if f.severity == "high")

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "target_path": self.target_path,
            "frameworks_detected": [f.value for f in self.frameworks_detected],
            "total_findings": len(self.all_findings),
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "orchestration_findings": len(self.orchestration_findings),
            "communication_findings": len(self.communication_findings),
            "delegation_findings": len(self.delegation_findings),
            "framework_findings": len(self.framework_findings),
            "workflows_detected": len(self.workflows),
            "delegation_chains": len(self.delegation_chains),
            "total_agents_found": self.total_agents_found,
            "findings": [f.to_dict() for f in self.all_findings],
        }


@register_scanner
class MultiAgentSecurityScanner(BaseScanner):
    """Comprehensive multi-agent security scanner."""

    name = "multiagent"
    description = "Scans multi-agent AI systems for security vulnerabilities"
    version = "1.0.0"

    FILE_PATTERNS = ["**/*.py", "**/*.yaml", "**/*.yml", "**/*.json"]

    def __init__(self, path: str = ".", config: Optional[Any] = None, **kwargs):
        super().__init__(path, config, **kwargs)
        self.framework_detector = FrameworkDetector()
        self.orchestration_analyzer = OrchestrationAnalyzer()
        self.communication_analyzer = CommunicationAnalyzer()
        self.delegation_analyzer = DelegationAnalyzer()
        self.langgraph_analyzer = LangGraphAnalyzer()
        self.autogen_analyzer = AutoGenAnalyzer()

    def discover_targets(self) -> List[Path]:
        """Discover files that may contain multi-agent code."""
        if self.path.is_file():
            return [self.path]

        targets = []
        for pattern in self.FILE_PATTERNS:
            for file_path in self.path.glob(pattern):
                if file_path.is_file() and self._is_multi_agent_file(file_path):
                    targets.append(file_path)

        return targets

    def _is_multi_agent_file(self, file_path: Path) -> bool:
        """Check if file contains multi-agent patterns."""
        try:
            content = file_path.read_text()
            frameworks = self.framework_detector.detect(content)
            return MultiAgentFramework.UNKNOWN not in frameworks or len(frameworks) > 1
        except Exception:
            return False

    def scan(self, target: str = None, **kwargs) -> ScanResult:
        """Execute the multi-agent security scan."""
        if target:
            self.path = Path(target)

        self.findings = []

        for file_path in self.discover_targets():
            self._scan_file(file_path)

        return ScanResult(
            findings=self.findings,
            scan_path=str(self.path),
            scanner_name=self.name,
        )

    def scan_comprehensive(
        self,
        target_path: str,
        scan_orchestration: bool = True,
        scan_communication: bool = True,
        scan_delegation: bool = True,
        scan_frameworks: bool = True,
    ) -> MultiAgentSecurityReport:
        """Run comprehensive multi-agent security scan."""
        self.path = Path(target_path)
        report = MultiAgentSecurityReport(target_path=target_path)

        all_frameworks: set = set()
        total_agents = 0

        for file_path in self.discover_targets():
            try:
                content = file_path.read_text()
            except Exception:
                continue

            # Detect frameworks
            frameworks = self.framework_detector.detect(content)
            all_frameworks.update(frameworks)

            # Count agents
            total_agents += self._count_agents(content)

            # Orchestration analysis
            if scan_orchestration:
                findings = self.orchestration_analyzer.analyze_file(file_path)
                report.orchestration_findings.extend(findings)
                report.workflows.extend(self.orchestration_analyzer.workflows)

            # Communication analysis
            if scan_communication:
                findings = self.communication_analyzer.analyze_file(file_path)
                report.communication_findings.extend(findings)

            # Delegation analysis
            if scan_delegation:
                findings = self.delegation_analyzer.analyze_file(file_path)
                report.delegation_findings.extend(findings)
                report.delegation_chains.extend(self.delegation_analyzer.chains)

            # Framework-specific analysis
            if scan_frameworks:
                for framework in frameworks:
                    if framework == MultiAgentFramework.LANGGRAPH:
                        findings = self.langgraph_analyzer.analyze(content, str(file_path))
                        report.framework_findings.extend(findings)
                    elif framework == MultiAgentFramework.AUTOGEN:
                        findings = self.autogen_analyzer.analyze(content, str(file_path))
                        report.framework_findings.extend(findings)

        report.frameworks_detected = list(all_frameworks - {MultiAgentFramework.UNKNOWN})
        report.total_agents_found = total_agents

        # Also store findings for standard scan result
        self.findings = report.all_findings

        return report

    def _scan_file(self, file_path: Path) -> None:
        """Scan a single file for multi-agent security issues."""
        try:
            content = file_path.read_text()
        except Exception:
            return

        # Detect frameworks
        frameworks = self.framework_detector.detect(content)

        # Run all analyzers
        self.findings.extend(self.orchestration_analyzer.analyze_file(file_path))
        self.findings.extend(self.communication_analyzer.analyze_file(file_path))
        self.findings.extend(self.delegation_analyzer.analyze_file(file_path))

        # Framework-specific analysis
        for framework in frameworks:
            if framework == MultiAgentFramework.LANGGRAPH:
                self.findings.extend(self.langgraph_analyzer.analyze(content, str(file_path)))
            elif framework == MultiAgentFramework.AUTOGEN:
                self.findings.extend(self.autogen_analyzer.analyze(content, str(file_path)))

    def _count_agents(self, content: str) -> int:
        """Count agent definitions in content."""
        import re
        patterns = [
            r'Agent\s*\(',
            r'AssistantAgent\s*\(',
            r'UserProxyAgent\s*\(',
            r'ConversableAgent\s*\(',
            r'def\s+\w+_agent\s*\(',
            r'class\s+\w+Agent\s*[:\(]',
        ]
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, content))
        return count

    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all security rules for this scanner."""
        from .orchestration import ORCHESTRATION_RULES
        from .communication import COMMUNICATION_RULES
        from .delegation import DELEGATION_RULES
        from .frameworks import FRAMEWORK_RULES

        rules = []
        for rule_dict in [ORCHESTRATION_RULES, COMMUNICATION_RULES, DELEGATION_RULES, FRAMEWORK_RULES]:
            for rule in rule_dict.values():
                rules.append({
                    "id": rule["id"],
                    "title": rule["title"],
                    "severity": str(rule["severity"]),
                    "description": rule["description"],
                    "cwe_id": rule.get("cwe_id", ""),
                })

        return rules
