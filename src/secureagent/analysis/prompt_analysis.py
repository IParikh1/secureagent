"""Prompt data exposure analysis for AI agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set
import re

from secureagent.core.models.agent import AgentInventoryItem
from secureagent.core.models.severity import Severity


class PromptRisk(Enum):
    """Types of prompt-related risks."""

    PII_IN_PROMPT = "pii_in_prompt"
    CREDENTIAL_IN_PROMPT = "credential_in_prompt"
    INJECTION_VULNERABLE = "injection_vulnerable"
    CONTEXT_OVERFLOW = "context_overflow"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    MEMORY_EXPOSURE = "memory_exposure"
    TOOL_RESULT_EXPOSURE = "tool_result_exposure"
    RAG_DATA_EXPOSURE = "rag_data_exposure"


class DataExposureType(Enum):
    """Types of data that can be exposed in prompts."""

    USER_INPUT = "user_input"
    SYSTEM_PROMPT = "system_prompt"
    CONVERSATION_HISTORY = "conversation_history"
    TOOL_RESULTS = "tool_results"
    RAG_CONTEXT = "rag_context"
    MEMORY_CONTENT = "memory_content"
    FUNCTION_PARAMETERS = "function_parameters"


@dataclass
class PromptExposure:
    """Represents a data exposure in prompts."""

    exposure_type: DataExposureType
    risk: PromptRisk
    severity: Severity
    description: str
    affected_data: List[str] = field(default_factory=list)
    mitigation: str = ""


@dataclass
class PromptAnalysisReport:
    """Prompt analysis report for an agent."""

    agent_id: str
    agent_name: str
    exposures: List[PromptExposure] = field(default_factory=list)
    prompt_components: List[DataExposureType] = field(default_factory=list)
    has_memory: bool = False
    has_rag: bool = False
    has_tools: bool = False
    injection_risk_score: float = 0.0
    data_exposure_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)

    @property
    def critical_exposures(self) -> List[PromptExposure]:
        """Get critical severity exposures."""
        return [e for e in self.exposures if e.severity == Severity.CRITICAL]

    @property
    def overall_risk_score(self) -> float:
        """Calculate overall risk score."""
        return (self.injection_risk_score + self.data_exposure_score) / 2


class PromptAnalyzer:
    """Analyzes prompt data exposure for AI agents."""

    # PII patterns to detect
    PII_PATTERNS = [
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "email address"),
        (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', "phone number"),
        (r'\b\d{3}[-]?\d{2}[-]?\d{4}\b', "SSN"),
        (r'\b\d{16}\b', "credit card number"),
        (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b', "credit card"),
    ]

    # Credential patterns
    CREDENTIAL_PATTERNS = [
        (r'sk-[a-zA-Z0-9]{20,}', "API key"),
        (r'password["\s:=]+["\'][^"\']+["\']', "password"),
        (r'secret["\s:=]+["\'][^"\']+["\']', "secret"),
        (r'token["\s:=]+["\'][^"\']+["\']', "token"),
        (r'Bearer\s+[a-zA-Z0-9\-_.]+', "bearer token"),
    ]

    def __init__(self):
        """Initialize the analyzer."""
        self._reports: Dict[str, PromptAnalysisReport] = {}

    def analyze(self, agent: AgentInventoryItem) -> PromptAnalysisReport:
        """Analyze prompt data exposure for an agent.

        Args:
            agent: Agent to analyze

        Returns:
            PromptAnalysisReport with analysis results
        """
        report = PromptAnalysisReport(
            agent_id=agent.id,
            agent_name=agent.name,
        )

        # Determine agent capabilities
        self._analyze_capabilities(agent, report)

        # Analyze exposure risks
        self._analyze_user_input_exposure(agent, report)
        self._analyze_memory_exposure(agent, report)
        self._analyze_tool_exposure(agent, report)
        self._analyze_rag_exposure(agent, report)
        self._analyze_injection_risk(agent, report)

        # Calculate risk scores
        self._calculate_risk_scores(report)

        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)

        self._reports[agent.id] = report
        return report

    def _analyze_capabilities(
        self, agent: AgentInventoryItem, report: PromptAnalysisReport
    ) -> None:
        """Analyze agent capabilities affecting prompt exposure."""
        # Check for memory
        memory_patterns = ["memory", "history", "conversation", "context"]
        for tool in agent.tools:
            if any(p in tool.name.lower() for p in memory_patterns):
                report.has_memory = True
                break

        # Check for RAG/retrieval
        rag_patterns = ["retrieval", "rag", "search", "vector", "embedding"]
        for tool in agent.tools:
            if any(p in tool.name.lower() for p in rag_patterns):
                report.has_rag = True
                break

        # Check for tools
        report.has_tools = len(agent.tools) > 0

        # Build prompt components list
        report.prompt_components.append(DataExposureType.USER_INPUT)
        report.prompt_components.append(DataExposureType.SYSTEM_PROMPT)

        if report.has_memory:
            report.prompt_components.append(DataExposureType.CONVERSATION_HISTORY)
            report.prompt_components.append(DataExposureType.MEMORY_CONTENT)

        if report.has_tools:
            report.prompt_components.append(DataExposureType.TOOL_RESULTS)
            report.prompt_components.append(DataExposureType.FUNCTION_PARAMETERS)

        if report.has_rag:
            report.prompt_components.append(DataExposureType.RAG_CONTEXT)

    def _analyze_user_input_exposure(
        self, agent: AgentInventoryItem, report: PromptAnalysisReport
    ) -> None:
        """Analyze user input exposure risks."""
        # Check for input validation guardrails
        has_input_validation = any(
            "input" in g.name.lower() or "validate" in g.name.lower()
            for g in agent.guardrails
        )

        if not has_input_validation:
            report.exposures.append(
                PromptExposure(
                    exposure_type=DataExposureType.USER_INPUT,
                    risk=PromptRisk.INJECTION_VULNERABLE,
                    severity=Severity.HIGH,
                    description="User input enters prompts without validation",
                    affected_data=["user_input"],
                    mitigation="Implement input validation and sanitization",
                )
            )

    def _analyze_memory_exposure(
        self, agent: AgentInventoryItem, report: PromptAnalysisReport
    ) -> None:
        """Analyze memory-related exposure risks."""
        if not report.has_memory:
            return

        # Check for memory encryption
        has_memory_protection = any(
            "encrypt" in g.name.lower() or "memory" in g.name.lower()
            for g in agent.guardrails
        )

        if not has_memory_protection:
            report.exposures.append(
                PromptExposure(
                    exposure_type=DataExposureType.MEMORY_CONTENT,
                    risk=PromptRisk.MEMORY_EXPOSURE,
                    severity=Severity.MEDIUM,
                    description="Conversation history stored without protection",
                    affected_data=["conversation_history", "memory"],
                    mitigation="Implement memory encryption and retention policies",
                )
            )

        # Memory could accumulate PII
        report.exposures.append(
            PromptExposure(
                exposure_type=DataExposureType.CONVERSATION_HISTORY,
                risk=PromptRisk.PII_IN_PROMPT,
                severity=Severity.MEDIUM,
                description="Conversation history may accumulate PII over time",
                affected_data=["pii", "user_data"],
                mitigation="Implement PII detection and scrubbing in memory",
            )
        )

    def _analyze_tool_exposure(
        self, agent: AgentInventoryItem, report: PromptAnalysisReport
    ) -> None:
        """Analyze tool-related exposure risks."""
        if not report.has_tools:
            return

        # Tool results enter prompts
        sensitive_tools = []
        for tool in agent.tools:
            tool_lower = tool.name.lower()
            if any(
                p in tool_lower
                for p in ["database", "file", "user", "customer", "api"]
            ):
                sensitive_tools.append(tool.name)

        if sensitive_tools:
            report.exposures.append(
                PromptExposure(
                    exposure_type=DataExposureType.TOOL_RESULTS,
                    risk=PromptRisk.TOOL_RESULT_EXPOSURE,
                    severity=Severity.MEDIUM,
                    description=f"Tool results from {', '.join(sensitive_tools)} enter prompts",
                    affected_data=sensitive_tools,
                    mitigation="Implement output filtering on tool results before prompt inclusion",
                )
            )

        # Function parameters could contain sensitive data
        report.exposures.append(
            PromptExposure(
                exposure_type=DataExposureType.FUNCTION_PARAMETERS,
                risk=PromptRisk.CREDENTIAL_IN_PROMPT,
                severity=Severity.LOW,
                description="Function parameters included in prompt context",
                affected_data=["function_calls"],
                mitigation="Validate and sanitize function parameters",
            )
        )

    def _analyze_rag_exposure(
        self, agent: AgentInventoryItem, report: PromptAnalysisReport
    ) -> None:
        """Analyze RAG-related exposure risks."""
        if not report.has_rag:
            return

        report.exposures.append(
            PromptExposure(
                exposure_type=DataExposureType.RAG_CONTEXT,
                risk=PromptRisk.RAG_DATA_EXPOSURE,
                severity=Severity.MEDIUM,
                description="Retrieved documents injected into prompts",
                affected_data=["documents", "knowledge_base"],
                mitigation="Implement access controls on retrievable documents, filter sensitive content",
            )
        )

        # RAG can introduce PII from documents
        report.exposures.append(
            PromptExposure(
                exposure_type=DataExposureType.RAG_CONTEXT,
                risk=PromptRisk.PII_IN_PROMPT,
                severity=Severity.HIGH,
                description="Retrieved documents may contain PII",
                affected_data=["document_pii"],
                mitigation="Scan knowledge base for PII, implement document-level access controls",
            )
        )

    def _analyze_injection_risk(
        self, agent: AgentInventoryItem, report: PromptAnalysisReport
    ) -> None:
        """Analyze prompt injection risk."""
        # Check for injection protection
        has_injection_protection = any(
            any(p in g.name.lower() for p in ["injection", "jailbreak", "guard"])
            for g in agent.guardrails
        )

        if not has_injection_protection:
            severity = Severity.HIGH
            if report.has_tools:
                severity = Severity.CRITICAL  # Tools make injection more dangerous

            report.exposures.append(
                PromptExposure(
                    exposure_type=DataExposureType.USER_INPUT,
                    risk=PromptRisk.INJECTION_VULNERABLE,
                    severity=severity,
                    description="No prompt injection protection detected",
                    affected_data=["all_prompt_data"],
                    mitigation="Implement prompt injection detection and prevention",
                )
            )

    def _calculate_risk_scores(self, report: PromptAnalysisReport) -> None:
        """Calculate risk scores."""
        # Injection risk score
        injection_exposures = [
            e for e in report.exposures if e.risk == PromptRisk.INJECTION_VULNERABLE
        ]
        if injection_exposures:
            max_severity = max(
                e.severity.value for e in injection_exposures if hasattr(e.severity, 'value')
            ) if injection_exposures else 0
            report.injection_risk_score = min(1.0, max_severity / 5 + 0.3)
        else:
            report.injection_risk_score = 0.1

        # Data exposure score
        severity_weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.7,
            Severity.MEDIUM: 0.4,
            Severity.LOW: 0.2,
            Severity.INFO: 0.1,
        }

        if report.exposures:
            total_weight = sum(
                severity_weights.get(e.severity, 0.1) for e in report.exposures
            )
            report.data_exposure_score = min(1.0, total_weight / len(report.exposures))
        else:
            report.data_exposure_score = 0.1

    def _generate_recommendations(
        self, report: PromptAnalysisReport
    ) -> List[str]:
        """Generate recommendations."""
        recommendations = []

        # Critical injection risk
        if report.injection_risk_score > 0.7:
            recommendations.append(
                "CRITICAL: Implement prompt injection protection immediately"
            )

        # Memory-related
        if report.has_memory:
            memory_exposures = [
                e for e in report.exposures if e.risk == PromptRisk.MEMORY_EXPOSURE
            ]
            if memory_exposures:
                recommendations.append(
                    "Implement memory encryption and PII scrubbing"
                )

        # RAG-related
        if report.has_rag:
            recommendations.append(
                "Scan knowledge base for sensitive data before retrieval"
            )
            recommendations.append(
                "Implement document-level access controls for RAG"
            )

        # Tool-related
        if report.has_tools:
            recommendations.append(
                "Filter tool results before including in prompts"
            )

        # General
        if not any(
            e.risk == PromptRisk.INJECTION_VULNERABLE for e in report.exposures
        ):
            pass  # Has injection protection
        else:
            recommendations.append(
                "Add input validation guardrails"
            )

        return recommendations

    def scan_text_for_pii(self, text: str) -> List[tuple]:
        """Scan text for PII patterns.

        Args:
            text: Text to scan

        Returns:
            List of (pattern_name, match) tuples
        """
        findings = []

        for pattern, name in self.PII_PATTERNS:
            matches = re.findall(pattern, text)
            for match in matches:
                findings.append((name, match))

        return findings

    def scan_text_for_credentials(self, text: str) -> List[tuple]:
        """Scan text for credential patterns.

        Args:
            text: Text to scan

        Returns:
            List of (pattern_name, match) tuples
        """
        findings = []

        for pattern, name in self.CREDENTIAL_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                findings.append((name, match[:10] + "..."))  # Mask credential

        return findings
