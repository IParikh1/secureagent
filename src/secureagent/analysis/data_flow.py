"""Data flow analysis for AI agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from secureagent.core.models.agent import AgentInventoryItem
from secureagent.core.models.data_flow import DataFlow, DataEndpoint, FlowType, DataType
from secureagent.core.models.severity import Severity


class DataFlowRisk(Enum):
    """Types of data flow risks."""

    PII_EXPOSURE = "pii_exposure"
    CREDENTIAL_FLOW = "credential_flow"
    UNENCRYPTED_TRANSIT = "unencrypted_transit"
    EXTERNAL_EGRESS = "external_egress"
    NO_INPUT_VALIDATION = "no_input_validation"
    NO_OUTPUT_FILTERING = "no_output_filtering"
    CROSS_BOUNDARY = "cross_boundary"
    DATA_MIXING = "data_mixing"


@dataclass
class DataFlowFinding:
    """A finding from data flow analysis."""

    risk_type: DataFlowRisk
    severity: Severity
    flow: DataFlow
    description: str
    recommendation: str


@dataclass
class DataFlowReport:
    """Data flow analysis report for an agent."""

    agent_id: str
    agent_name: str
    flows: List[DataFlow] = field(default_factory=list)
    findings: List[DataFlowFinding] = field(default_factory=list)
    input_endpoints: List[DataEndpoint] = field(default_factory=list)
    output_endpoints: List[DataEndpoint] = field(default_factory=list)
    data_types_processed: Set[DataType] = field(default_factory=set)

    @property
    def critical_findings(self) -> List[DataFlowFinding]:
        """Get critical severity findings."""
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def has_pii_exposure(self) -> bool:
        """Check if PII exposure risk exists."""
        return any(f.risk_type == DataFlowRisk.PII_EXPOSURE for f in self.findings)

    @property
    def has_external_egress(self) -> bool:
        """Check if data flows to external systems."""
        return any(f.risk_type == DataFlowRisk.EXTERNAL_EGRESS for f in self.findings)


class DataFlowAnalyzer:
    """Analyzes data flows through AI agents."""

    def __init__(self):
        """Initialize the analyzer."""
        self._reports: Dict[str, DataFlowReport] = {}

    def analyze(self, agent: AgentInventoryItem) -> DataFlowReport:
        """Analyze data flows for an agent.

        Args:
            agent: Agent to analyze

        Returns:
            DataFlowReport with analysis results
        """
        report = DataFlowReport(
            agent_id=agent.id,
            agent_name=agent.name,
        )

        # Build data flow graph from agent configuration
        self._build_flow_graph(agent, report)

        # Analyze for risks
        self._analyze_pii_exposure(agent, report)
        self._analyze_credential_flows(agent, report)
        self._analyze_external_egress(agent, report)
        self._analyze_input_validation(agent, report)
        self._analyze_output_filtering(agent, report)

        self._reports[agent.id] = report
        return report

    def _build_flow_graph(
        self, agent: AgentInventoryItem, report: DataFlowReport
    ) -> None:
        """Build data flow graph from agent configuration."""
        # Input endpoints from data sources
        for source in agent.data_sources:
            endpoint = DataEndpoint(
                name=source.name,
                endpoint_type=source.source_type,
                location=source.name,
            )
            report.input_endpoints.append(endpoint)

            # Create flow from source to agent
            flow = DataFlow(
                source=endpoint,
                destination=DataEndpoint(
                    name=agent.name,
                    endpoint_type="agent",
                    location=agent.id,
                ),
                flow_type=FlowType.DATA_SOURCE,
                data_types=self._infer_data_types(source.name),
            )
            report.flows.append(flow)
            report.data_types_processed.update(flow.data_types)

        # Output endpoints from tools
        for tool in agent.tools:
            if self._is_output_tool(tool.name):
                endpoint = DataEndpoint(
                    name=tool.name,
                    endpoint_type="tool",
                    location=tool.tool_type,
                )
                report.output_endpoints.append(endpoint)

                # Create flow from agent to tool
                flow = DataFlow(
                    source=DataEndpoint(
                        name=agent.name,
                        endpoint_type="agent",
                        location=agent.id,
                    ),
                    destination=endpoint,
                    flow_type=FlowType.TOOL_CALL,
                )
                report.flows.append(flow)

        # Model calls
        for model in agent.models:
            flow = DataFlow(
                source=DataEndpoint(
                    name=agent.name,
                    endpoint_type="agent",
                    location=agent.id,
                ),
                destination=DataEndpoint(
                    name=model.model_id,
                    endpoint_type="llm",
                    location=model.provider,
                ),
                flow_type=FlowType.PROMPT_INPUT,
            )
            report.flows.append(flow)

    def _infer_data_types(self, source_name: str) -> List[DataType]:
        """Infer data types from source name."""
        name_lower = source_name.lower()
        types = []

        if any(p in name_lower for p in ["user", "customer", "personal", "profile"]):
            types.append(DataType.PII)
        if any(p in name_lower for p in ["password", "secret", "credential", "key", "token"]):
            types.append(DataType.CREDENTIALS)
        if any(p in name_lower for p in ["health", "medical", "patient"]):
            types.append(DataType.PHI)
        if any(p in name_lower for p in ["payment", "card", "billing"]):
            types.append(DataType.PCI)
        if any(p in name_lower for p in ["internal", "private", "confidential"]):
            types.append(DataType.INTERNAL)

        if not types:
            types.append(DataType.GENERAL)

        return types

    def _is_output_tool(self, tool_name: str) -> bool:
        """Check if tool produces output."""
        output_patterns = [
            "write", "send", "post", "email", "http", "api",
            "database", "file", "storage", "publish",
        ]
        return any(p in tool_name.lower() for p in output_patterns)

    def _analyze_pii_exposure(
        self, agent: AgentInventoryItem, report: DataFlowReport
    ) -> None:
        """Analyze for PII exposure risks."""
        for flow in report.flows:
            if DataType.PII in flow.data_types:
                # Check if PII flows to external systems
                if flow.destination.endpoint_type in ["tool", "api", "llm"]:
                    report.findings.append(
                        DataFlowFinding(
                            risk_type=DataFlowRisk.PII_EXPOSURE,
                            severity=Severity.HIGH,
                            flow=flow,
                            description=f"PII data flows to {flow.destination.name}",
                            recommendation="Implement data masking or anonymization before transmission",
                        )
                    )

    def _analyze_credential_flows(
        self, agent: AgentInventoryItem, report: DataFlowReport
    ) -> None:
        """Analyze for credential flow risks."""
        for flow in report.flows:
            if DataType.CREDENTIALS in flow.data_types:
                report.findings.append(
                    DataFlowFinding(
                        risk_type=DataFlowRisk.CREDENTIAL_FLOW,
                        severity=Severity.CRITICAL,
                        flow=flow,
                        description=f"Credentials flow from {flow.source.name} to {flow.destination.name}",
                        recommendation="Remove credential access or implement secure secret management",
                    )
                )

    def _analyze_external_egress(
        self, agent: AgentInventoryItem, report: DataFlowReport
    ) -> None:
        """Analyze for external data egress."""
        external_patterns = ["http", "api", "webhook", "email", "slack", "s3"]

        for flow in report.flows:
            if any(p in flow.destination.name.lower() for p in external_patterns):
                severity = Severity.HIGH
                if any(dt in flow.data_types for dt in [DataType.PII, DataType.CREDENTIALS, DataType.PHI]):
                    severity = Severity.CRITICAL

                report.findings.append(
                    DataFlowFinding(
                        risk_type=DataFlowRisk.EXTERNAL_EGRESS,
                        severity=severity,
                        flow=flow,
                        description=f"Data flows to external system: {flow.destination.name}",
                        recommendation="Implement allowlists for external destinations, monitor egress",
                    )
                )

    def _analyze_input_validation(
        self, agent: AgentInventoryItem, report: DataFlowReport
    ) -> None:
        """Analyze for input validation gaps."""
        # Check if agent has guardrails for input
        has_input_guardrails = any(
            "input" in g.name.lower() or "prompt" in g.name.lower()
            for g in agent.guardrails
        )

        if not has_input_guardrails and len(report.input_endpoints) > 0:
            report.findings.append(
                DataFlowFinding(
                    risk_type=DataFlowRisk.NO_INPUT_VALIDATION,
                    severity=Severity.MEDIUM,
                    flow=report.flows[0] if report.flows else DataFlow(
                        source=DataEndpoint(name="external", endpoint_type="input"),
                        destination=DataEndpoint(name=agent.name, endpoint_type="agent"),
                    ),
                    description="No input validation guardrails detected",
                    recommendation="Implement input validation and sanitization",
                )
            )

    def _analyze_output_filtering(
        self, agent: AgentInventoryItem, report: DataFlowReport
    ) -> None:
        """Analyze for output filtering gaps."""
        has_output_guardrails = any(
            "output" in g.name.lower() or "response" in g.name.lower()
            for g in agent.guardrails
        )

        if not has_output_guardrails and len(report.output_endpoints) > 0:
            report.findings.append(
                DataFlowFinding(
                    risk_type=DataFlowRisk.NO_OUTPUT_FILTERING,
                    severity=Severity.MEDIUM,
                    flow=DataFlow(
                        source=DataEndpoint(name=agent.name, endpoint_type="agent"),
                        destination=DataEndpoint(name="output", endpoint_type="output"),
                    ),
                    description="No output filtering guardrails detected",
                    recommendation="Implement output filtering to prevent data leakage",
                )
            )

    def trace_data_type(
        self, agent: AgentInventoryItem, data_type: DataType
    ) -> List[DataFlow]:
        """Trace flows of a specific data type.

        Args:
            agent: Agent to analyze
            data_type: Data type to trace

        Returns:
            List of flows containing the data type
        """
        report = self.analyze(agent)
        return [f for f in report.flows if data_type in f.data_types]

    def find_egress_paths(
        self, agent: AgentInventoryItem
    ) -> List[DataFlow]:
        """Find all data egress paths.

        Args:
            agent: Agent to analyze

        Returns:
            List of flows to external systems
        """
        report = self.analyze(agent)
        external_types = ["tool", "api", "llm", "webhook"]
        return [
            f for f in report.flows
            if f.destination.endpoint_type in external_types
        ]
