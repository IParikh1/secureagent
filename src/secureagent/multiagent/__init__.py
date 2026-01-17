"""Multi-Agent Security Analysis Module for SecureAgent.

Provides comprehensive security analysis for multi-agent AI systems:
- Agent orchestration security (LangGraph, AutoGen, CrewAI)
- Agent communication channel security
- Delegation attack detection
- Swarm behavior analysis
- Context isolation testing
- Agent federation security
"""

from .orchestration import (
    OrchestrationPattern,
    OrchestrationRisk,
    OrchestrationAnalyzer,
    WorkflowNode,
    WorkflowEdge,
    AgentWorkflow,
)
from .communication import (
    MessageType,
    ChannelSecurity,
    CommunicationThreat,
    AgentMessage,
    CommunicationAnalyzer,
)
from .delegation import (
    DelegationType,
    DelegationRisk,
    DelegationChain,
    DelegationAttack,
    DelegationAnalyzer,
)
from .frameworks import (
    MultiAgentFramework,
    FrameworkConfig,
    LangGraphAnalyzer,
    AutoGenAnalyzer,
    FrameworkDetector,
)
from .scanner import (
    MultiAgentSecurityReport,
    MultiAgentSecurityScanner,
)

__all__ = [
    # Orchestration analysis
    "OrchestrationPattern",
    "OrchestrationRisk",
    "OrchestrationAnalyzer",
    "WorkflowNode",
    "WorkflowEdge",
    "AgentWorkflow",
    # Communication security
    "MessageType",
    "ChannelSecurity",
    "CommunicationThreat",
    "AgentMessage",
    "CommunicationAnalyzer",
    # Delegation analysis
    "DelegationType",
    "DelegationRisk",
    "DelegationChain",
    "DelegationAttack",
    "DelegationAnalyzer",
    # Framework support
    "MultiAgentFramework",
    "FrameworkConfig",
    "LangGraphAnalyzer",
    "AutoGenAnalyzer",
    "FrameworkDetector",
    # Main scanner
    "MultiAgentSecurityReport",
    "MultiAgentSecurityScanner",
]
