"""AutoGPT and CrewAI configuration models."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class AgentFramework(Enum):
    """Supported multi-agent frameworks."""
    AUTOGPT = "autogpt"
    CREWAI = "crewai"
    UNKNOWN = "unknown"


class AgentRole(Enum):
    """Common agent roles in multi-agent systems."""
    MANAGER = "manager"
    RESEARCHER = "researcher"
    WRITER = "writer"
    CODER = "coder"
    REVIEWER = "reviewer"
    EXECUTOR = "executor"
    CUSTOM = "custom"


@dataclass
class MultiAgentTool:
    """Represents a tool available to an agent."""

    name: str
    tool_type: str
    description: Optional[str] = None
    is_dangerous: bool = False
    has_shell_access: bool = False
    has_file_access: bool = False
    has_network_access: bool = False
    has_code_execution: bool = False


@dataclass
class MultiAgent:
    """Represents an agent in a multi-agent system."""

    name: str
    role: str
    framework: AgentFramework = AgentFramework.UNKNOWN
    goal: Optional[str] = None
    backstory: Optional[str] = None
    tools: List[MultiAgentTool] = field(default_factory=list)
    allow_delegation: bool = False
    verbose: bool = False
    memory: bool = False
    max_iterations: Optional[int] = None
    max_rpm: Optional[int] = None
    raw_config: Dict[str, Any] = field(default_factory=dict)

    @property
    def has_dangerous_tools(self) -> bool:
        """Check if agent has dangerous tools."""
        return any(t.is_dangerous for t in self.tools)

    @property
    def has_iteration_limits(self) -> bool:
        """Check if iteration limits are set."""
        return self.max_iterations is not None


@dataclass
class MultiAgentTask:
    """Represents a task in a multi-agent system."""

    description: str
    agent: Optional[str] = None
    expected_output: Optional[str] = None
    async_execution: bool = False
    context: List[str] = field(default_factory=list)


@dataclass
class MultiAgentCrew:
    """Represents a crew/team of agents."""

    name: Optional[str] = None
    agents: List[MultiAgent] = field(default_factory=list)
    tasks: List[MultiAgentTask] = field(default_factory=list)
    process: str = "sequential"  # sequential, hierarchical
    verbose: bool = False
    memory: bool = False
    manager_llm: Optional[str] = None


@dataclass
class MultiAgentConfig:
    """Parsed multi-agent configuration from code analysis."""

    file_path: str
    framework: AgentFramework = AgentFramework.UNKNOWN
    agents: List[MultiAgent] = field(default_factory=list)
    crews: List[MultiAgentCrew] = field(default_factory=list)
    tasks: List[MultiAgentTask] = field(default_factory=list)
    api_keys_found: List[str] = field(default_factory=list)
    raw_content: str = ""
    parse_errors: List[str] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """Check if there were parsing errors."""
        return len(self.parse_errors) > 0

    @property
    def agent_count(self) -> int:
        """Get number of agents found."""
        return len(self.agents)

    @property
    def has_hierarchical_process(self) -> bool:
        """Check if any crew uses hierarchical process."""
        return any(c.process == "hierarchical" for c in self.crews)
