"""LangChain configuration models."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class LangChainComponentType(Enum):
    """Types of LangChain components."""
    AGENT = "agent"
    CHAIN = "chain"
    TOOL = "tool"
    MEMORY = "memory"
    LLM = "llm"
    PROMPT = "prompt"
    RETRIEVER = "retriever"
    CALLBACK = "callback"


@dataclass
class LangChainTool:
    """Represents a LangChain tool configuration."""

    name: str
    tool_type: str
    description: Optional[str] = None
    is_dangerous: bool = False
    has_shell_access: bool = False
    has_file_access: bool = False
    has_network_access: bool = False
    raw_config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LangChainAgent:
    """Represents a LangChain agent configuration."""

    name: str
    agent_type: str
    tools: List[LangChainTool] = field(default_factory=list)
    memory_type: Optional[str] = None
    llm_provider: Optional[str] = None
    max_iterations: Optional[int] = None
    max_execution_time: Optional[float] = None
    verbose: bool = False
    raw_config: Dict[str, Any] = field(default_factory=dict)

    @property
    def has_dangerous_tools(self) -> bool:
        """Check if agent has any dangerous tools."""
        return any(t.is_dangerous for t in self.tools)

    @property
    def has_iteration_limits(self) -> bool:
        """Check if agent has iteration limits set."""
        return self.max_iterations is not None or self.max_execution_time is not None


@dataclass
class LangChainConfig:
    """Parsed LangChain configuration from code analysis."""

    file_path: str
    agents: List[LangChainAgent] = field(default_factory=list)
    tools: List[LangChainTool] = field(default_factory=list)
    api_keys_found: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
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
    def tool_count(self) -> int:
        """Get number of tools found."""
        return len(self.tools)
