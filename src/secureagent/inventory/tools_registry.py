"""Tools and Connectors Registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set


class ToolCategory(Enum):
    """Categories of tools."""

    SHELL = "shell"
    FILE_SYSTEM = "file_system"
    NETWORK = "network"
    DATABASE = "database"
    CODE_EXECUTION = "code_execution"
    WEB_BROWSER = "web_browser"
    API_CLIENT = "api_client"
    MEMORY = "memory"
    SEARCH = "search"
    COMMUNICATION = "communication"
    OTHER = "other"


class RiskLevel(Enum):
    """Risk levels for tools."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ToolInfo:
    """Information about a tool or connector."""

    name: str
    tool_type: str
    category: ToolCategory = ToolCategory.OTHER
    risk_level: RiskLevel = RiskLevel.MEDIUM
    description: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    requires_sandbox: bool = False
    requires_approval: bool = False
    risk_notes: List[str] = field(default_factory=list)

    @property
    def is_dangerous(self) -> bool:
        """Check if tool is considered dangerous."""
        return self.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]


@dataclass
class ToolUsage:
    """Tracks how a tool is used by agents."""

    tool: ToolInfo
    agent_ids: Set[str] = field(default_factory=set)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


# Known dangerous tools
KNOWN_TOOLS: Dict[str, ToolInfo] = {
    # Shell/Command execution
    "ShellTool": ToolInfo(
        name="ShellTool",
        tool_type="langchain",
        category=ToolCategory.SHELL,
        risk_level=RiskLevel.CRITICAL,
        description="Executes shell commands",
        capabilities=["shell_execution", "system_access"],
        requires_sandbox=True,
        requires_approval=True,
        risk_notes=["Can execute arbitrary commands", "Full system access"],
    ),
    "BashProcess": ToolInfo(
        name="BashProcess",
        tool_type="langchain",
        category=ToolCategory.SHELL,
        risk_level=RiskLevel.CRITICAL,
        description="Executes bash commands",
        capabilities=["shell_execution"],
        requires_sandbox=True,
        requires_approval=True,
    ),
    # Code execution
    "PythonREPL": ToolInfo(
        name="PythonREPL",
        tool_type="langchain",
        category=ToolCategory.CODE_EXECUTION,
        risk_level=RiskLevel.CRITICAL,
        description="Executes Python code",
        capabilities=["code_execution", "file_access", "network_access"],
        requires_sandbox=True,
        requires_approval=True,
        risk_notes=["Can execute arbitrary Python code"],
    ),
    "code_interpreter": ToolInfo(
        name="code_interpreter",
        tool_type="openai",
        category=ToolCategory.CODE_EXECUTION,
        risk_level=RiskLevel.HIGH,
        description="OpenAI code interpreter",
        capabilities=["code_execution", "data_analysis"],
        requires_sandbox=True,
        risk_notes=["Sandboxed but can still process sensitive data"],
    ),
    # File system
    "WriteFileTool": ToolInfo(
        name="WriteFileTool",
        tool_type="langchain",
        category=ToolCategory.FILE_SYSTEM,
        risk_level=RiskLevel.HIGH,
        description="Writes files to disk",
        capabilities=["file_write"],
        requires_approval=True,
        risk_notes=["Can overwrite files", "Path traversal risk"],
    ),
    "ReadFileTool": ToolInfo(
        name="ReadFileTool",
        tool_type="langchain",
        category=ToolCategory.FILE_SYSTEM,
        risk_level=RiskLevel.MEDIUM,
        description="Reads files from disk",
        capabilities=["file_read"],
        risk_notes=["Can access sensitive files"],
    ),
    "file_search": ToolInfo(
        name="file_search",
        tool_type="openai",
        category=ToolCategory.SEARCH,
        risk_level=RiskLevel.MEDIUM,
        description="OpenAI file search/retrieval",
        capabilities=["file_search", "document_retrieval"],
        risk_notes=["May expose sensitive document contents"],
    ),
    # Network
    "RequestsGetTool": ToolInfo(
        name="RequestsGetTool",
        tool_type="langchain",
        category=ToolCategory.NETWORK,
        risk_level=RiskLevel.MEDIUM,
        description="Makes HTTP GET requests",
        capabilities=["network_access", "data_fetching"],
        risk_notes=["SSRF risk", "Can access internal endpoints"],
    ),
    "RequestsPostTool": ToolInfo(
        name="RequestsPostTool",
        tool_type="langchain",
        category=ToolCategory.NETWORK,
        risk_level=RiskLevel.HIGH,
        description="Makes HTTP POST requests",
        capabilities=["network_access", "data_sending"],
        requires_approval=True,
        risk_notes=["Can exfiltrate data", "SSRF risk"],
    ),
    # Database
    "SQLDatabaseToolkit": ToolInfo(
        name="SQLDatabaseToolkit",
        tool_type="langchain",
        category=ToolCategory.DATABASE,
        risk_level=RiskLevel.HIGH,
        description="SQL database access",
        capabilities=["database_query", "database_write"],
        requires_approval=True,
        risk_notes=["SQL injection risk", "Data exposure risk"],
    ),
    # Web browsing
    "browser": ToolInfo(
        name="browser",
        tool_type="crewai",
        category=ToolCategory.WEB_BROWSER,
        risk_level=RiskLevel.MEDIUM,
        description="Web browser automation",
        capabilities=["web_browsing", "web_scraping"],
        risk_notes=["Can access arbitrary URLs", "XSS risk"],
    ),
}


class ToolsRegistry:
    """Registry for tracking tools and connectors used by agents."""

    def __init__(self):
        """Initialize the registry."""
        self._usage: Dict[str, ToolUsage] = {}
        self._custom_tools: Dict[str, ToolInfo] = {}

    def register_usage(
        self, tool_name: str, tool_type: str, agent_id: str
    ) -> None:
        """Register that an agent uses a tool.

        Args:
            tool_name: Name of the tool
            tool_type: Type of tool (framework)
            agent_id: Agent using the tool
        """
        key = f"{tool_type}/{tool_name}"
        now = datetime.now()

        if key not in self._usage:
            tool_info = self._get_tool_info(tool_name, tool_type)
            self._usage[key] = ToolUsage(
                tool=tool_info,
                first_seen=now,
            )

        self._usage[key].agent_ids.add(agent_id)
        self._usage[key].last_seen = now

    def _get_tool_info(self, tool_name: str, tool_type: str) -> ToolInfo:
        """Get tool information."""
        # Check known tools
        if tool_name in KNOWN_TOOLS:
            return KNOWN_TOOLS[tool_name]

        # Check custom tools
        key = f"{tool_type}/{tool_name}"
        if key in self._custom_tools:
            return self._custom_tools[key]

        # Create basic info for unknown tool
        return ToolInfo(
            name=tool_name,
            tool_type=tool_type,
            risk_level=self._infer_risk_level(tool_name),
        )

    def _infer_risk_level(self, tool_name: str) -> RiskLevel:
        """Infer risk level from tool name."""
        name_lower = tool_name.lower()

        critical_patterns = ["shell", "exec", "system", "bash", "cmd", "terminal"]
        high_patterns = ["write", "delete", "sql", "database", "http", "request"]
        medium_patterns = ["read", "file", "browser", "web", "search"]

        if any(p in name_lower for p in critical_patterns):
            return RiskLevel.CRITICAL
        if any(p in name_lower for p in high_patterns):
            return RiskLevel.HIGH
        if any(p in name_lower for p in medium_patterns):
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    def add_custom_tool(self, tool: ToolInfo) -> None:
        """Add a custom tool definition.

        Args:
            tool: Tool information
        """
        key = f"{tool.tool_type}/{tool.name}"
        self._custom_tools[key] = tool

    def get_tool(self, tool_name: str, tool_type: str) -> Optional[ToolInfo]:
        """Get tool information.

        Args:
            tool_name: Name of the tool
            tool_type: Type of tool

        Returns:
            ToolInfo if found
        """
        key = f"{tool_type}/{tool_name}"

        if key in self._usage:
            return self._usage[key].tool

        return self._get_tool_info(tool_name, tool_type)

    def get_all_usage(self) -> List[ToolUsage]:
        """Get all tool usage records.

        Returns:
            List of ToolUsage objects
        """
        return list(self._usage.values())

    def get_dangerous_tools(self) -> List[ToolUsage]:
        """Get all dangerous tools in use.

        Returns:
            List of dangerous tool usage records
        """
        return [u for u in self._usage.values() if u.tool.is_dangerous]

    def get_agents_using_tool(self, tool_name: str, tool_type: str) -> Set[str]:
        """Get all agents using a specific tool.

        Args:
            tool_name: Name of the tool
            tool_type: Type of tool

        Returns:
            Set of agent IDs
        """
        key = f"{tool_type}/{tool_name}"
        if key in self._usage:
            return self._usage[key].agent_ids
        return set()

    def get_tools_by_agent(self, agent_id: str) -> List[ToolInfo]:
        """Get all tools used by an agent.

        Args:
            agent_id: Agent ID

        Returns:
            List of tools used by the agent
        """
        tools = []
        for usage in self._usage.values():
            if agent_id in usage.agent_ids:
                tools.append(usage.tool)
        return tools

    def get_tools_by_category(self, category: ToolCategory) -> List[ToolUsage]:
        """Get tools by category.

        Args:
            category: Tool category

        Returns:
            List of matching tool usage records
        """
        return [u for u in self._usage.values() if u.tool.category == category]

    def get_tools_by_risk(self, risk_level: RiskLevel) -> List[ToolUsage]:
        """Get tools by risk level.

        Args:
            risk_level: Risk level

        Returns:
            List of matching tool usage records
        """
        return [u for u in self._usage.values() if u.tool.risk_level == risk_level]

    def get_stats(self) -> Dict[str, any]:
        """Get registry statistics.

        Returns:
            Dictionary of statistics
        """
        total_tools = len(self._usage)
        dangerous_tools = len(self.get_dangerous_tools())

        by_category: Dict[str, int] = {}
        by_risk: Dict[str, int] = {}

        for usage in self._usage.values():
            cat = usage.tool.category.value
            risk = usage.tool.risk_level.value
            by_category[cat] = by_category.get(cat, 0) + 1
            by_risk[risk] = by_risk.get(risk, 0) + 1

        return {
            "total_tools": total_tools,
            "dangerous_tools": dangerous_tools,
            "by_category": by_category,
            "by_risk": by_risk,
            "most_used": sorted(
                self._usage.values(),
                key=lambda u: len(u.agent_ids),
                reverse=True,
            )[:5],
        }
