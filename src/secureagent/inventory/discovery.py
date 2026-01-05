"""Agent auto-discovery module."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Generator, List, Optional, Dict, Any

from secureagent.core.models.agent import (
    AgentInventoryItem,
    AgentFramework,
    ToolReference,
    ModelReference,
    DataSource,
    Permission,
)


@dataclass
class DiscoveryResult:
    """Result of agent discovery."""

    agents: List[AgentInventoryItem] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scanned_files: int = 0
    discovery_time: float = 0.0

    @property
    def agent_count(self) -> int:
        """Get number of discovered agents."""
        return len(self.agents)


class AgentDiscovery:
    """Discovers AI agents across a codebase."""

    # File patterns for different frameworks
    FRAMEWORK_PATTERNS = {
        AgentFramework.MCP: [
            "**/mcp.json",
            "**/.mcp.json",
            "**/mcp_config.json",
            "**/claude_desktop_config.json",
        ],
        AgentFramework.LANGCHAIN: [
            "**/*.py",
        ],
        AgentFramework.OPENAI_ASSISTANTS: [
            "**/*.py",
        ],
        AgentFramework.CREWAI: [
            "**/*.py",
            "**/*.yaml",
            "**/*.yml",
        ],
        AgentFramework.AUTOGPT: [
            "**/*.yaml",
            "**/*.yml",
            "**/*.json",
        ],
    }

    # Import patterns to identify frameworks in Python files
    FRAMEWORK_IMPORTS = {
        AgentFramework.LANGCHAIN: ["langchain", "langchain_core", "langchain_community"],
        AgentFramework.OPENAI_ASSISTANTS: ["openai"],
        AgentFramework.CREWAI: ["crewai"],
        AgentFramework.AUTOGPT: ["autogpt"],
    }

    def __init__(self, path: Path):
        """Initialize discovery.

        Args:
            path: Root path to scan
        """
        self.path = Path(path)
        self.discovered_agents: List[AgentInventoryItem] = []

    def discover(self, frameworks: Optional[List[AgentFramework]] = None) -> DiscoveryResult:
        """Discover agents in the codebase.

        Args:
            frameworks: Optional list of frameworks to scan for. If None, scans all.

        Returns:
            DiscoveryResult with discovered agents
        """
        import time

        start_time = time.time()
        result = DiscoveryResult()

        if frameworks is None:
            frameworks = list(AgentFramework)

        for framework in frameworks:
            try:
                agents = self._discover_framework(framework)
                result.agents.extend(agents)
            except Exception as e:
                result.errors.append(f"Error discovering {framework.value}: {e}")

        result.discovery_time = time.time() - start_time
        self.discovered_agents = result.agents
        return result

    def _discover_framework(self, framework: AgentFramework) -> List[AgentInventoryItem]:
        """Discover agents for a specific framework."""
        agents = []

        if framework == AgentFramework.MCP:
            agents.extend(self._discover_mcp_agents())
        elif framework == AgentFramework.LANGCHAIN:
            agents.extend(self._discover_langchain_agents())
        elif framework == AgentFramework.OPENAI_ASSISTANTS:
            agents.extend(self._discover_openai_agents())
        elif framework == AgentFramework.CREWAI:
            agents.extend(self._discover_crewai_agents())
        elif framework == AgentFramework.AUTOGPT:
            agents.extend(self._discover_autogpt_agents())

        return agents

    def _discover_mcp_agents(self) -> List[AgentInventoryItem]:
        """Discover MCP server agents."""
        agents = []

        for pattern in self.FRAMEWORK_PATTERNS[AgentFramework.MCP]:
            for config_file in self.path.glob(pattern):
                try:
                    content = config_file.read_text()
                    data = json.loads(content)

                    servers = data.get("mcpServers", data.get("servers", {}))
                    for name, server_config in servers.items():
                        agent = self._create_mcp_agent(name, server_config, config_file)
                        agents.append(agent)
                except Exception:
                    continue

        return agents

    def _create_mcp_agent(
        self, name: str, config: Dict[str, Any], config_path: Path
    ) -> AgentInventoryItem:
        """Create agent inventory item from MCP config."""
        tools = []
        permissions = []

        # Extract tools from raw config
        if "tools" in config:
            for tool_name in config.get("tools", []):
                tools.append(
                    ToolReference(
                        name=tool_name,
                        tool_type="mcp_tool",
                    )
                )

        # Check for dangerous permissions
        if config.get("command"):
            permissions.append(
                Permission(
                    action="execute_command",
                    resource=config.get("command"),
                    granted=True,
                )
            )

        return AgentInventoryItem(
            id=f"mcp-{name}",
            name=name,
            framework=AgentFramework.MCP,
            tools=tools,
            permissions=permissions,
            discovered_at=datetime.now(),
            config_path=str(config_path),
        )

    def _discover_langchain_agents(self) -> List[AgentInventoryItem]:
        """Discover LangChain agents."""
        agents = []

        for py_file in self._find_framework_files(AgentFramework.LANGCHAIN):
            try:
                content = py_file.read_text()
                found_agents = self._parse_langchain_agents(content, py_file)
                agents.extend(found_agents)
            except Exception:
                continue

        return agents

    def _parse_langchain_agents(
        self, content: str, file_path: Path
    ) -> List[AgentInventoryItem]:
        """Parse LangChain agent definitions from code."""
        agents = []

        # Look for agent initialization patterns
        agent_patterns = [
            r'(?:create_react_agent|initialize_agent|AgentExecutor)\s*\(',
            r'Agent\s*\(',
        ]

        for pattern in agent_patterns:
            for match in re.finditer(pattern, content):
                # Extract agent info from context
                agent = AgentInventoryItem(
                    id=f"langchain-{file_path.stem}-{match.start()}",
                    name=f"LangChain Agent ({file_path.stem})",
                    framework=AgentFramework.LANGCHAIN,
                    discovered_at=datetime.now(),
                    config_path=str(file_path),
                )

                # Try to extract model info
                model_match = re.search(
                    r'(?:ChatOpenAI|ChatAnthropic|OpenAI)\s*\([^)]*model[_name]*\s*=\s*["\']([^"\']+)["\']',
                    content,
                )
                if model_match:
                    agent.models.append(
                        ModelReference(
                            provider="openai" if "OpenAI" in model_match.group(0) else "anthropic",
                            model_id=model_match.group(1),
                        )
                    )

                # Extract tools
                tools_match = re.search(r'tools\s*=\s*\[([^\]]+)\]', content)
                if tools_match:
                    tool_names = re.findall(r'\b(\w+Tool)\b', tools_match.group(1))
                    for tool_name in tool_names:
                        agent.tools.append(
                            ToolReference(name=tool_name, tool_type="langchain_tool")
                        )

                agents.append(agent)
                break  # One agent per file for simplicity

        return agents

    def _discover_openai_agents(self) -> List[AgentInventoryItem]:
        """Discover OpenAI Assistants."""
        agents = []

        for py_file in self._find_framework_files(AgentFramework.OPENAI_ASSISTANTS):
            try:
                content = py_file.read_text()
                if "assistants.create" in content or "beta.assistants" in content:
                    found_agents = self._parse_openai_assistants(content, py_file)
                    agents.extend(found_agents)
            except Exception:
                continue

        return agents

    def _parse_openai_assistants(
        self, content: str, file_path: Path
    ) -> List[AgentInventoryItem]:
        """Parse OpenAI Assistant definitions."""
        agents = []

        # Look for assistant creation
        for match in re.finditer(r'assistants\.create\s*\(', content):
            agent = AgentInventoryItem(
                id=f"openai-{file_path.stem}-{match.start()}",
                name=f"OpenAI Assistant ({file_path.stem})",
                framework=AgentFramework.OPENAI_ASSISTANTS,
                discovered_at=datetime.now(),
                config_path=str(file_path),
            )

            # Extract model
            model_match = re.search(
                r'model\s*=\s*["\']([^"\']+)["\']', content[match.start() : match.start() + 500]
            )
            if model_match:
                agent.models.append(
                    ModelReference(provider="openai", model_id=model_match.group(1))
                )

            # Check for tools
            if "code_interpreter" in content:
                agent.tools.append(
                    ToolReference(name="code_interpreter", tool_type="openai_tool")
                )
            if "file_search" in content or "retrieval" in content:
                agent.tools.append(
                    ToolReference(name="file_search", tool_type="openai_tool")
                )

            agents.append(agent)

        return agents

    def _discover_crewai_agents(self) -> List[AgentInventoryItem]:
        """Discover CrewAI agents."""
        agents = []

        for py_file in self._find_framework_files(AgentFramework.CREWAI):
            try:
                content = py_file.read_text()
                if "crewai" in content.lower():
                    found_agents = self._parse_crewai_agents(content, py_file)
                    agents.extend(found_agents)
            except Exception:
                continue

        return agents

    def _parse_crewai_agents(
        self, content: str, file_path: Path
    ) -> List[AgentInventoryItem]:
        """Parse CrewAI agent definitions."""
        agents = []

        # Look for Agent definitions
        for match in re.finditer(r'Agent\s*\(\s*role\s*=\s*["\']([^"\']+)["\']', content):
            role = match.group(1)

            agent = AgentInventoryItem(
                id=f"crewai-{file_path.stem}-{role.lower().replace(' ', '-')}",
                name=role,
                framework=AgentFramework.CREWAI,
                discovered_at=datetime.now(),
                config_path=str(file_path),
            )

            # Extract tools from nearby context
            context_start = max(0, match.start() - 100)
            context_end = min(len(content), match.end() + 500)
            context = content[context_start:context_end]

            tools_match = re.search(r'tools\s*=\s*\[([^\]]+)\]', context)
            if tools_match:
                for tool in re.findall(r'\b(\w+)\b', tools_match.group(1)):
                    if tool[0].isupper():  # Likely a tool class
                        agent.tools.append(
                            ToolReference(name=tool, tool_type="crewai_tool")
                        )

            agents.append(agent)

        return agents

    def _discover_autogpt_agents(self) -> List[AgentInventoryItem]:
        """Discover AutoGPT agents."""
        agents = []

        for pattern in self.FRAMEWORK_PATTERNS[AgentFramework.AUTOGPT]:
            for config_file in self.path.glob(pattern):
                try:
                    content = config_file.read_text()
                    if "ai_goals" in content or "ai_role" in content:
                        agent = AgentInventoryItem(
                            id=f"autogpt-{config_file.stem}",
                            name=f"AutoGPT Agent ({config_file.stem})",
                            framework=AgentFramework.AUTOGPT,
                            discovered_at=datetime.now(),
                            config_path=str(config_file),
                        )
                        agents.append(agent)
                except Exception:
                    continue

        return agents

    def _find_framework_files(
        self, framework: AgentFramework
    ) -> Generator[Path, None, None]:
        """Find files containing framework imports."""
        imports = self.FRAMEWORK_IMPORTS.get(framework, [])

        for pattern in self.FRAMEWORK_PATTERNS.get(framework, []):
            for file_path in self.path.glob(pattern):
                try:
                    if file_path.suffix == ".py":
                        content = file_path.read_text()
                        if any(imp in content for imp in imports):
                            yield file_path
                    else:
                        yield file_path
                except Exception:
                    continue
