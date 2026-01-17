"""AutoGPT and CrewAI multi-agent scanner implementation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Generator, Optional, List

from secureagent.core.models.finding import Finding, FindingDomain, Location
from secureagent.core.models.severity import Severity
from secureagent.core.scanner.base import BaseScanner
from secureagent.core.scanner.registry import register_scanner
from secureagent.scanners.autogpt.models import (
    MultiAgentConfig,
    MultiAgent,
    MultiAgentTool,
    MultiAgentCrew,
    AgentFramework,
)
from secureagent.scanners.autogpt.rules import get_rule


@register_scanner
class AutoGPTScanner(BaseScanner):
    """Scanner for AutoGPT and CrewAI multi-agent systems."""

    name = "autogpt"
    description = "Scans AutoGPT and CrewAI multi-agent code for security vulnerabilities"
    version = "1.0.0"

    FILE_PATTERNS = ["**/*.py", "**/*.yaml", "**/*.yml"]

    FRAMEWORK_IMPORTS = {
        "crewai": AgentFramework.CREWAI,
        "autogpt": AgentFramework.AUTOGPT,
    }

    DANGEROUS_TOOLS = {
        "shell": ("shell access", True, False, False, False),
        "bash": ("shell access", True, False, False, False),
        "terminal": ("shell access", True, False, False, False),
        "execute_shell": ("shell access", True, False, False, False),
        "file_write": ("file write", False, True, False, False),
        "file_read": ("file read", False, True, False, False),
        "code_interpreter": ("code execution", False, False, False, True),
        "python_repl": ("code execution", False, False, False, True),
        "browser": ("web access", False, False, True, False),
        "web_search": ("web access", False, False, True, False),
        "requests": ("network access", False, False, True, False),
        "http": ("network access", False, False, True, False),
    }

    def discover_targets(self) -> Generator[Path, None, None]:
        """Discover files that may contain multi-agent code."""
        if self.path.is_file():
            yield self.path
            return

        for pattern in self.FILE_PATTERNS:
            for file_path in self.path.glob(pattern):
                if file_path.is_file() and self._has_framework_imports(file_path):
                    yield file_path

    def _has_framework_imports(self, file_path: Path) -> bool:
        """Check if file has multi-agent framework imports."""
        try:
            content = file_path.read_text()
            return any(imp in content.lower() for imp in self.FRAMEWORK_IMPORTS.keys())
        except Exception:
            return False

    def scan(self) -> List[Finding]:
        """Execute the multi-agent security scan."""
        self.findings = []

        for file_path in self.discover_targets():
            config = self._analyze_file(file_path)
            if config and not config.has_errors:
                self._scan_config(config)

        return self.findings

    def _analyze_file(self, file_path: Path) -> Optional[MultiAgentConfig]:
        """Analyze a file for multi-agent patterns."""
        try:
            content = file_path.read_text()
            config = MultiAgentConfig(
                file_path=str(file_path),
                raw_content=content,
            )

            # Detect framework
            for framework_name, framework_enum in self.FRAMEWORK_IMPORTS.items():
                if framework_name in content.lower():
                    config.framework = framework_enum
                    break

            # Analyze based on framework
            if config.framework == AgentFramework.CREWAI:
                self._analyze_crewai(content, config)
            elif config.framework == AgentFramework.AUTOGPT:
                self._analyze_autogpt(content, config)

            # Common analysis
            self._analyze_common_patterns(content, config)

            return config

        except Exception as e:
            return MultiAgentConfig(
                file_path=str(file_path),
                parse_errors=[f"Error reading file: {e}"],
            )

    def _analyze_crewai(self, content: str, config: MultiAgentConfig) -> None:
        """Analyze CrewAI-specific patterns."""
        # Find Agent definitions
        agent_pattern = r'Agent\s*\('
        for match in re.finditer(agent_pattern, content):
            agent = self._extract_crewai_agent(content, match.start())
            if agent:
                agent.framework = AgentFramework.CREWAI
                config.agents.append(agent)

        # Find Crew definitions
        crew_pattern = r'Crew\s*\('
        for match in re.finditer(crew_pattern, content):
            crew = self._extract_crewai_crew(content, match.start())
            if crew:
                config.crews.append(crew)

    def _extract_crewai_agent(self, content: str, start_pos: int) -> Optional[MultiAgent]:
        """Extract CrewAI agent configuration."""
        end_pos = self._find_matching_paren(content, start_pos)
        if end_pos == -1:
            end_pos = min(start_pos + 1000, len(content))

        chunk = content[start_pos:end_pos]
        agent = MultiAgent(name="", role="")

        # Extract role
        role_match = re.search(r'role\s*=\s*["\']([^"\']+)["\']', chunk)
        if role_match:
            agent.role = role_match.group(1)
            agent.name = role_match.group(1)

        # Extract goal
        goal_match = re.search(r'goal\s*=\s*["\']([^"\']+)["\']', chunk)
        if goal_match:
            agent.goal = goal_match.group(1)

        # Check allow_delegation
        if "allow_delegation=True" in chunk or "allow_delegation = True" in chunk:
            agent.allow_delegation = True

        # Check verbose
        if "verbose=True" in chunk or "verbose = True" in chunk:
            agent.verbose = True

        # Check memory
        if "memory=True" in chunk or "memory = True" in chunk:
            agent.memory = True

        # Extract max_iterations
        iter_match = re.search(r'max_iter\s*=\s*(\d+)', chunk)
        if iter_match:
            agent.max_iterations = int(iter_match.group(1))

        # Extract tools
        tools_match = re.search(r'tools\s*=\s*\[([^\]]*)\]', chunk)
        if tools_match:
            tools_str = tools_match.group(1)
            for tool_name, (risk_type, shell, file_acc, net, code) in self.DANGEROUS_TOOLS.items():
                if tool_name.lower() in tools_str.lower():
                    tool = MultiAgentTool(
                        name=tool_name,
                        tool_type=tool_name,
                        is_dangerous=True,
                        has_shell_access=shell,
                        has_file_access=file_acc,
                        has_network_access=net,
                        has_code_execution=code,
                    )
                    agent.tools.append(tool)

        return agent if agent.role else None

    def _extract_crewai_crew(self, content: str, start_pos: int) -> Optional[MultiAgentCrew]:
        """Extract CrewAI crew configuration."""
        end_pos = self._find_matching_paren(content, start_pos)
        if end_pos == -1:
            end_pos = min(start_pos + 1000, len(content))

        chunk = content[start_pos:end_pos]
        crew = MultiAgentCrew()

        # Check process type
        if "hierarchical" in chunk.lower():
            crew.process = "hierarchical"

        # Check verbose
        if "verbose=True" in chunk or "verbose = True" in chunk:
            crew.verbose = True

        # Check memory
        if "memory=True" in chunk or "memory = True" in chunk:
            crew.memory = True

        return crew

    def _analyze_autogpt(self, content: str, config: MultiAgentConfig) -> None:
        """Analyze AutoGPT-specific patterns."""
        # AutoGPT typically uses YAML configs
        if ".yaml" in config.file_path or ".yml" in config.file_path:
            self._analyze_autogpt_yaml(content, config)
        else:
            # Python-based AutoGPT configuration
            self._analyze_autogpt_python(content, config)

    def _analyze_autogpt_yaml(self, content: str, config: MultiAgentConfig) -> None:
        """Analyze AutoGPT YAML configuration."""
        # Look for agent definitions
        if "ai_goals:" in content or "ai_role:" in content:
            agent = MultiAgent(name="autogpt_agent", role="autonomous")
            agent.framework = AgentFramework.AUTOGPT

            # Check for dangerous configurations
            if "execute_local_commands" in content:
                tool = MultiAgentTool(
                    name="execute_local_commands",
                    tool_type="shell",
                    is_dangerous=True,
                    has_shell_access=True,
                )
                agent.tools.append(tool)

            config.agents.append(agent)

    def _analyze_autogpt_python(self, content: str, config: MultiAgentConfig) -> None:
        """Analyze AutoGPT Python code."""
        # Similar to CrewAI but with AutoGPT patterns
        pass

    def _analyze_common_patterns(self, content: str, config: MultiAgentConfig) -> None:
        """Analyze patterns common to all frameworks."""
        # Check for hardcoded API keys
        api_key_patterns = [
            (r'openai_api_key\s*=\s*["\']([^"\']+)["\']', "OpenAI API key"),
            (r'api_key\s*=\s*["\']sk-[^"\']+["\']', "OpenAI API key"),
            (r'["\']sk-[a-zA-Z0-9]{20,}["\']', "OpenAI API key"),
            (r'anthropic_api_key\s*=\s*["\']([^"\']+)["\']', "Anthropic API key"),
        ]

        for pattern, key_type in api_key_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if not str(match).startswith("os.") and not str(match).startswith("${"):
                    config.api_keys_found.append(key_type)

    def _find_matching_paren(self, content: str, start: int) -> int:
        """Find matching closing parenthesis."""
        paren_count = 0
        in_string = False
        string_char = None

        for i, char in enumerate(content[start:], start):
            if char in '"\'':
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False
            elif not in_string:
                if char == '(':
                    paren_count += 1
                elif char == ')':
                    paren_count -= 1
                    if paren_count == 0:
                        return i

        return -1

    def _scan_config(self, config: MultiAgentConfig) -> None:
        """Scan analyzed configuration for vulnerabilities."""
        self._check_hardcoded_keys(config)
        self._check_agent_autonomy(config)
        self._check_dangerous_tools(config)
        self._check_inter_agent_trust(config)
        self._check_memory_limits(config)
        self._check_delegation(config)
        self._check_web_access(config)
        self._check_verbose_mode(config)
        self._check_iteration_limits(config)

    def _check_hardcoded_keys(self, config: MultiAgentConfig) -> None:
        """Check for hardcoded API keys (AG-001)."""
        rule = get_rule("AG-001")

        patterns = [
            (r'api_key\s*=\s*["\'](?!os\.)[^"\']{20,}["\']', "api_key assignment"),
            (r'["\']sk-[a-zA-Z0-9]{20,}["\']', "OpenAI API key"),
        ]

        for pattern, desc in patterns:
            for match in re.finditer(pattern, config.raw_content):
                line_num = config.raw_content[:match.start()].count('\n') + 1

                self.findings.append(
                    Finding(
                        rule_id="AG-001",
                        title=rule["title"],
                        description=f"Found {desc}. {rule['description']}.",
                        severity=rule["severity"],
                        domain=FindingDomain.AUTOGPT,
                        location=Location(
                            file_path=config.file_path,
                            line_number=line_num,
                            snippet="[API key redacted]",
                        ),
                        remediation=rule["remediation"],
                        references=rule["references"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    )
                )

    def _check_agent_autonomy(self, config: MultiAgentConfig) -> None:
        """Check for unrestricted agent autonomy (AG-002)."""
        rule = get_rule("AG-002")

        # Check for hierarchical crews without human oversight
        for crew in config.crews:
            if crew.process == "hierarchical":
                # Check if human-in-loop is mentioned
                has_hitl = "human" in config.raw_content.lower() or "approval" in config.raw_content.lower()

                if not has_hitl:
                    line_num = None
                    idx = config.raw_content.find("hierarchical")
                    if idx != -1:
                        line_num = config.raw_content[:idx].count('\n') + 1

                    self.findings.append(
                        Finding(
                            rule_id="AG-002",
                            title=rule["title"],
                            description=f"Hierarchical crew without apparent human oversight. {rule['description']}.",
                            severity=rule["severity"],
                            domain=FindingDomain.AUTOGPT,
                            location=Location(
                                file_path=config.file_path,
                                line_number=line_num,
                                snippet="process='hierarchical'",
                            ),
                            remediation=rule["remediation"],
                            references=rule["references"],
                            cwe_id=rule["cwe_id"],
                            owasp_id=rule["owasp_id"],
                        )
                    )

    def _check_dangerous_tools(self, config: MultiAgentConfig) -> None:
        """Check for dangerous tool access (AG-003)."""
        rule = get_rule("AG-003")

        for agent in config.agents:
            for tool in agent.tools:
                if tool.is_dangerous:
                    capabilities = []
                    if tool.has_shell_access:
                        capabilities.append("shell execution")
                    if tool.has_file_access:
                        capabilities.append("file system access")
                    if tool.has_network_access:
                        capabilities.append("network access")
                    if tool.has_code_execution:
                        capabilities.append("code execution")

                    line_num = None
                    idx = config.raw_content.lower().find(tool.name.lower())
                    if idx != -1:
                        line_num = config.raw_content[:idx].count('\n') + 1

                    self.findings.append(
                        Finding(
                            rule_id="AG-003",
                            title=rule["title"],
                            description=f"Agent '{agent.name}' has tool '{tool.name}' with "
                            f"{', '.join(capabilities)}. {rule['description']}.",
                            severity=rule["severity"],
                            domain=FindingDomain.AUTOGPT,
                            location=Location(
                                file_path=config.file_path,
                                line_number=line_num,
                                snippet=tool.name,
                            ),
                            remediation=rule["remediation"],
                            references=rule["references"],
                            cwe_id=rule["cwe_id"],
                            owasp_id=rule["owasp_id"],
                        )
                    )

    def _check_inter_agent_trust(self, config: MultiAgentConfig) -> None:
        """Check for inter-agent trust issues (AG-004)."""
        rule = get_rule("AG-004")

        # If multiple agents and delegation enabled
        if len(config.agents) > 1:
            delegates = [a for a in config.agents if a.allow_delegation]
            if delegates:
                # Check for validation
                has_validation = "validate" in config.raw_content.lower()

                if not has_validation:
                    self.findings.append(
                        Finding(
                            rule_id="AG-004",
                            title=rule["title"],
                            description=f"{len(delegates)} agents with delegation enabled "
                            f"without apparent message validation. {rule['description']}.",
                            severity=rule["severity"],
                            domain=FindingDomain.AUTOGPT,
                            location=Location(
                                file_path=config.file_path,
                                snippet=f"Agents: {', '.join(a.name for a in delegates)}",
                            ),
                            remediation=rule["remediation"],
                            references=rule["references"],
                            cwe_id=rule["cwe_id"],
                            owasp_id=rule["owasp_id"],
                        )
                    )

    def _check_memory_limits(self, config: MultiAgentConfig) -> None:
        """Check for memory without limits (AG-005)."""
        rule = get_rule("AG-005")

        for agent in config.agents:
            if agent.memory:
                # Check if memory limits are configured
                has_limits = "max_memory" in config.raw_content.lower() or "memory_limit" in config.raw_content.lower()

                if not has_limits:
                    line_num = None
                    idx = config.raw_content.find("memory=True")
                    if idx == -1:
                        idx = config.raw_content.find("memory = True")
                    if idx != -1:
                        line_num = config.raw_content[:idx].count('\n') + 1

                    self.findings.append(
                        Finding(
                            rule_id="AG-005",
                            title=rule["title"],
                            description=f"Agent '{agent.name}' has memory enabled without limits. "
                            f"{rule['description']}.",
                            severity=rule["severity"],
                            domain=FindingDomain.AUTOGPT,
                            location=Location(
                                file_path=config.file_path,
                                line_number=line_num,
                                snippet="memory=True",
                            ),
                            remediation=rule["remediation"],
                            references=rule["references"],
                            cwe_id=rule["cwe_id"],
                            owasp_id=rule["owasp_id"],
                        )
                    )

    def _check_delegation(self, config: MultiAgentConfig) -> None:
        """Check for unconstrained delegation (AG-006)."""
        rule = get_rule("AG-006")

        for agent in config.agents:
            if agent.allow_delegation:
                line_num = None
                idx = config.raw_content.find("allow_delegation=True")
                if idx == -1:
                    idx = config.raw_content.find("allow_delegation = True")
                if idx != -1:
                    line_num = config.raw_content[:idx].count('\n') + 1

                self.findings.append(
                    Finding(
                        rule_id="AG-006",
                        title=rule["title"],
                        description=f"Agent '{agent.name}' can delegate tasks without restrictions. "
                        f"{rule['description']}.",
                        severity=rule["severity"],
                        domain=FindingDomain.AUTOGPT,
                        location=Location(
                            file_path=config.file_path,
                            line_number=line_num,
                            snippet="allow_delegation=True",
                        ),
                        remediation=rule["remediation"],
                        references=rule["references"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    )
                )

    def _check_web_access(self, config: MultiAgentConfig) -> None:
        """Check for web access without filtering (AG-007)."""
        rule = get_rule("AG-007")

        web_tools = ["browser", "web_search", "scrape", "http", "requests"]

        for agent in config.agents:
            for tool in agent.tools:
                if tool.has_network_access or any(w in tool.name.lower() for w in web_tools):
                    # Check for URL filtering
                    has_filtering = "allowlist" in config.raw_content.lower() or "whitelist" in config.raw_content.lower()

                    if not has_filtering:
                        line_num = None
                        idx = config.raw_content.lower().find(tool.name.lower())
                        if idx != -1:
                            line_num = config.raw_content[:idx].count('\n') + 1

                        self.findings.append(
                            Finding(
                                rule_id="AG-007",
                                title=rule["title"],
                                description=f"Agent '{agent.name}' has web access via '{tool.name}' "
                                f"without URL filtering. {rule['description']}.",
                                severity=rule["severity"],
                                domain=FindingDomain.AUTOGPT,
                                location=Location(
                                    file_path=config.file_path,
                                    line_number=line_num,
                                    snippet=tool.name,
                                ),
                                remediation=rule["remediation"],
                                references=rule["references"],
                                cwe_id=rule["cwe_id"],
                                owasp_id=rule["owasp_id"],
                            )
                        )

    def _check_verbose_mode(self, config: MultiAgentConfig) -> None:
        """Check for verbose logging (AG-008)."""
        rule = get_rule("AG-008")

        for match in re.finditer(r'verbose\s*=\s*True', config.raw_content):
            line_num = config.raw_content[:match.start()].count('\n') + 1

            self.findings.append(
                Finding(
                    rule_id="AG-008",
                    title=rule["title"],
                    description=f"Verbose mode enabled. {rule['description']}.",
                    severity=rule["severity"],
                    domain=FindingDomain.AUTOGPT,
                    location=Location(
                        file_path=config.file_path,
                        line_number=line_num,
                        snippet="verbose=True",
                    ),
                    remediation=rule["remediation"],
                    references=rule["references"],
                    cwe_id=rule["cwe_id"],
                    owasp_id=rule["owasp_id"],
                )
            )

    def _check_iteration_limits(self, config: MultiAgentConfig) -> None:
        """Check for agents without iteration limits (AG-009)."""
        rule = get_rule("AG-009")

        for agent in config.agents:
            if not agent.has_iteration_limits:
                line_num = None
                idx = config.raw_content.find(agent.role if agent.role else agent.name)
                if idx != -1:
                    line_num = config.raw_content[:idx].count('\n') + 1

                self.findings.append(
                    Finding(
                        rule_id="AG-009",
                        title=rule["title"],
                        description=f"Agent '{agent.name}' has no iteration limits set. "
                        f"{rule['description']}.",
                        severity=rule["severity"],
                        domain=FindingDomain.AUTOGPT,
                        location=Location(
                            file_path=config.file_path,
                            line_number=line_num,
                            snippet=agent.name or agent.role,
                        ),
                        remediation=rule["remediation"],
                        references=rule["references"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    )
                )
