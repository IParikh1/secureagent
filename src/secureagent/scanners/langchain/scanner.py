"""LangChain agent scanner implementation."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Generator, Optional, List

from secureagent.core.models.finding import Finding, FindingDomain, Location
from secureagent.core.models.severity import Severity
from secureagent.core.scanner.base import BaseScanner
from secureagent.core.scanner.registry import register_scanner
from secureagent.scanners.langchain.models import LangChainConfig, LangChainAgent, LangChainTool
from secureagent.scanners.langchain.rules import get_rule


@register_scanner
class LangChainScanner(BaseScanner):
    """Scanner for LangChain agent code and configurations."""

    name = "langchain"
    description = "Scans LangChain agent code for security vulnerabilities"
    version = "1.0.0"

    # Patterns for finding LangChain files
    FILE_PATTERNS = [
        "**/*.py",
    ]

    # LangChain imports to look for
    LANGCHAIN_IMPORTS = [
        "langchain",
        "langchain_core",
        "langchain_community",
        "langchain_openai",
        "langchain_anthropic",
    ]

    # Dangerous tools to flag
    DANGEROUS_TOOLS = {
        "ShellTool": ("shell access", True, False, False),
        "BashProcess": ("shell access", True, False, False),
        "PythonREPL": ("code execution", False, False, False),
        "PythonREPLTool": ("code execution", False, False, False),
        "Terminal": ("terminal access", True, False, False),
        "FileManagementToolkit": ("file access", False, True, False),
        "WriteFileTool": ("file write", False, True, False),
        "ReadFileTool": ("file read", False, True, False),
        "DeleteFileTool": ("file delete", False, True, False),
        "RequestsGetTool": ("network access", False, False, True),
        "RequestsPostTool": ("network access", False, False, True),
        "SQLDatabaseToolkit": ("database access", False, False, False),
    }

    def discover_targets(self) -> Generator[Path, None, None]:
        """Discover Python files that may contain LangChain code.

        Yields:
            Paths to Python files with LangChain imports
        """
        if self.path.is_file():
            if self.path.suffix == ".py":
                yield self.path
            return

        for pattern in self.FILE_PATTERNS:
            for py_file in self.path.glob(pattern):
                if py_file.is_file() and self._has_langchain_imports(py_file):
                    yield py_file

    def _has_langchain_imports(self, file_path: Path) -> bool:
        """Check if a file has LangChain imports."""
        try:
            content = file_path.read_text()
            return any(imp in content for imp in self.LANGCHAIN_IMPORTS)
        except Exception:
            return False

    def scan(self) -> List[Finding]:
        """Execute the LangChain security scan.

        Returns:
            List of security findings
        """
        self.findings = []

        for py_file in self.discover_targets():
            config = self._analyze_file(py_file)
            if config and not config.has_errors:
                self._scan_config(config)

        return self.findings

    def _analyze_file(self, file_path: Path) -> Optional[LangChainConfig]:
        """Analyze a Python file for LangChain patterns.

        Args:
            file_path: Path to the Python file

        Returns:
            LangChainConfig with analysis results
        """
        try:
            content = file_path.read_text()
            config = LangChainConfig(
                file_path=str(file_path),
                raw_content=content,
            )

            # Parse AST
            try:
                tree = ast.parse(content)
                self._analyze_ast(tree, config)
            except SyntaxError as e:
                config.parse_errors.append(f"Syntax error: {e}")

            # Also do regex-based analysis for patterns AST might miss
            self._analyze_patterns(content, config)

            return config

        except Exception as e:
            return LangChainConfig(
                file_path=str(file_path),
                parse_errors=[f"Error reading file: {e}"],
            )

    def _analyze_ast(self, tree: ast.AST, config: LangChainConfig) -> None:
        """Analyze AST for LangChain patterns."""
        for node in ast.walk(tree):
            # Check imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    config.imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    config.imports.append(node.module)

            # Check for agent initialization
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name and "agent" in func_name.lower():
                    agent = self._extract_agent_config(node, config.raw_content)
                    if agent:
                        config.agents.append(agent)

                # Check for dangerous tool instantiation
                if func_name in self.DANGEROUS_TOOLS:
                    risk_type, shell, file_access, network = self.DANGEROUS_TOOLS[func_name]
                    tool = LangChainTool(
                        name=func_name,
                        tool_type=func_name,
                        is_dangerous=True,
                        has_shell_access=shell,
                        has_file_access=file_access,
                        has_network_access=network,
                    )
                    config.tools.append(tool)

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Get the name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def _extract_agent_config(self, node: ast.Call, content: str) -> Optional[LangChainAgent]:
        """Extract agent configuration from AST node."""
        func_name = self._get_call_name(node)
        if not func_name:
            return None

        agent = LangChainAgent(
            name=func_name,
            agent_type=func_name,
        )

        # Extract keyword arguments
        for kw in node.keywords:
            if kw.arg == "max_iterations" and isinstance(kw.value, ast.Constant):
                agent.max_iterations = kw.value.value
            elif kw.arg == "max_execution_time" and isinstance(kw.value, ast.Constant):
                agent.max_execution_time = kw.value.value
            elif kw.arg == "verbose" and isinstance(kw.value, ast.Constant):
                agent.verbose = kw.value.value

        return agent

    def _analyze_patterns(self, content: str, config: LangChainConfig) -> None:
        """Analyze content with regex patterns."""
        # Check for hardcoded API keys
        api_key_patterns = [
            (r'openai_api_key\s*=\s*["\']([^"\']+)["\']', "OpenAI API key"),
            (r'anthropic_api_key\s*=\s*["\']([^"\']+)["\']', "Anthropic API key"),
            (r'api_key\s*=\s*["\']sk-[^"\']+["\']', "API key"),
            (r'OPENAI_API_KEY\s*=\s*["\']([^"\']+)["\']', "OpenAI API key"),
        ]

        for pattern, key_type in api_key_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if not match.startswith("${") and not match.startswith("os."):
                    config.api_keys_found.append(key_type)

    def _scan_config(self, config: LangChainConfig) -> None:
        """Scan analyzed configuration for vulnerabilities."""
        self._check_hardcoded_keys(config)
        self._check_dangerous_tools(config)
        self._check_prompt_injection(config)
        self._check_memory_config(config)
        self._check_agent_limits(config)
        self._check_python_execution(config)
        self._check_sql_injection(config)
        self._check_verbose_mode(config)

    def _check_hardcoded_keys(self, config: LangChainConfig) -> None:
        """Check for hardcoded API keys (LC-001)."""
        rule = get_rule("LC-001")

        patterns = [
            (r'openai_api_key\s*=\s*["\'](?!os\.)[^"\']{20,}["\']', "OpenAI API key"),
            (r'anthropic_api_key\s*=\s*["\'](?!os\.)[^"\']{20,}["\']', "Anthropic API key"),
            (r'api_key\s*=\s*["\']sk-[a-zA-Z0-9]{20,}["\']', "API key"),
            (r'["\']sk-[a-zA-Z0-9]{20,}["\']', "OpenAI API key"),
            (r'["\']sk-ant-[a-zA-Z0-9\-_]{20,}["\']', "Anthropic API key"),
        ]

        lines = config.raw_content.split('\n')

        for pattern, key_type in patterns:
            for match in re.finditer(pattern, config.raw_content):
                line_num = config.raw_content[:match.start()].count('\n') + 1

                self.findings.append(
                    Finding(
                        domain=FindingDomain.LANGCHAIN,
                        rule_id="LC-001",
                        title=rule["title"],
                        description=f"Found hardcoded {key_type}. {rule['description']}.",
                        severity=rule["severity"],
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

    def _check_dangerous_tools(self, config: LangChainConfig) -> None:
        """Check for dangerous tool configurations (LC-002)."""
        rule = get_rule("LC-002")

        for tool in config.tools:
            if tool.is_dangerous:
                # Find line number
                line_num = None
                idx = config.raw_content.find(tool.name)
                if idx != -1:
                    line_num = config.raw_content[:idx].count('\n') + 1

                capabilities = []
                if tool.has_shell_access:
                    capabilities.append("shell execution")
                if tool.has_file_access:
                    capabilities.append("file system access")
                if tool.has_network_access:
                    capabilities.append("network access")

                self.findings.append(
                    Finding(
                        domain=FindingDomain.LANGCHAIN,
                        rule_id="LC-002",
                        title=rule["title"],
                        description=f"Tool '{tool.name}' has {', '.join(capabilities) or 'dangerous capabilities'}. "
                        f"{rule['description']}.",
                        severity=rule["severity"],
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

    def _check_prompt_injection(self, config: LangChainConfig) -> None:
        """Check for prompt injection vulnerabilities (LC-003)."""
        rule = get_rule("LC-003")

        # Patterns indicating unsafe prompt construction
        unsafe_patterns = [
            (r'f["\'].*\{user.*\}.*["\']', "f-string with user input"),
            (r'\.format\s*\(\s*user', ".format() with user input"),
            (r'prompt\s*\+\s*user', "string concatenation with user input"),
            (r'template\s*%\s*user', "% formatting with user input"),
        ]

        for pattern, pattern_desc in unsafe_patterns:
            for match in re.finditer(pattern, config.raw_content, re.IGNORECASE):
                line_num = config.raw_content[:match.start()].count('\n') + 1

                self.findings.append(
                    Finding(
                        domain=FindingDomain.LANGCHAIN,
                        rule_id="LC-003",
                        title=rule["title"],
                        description=f"Detected {pattern_desc} in prompt construction. {rule['description']}.",
                        severity=rule["severity"],
                        location=Location(
                            file_path=config.file_path,
                            line_number=line_num,
                            snippet=match.group(0)[:50],
                        ),
                        remediation=rule["remediation"],
                        references=rule["references"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    )
                )

    def _check_memory_config(self, config: LangChainConfig) -> None:
        """Check for insecure memory configuration (LC-004)."""
        rule = get_rule("LC-004")

        # Check for memory without encryption
        memory_patterns = [
            (r'ConversationBufferMemory\s*\(', "ConversationBufferMemory"),
            (r'ConversationSummaryMemory\s*\(', "ConversationSummaryMemory"),
            (r'ChatMessageHistory\s*\(', "ChatMessageHistory"),
        ]

        for pattern, memory_type in memory_patterns:
            for match in re.finditer(pattern, config.raw_content):
                # Check if there's encryption mentioned nearby
                context_start = max(0, match.start() - 200)
                context_end = min(len(config.raw_content), match.end() + 200)
                context = config.raw_content[context_start:context_end]

                if "encrypt" not in context.lower():
                    line_num = config.raw_content[:match.start()].count('\n') + 1

                    self.findings.append(
                        Finding(
                        domain=FindingDomain.LANGCHAIN,
                        rule_id="LC-004",
                            title=rule["title"],
                            description=f"{memory_type} used without apparent encryption. {rule['description']}.",
                            severity=rule["severity"],
                            location=Location(
                                file_path=config.file_path,
                                line_number=line_num,
                                snippet=memory_type,
                            ),
                            remediation=rule["remediation"],
                            references=rule["references"],
                            cwe_id=rule["cwe_id"],
                            owasp_id=rule["owasp_id"],
                        )
                    )

    def _check_agent_limits(self, config: LangChainConfig) -> None:
        """Check for agents without iteration limits (LC-005)."""
        rule = get_rule("LC-005")

        for agent in config.agents:
            if not agent.has_iteration_limits:
                # Find agent in source
                line_num = None
                idx = config.raw_content.find(agent.name)
                if idx != -1:
                    line_num = config.raw_content[:idx].count('\n') + 1

                self.findings.append(
                    Finding(
                        domain=FindingDomain.LANGCHAIN,
                        rule_id="LC-005",
                        title=rule["title"],
                        description=f"Agent '{agent.name}' has no max_iterations or max_execution_time set. "
                        f"{rule['description']}.",
                        severity=rule["severity"],
                        location=Location(
                            file_path=config.file_path,
                            line_number=line_num,
                            snippet=agent.name,
                        ),
                        remediation=rule["remediation"],
                        references=rule["references"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    )
                )

    def _check_python_execution(self, config: LangChainConfig) -> None:
        """Check for unsafe Python execution (LC-006)."""
        rule = get_rule("LC-006")

        dangerous_patterns = [
            (r'PythonREPL\s*\(', "PythonREPL"),
            (r'PythonREPLTool\s*\(', "PythonREPLTool"),
            (r'exec\s*\(', "exec()"),
            (r'eval\s*\(', "eval()"),
        ]

        for pattern, exec_type in dangerous_patterns:
            for match in re.finditer(pattern, config.raw_content):
                line_num = config.raw_content[:match.start()].count('\n') + 1

                self.findings.append(
                    Finding(
                        domain=FindingDomain.LANGCHAIN,
                        rule_id="LC-006",
                        title=rule["title"],
                        description=f"{exec_type} used without sandboxing. {rule['description']}.",
                        severity=rule["severity"],
                        location=Location(
                            file_path=config.file_path,
                            line_number=line_num,
                            snippet=exec_type,
                        ),
                        remediation=rule["remediation"],
                        references=rule["references"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    )
                )

    def _check_sql_injection(self, config: LangChainConfig) -> None:
        """Check for SQL injection risks (LC-007)."""
        rule = get_rule("LC-007")

        sql_patterns = [
            (r'SQLDatabase\s*\(', "SQLDatabase connection"),
            (r'create_sql_agent\s*\(', "SQL agent"),
            (r'SQLDatabaseToolkit\s*\(', "SQLDatabaseToolkit"),
        ]

        for pattern, sql_type in sql_patterns:
            for match in re.finditer(pattern, config.raw_content):
                line_num = config.raw_content[:match.start()].count('\n') + 1

                self.findings.append(
                    Finding(
                        domain=FindingDomain.LANGCHAIN,
                        rule_id="LC-007",
                        title=rule["title"],
                        description=f"{sql_type} used - ensure queries are parameterized. {rule['description']}.",
                        severity=rule["severity"],
                        location=Location(
                            file_path=config.file_path,
                            line_number=line_num,
                            snippet=sql_type,
                        ),
                        remediation=rule["remediation"],
                        references=rule["references"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    )
                )

    def _check_verbose_mode(self, config: LangChainConfig) -> None:
        """Check for verbose mode enabled (LC-008)."""
        rule = get_rule("LC-008")

        for match in re.finditer(r'verbose\s*=\s*True', config.raw_content):
            line_num = config.raw_content[:match.start()].count('\n') + 1

            self.findings.append(
                Finding(
                        domain=FindingDomain.LANGCHAIN,
                        rule_id="LC-008",
                    title=rule["title"],
                    description=f"Verbose mode enabled. {rule['description']}.",
                    severity=rule["severity"],
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
