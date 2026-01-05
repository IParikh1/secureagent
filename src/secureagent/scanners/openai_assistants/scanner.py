"""OpenAI Assistants scanner implementation."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Generator, Optional, List

from secureagent.core.models.finding import Finding, FindingDomain, Location
from secureagent.core.models.severity import Severity
from secureagent.core.scanner.base import BaseScanner
from secureagent.core.scanner.registry import register_scanner
from secureagent.scanners.openai_assistants.models import (
    OpenAIConfig,
    OpenAIAssistant,
    OpenAIFunction,
    OpenAIToolType,
)
from secureagent.scanners.openai_assistants.rules import get_rule


@register_scanner
class OpenAIAssistantsScanner(BaseScanner):
    """Scanner for OpenAI Assistants API code and configurations."""

    name = "openai_assistants"
    description = "Scans OpenAI Assistants API code for security vulnerabilities"
    version = "1.0.0"

    # Patterns for finding OpenAI files
    FILE_PATTERNS = [
        "**/*.py",
    ]

    # OpenAI imports to look for
    OPENAI_IMPORTS = [
        "openai",
        "from openai",
    ]

    # Dangerous function name patterns
    DANGEROUS_FUNCTION_PATTERNS = [
        "shell",
        "exec",
        "execute",
        "run_command",
        "system",
        "bash",
        "terminal",
        "file_write",
        "write_file",
        "delete",
        "remove",
        "send_email",
        "http_request",
        "database",
        "sql",
    ]

    def discover_targets(self) -> Generator[Path, None, None]:
        """Discover Python files that may contain OpenAI code.

        Yields:
            Paths to Python files with OpenAI imports
        """
        if self.path.is_file():
            if self.path.suffix == ".py":
                yield self.path
            return

        for pattern in self.FILE_PATTERNS:
            for py_file in self.path.glob(pattern):
                if py_file.is_file() and self._has_openai_imports(py_file):
                    yield py_file

    def _has_openai_imports(self, file_path: Path) -> bool:
        """Check if a file has OpenAI imports."""
        try:
            content = file_path.read_text()
            return any(imp in content for imp in self.OPENAI_IMPORTS)
        except Exception:
            return False

    def scan(self) -> List[Finding]:
        """Execute the OpenAI Assistants security scan.

        Returns:
            List of security findings
        """
        self.findings = []

        for py_file in self.discover_targets():
            config = self._analyze_file(py_file)
            if config and not config.has_errors:
                self._scan_config(config)

        return self.findings

    def _analyze_file(self, file_path: Path) -> Optional[OpenAIConfig]:
        """Analyze a Python file for OpenAI Assistants patterns.

        Args:
            file_path: Path to the Python file

        Returns:
            OpenAIConfig with analysis results
        """
        try:
            content = file_path.read_text()
            config = OpenAIConfig(
                file_path=str(file_path),
                raw_content=content,
            )

            # Analyze with regex patterns
            self._analyze_patterns(content, config)

            return config

        except Exception as e:
            return OpenAIConfig(
                file_path=str(file_path),
                parse_errors=[f"Error reading file: {e}"],
            )

    def _analyze_patterns(self, content: str, config: OpenAIConfig) -> None:
        """Analyze content with regex patterns."""
        # Check for hardcoded API keys
        api_key_patterns = [
            r'openai\.api_key\s*=\s*["\']([^"\']+)["\']',
            r'api_key\s*=\s*["\']sk-[^"\']+["\']',
            r'OPENAI_API_KEY\s*=\s*["\']([^"\']+)["\']',
            r'["\']sk-[a-zA-Z0-9]{20,}["\']',
        ]

        for pattern in api_key_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if not str(match).startswith("os.") and not str(match).startswith("${"):
                    config.api_keys_found.append("OpenAI API key")

        # Look for assistant creation patterns
        assistant_patterns = [
            r'client\.beta\.assistants\.create\s*\(',
            r'assistants\.create\s*\(',
            r'create_assistant\s*\(',
        ]

        for pattern in assistant_patterns:
            for match in re.finditer(pattern, content):
                assistant = self._extract_assistant_config(content, match.start())
                if assistant:
                    config.assistants.append(assistant)

        # Look for function definitions
        function_patterns = [
            r'"type"\s*:\s*"function"',
            r"'type'\s*:\s*'function'",
        ]

        for pattern in function_patterns:
            for match in re.finditer(pattern, content):
                func = self._extract_function_config(content, match.start())
                if func:
                    config.functions.append(func)

    def _extract_assistant_config(self, content: str, start_pos: int) -> Optional[OpenAIAssistant]:
        """Extract assistant configuration from code."""
        assistant = OpenAIAssistant()

        # Find the scope of the create call
        end_pos = self._find_matching_paren(content, start_pos)
        if end_pos == -1:
            end_pos = min(start_pos + 1000, len(content))

        chunk = content[start_pos:end_pos]

        # Extract tools
        if "code_interpreter" in chunk:
            assistant.tools.append(OpenAIToolType.CODE_INTERPRETER)
        if "file_search" in chunk or "retrieval" in chunk:
            assistant.tools.append(OpenAIToolType.FILE_SEARCH)
        if '"function"' in chunk or "'function'" in chunk:
            assistant.tools.append(OpenAIToolType.FUNCTION)

        # Check for instructions
        instructions_match = re.search(r'instructions\s*=\s*["\']([^"\']*)["\']', chunk)
        if instructions_match:
            assistant.instructions = instructions_match.group(1)

        # Extract name if present
        name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', chunk)
        if name_match:
            assistant.name = name_match.group(1)

        return assistant

    def _extract_function_config(self, content: str, start_pos: int) -> Optional[OpenAIFunction]:
        """Extract function configuration from code."""
        # Look backwards and forwards for the function definition
        search_start = max(0, start_pos - 500)
        search_end = min(len(content), start_pos + 500)
        chunk = content[search_start:search_end]

        # Extract function name
        name_match = re.search(r'"name"\s*:\s*"([^"]+)"', chunk)
        if not name_match:
            name_match = re.search(r"'name'\s*:\s*'([^']+)'", chunk)

        if not name_match:
            return None

        func_name = name_match.group(1)
        func = OpenAIFunction(name=func_name)

        # Check if function is dangerous
        func.is_dangerous = any(
            pattern in func_name.lower() for pattern in self.DANGEROUS_FUNCTION_PATTERNS
        )

        return func

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

    def _scan_config(self, config: OpenAIConfig) -> None:
        """Scan analyzed configuration for vulnerabilities."""
        self._check_hardcoded_keys(config)
        self._check_code_interpreter(config)
        self._check_file_search(config)
        self._check_function_calling(config)
        self._check_dangerous_functions(config)
        self._check_instructions(config)

    def _check_hardcoded_keys(self, config: OpenAIConfig) -> None:
        """Check for hardcoded API keys (OAI-001)."""
        rule = get_rule("OAI-001")

        patterns = [
            (r'openai\.api_key\s*=\s*["\'](?!os\.)[^"\']{20,}["\']', "openai.api_key assignment"),
            (r'api_key\s*=\s*["\']sk-[a-zA-Z0-9]{20,}["\']', "api_key parameter"),
            (r'["\']sk-[a-zA-Z0-9]{20,}["\']', "OpenAI API key literal"),
            (r'["\']sk-proj-[a-zA-Z0-9\-_]{20,}["\']', "OpenAI Project API key"),
        ]

        for pattern, desc in patterns:
            for match in re.finditer(pattern, config.raw_content):
                line_num = config.raw_content[:match.start()].count('\n') + 1

                self.findings.append(
                    Finding(
                        rule_id="OAI-001",
                        domain=FindingDomain.OPENAI,
                        title=rule["title"],
                        description=f"Found {desc}. {rule['description']}.",
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

    def _check_code_interpreter(self, config: OpenAIConfig) -> None:
        """Check for code interpreter usage (OAI-002)."""
        rule = get_rule("OAI-002")

        for assistant in config.assistants:
            if assistant.has_code_interpreter:
                # Find in source
                line_num = None
                idx = config.raw_content.find("code_interpreter")
                if idx != -1:
                    line_num = config.raw_content[:idx].count('\n') + 1

                self.findings.append(
                    Finding(
                        rule_id="OAI-002",
                        domain=FindingDomain.OPENAI,
                        title=rule["title"],
                        description=f"Assistant '{assistant.name or 'unnamed'}' has code interpreter enabled. "
                        f"{rule['description']}.",
                        severity=rule["severity"],
                        location=Location(
                            file_path=config.file_path,
                            line_number=line_num,
                            snippet="code_interpreter",
                        ),
                        remediation=rule["remediation"],
                        references=rule["references"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    )
                )

    def _check_file_search(self, config: OpenAIConfig) -> None:
        """Check for file search/retrieval usage (OAI-003)."""
        rule = get_rule("OAI-003")

        for assistant in config.assistants:
            if assistant.has_file_search:
                # Find in source
                line_num = None
                for term in ["file_search", "retrieval"]:
                    idx = config.raw_content.find(term)
                    if idx != -1:
                        line_num = config.raw_content[:idx].count('\n') + 1
                        break

                self.findings.append(
                    Finding(
                        rule_id="OAI-003",
                        domain=FindingDomain.OPENAI,
                        title=rule["title"],
                        description=f"Assistant '{assistant.name or 'unnamed'}' has file search enabled. "
                        f"{rule['description']}.",
                        severity=rule["severity"],
                        location=Location(
                            file_path=config.file_path,
                            line_number=line_num,
                            snippet="file_search/retrieval",
                        ),
                        remediation=rule["remediation"],
                        references=rule["references"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    )
                )

    def _check_function_calling(self, config: OpenAIConfig) -> None:
        """Check for function calling configuration (OAI-004)."""
        rule = get_rule("OAI-004")

        for assistant in config.assistants:
            if assistant.has_functions:
                # Check if validation is mentioned nearby
                has_validation = "validate" in config.raw_content.lower() or "sanitize" in config.raw_content.lower()

                if not has_validation:
                    line_num = None
                    idx = config.raw_content.find('"function"')
                    if idx == -1:
                        idx = config.raw_content.find("'function'")
                    if idx != -1:
                        line_num = config.raw_content[:idx].count('\n') + 1

                    self.findings.append(
                        Finding(
                            rule_id="OAI-004",
                        domain=FindingDomain.OPENAI,
                        title=rule["title"],
                            description=f"Assistant '{assistant.name or 'unnamed'}' has function calling "
                            f"without apparent validation. {rule['description']}.",
                            severity=rule["severity"],
                            location=Location(
                                file_path=config.file_path,
                                line_number=line_num,
                                snippet="function",
                            ),
                            remediation=rule["remediation"],
                            references=rule["references"],
                            cwe_id=rule["cwe_id"],
                            owasp_id=rule["owasp_id"],
                        )
                    )

    def _check_dangerous_functions(self, config: OpenAIConfig) -> None:
        """Check for dangerous function definitions (OAI-005)."""
        rule = get_rule("OAI-005")

        for func in config.functions:
            if func.is_dangerous:
                line_num = None
                idx = config.raw_content.find(func.name)
                if idx != -1:
                    line_num = config.raw_content[:idx].count('\n') + 1

                self.findings.append(
                    Finding(
                        rule_id="OAI-005",
                        domain=FindingDomain.OPENAI,
                        title=rule["title"],
                        description=f"Function '{func.name}' has potentially dangerous capabilities. "
                        f"{rule['description']}.",
                        severity=rule["severity"],
                        location=Location(
                            file_path=config.file_path,
                            line_number=line_num,
                            snippet=func.name,
                        ),
                        remediation=rule["remediation"],
                        references=rule["references"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    )
                )

    def _check_instructions(self, config: OpenAIConfig) -> None:
        """Check for missing instructions (OAI-006)."""
        rule = get_rule("OAI-006")

        for assistant in config.assistants:
            if not assistant.has_instructions:
                line_num = None
                idx = config.raw_content.find("assistants.create")
                if idx != -1:
                    line_num = config.raw_content[:idx].count('\n') + 1

                self.findings.append(
                    Finding(
                        rule_id="OAI-006",
                        domain=FindingDomain.OPENAI,
                        title=rule["title"],
                        description=f"Assistant '{assistant.name or 'unnamed'}' has no instructions set. "
                        f"{rule['description']}.",
                        severity=rule["severity"],
                        location=Location(
                            file_path=config.file_path,
                            line_number=line_num,
                            snippet="assistants.create",
                        ),
                        remediation=rule["remediation"],
                        references=rule["references"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    )
                )
