"""MCP configuration scanner implementation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Generator, Optional, List, Dict, Any

from secureagent.core.models.finding import Finding, FindingDomain, Location
from secureagent.core.models.severity import Severity
from secureagent.core.scanner.base import BaseScanner
from secureagent.core.scanner.registry import register_scanner
from secureagent.scanners.mcp.models import MCPConfig, MCPServer
from secureagent.scanners.mcp.rules import get_rule


@register_scanner
class MCPScanner(BaseScanner):
    """Scanner for MCP configuration files and server implementations."""

    name = "mcp"
    description = "Scans MCP configurations for security vulnerabilities"
    version = "1.0.0"

    # Known MCP config file patterns
    CONFIG_PATTERNS = [
        "**/mcp.json",
        "**/.mcp.json",
        "**/mcp_config.json",
        "**/claude_desktop_config.json",
        "**/.cursor/mcp.json",
        "**/.claude/mcp.json",
        "**/mcp-server*/config.json",
        "**/*_mcp.json",
        "**/*mcp*.json",
    ]

    def discover_targets(self) -> Generator[Path, None, None]:
        """Discover MCP configuration files.

        Yields:
            Paths to MCP configuration files
        """
        if self.path.is_file():
            yield self.path
            return

        for pattern in self.CONFIG_PATTERNS:
            for config_file in self.path.glob(pattern):
                if config_file.is_file():
                    yield config_file

    def scan(self) -> List[Finding]:
        """Execute the MCP security scan.

        Returns:
            List of security findings
        """
        self.findings = []

        for config_path in self.discover_targets():
            config = self._parse_config(config_path)
            if config:
                self._scan_config(config)

        return self.findings

    def _parse_config(self, config_path: Path) -> Optional[MCPConfig]:
        """Parse an MCP configuration file.

        Args:
            config_path: Path to the configuration file

        Returns:
            Parsed MCPConfig or None if parsing failed
        """
        try:
            content = config_path.read_text()
            data = json.loads(content)

            servers = {}
            mcp_servers = data.get("mcpServers", data.get("servers", {}))

            for name, server_data in mcp_servers.items():
                servers[name] = MCPServer(
                    name=name,
                    command=server_data.get("command"),
                    args=server_data.get("args", []),
                    env=server_data.get("env", {}),
                    url=server_data.get("url"),
                    raw_config=server_data,
                )

            return MCPConfig(
                file_path=str(config_path),
                servers=servers,
                raw_content=content,
            )
        except json.JSONDecodeError as e:
            return MCPConfig(
                file_path=str(config_path),
                parse_errors=[f"JSON parse error: {e}"],
                raw_content=config_path.read_text() if config_path.exists() else "",
            )
        except Exception as e:
            return MCPConfig(
                file_path=str(config_path),
                parse_errors=[f"Error reading config: {e}"],
            )

    def _scan_config(self, config: MCPConfig) -> None:
        """Scan a parsed MCP configuration for vulnerabilities.

        Args:
            config: Parsed MCP configuration
        """
        if config.parse_errors:
            for error in config.parse_errors:
                self.findings.append(
                    Finding(
                        rule_id="MCP-000",
                        domain=FindingDomain.MCP,
                        title="Configuration Parse Error",
                        description=f"Failed to parse MCP configuration: {error}",
                        severity=Severity.INFO,
                        location=Location(file_path=config.file_path),
                        remediation="Fix the configuration file syntax",
                    )
                )
            return

        # Run all security checks
        self._check_hardcoded_credentials(config)
        self._check_command_injection(config)
        self._check_path_traversal(config)
        self._check_ssrf_risks(config)
        self._check_sensitive_env_vars(config)
        self._check_no_auth(config)
        self._check_insecure_permissions(config)

    def _check_hardcoded_credentials(self, config: MCPConfig) -> None:
        """Check for hardcoded credentials in configuration (MCP-002)."""
        credential_patterns = [
            (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API key"),
            (r'sk-proj-[a-zA-Z0-9\-_]{20,}', "OpenAI Project API key"),
            (r'sk-ant-[a-zA-Z0-9\-_]{20,}', "Anthropic API key"),
            (r'ANTHROPIC[_-]?API[_-]?KEY["\s:=]+["\']?[a-zA-Z0-9\-_]{20,}', "Anthropic API key"),
            (r'OPENAI[_-]?API[_-]?KEY["\s:=]+["\']?sk-[a-zA-Z0-9]{20,}', "OpenAI API key"),
            (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
            (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token"),
            (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', "GitHub Fine-grained PAT"),
            (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', "Slack Token"),
            (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
            (r'ya29\.[0-9A-Za-z\-_]+', "Google OAuth Token"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'["\']?password["\']?\s*[:=]\s*["\'](?!\$\{)[^"\']{8,}["\']', "Hardcoded password"),
            (r'["\']?secret["\']?\s*[:=]\s*["\'](?!\$\{)[^"\']{8,}["\']', "Hardcoded secret"),
            (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'](?!\$\{)[^"\']{16,}["\']', "Hardcoded API key"),
            (r'Bearer\s+[a-zA-Z0-9\-_.]+', "Bearer token"),
            (r'Basic\s+[a-zA-Z0-9+/=]+', "Basic auth credentials"),
        ]

        rule = get_rule("MCP-002")
        content = config.raw_content
        lines = content.split('\n')

        for pattern, cred_type in credential_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                matched_text = match.group(0)
                if len(matched_text) > 10:
                    masked = matched_text[:6] + "..." + matched_text[-4:]
                else:
                    masked = matched_text[:3] + "..."

                self.findings.append(
                    Finding(
                        rule_id="MCP-002",
                        domain=FindingDomain.MCP,
                        title=rule["title"],
                        description=f"Found {cred_type} in configuration file. {rule['description']}.",
                        severity=rule["severity"],
                        location=Location(
                            file_path=config.file_path,
                            line_number=line_num,
                            snippet=f"Detected: {masked}",
                        ),
                        remediation=rule["remediation"],
                        references=rule["references"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    )
                )

    def _check_command_injection(self, config: MCPConfig) -> None:
        """Check for potential command injection vulnerabilities (MCP-003)."""
        dangerous_patterns = [
            (r'\$\([^)]+\)', "Command substitution"),
            (r'`[^`]+`', "Backtick command substitution"),
            (r'\|\s*\w+', "Pipe to command"),
            (r';\s*\w+', "Command chaining with semicolon"),
            (r'&&\s*\w+', "Command chaining with &&"),
            (r'\|\|\s*\w+', "Command chaining with ||"),
            (r'>\s*/\w+', "Output redirection"),
            (r'<\s*/\w+', "Input redirection"),
        ]

        rule = get_rule("MCP-003")

        for server_name, server in config.servers.items():
            check_strings = [server.command or ""] + server.args

            for check_str in check_strings:
                for pattern, pattern_name in dangerous_patterns:
                    if re.search(pattern, check_str):
                        line_num = self._find_line_number(config.raw_content, check_str)

                        self.findings.append(
                            Finding(
                                rule_id="MCP-003",
                                domain=FindingDomain.MCP,
                                title=rule["title"],
                                description=f"Server '{server_name}' contains {pattern_name} "
                                f"in its command configuration. {rule['description']}.",
                                severity=rule["severity"],
                                location=Location(
                                    file_path=config.file_path,
                                    line_number=line_num,
                                    snippet=check_str[:100],
                                ),
                                remediation=rule["remediation"],
                                references=rule["references"],
                                cwe_id=rule["cwe_id"],
                                owasp_id=rule["owasp_id"],
                            )
                        )

    def _check_path_traversal(self, config: MCPConfig) -> None:
        """Check for path traversal vulnerabilities (MCP-005)."""
        traversal_patterns = [
            r'\.\./+',
            r'\.\.\\+',
            r'/etc/',
            r'/var/',
            r'/tmp/',
            r'/home/',
            r'/root/',
            r'C:\\',
            r'%2e%2e',
            r'%252e',
        ]

        rule = get_rule("MCP-005")

        for server_name, server in config.servers.items():
            check_strings = [server.command or ""] + server.args
            check_strings.extend(server.env.values())

            for check_str in check_strings:
                for pattern in traversal_patterns:
                    if re.search(pattern, check_str, re.IGNORECASE):
                        line_num = self._find_line_number(config.raw_content, check_str)

                        self.findings.append(
                            Finding(
                                rule_id="MCP-005",
                                domain=FindingDomain.MCP,
                                title=rule["title"],
                                description=f"Server '{server_name}' references absolute paths "
                                f"or contains path traversal sequences. {rule['description']}.",
                                severity=rule["severity"],
                                location=Location(
                                    file_path=config.file_path,
                                    line_number=line_num,
                                    snippet=check_str[:100],
                                ),
                                remediation=rule["remediation"],
                                references=rule["references"],
                                cwe_id=rule["cwe_id"],
                                owasp_id=rule["owasp_id"],
                            )
                        )
                        break

    def _check_ssrf_risks(self, config: MCPConfig) -> None:
        """Check for SSRF vulnerabilities (MCP-004)."""
        risky_url_patterns = [
            (r'http://localhost', "localhost HTTP"),
            (r'http://127\.0\.0\.1', "127.0.0.1 HTTP"),
            (r'http://0\.0\.0\.0', "0.0.0.0 HTTP"),
            (r'http://\[::1\]', "IPv6 localhost HTTP"),
            (r'http://169\.254\.', "AWS metadata endpoint range"),
            (r'http://metadata\.google', "GCP metadata endpoint"),
            (r'http://192\.168\.', "Private network"),
            (r'http://10\.', "Private network"),
            (r'http://172\.(1[6-9]|2[0-9]|3[0-1])\.', "Private network"),
        ]

        rule = get_rule("MCP-004")

        for server_name, server in config.servers.items():
            check_strings = [server.url or ""] + list(server.env.values())

            for check_str in check_strings:
                for pattern, risk_type in risky_url_patterns:
                    if re.search(pattern, check_str, re.IGNORECASE):
                        line_num = self._find_line_number(config.raw_content, check_str)

                        self.findings.append(
                            Finding(
                                rule_id="MCP-004",
                                domain=FindingDomain.MCP,
                                title=rule["title"],
                                description=f"Server '{server_name}' references {risk_type}. "
                                f"{rule['description']}.",
                                severity=rule["severity"],
                                location=Location(
                                    file_path=config.file_path,
                                    line_number=line_num,
                                    snippet=check_str[:100],
                                ),
                                remediation=rule["remediation"],
                                references=rule["references"],
                                cwe_id=rule["cwe_id"],
                                owasp_id=rule["owasp_id"],
                            )
                        )

    def _check_sensitive_env_vars(self, config: MCPConfig) -> None:
        """Check for sensitive environment variable exposure (MCP-006)."""
        sensitive_env_vars = [
            "DATABASE_URL",
            "DB_PASSWORD",
            "MYSQL_PASSWORD",
            "POSTGRES_PASSWORD",
            "MONGO_URI",
            "REDIS_URL",
            "JWT_SECRET",
            "SESSION_SECRET",
            "ENCRYPTION_KEY",
            "PRIVATE_KEY",
            "SSH_KEY",
        ]

        rule = get_rule("MCP-006")

        for server_name, server in config.servers.items():
            for env_name, env_value in server.env.items():
                env_upper = env_name.upper()
                is_sensitive = any(s in env_upper for s in sensitive_env_vars)
                is_hardcoded = not (
                    env_value.startswith("${") or env_value.startswith("$")
                )

                if is_sensitive and is_hardcoded and len(env_value) > 0:
                    line_num = self._find_line_number(config.raw_content, env_name)

                    self.findings.append(
                        Finding(
                            rule_id="MCP-006",
                            domain=FindingDomain.MCP,
                            title=rule["title"],
                            description=f"Server '{server_name}' has sensitive environment "
                            f"variable '{env_name}' with a hardcoded value. {rule['description']}.",
                            severity=rule["severity"],
                            location=Location(
                                file_path=config.file_path,
                                line_number=line_num,
                                snippet=f"{env_name}=***",
                            ),
                            remediation=rule["remediation"],
                            references=rule["references"],
                            cwe_id=rule["cwe_id"],
                            owasp_id=rule["owasp_id"],
                        )
                    )

    def _check_no_auth(self, config: MCPConfig) -> None:
        """Check for servers without authentication (MCP-001)."""
        auth_indicators = [
            "auth",
            "token",
            "key",
            "bearer",
            "authorization",
            "credentials",
            "password",
            "secret",
        ]

        rule = get_rule("MCP-001")

        for server_name, server in config.servers.items():
            if server.url:
                has_auth = False

                for env_name in server.env.keys():
                    if any(auth in env_name.lower() for auth in auth_indicators):
                        has_auth = True
                        break

                raw_str = json.dumps(server.raw_config).lower()
                if any(auth in raw_str for auth in auth_indicators):
                    has_auth = True

                if not has_auth:
                    line_num = self._find_line_number(config.raw_content, server_name)

                    self.findings.append(
                        Finding(
                            rule_id="MCP-001",
                            domain=FindingDomain.MCP,
                            title=rule["title"],
                            description=f"Remote MCP server '{server_name}' appears to have "
                            f"no authentication configured. {rule['description']}.",
                            severity=rule["severity"],
                            location=Location(
                                file_path=config.file_path,
                                line_number=line_num,
                                snippet=f"url: {server.url}",
                            ),
                            remediation=rule["remediation"],
                            references=rule["references"],
                            cwe_id=rule["cwe_id"],
                            owasp_id=rule["owasp_id"],
                        )
                    )

    def _check_insecure_permissions(self, config: MCPConfig) -> None:
        """Check for overly permissive tool configurations (MCP-007)."""
        dangerous_tools = [
            ("shell", "Shell access"),
            ("exec", "Code execution"),
            ("execute", "Code execution"),
            ("run", "Process execution"),
            ("eval", "Code evaluation"),
            ("system", "System command"),
            ("cmd", "Command execution"),
            ("bash", "Bash shell"),
            ("powershell", "PowerShell"),
            ("terminal", "Terminal access"),
            ("file_write", "File write access"),
            ("delete", "Delete operations"),
            ("rm", "Remove operations"),
            ("sudo", "Privileged execution"),
            ("admin", "Administrative access"),
        ]

        rule = get_rule("MCP-007")

        for server_name, server in config.servers.items():
            raw_str = json.dumps(server.raw_config).lower()

            for tool_pattern, risk_type in dangerous_tools:
                if tool_pattern in raw_str:
                    line_num = self._find_line_number(config.raw_content, server_name)

                    self.findings.append(
                        Finding(
                            rule_id="MCP-007",
                            domain=FindingDomain.MCP,
                            title=rule["title"],
                            description=f"Server '{server_name}' appears to provide "
                            f"{risk_type} capabilities. {rule['description']}.",
                            severity=rule["severity"],
                            location=Location(
                                file_path=config.file_path,
                                line_number=line_num,
                                snippet=f"Tool pattern: {tool_pattern}",
                            ),
                            remediation=rule["remediation"],
                            references=rule["references"],
                            cwe_id=rule["cwe_id"],
                            owasp_id=rule["owasp_id"],
                        )
                    )
                    break

    def _find_line_number(self, content: str, search_str: str) -> Optional[int]:
        """Find the line number containing a string."""
        if not search_str:
            return None

        idx = content.find(search_str)
        if idx == -1:
            escaped = json.dumps(search_str)[1:-1]
            idx = content.find(escaped)

        if idx != -1:
            return content[:idx].count('\n') + 1

        return None
