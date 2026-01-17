"""Multi-agent framework detection and analysis (LangGraph, AutoGen, etc.)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any

from secureagent.core.models.finding import Finding, Location
from secureagent.core.models.severity import Severity


class MultiAgentFramework(str, Enum):
    """Supported multi-agent frameworks."""
    LANGGRAPH = "langgraph"
    AUTOGEN = "autogen"
    CREWAI = "crewai"
    AUTOGPT = "autogpt"
    LANGCHAIN = "langchain"
    SEMANTIC_KERNEL = "semantic_kernel"
    CAMEL = "camel"
    METAGPT = "metagpt"
    CHATDEV = "chatdev"
    AGENTS = "agents"
    UNKNOWN = "unknown"


@dataclass
class FrameworkConfig:
    """Configuration detected for a multi-agent framework."""
    framework: MultiAgentFramework
    file_path: str
    version: Optional[str] = None
    agents: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    workflows: List[str] = field(default_factory=list)
    has_human_in_loop: bool = False
    has_memory: bool = False
    has_persistence: bool = False
    security_features: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# Framework-specific security rules
FRAMEWORK_RULES = {
    "MA-FW-001": {
        "id": "MA-FW-001",
        "title": "Insecure LangGraph State Management",
        "severity": Severity.HIGH,
        "description": "LangGraph state contains sensitive data without protection",
        "cwe_id": "CWE-312",
        "owasp_id": "LLM02",
        "remediation": "Encrypt sensitive fields in LangGraph state",
        "frameworks": [MultiAgentFramework.LANGGRAPH],
    },
    "MA-FW-002": {
        "id": "MA-FW-002",
        "title": "AutoGen Code Execution Without Sandbox",
        "severity": Severity.CRITICAL,
        "description": "AutoGen configured for code execution without sandboxing",
        "cwe_id": "CWE-94",
        "owasp_id": "LLM01",
        "remediation": "Enable Docker sandbox for AutoGen code execution",
        "frameworks": [MultiAgentFramework.AUTOGEN],
    },
    "MA-FW-003": {
        "id": "MA-FW-003",
        "title": "Unrestricted Tool Access",
        "severity": Severity.HIGH,
        "description": "Agent has unrestricted access to dangerous tools",
        "cwe_id": "CWE-250",
        "owasp_id": "LLM05",
        "remediation": "Implement tool access controls and sandboxing",
        "frameworks": [MultiAgentFramework.LANGGRAPH, MultiAgentFramework.AUTOGEN, MultiAgentFramework.CREWAI],
    },
    "MA-FW-004": {
        "id": "MA-FW-004",
        "title": "Missing Human Approval for Critical Actions",
        "severity": Severity.HIGH,
        "description": "Critical agent actions executed without human approval",
        "cwe_id": "CWE-284",
        "owasp_id": "LLM08",
        "remediation": "Implement human-in-the-loop for critical operations",
        "frameworks": [MultiAgentFramework.LANGGRAPH, MultiAgentFramework.AUTOGEN],
    },
    "MA-FW-005": {
        "id": "MA-FW-005",
        "title": "Insecure GroupChat Configuration",
        "severity": Severity.MEDIUM,
        "description": "AutoGen GroupChat allows unrestricted agent interaction",
        "cwe_id": "CWE-284",
        "owasp_id": "LLM08",
        "remediation": "Configure GroupChat with message validation and speaker limits",
        "frameworks": [MultiAgentFramework.AUTOGEN],
    },
    "MA-FW-006": {
        "id": "MA-FW-006",
        "title": "LangGraph Checkpoint Without Encryption",
        "severity": Severity.MEDIUM,
        "description": "LangGraph checkpoints stored without encryption",
        "cwe_id": "CWE-311",
        "owasp_id": "LLM02",
        "remediation": "Enable encryption for LangGraph checkpoint storage",
        "frameworks": [MultiAgentFramework.LANGGRAPH],
    },
    "MA-FW-007": {
        "id": "MA-FW-007",
        "title": "Unsafe Function Calling",
        "severity": Severity.CRITICAL,
        "description": "Agent function calling without input validation",
        "cwe_id": "CWE-20",
        "owasp_id": "LLM01",
        "remediation": "Validate all function call inputs before execution",
        "frameworks": [MultiAgentFramework.LANGGRAPH, MultiAgentFramework.AUTOGEN, MultiAgentFramework.LANGCHAIN],
    },
    "MA-FW-008": {
        "id": "MA-FW-008",
        "title": "Missing Rate Limiting",
        "severity": Severity.MEDIUM,
        "description": "No rate limiting on agent API calls or tool usage",
        "cwe_id": "CWE-770",
        "owasp_id": "LLM04",
        "remediation": "Implement rate limiting for agent operations",
        "frameworks": [MultiAgentFramework.LANGGRAPH, MultiAgentFramework.AUTOGEN, MultiAgentFramework.CREWAI],
    },
    "MA-FW-009": {
        "id": "MA-FW-009",
        "title": "Semantic Kernel Plugin Injection",
        "severity": Severity.HIGH,
        "description": "Semantic Kernel plugins loaded without verification",
        "cwe_id": "CWE-94",
        "owasp_id": "LLM01",
        "remediation": "Verify plugin sources and signatures before loading",
        "frameworks": [MultiAgentFramework.SEMANTIC_KERNEL],
    },
    "MA-FW-010": {
        "id": "MA-FW-010",
        "title": "Unsafe Agent Spawning",
        "severity": Severity.HIGH,
        "description": "Framework allows dynamic agent creation without limits",
        "cwe_id": "CWE-770",
        "owasp_id": "LLM04",
        "remediation": "Implement agent creation limits and approval workflow",
        "frameworks": [MultiAgentFramework.AUTOGEN, MultiAgentFramework.METAGPT],
    },
}


class FrameworkDetector:
    """Detector for multi-agent frameworks."""

    FRAMEWORK_PATTERNS = {
        MultiAgentFramework.LANGGRAPH: [
            r'from\s+langgraph', r'import\s+langgraph',
            r'StateGraph', r'MessageGraph', r'add_node', r'add_edge',
            r'compile\s*\(\s*\)', r'MemorySaver', r'checkpoint'
        ],
        MultiAgentFramework.AUTOGEN: [
            r'from\s+autogen', r'import\s+autogen',
            r'AssistantAgent', r'UserProxyAgent', r'ConversableAgent',
            r'GroupChat', r'GroupChatManager', r'initiate_chat'
        ],
        MultiAgentFramework.CREWAI: [
            r'from\s+crewai', r'import\s+crewai',
            r'Agent\s*\(', r'Crew\s*\(', r'Task\s*\(',
            r'allow_delegation', r'kickoff'
        ],
        MultiAgentFramework.AUTOGPT: [
            r'autogpt', r'ai_goals', r'ai_role', r'ai_name',
            r'execute_local_commands', r'Agent\s*\(\s*name'
        ],
        MultiAgentFramework.LANGCHAIN: [
            r'from\s+langchain', r'import\s+langchain',
            r'AgentExecutor', r'create_.*_agent', r'initialize_agent',
            r'LLMChain', r'ConversationChain'
        ],
        MultiAgentFramework.SEMANTIC_KERNEL: [
            r'semantic_kernel', r'from\s+semantic_kernel',
            r'Kernel\s*\(', r'add_plugin', r'SKContext',
            r'kernel\.run'
        ],
        MultiAgentFramework.METAGPT: [
            r'from\s+metagpt', r'import\s+metagpt',
            r'Role\s*\(', r'Team\s*\(', r'run_project'
        ],
    }

    def detect(self, content: str) -> List[MultiAgentFramework]:
        """Detect frameworks used in content."""
        detected: List[MultiAgentFramework] = []

        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            if any(re.search(p, content, re.IGNORECASE) for p in patterns):
                detected.append(framework)

        return detected if detected else [MultiAgentFramework.UNKNOWN]

    def detect_in_file(self, file_path: Path) -> List[MultiAgentFramework]:
        """Detect frameworks in a file."""
        try:
            content = file_path.read_text()
            return self.detect(content)
        except Exception:
            return [MultiAgentFramework.UNKNOWN]


class LangGraphAnalyzer:
    """Security analyzer for LangGraph framework."""

    def __init__(self):
        self.findings: List[Finding] = []

    def analyze(self, content: str, file_path: str) -> List[Finding]:
        """Analyze LangGraph code for security issues."""
        self.findings = []

        self._check_state_security(content, file_path)
        self._check_tool_access(content, file_path)
        self._check_human_in_loop(content, file_path)
        self._check_checkpoint_security(content, file_path)
        self._check_function_calling(content, file_path)
        self._check_rate_limiting(content, file_path)

        return self.findings

    def _check_state_security(self, content: str, file_path: str) -> None:
        """Check LangGraph state for sensitive data."""
        # State with sensitive fields
        sensitive_in_state = re.search(
            r'class\s+\w*State.*?(?:password|secret|api_key|token|credential)',
            content, re.IGNORECASE | re.DOTALL
        )

        if sensitive_in_state:
            encryption_patterns = ['encrypt', 'SecretStr', 'mask']
            has_protection = any(p in content for p in encryption_patterns)

            if not has_protection:
                rule = FRAMEWORK_RULES["MA-FW-001"]
                self.findings.append(Finding(
                    rule_id="MA-FW-001",
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    location=Location(file_path=file_path),
                    remediation=rule["remediation"],
                    cwe_id=rule["cwe_id"],
                    owasp_id=rule["owasp_id"],
                ))

    def _check_tool_access(self, content: str, file_path: str) -> None:
        """Check for unrestricted tool access."""
        dangerous_tools = ['shell', 'execute', 'subprocess', 'os.system', 'eval(', 'exec(']
        has_dangerous = any(t in content.lower() for t in dangerous_tools)

        sandbox_patterns = ['sandbox', 'restricted', 'safe_execute', 'validate_tool']
        has_sandbox = any(p in content.lower() for p in sandbox_patterns)

        if has_dangerous and not has_sandbox:
            rule = FRAMEWORK_RULES["MA-FW-003"]
            self.findings.append(Finding(
                rule_id="MA-FW-003",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_human_in_loop(self, content: str, file_path: str) -> None:
        """Check for human-in-the-loop for critical actions."""
        critical_patterns = ['delete', 'payment', 'transaction', 'deploy', 'publish']
        has_critical = any(p in content.lower() for p in critical_patterns)

        hitl_patterns = ['interrupt', 'human_approval', 'confirm', 'await_human']
        has_hitl = any(p in content.lower() for p in hitl_patterns)

        if has_critical and not has_hitl:
            rule = FRAMEWORK_RULES["MA-FW-004"]
            self.findings.append(Finding(
                rule_id="MA-FW-004",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_checkpoint_security(self, content: str, file_path: str) -> None:
        """Check checkpoint storage security."""
        has_checkpoint = 'MemorySaver' in content or 'SqliteSaver' in content or 'checkpoint' in content.lower()

        encryption_patterns = ['encrypt', 'kms', 'aes', 'fernet']
        has_encryption = any(p in content.lower() for p in encryption_patterns)

        if has_checkpoint and not has_encryption:
            rule = FRAMEWORK_RULES["MA-FW-006"]
            self.findings.append(Finding(
                rule_id="MA-FW-006",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_function_calling(self, content: str, file_path: str) -> None:
        """Check function calling safety."""
        # Dynamic function calls without validation
        unsafe_patterns = [
            r'getattr\s*\(.*,\s*\w+\s*\)\s*\(',
            r'globals\s*\(\s*\)\s*\[',
            r'eval\s*\(',
        ]

        for pattern in unsafe_patterns:
            if re.search(pattern, content):
                validation = ['validate', 'sanitize', 'allowed_functions']
                has_validation = any(v in content.lower() for v in validation)

                if not has_validation:
                    rule = FRAMEWORK_RULES["MA-FW-007"]
                    self.findings.append(Finding(
                        rule_id="MA-FW-007",
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        location=Location(file_path=file_path),
                        remediation=rule["remediation"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    ))
                    break

    def _check_rate_limiting(self, content: str, file_path: str) -> None:
        """Check for rate limiting."""
        has_llm_calls = 'invoke' in content or 'ainvoke' in content or 'generate' in content

        rate_limit_patterns = ['rate_limit', 'throttle', 'RateLimiter', 'requests_per']
        has_rate_limit = any(p in content for p in rate_limit_patterns)

        if has_llm_calls and not has_rate_limit:
            rule = FRAMEWORK_RULES["MA-FW-008"]
            self.findings.append(Finding(
                rule_id="MA-FW-008",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))


class AutoGenAnalyzer:
    """Security analyzer for AutoGen framework."""

    def __init__(self):
        self.findings: List[Finding] = []

    def analyze(self, content: str, file_path: str) -> List[Finding]:
        """Analyze AutoGen code for security issues."""
        self.findings = []

        self._check_code_execution(content, file_path)
        self._check_groupchat_security(content, file_path)
        self._check_tool_access(content, file_path)
        self._check_human_in_loop(content, file_path)
        self._check_agent_spawning(content, file_path)
        self._check_function_calling(content, file_path)

        return self.findings

    def _check_code_execution(self, content: str, file_path: str) -> None:
        """Check for code execution without sandbox."""
        code_exec_patterns = [
            'code_execution_config', 'execute_code', 'UserProxyAgent',
            'python_repl', 'execute_function'
        ]
        has_code_exec = any(p in content for p in code_exec_patterns)

        # Check for Docker sandbox
        sandbox_patterns = [
            'use_docker=True', 'docker', 'sandbox', 'isolated',
            'code_execution_config=False'
        ]
        has_sandbox = any(p in content for p in sandbox_patterns)

        if has_code_exec and not has_sandbox:
            rule = FRAMEWORK_RULES["MA-FW-002"]
            self.findings.append(Finding(
                rule_id="MA-FW-002",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_groupchat_security(self, content: str, file_path: str) -> None:
        """Check GroupChat security configuration."""
        if 'GroupChat' in content:
            security_patterns = [
                'max_round', 'speaker_selection_method', 'allowed_transitions',
                'select_speaker_message_template'
            ]
            has_security_config = sum(1 for p in security_patterns if p in content)

            if has_security_config < 2:
                rule = FRAMEWORK_RULES["MA-FW-005"]
                self.findings.append(Finding(
                    rule_id="MA-FW-005",
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    location=Location(file_path=file_path),
                    remediation=rule["remediation"],
                    cwe_id=rule["cwe_id"],
                    owasp_id=rule["owasp_id"],
                ))

    def _check_tool_access(self, content: str, file_path: str) -> None:
        """Check for unrestricted tool access."""
        dangerous_tools = ['shell', 'os.system', 'subprocess', 'execute_command']
        has_dangerous = any(t in content.lower() for t in dangerous_tools)

        restriction_patterns = ['tool_filter', 'allowed_tools', 'restricted', 'sandbox']
        has_restrictions = any(p in content.lower() for p in restriction_patterns)

        if has_dangerous and not has_restrictions:
            rule = FRAMEWORK_RULES["MA-FW-003"]
            self.findings.append(Finding(
                rule_id="MA-FW-003",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_human_in_loop(self, content: str, file_path: str) -> None:
        """Check for human-in-the-loop configuration."""
        has_auto_reply = 'is_termination_msg' in content or 'max_consecutive_auto_reply' in content

        hitl_patterns = ['human_input_mode', 'ALWAYS', 'TERMINATE', 'a]sk_human']
        has_hitl = any(p in content for p in hitl_patterns)

        critical_ops = ['payment', 'delete', 'deploy', 'transaction']
        has_critical = any(op in content.lower() for op in critical_ops)

        if has_critical and not has_hitl:
            rule = FRAMEWORK_RULES["MA-FW-004"]
            self.findings.append(Finding(
                rule_id="MA-FW-004",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_agent_spawning(self, content: str, file_path: str) -> None:
        """Check for unsafe agent spawning."""
        spawn_patterns = ['register_for_', 'create_agent', 'spawn_agent']
        has_spawning = any(p in content for p in spawn_patterns)

        limit_patterns = ['max_agents', 'agent_limit', 'agent_pool']
        has_limits = any(p in content.lower() for p in limit_patterns)

        if has_spawning and not has_limits:
            rule = FRAMEWORK_RULES["MA-FW-010"]
            self.findings.append(Finding(
                rule_id="MA-FW-010",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_function_calling(self, content: str, file_path: str) -> None:
        """Check function calling safety."""
        has_functions = 'function_map' in content or 'register_function' in content

        validation_patterns = ['validate', 'allowed_functions', 'function_filter']
        has_validation = any(p in content.lower() for p in validation_patterns)

        if has_functions and not has_validation:
            rule = FRAMEWORK_RULES["MA-FW-007"]
            self.findings.append(Finding(
                rule_id="MA-FW-007",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))
