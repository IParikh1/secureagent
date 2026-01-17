"""Multi-agent delegation security analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Set, Any

from secureagent.core.models.finding import Finding, Location
from secureagent.core.models.severity import Severity


class DelegationType(str, Enum):
    """Types of task delegation."""
    DIRECT = "direct"  # Agent A directly assigns to Agent B
    CHAIN = "chain"  # Task passes through multiple agents
    BROADCAST = "broadcast"  # Task sent to all capable agents
    HIERARCHICAL = "hierarchical"  # Manager delegates to workers
    PEER = "peer"  # Peer-to-peer delegation
    RECURSIVE = "recursive"  # Agent can delegate back to itself
    CONDITIONAL = "conditional"  # Delegation based on conditions
    UNKNOWN = "unknown"


class DelegationRisk(str, Enum):
    """Risk levels for delegation patterns."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class DelegationChain:
    """Represents a chain of delegations."""
    chain_id: str
    agents: List[str] = field(default_factory=list)
    delegation_types: List[DelegationType] = field(default_factory=list)
    capabilities_at_each_step: List[List[str]] = field(default_factory=list)
    has_privilege_escalation: bool = False
    has_cycle: bool = False
    max_depth: int = 0


@dataclass
class DelegationAttack:
    """Represents a delegation-based attack pattern."""
    attack_id: str
    attack_type: str
    severity: Severity
    description: str
    source_agent: str = ""
    target_agents: List[str] = field(default_factory=list)
    exploitation_path: List[str] = field(default_factory=list)
    remediation: str = ""


# Delegation security rules
DELEGATION_RULES = {
    "MA-DEL-001": {
        "id": "MA-DEL-001",
        "title": "Circular Delegation Chain",
        "severity": Severity.HIGH,
        "description": "Delegation chain contains cycles that could cause infinite loops",
        "cwe_id": "CWE-835",
        "owasp_id": "LLM04",
        "remediation": "Implement delegation depth limits and cycle detection",
    },
    "MA-DEL-002": {
        "id": "MA-DEL-002",
        "title": "Delegation Privilege Escalation",
        "severity": Severity.CRITICAL,
        "description": "Lower-privileged agent can escalate privileges through delegation",
        "cwe_id": "CWE-269",
        "owasp_id": "LLM08",
        "remediation": "Implement capability-based delegation with no escalation",
    },
    "MA-DEL-003": {
        "id": "MA-DEL-003",
        "title": "Unlimited Delegation Depth",
        "severity": Severity.MEDIUM,
        "description": "No limit on delegation chain depth, enabling resource exhaustion",
        "cwe_id": "CWE-770",
        "owasp_id": "LLM04",
        "remediation": "Set maximum delegation depth and track delegation history",
    },
    "MA-DEL-004": {
        "id": "MA-DEL-004",
        "title": "Delegation Without Authorization",
        "severity": Severity.HIGH,
        "description": "Agent can delegate tasks without authorization checks",
        "cwe_id": "CWE-862",
        "owasp_id": "LLM08",
        "remediation": "Require explicit authorization for all delegation operations",
    },
    "MA-DEL-005": {
        "id": "MA-DEL-005",
        "title": "Task Injection via Delegation",
        "severity": Severity.CRITICAL,
        "description": "Delegated task content can be injected with malicious instructions",
        "cwe_id": "CWE-94",
        "owasp_id": "LLM01",
        "remediation": "Validate and sanitize all delegated task content",
    },
    "MA-DEL-006": {
        "id": "MA-DEL-006",
        "title": "Delegation to Untrusted Agent",
        "severity": Severity.HIGH,
        "description": "Tasks delegated to agents without trust verification",
        "cwe_id": "CWE-346",
        "owasp_id": "LLM08",
        "remediation": "Implement agent trust registry and verify before delegation",
    },
    "MA-DEL-007": {
        "id": "MA-DEL-007",
        "title": "Result Tampering in Delegation",
        "severity": Severity.HIGH,
        "description": "Delegation results can be tampered with by intermediate agents",
        "cwe_id": "CWE-345",
        "owasp_id": "LLM08",
        "remediation": "Sign delegation results and verify integrity",
    },
    "MA-DEL-008": {
        "id": "MA-DEL-008",
        "title": "Delegation Deadlock Risk",
        "severity": Severity.MEDIUM,
        "description": "Delegation pattern can cause deadlock between agents",
        "cwe_id": "CWE-833",
        "owasp_id": "LLM04",
        "remediation": "Implement timeout-based deadlock detection and recovery",
    },
    "MA-DEL-009": {
        "id": "MA-DEL-009",
        "title": "Capability Leakage via Delegation",
        "severity": Severity.HIGH,
        "description": "Agent capabilities leaked through delegation context",
        "cwe_id": "CWE-200",
        "owasp_id": "LLM02",
        "remediation": "Minimize delegation context and filter sensitive capabilities",
    },
    "MA-DEL-010": {
        "id": "MA-DEL-010",
        "title": "Recursive Self-Delegation",
        "severity": Severity.MEDIUM,
        "description": "Agent can delegate tasks back to itself causing infinite recursion",
        "cwe_id": "CWE-674",
        "owasp_id": "LLM04",
        "remediation": "Prevent self-delegation or implement recursion limits",
    },
}


class DelegationAnalyzer:
    """Analyzer for multi-agent delegation security."""

    def __init__(self):
        self.findings: List[Finding] = []
        self.chains: List[DelegationChain] = []
        self.attacks: List[DelegationAttack] = []

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file for delegation security issues."""
        self.findings = []

        try:
            content = file_path.read_text()
        except Exception:
            return self.findings

        # Detect delegation patterns
        chains = self._extract_delegation_chains(content, str(file_path))
        self.chains.extend(chains)

        # Analyze for security issues
        self._check_circular_delegation(content, str(file_path), chains)
        self._check_privilege_escalation(content, str(file_path), chains)
        self._check_delegation_depth(content, str(file_path))
        self._check_authorization(content, str(file_path))
        self._check_task_injection(content, str(file_path))
        self._check_untrusted_delegation(content, str(file_path))
        self._check_result_tampering(content, str(file_path))
        self._check_deadlock_risk(content, str(file_path), chains)
        self._check_capability_leakage(content, str(file_path))
        self._check_self_delegation(content, str(file_path))

        return self.findings

    def analyze_directory(self, dir_path: str) -> List[Finding]:
        """Analyze a directory for delegation issues."""
        self.findings = []
        path = Path(dir_path)

        for file_path in path.rglob("*.py"):
            self.analyze_file(file_path)

        return self.findings

    def _extract_delegation_chains(self, content: str, file_path: str) -> List[DelegationChain]:
        """Extract delegation chains from code."""
        chains: List[DelegationChain] = []

        # Find delegation patterns
        delegation_patterns = [
            (r'\.delegate\s*\(\s*(["\']?\w+["\']?)', "delegate"),
            (r'\.assign_task\s*\(\s*(["\']?\w+["\']?)', "assign"),
            (r'allow_delegation\s*=\s*True', "allow_delegation"),
            (r'\.hand_off\s*\(\s*(["\']?\w+["\']?)', "hand_off"),
            (r'\.transfer_to\s*\(\s*(["\']?\w+["\']?)', "transfer"),
        ]

        # Find agent definitions first
        agents: Dict[str, Set[str]] = {}  # agent_name -> capabilities
        agent_pattern = r'(\w+)\s*=\s*(?:Agent|AssistantAgent|ConversableAgent)\s*\('
        for match in re.finditer(agent_pattern, content):
            agent_name = match.group(1)
            agents[agent_name] = self._extract_agent_capabilities(content, match.start())

        # Build delegation graph
        delegation_graph: Dict[str, List[str]] = {}  # source -> targets

        for pattern, del_type in delegation_patterns:
            for match in re.finditer(pattern, content):
                # Find source agent context
                source_context = content[max(0, match.start()-500):match.start()]
                source_agent = None
                for agent in agents:
                    if agent in source_context:
                        source_agent = agent

                # Find target
                if match.groups():
                    target = match.group(1).strip("'\"")
                    if source_agent and target in agents:
                        if source_agent not in delegation_graph:
                            delegation_graph[source_agent] = []
                        delegation_graph[source_agent].append(target)

        # Build chains from graph
        for start_agent in delegation_graph:
            chain = self._build_chain(start_agent, delegation_graph, agents)
            if chain:
                chains.append(chain)

        return chains

    def _extract_agent_capabilities(self, content: str, start_pos: int) -> Set[str]:
        """Extract capabilities from agent definition."""
        capabilities: Set[str] = set()
        end_pos = content.find(')', start_pos)
        if end_pos == -1:
            end_pos = min(start_pos + 1000, len(content))

        chunk = content[start_pos:end_pos]

        # Check for various capabilities
        if 'shell' in chunk.lower() or 'execute' in chunk.lower():
            capabilities.add('shell')
        if 'file' in chunk.lower():
            capabilities.add('file')
        if 'http' in chunk.lower() or 'web' in chunk.lower():
            capabilities.add('network')
        if 'admin' in chunk.lower() or 'root' in chunk.lower():
            capabilities.add('admin')
        if 'code' in chunk.lower() or 'eval' in chunk.lower():
            capabilities.add('code_execution')

        return capabilities

    def _build_chain(
        self,
        start: str,
        graph: Dict[str, List[str]],
        agents: Dict[str, Set[str]]
    ) -> Optional[DelegationChain]:
        """Build a delegation chain from the graph."""
        chain = DelegationChain(chain_id=start)
        visited: Set[str] = set()
        current = start
        has_cycle = False

        while current in graph and current not in visited:
            visited.add(current)
            chain.agents.append(current)
            chain.capabilities_at_each_step.append(list(agents.get(current, set())))

            targets = graph[current]
            if targets:
                next_agent = targets[0]
                if next_agent in visited:
                    has_cycle = True
                    chain.has_cycle = True
                    break
                current = next_agent
            else:
                break

        if len(chain.agents) > 1:
            chain.max_depth = len(chain.agents)
            chain.has_privilege_escalation = self._check_chain_escalation(chain)
            return chain

        return None

    def _check_chain_escalation(self, chain: DelegationChain) -> bool:
        """Check if a chain has privilege escalation."""
        high_priv_caps = {'shell', 'admin', 'code_execution'}

        for i in range(len(chain.capabilities_at_each_step) - 1):
            current_caps = set(chain.capabilities_at_each_step[i])
            next_caps = set(chain.capabilities_at_each_step[i + 1])

            # Check if target has more sensitive caps than source
            sensitive_gained = (next_caps & high_priv_caps) - (current_caps & high_priv_caps)
            if sensitive_gained:
                return True

        return False

    def _check_circular_delegation(self, content: str, file_path: str, chains: List[DelegationChain]) -> None:
        """Check for circular delegation (MA-DEL-001)."""
        for chain in chains:
            if chain.has_cycle:
                rule = DELEGATION_RULES["MA-DEL-001"]
                self.findings.append(Finding(
                    rule_id="MA-DEL-001",
                    title=rule["title"],
                    description=f"Circular delegation detected: {' -> '.join(chain.agents)}. {rule['description']}",
                    severity=rule["severity"],
                    location=Location(file_path=file_path),
                    remediation=rule["remediation"],
                    cwe_id=rule["cwe_id"],
                    owasp_id=rule["owasp_id"],
                ))

    def _check_privilege_escalation(self, content: str, file_path: str, chains: List[DelegationChain]) -> None:
        """Check for privilege escalation (MA-DEL-002)."""
        for chain in chains:
            if chain.has_privilege_escalation:
                rule = DELEGATION_RULES["MA-DEL-002"]
                self.findings.append(Finding(
                    rule_id="MA-DEL-002",
                    title=rule["title"],
                    description=f"Privilege escalation path: {' -> '.join(chain.agents)}. {rule['description']}",
                    severity=rule["severity"],
                    location=Location(file_path=file_path),
                    remediation=rule["remediation"],
                    cwe_id=rule["cwe_id"],
                    owasp_id=rule["owasp_id"],
                ))

    def _check_delegation_depth(self, content: str, file_path: str) -> None:
        """Check for unlimited delegation depth (MA-DEL-003)."""
        has_delegation = 'delegate' in content.lower() or 'allow_delegation=True' in content

        depth_limits = ['max_delegation', 'delegation_limit', 'max_depth', 'depth_limit']
        has_limit = any(l in content.lower() for l in depth_limits)

        if has_delegation and not has_limit:
            rule = DELEGATION_RULES["MA-DEL-003"]
            self.findings.append(Finding(
                rule_id="MA-DEL-003",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_authorization(self, content: str, file_path: str) -> None:
        """Check for delegation without authorization (MA-DEL-004)."""
        delegation_patterns = ['.delegate(', '.assign_task(', '.hand_off(']
        has_delegation = any(p in content for p in delegation_patterns)

        auth_patterns = ['authorize', 'permission', 'can_delegate', 'is_allowed', 'check_access']
        has_auth = any(p in content.lower() for p in auth_patterns)

        if has_delegation and not has_auth:
            rule = DELEGATION_RULES["MA-DEL-004"]
            self.findings.append(Finding(
                rule_id="MA-DEL-004",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_task_injection(self, content: str, file_path: str) -> None:
        """Check for task injection via delegation (MA-DEL-005)."""
        # Look for dynamic task content in delegation
        injection_patterns = [
            r'delegate\s*\(\s*f["\']', r'delegate\s*\(\s*.*\+',
            r'task\s*=\s*f["\'].*delegate', r'delegate.*format\s*\(',
            r'assign_task\s*\(\s*f["\']'
        ]

        for pattern in injection_patterns:
            if re.search(pattern, content):
                sanitize_patterns = ['sanitize', 'validate_task', 'clean_task']
                has_sanitize = any(s in content.lower() for s in sanitize_patterns)

                if not has_sanitize:
                    rule = DELEGATION_RULES["MA-DEL-005"]
                    self.findings.append(Finding(
                        rule_id="MA-DEL-005",
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        location=Location(file_path=file_path),
                        remediation=rule["remediation"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    ))
                    break

    def _check_untrusted_delegation(self, content: str, file_path: str) -> None:
        """Check for delegation to untrusted agents (MA-DEL-006)."""
        has_delegation = 'delegate' in content.lower() or 'allow_delegation=True' in content

        trust_patterns = ['trusted_agents', 'agent_registry', 'verify_agent', 'is_trusted']
        has_trust_check = any(p in content.lower() for p in trust_patterns)

        if has_delegation and not has_trust_check:
            rule = DELEGATION_RULES["MA-DEL-006"]
            self.findings.append(Finding(
                rule_id="MA-DEL-006",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_result_tampering(self, content: str, file_path: str) -> None:
        """Check for result tampering (MA-DEL-007)."""
        # Delegation with result handling but no verification
        result_patterns = ['delegation_result', 'task_result', 'delegated_output', 'await delegate']
        has_results = any(p in content for p in result_patterns)

        verify_patterns = ['verify_result', 'sign_result', 'check_integrity', 'validate_output']
        has_verification = any(p in content.lower() for p in verify_patterns)

        if has_results and not has_verification:
            rule = DELEGATION_RULES["MA-DEL-007"]
            self.findings.append(Finding(
                rule_id="MA-DEL-007",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_deadlock_risk(self, content: str, file_path: str, chains: List[DelegationChain]) -> None:
        """Check for deadlock risk (MA-DEL-008)."""
        # Multiple agents with bidirectional delegation
        bidirectional = False
        agents_delegating: Set[str] = set()

        for chain in chains:
            if chain.has_cycle:
                bidirectional = True
                agents_delegating.update(chain.agents)

        timeout_patterns = ['timeout', 'deadline', 'max_wait']
        has_timeout = any(p in content.lower() for p in timeout_patterns)

        if bidirectional and not has_timeout:
            rule = DELEGATION_RULES["MA-DEL-008"]
            self.findings.append(Finding(
                rule_id="MA-DEL-008",
                title=rule["title"],
                description=f"Potential deadlock between: {', '.join(list(agents_delegating)[:3])}. {rule['description']}",
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_capability_leakage(self, content: str, file_path: str) -> None:
        """Check for capability leakage (MA-DEL-009)."""
        # Delegation with full context
        context_patterns = [
            r'delegate\s*\(.*context\s*=', r'delegate\s*\(.*state\s*=',
            r'delegate\s*\(.*\*\*', r'pass.*context.*delegate'
        ]

        has_context_passing = any(re.search(p, content) for p in context_patterns)

        filter_patterns = ['filter_context', 'minimal_context', 'sanitize_state']
        has_filtering = any(p in content.lower() for p in filter_patterns)

        if has_context_passing and not has_filtering:
            rule = DELEGATION_RULES["MA-DEL-009"]
            self.findings.append(Finding(
                rule_id="MA-DEL-009",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_self_delegation(self, content: str, file_path: str) -> None:
        """Check for recursive self-delegation (MA-DEL-010)."""
        # Agent delegating to itself
        self_delegation_patterns = [
            r'self\.delegate\s*\(\s*self', r'delegate\s*\(\s*self\)',
            r'agent\.delegate\s*\(\s*agent', r'\.delegate\s*\(\s*self\.'
        ]

        for pattern in self_delegation_patterns:
            if re.search(pattern, content):
                recursion_limit = ['recursion_limit', 'max_recursion', 'depth_check']
                has_limit = any(l in content.lower() for l in recursion_limit)

                if not has_limit:
                    rule = DELEGATION_RULES["MA-DEL-010"]
                    self.findings.append(Finding(
                        rule_id="MA-DEL-010",
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        location=Location(file_path=file_path),
                        remediation=rule["remediation"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    ))
                    break
