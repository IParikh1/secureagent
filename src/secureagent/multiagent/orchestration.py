"""Multi-agent orchestration security analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Set, Any

from secureagent.core.models.finding import Finding, Location
from secureagent.core.models.severity import Severity


class OrchestrationPattern(str, Enum):
    """Types of agent orchestration patterns."""
    SEQUENTIAL = "sequential"  # Agents run one after another
    PARALLEL = "parallel"  # Agents run concurrently
    HIERARCHICAL = "hierarchical"  # Manager-worker pattern
    CONSENSUS = "consensus"  # Agents vote/agree on decisions
    SWARM = "swarm"  # Autonomous agents with emergent behavior
    PIPELINE = "pipeline"  # Data flows through agent chain
    ROUTER = "router"  # Central agent routes to specialists
    LOOP = "loop"  # Agents in a feedback loop
    DAG = "dag"  # Directed acyclic graph workflow
    UNKNOWN = "unknown"


class OrchestrationRisk(str, Enum):
    """Risk levels for orchestration patterns."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class WorkflowNode:
    """Represents a node (agent) in an orchestration workflow."""
    node_id: str
    agent_name: str
    agent_type: str = "unknown"
    capabilities: List[str] = field(default_factory=list)
    has_external_access: bool = False
    has_tool_access: bool = False
    is_entry_point: bool = False
    is_exit_point: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowEdge:
    """Represents an edge (connection) between agents."""
    source_id: str
    target_id: str
    edge_type: str = "message"  # message, delegation, data, control
    is_bidirectional: bool = False
    has_validation: bool = False
    data_types: List[str] = field(default_factory=list)
    conditions: List[str] = field(default_factory=list)


@dataclass
class AgentWorkflow:
    """Represents a complete agent workflow/orchestration."""
    workflow_id: str
    name: str = ""
    pattern: OrchestrationPattern = OrchestrationPattern.UNKNOWN
    nodes: List[WorkflowNode] = field(default_factory=list)
    edges: List[WorkflowEdge] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    exit_points: List[str] = field(default_factory=list)
    has_cycles: bool = False
    max_depth: int = 0

    def get_node(self, node_id: str) -> Optional[WorkflowNode]:
        """Get a node by ID."""
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        return None

    def get_successors(self, node_id: str) -> List[str]:
        """Get successor node IDs."""
        return [e.target_id for e in self.edges if e.source_id == node_id]

    def get_predecessors(self, node_id: str) -> List[str]:
        """Get predecessor node IDs."""
        return [e.source_id for e in self.edges if e.target_id == node_id]


# Security rules for orchestration patterns
ORCHESTRATION_RULES = {
    "MA-ORCH-001": {
        "id": "MA-ORCH-001",
        "title": "Circular Agent Dependency",
        "severity": Severity.HIGH,
        "description": "Detected circular dependencies in agent workflow that could cause infinite loops",
        "cwe_id": "CWE-835",
        "owasp_id": "LLM04",
        "remediation": "Break circular dependencies by adding termination conditions or loop limits",
    },
    "MA-ORCH-002": {
        "id": "MA-ORCH-002",
        "title": "Uncontrolled Agent Spawning",
        "severity": Severity.HIGH,
        "description": "Agent can spawn new agents without limits, risking resource exhaustion",
        "cwe_id": "CWE-770",
        "owasp_id": "LLM04",
        "remediation": "Implement agent spawn limits and resource quotas",
    },
    "MA-ORCH-003": {
        "id": "MA-ORCH-003",
        "title": "No Workflow Timeout",
        "severity": Severity.MEDIUM,
        "description": "Agent workflow has no global timeout, risking runaway execution",
        "cwe_id": "CWE-400",
        "owasp_id": "LLM04",
        "remediation": "Add global workflow timeout and per-agent execution limits",
    },
    "MA-ORCH-004": {
        "id": "MA-ORCH-004",
        "title": "Privilege Escalation Path",
        "severity": Severity.CRITICAL,
        "description": "Agent workflow allows privilege escalation through delegation chain",
        "cwe_id": "CWE-269",
        "owasp_id": "LLM08",
        "remediation": "Implement capability-based access control with no escalation",
    },
    "MA-ORCH-005": {
        "id": "MA-ORCH-005",
        "title": "Single Point of Failure",
        "severity": Severity.MEDIUM,
        "description": "Critical workflow path depends on single agent without fallback",
        "cwe_id": "CWE-654",
        "owasp_id": "LLM04",
        "remediation": "Add redundancy or fallback handlers for critical paths",
    },
    "MA-ORCH-006": {
        "id": "MA-ORCH-006",
        "title": "Unrestricted Parallel Execution",
        "severity": Severity.MEDIUM,
        "description": "No limit on parallel agent execution, risking resource exhaustion",
        "cwe_id": "CWE-770",
        "owasp_id": "LLM04",
        "remediation": "Implement concurrency limits for parallel agent execution",
    },
    "MA-ORCH-007": {
        "id": "MA-ORCH-007",
        "title": "State Corruption Risk",
        "severity": Severity.HIGH,
        "description": "Multiple agents can modify shared state without synchronization",
        "cwe_id": "CWE-362",
        "owasp_id": "LLM04",
        "remediation": "Implement state locking or use immutable state patterns",
    },
    "MA-ORCH-008": {
        "id": "MA-ORCH-008",
        "title": "Cascading Failure Risk",
        "severity": Severity.MEDIUM,
        "description": "Agent failure can cascade through workflow without isolation",
        "cwe_id": "CWE-636",
        "owasp_id": "LLM04",
        "remediation": "Implement circuit breakers and failure isolation between agents",
    },
    "MA-ORCH-009": {
        "id": "MA-ORCH-009",
        "title": "External Entry Point Without Validation",
        "severity": Severity.HIGH,
        "description": "Workflow entry point accepts external input without validation",
        "cwe_id": "CWE-20",
        "owasp_id": "LLM03",
        "remediation": "Validate and sanitize all external inputs at workflow entry points",
    },
    "MA-ORCH-010": {
        "id": "MA-ORCH-010",
        "title": "Sensitive Data in Workflow State",
        "severity": Severity.MEDIUM,
        "description": "Sensitive data passed through workflow without encryption",
        "cwe_id": "CWE-311",
        "owasp_id": "LLM02",
        "remediation": "Encrypt sensitive data in workflow state and transit",
    },
}


class OrchestrationAnalyzer:
    """Analyzer for multi-agent orchestration security."""

    def __init__(self):
        self.findings: List[Finding] = []
        self.workflows: List[AgentWorkflow] = []

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file for orchestration security issues."""
        self.findings = []

        try:
            content = file_path.read_text()
        except Exception:
            return self.findings

        # Detect orchestration patterns
        workflow = self._extract_workflow(content, str(file_path))
        if workflow:
            self.workflows.append(workflow)
            self._analyze_workflow(workflow, str(file_path), content)

        return self.findings

    def analyze_directory(self, dir_path: str) -> List[Finding]:
        """Analyze a directory for orchestration issues."""
        self.findings = []
        path = Path(dir_path)

        for file_path in path.rglob("*.py"):
            self.analyze_file(file_path)

        return self.findings

    def _extract_workflow(self, content: str, file_path: str) -> Optional[AgentWorkflow]:
        """Extract workflow structure from code."""
        workflow = AgentWorkflow(workflow_id=file_path)

        # Detect LangGraph patterns
        if "StateGraph" in content or "langgraph" in content.lower():
            workflow.pattern = OrchestrationPattern.DAG
            self._extract_langgraph_workflow(content, workflow)

        # Detect AutoGen patterns
        elif "autogen" in content.lower() and ("GroupChat" in content or "AssistantAgent" in content):
            workflow.pattern = OrchestrationPattern.CONSENSUS
            self._extract_autogen_workflow(content, workflow)

        # Detect CrewAI patterns
        elif "crewai" in content.lower():
            if "hierarchical" in content.lower():
                workflow.pattern = OrchestrationPattern.HIERARCHICAL
            else:
                workflow.pattern = OrchestrationPattern.SEQUENTIAL
            self._extract_crewai_workflow(content, workflow)

        # Detect generic patterns
        else:
            self._detect_generic_patterns(content, workflow)

        if workflow.nodes:
            # Detect cycles
            workflow.has_cycles = self._detect_cycles(workflow)
            # Calculate max depth
            workflow.max_depth = self._calculate_max_depth(workflow)
            return workflow

        return None

    def _extract_langgraph_workflow(self, content: str, workflow: AgentWorkflow) -> None:
        """Extract LangGraph workflow structure."""
        # Find node additions
        node_pattern = r'\.add_node\s*\(\s*["\'](\w+)["\']'
        for match in re.finditer(node_pattern, content):
            node_id = match.group(1)
            node = WorkflowNode(node_id=node_id, agent_name=node_id)

            # Check for tool access
            if f'"{node_id}"' in content and "tool" in content.lower():
                node.has_tool_access = True

            workflow.nodes.append(node)

        # Find edges
        edge_pattern = r'\.add_edge\s*\(\s*["\'](\w+)["\']\s*,\s*["\'](\w+)["\']'
        for match in re.finditer(edge_pattern, content):
            source, target = match.group(1), match.group(2)
            edge = WorkflowEdge(source_id=source, target_id=target)
            workflow.edges.append(edge)

        # Find conditional edges
        cond_edge_pattern = r'\.add_conditional_edges\s*\(\s*["\'](\w+)["\']'
        for match in re.finditer(cond_edge_pattern, content):
            source = match.group(1)
            # Conditional edges can go to multiple targets
            edge = WorkflowEdge(source_id=source, target_id="conditional", edge_type="control")
            workflow.edges.append(edge)

        # Detect entry and exit points
        if "START" in content or "__start__" in content:
            workflow.entry_points.append("__start__")
        if "END" in content or "__end__" in content:
            workflow.exit_points.append("__end__")

    def _extract_autogen_workflow(self, content: str, workflow: AgentWorkflow) -> None:
        """Extract AutoGen workflow structure."""
        # Find agent definitions
        agent_pattern = r'(\w+)\s*=\s*(?:AssistantAgent|UserProxyAgent|ConversableAgent)\s*\('
        for match in re.finditer(agent_pattern, content):
            agent_name = match.group(1)
            node = WorkflowNode(node_id=agent_name, agent_name=agent_name)

            # Check agent type
            if "UserProxyAgent" in content[match.start():match.start()+200]:
                node.is_entry_point = True
                node.has_external_access = True

            workflow.nodes.append(node)

        # Find GroupChat
        groupchat_pattern = r'GroupChat\s*\(\s*agents\s*=\s*\[([^\]]+)\]'
        for match in re.finditer(groupchat_pattern, content):
            agents_str = match.group(1)
            # All agents in group chat can communicate with each other
            agent_names = re.findall(r'\b(\w+)\b', agents_str)
            for i, src in enumerate(agent_names):
                for tgt in agent_names[i+1:]:
                    edge = WorkflowEdge(source_id=src, target_id=tgt, is_bidirectional=True)
                    workflow.edges.append(edge)

    def _extract_crewai_workflow(self, content: str, workflow: AgentWorkflow) -> None:
        """Extract CrewAI workflow structure."""
        # Find agent definitions
        agent_pattern = r'(\w+)\s*=\s*Agent\s*\('
        for match in re.finditer(agent_pattern, content):
            agent_name = match.group(1)
            node = WorkflowNode(node_id=agent_name, agent_name=agent_name)

            # Check for delegation
            chunk = content[match.start():match.start()+500]
            if "allow_delegation=True" in chunk:
                node.capabilities.append("delegation")
            if "tools=" in chunk:
                node.has_tool_access = True

            workflow.nodes.append(node)

        # In CrewAI, agents in a crew can interact
        crew_pattern = r'Crew\s*\(\s*agents\s*=\s*\[([^\]]+)\]'
        for match in re.finditer(crew_pattern, content):
            agents_str = match.group(1)
            agent_names = re.findall(r'\b(\w+)\b', agents_str)

            # Sequential: each agent passes to next
            for i in range(len(agent_names) - 1):
                edge = WorkflowEdge(source_id=agent_names[i], target_id=agent_names[i+1])
                workflow.edges.append(edge)

    def _detect_generic_patterns(self, content: str, workflow: AgentWorkflow) -> None:
        """Detect generic multi-agent patterns."""
        # Look for common agent patterns
        patterns = [
            (r'async\s+def\s+(\w+_agent)\s*\(', "async agent"),
            (r'class\s+(\w+Agent)\s*[:\(]', "agent class"),
            (r'def\s+run_(\w+)\s*\(', "runner function"),
        ]

        for pattern, agent_type in patterns:
            for match in re.finditer(pattern, content):
                node = WorkflowNode(
                    node_id=match.group(1),
                    agent_name=match.group(1),
                    agent_type=agent_type
                )
                workflow.nodes.append(node)

    def _detect_cycles(self, workflow: AgentWorkflow) -> bool:
        """Detect cycles in workflow using DFS."""
        visited: Set[str] = set()
        rec_stack: Set[str] = set()

        def dfs(node_id: str) -> bool:
            visited.add(node_id)
            rec_stack.add(node_id)

            for successor in workflow.get_successors(node_id):
                if successor not in visited:
                    if dfs(successor):
                        return True
                elif successor in rec_stack:
                    return True

            rec_stack.remove(node_id)
            return False

        for node in workflow.nodes:
            if node.node_id not in visited:
                if dfs(node.node_id):
                    return True

        return False

    def _calculate_max_depth(self, workflow: AgentWorkflow) -> int:
        """Calculate maximum depth of workflow."""
        if not workflow.nodes:
            return 0

        depths: Dict[str, int] = {}

        def get_depth(node_id: str, visited: Set[str]) -> int:
            if node_id in depths:
                return depths[node_id]
            if node_id in visited:
                return 0  # Cycle detected

            visited.add(node_id)
            successors = workflow.get_successors(node_id)

            if not successors:
                depths[node_id] = 1
            else:
                depths[node_id] = 1 + max(
                    get_depth(s, visited) for s in successors
                )

            visited.remove(node_id)
            return depths[node_id]

        # Find entry points or use all nodes with no predecessors
        entry_nodes = [n.node_id for n in workflow.nodes
                       if not workflow.get_predecessors(n.node_id)]

        if not entry_nodes:
            entry_nodes = [workflow.nodes[0].node_id]

        return max(get_depth(n, set()) for n in entry_nodes)

    def _analyze_workflow(self, workflow: AgentWorkflow, file_path: str, content: str) -> None:
        """Analyze workflow for security issues."""
        self._check_circular_dependencies(workflow, file_path, content)
        self._check_agent_spawning(workflow, file_path, content)
        self._check_workflow_timeout(workflow, file_path, content)
        self._check_privilege_escalation(workflow, file_path, content)
        self._check_single_point_of_failure(workflow, file_path, content)
        self._check_parallel_execution(workflow, file_path, content)
        self._check_state_corruption(workflow, file_path, content)
        self._check_cascading_failure(workflow, file_path, content)
        self._check_entry_validation(workflow, file_path, content)
        self._check_sensitive_data(workflow, file_path, content)

    def _check_circular_dependencies(self, workflow: AgentWorkflow, file_path: str, content: str) -> None:
        """Check for circular dependencies (MA-ORCH-001)."""
        if workflow.has_cycles:
            rule = ORCHESTRATION_RULES["MA-ORCH-001"]

            # Check if there's loop termination
            has_termination = any(term in content.lower() for term in
                ["max_iterations", "max_steps", "recursion_limit", "loop_limit"])

            if not has_termination:
                self.findings.append(Finding(
                    rule_id="MA-ORCH-001",
                    title=rule["title"],
                    description=f"Workflow contains cycles without termination conditions. {rule['description']}",
                    severity=rule["severity"],
                    location=Location(file_path=file_path),
                    remediation=rule["remediation"],
                    cwe_id=rule["cwe_id"],
                    owasp_id=rule["owasp_id"],
                ))

    def _check_agent_spawning(self, workflow: AgentWorkflow, file_path: str, content: str) -> None:
        """Check for uncontrolled agent spawning (MA-ORCH-002)."""
        spawn_patterns = [
            r'spawn.*agent', r'create.*agent', r'new.*Agent\(',
            r'fork\s*\(', r'multiprocessing', r'ThreadPoolExecutor'
        ]

        has_spawning = any(re.search(p, content, re.IGNORECASE) for p in spawn_patterns)
        has_limits = any(limit in content.lower() for limit in
            ["max_agents", "agent_limit", "pool_size", "max_workers"])

        if has_spawning and not has_limits:
            rule = ORCHESTRATION_RULES["MA-ORCH-002"]
            self.findings.append(Finding(
                rule_id="MA-ORCH-002",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_workflow_timeout(self, workflow: AgentWorkflow, file_path: str, content: str) -> None:
        """Check for workflow timeout (MA-ORCH-003)."""
        timeout_patterns = ["timeout=", "timeout:", "max_time", "deadline", "time_limit"]
        has_timeout = any(p in content.lower() for p in timeout_patterns)

        if not has_timeout and len(workflow.nodes) > 1:
            rule = ORCHESTRATION_RULES["MA-ORCH-003"]
            self.findings.append(Finding(
                rule_id="MA-ORCH-003",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_privilege_escalation(self, workflow: AgentWorkflow, file_path: str, content: str) -> None:
        """Check for privilege escalation paths (MA-ORCH-004)."""
        # Find agents with different capability levels
        high_priv_indicators = ["admin", "sudo", "root", "shell", "execute", "system"]

        high_priv_nodes = []
        low_priv_nodes = []

        for node in workflow.nodes:
            node_content_idx = content.lower().find(node.node_id.lower())
            if node_content_idx != -1:
                chunk = content[node_content_idx:node_content_idx+500].lower()
                if any(p in chunk for p in high_priv_indicators):
                    high_priv_nodes.append(node.node_id)
                else:
                    low_priv_nodes.append(node.node_id)

        # Check if low-priv can reach high-priv through delegation
        for low in low_priv_nodes:
            for high in high_priv_nodes:
                if self._can_reach(workflow, low, high):
                    rule = ORCHESTRATION_RULES["MA-ORCH-004"]
                    self.findings.append(Finding(
                        rule_id="MA-ORCH-004",
                        title=rule["title"],
                        description=f"Agent '{low}' can reach privileged agent '{high}' through delegation. {rule['description']}",
                        severity=rule["severity"],
                        location=Location(file_path=file_path),
                        remediation=rule["remediation"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    ))
                    break

    def _can_reach(self, workflow: AgentWorkflow, source: str, target: str) -> bool:
        """Check if source can reach target in workflow."""
        visited: Set[str] = set()
        queue = [source]

        while queue:
            current = queue.pop(0)
            if current == target:
                return True
            if current in visited:
                continue
            visited.add(current)
            queue.extend(workflow.get_successors(current))

        return False

    def _check_single_point_of_failure(self, workflow: AgentWorkflow, file_path: str, content: str) -> None:
        """Check for single points of failure (MA-ORCH-005)."""
        if len(workflow.nodes) < 3:
            return

        # Find nodes that are on all paths from entry to exit
        critical_nodes = []
        for node in workflow.nodes:
            if node.is_entry_point or node.is_exit_point:
                continue
            # Check if removing this node disconnects the graph
            predecessors = workflow.get_predecessors(node.node_id)
            successors = workflow.get_successors(node.node_id)
            if predecessors and successors and len(predecessors) == 1 and len(successors) == 1:
                critical_nodes.append(node.node_id)

        # Check for fallback/retry logic
        has_fallback = any(f in content.lower() for f in
            ["fallback", "retry", "backup", "failover", "circuit_breaker"])

        if critical_nodes and not has_fallback:
            rule = ORCHESTRATION_RULES["MA-ORCH-005"]
            self.findings.append(Finding(
                rule_id="MA-ORCH-005",
                title=rule["title"],
                description=f"Critical nodes without fallback: {', '.join(critical_nodes[:3])}. {rule['description']}",
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_parallel_execution(self, workflow: AgentWorkflow, file_path: str, content: str) -> None:
        """Check for unrestricted parallel execution (MA-ORCH-006)."""
        parallel_patterns = [
            r'asyncio\.gather', r'concurrent\.futures', r'multiprocessing\.Pool',
            r'ThreadPoolExecutor', r'ProcessPoolExecutor', r'parallel\s*=\s*True'
        ]

        has_parallel = any(re.search(p, content) for p in parallel_patterns)
        has_limits = any(limit in content for limit in
            ["max_workers=", "max_workers:", "semaphore", "Semaphore", "limit="])

        if has_parallel and not has_limits:
            rule = ORCHESTRATION_RULES["MA-ORCH-006"]
            self.findings.append(Finding(
                rule_id="MA-ORCH-006",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_state_corruption(self, workflow: AgentWorkflow, file_path: str, content: str) -> None:
        """Check for state corruption risks (MA-ORCH-007)."""
        # Multiple agents + shared state + no locking
        shared_state_patterns = [
            r'global\s+\w+', r'shared_state', r'state\s*=\s*\{\}',
            r'class\s+\w*State', r'mutable.*state'
        ]
        lock_patterns = ['Lock()', 'RLock()', 'Semaphore', 'mutex', 'synchronized']

        has_shared_state = any(re.search(p, content) for p in shared_state_patterns)
        has_locking = any(p in content for p in lock_patterns)

        if has_shared_state and len(workflow.nodes) > 1 and not has_locking:
            rule = ORCHESTRATION_RULES["MA-ORCH-007"]
            self.findings.append(Finding(
                rule_id="MA-ORCH-007",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_cascading_failure(self, workflow: AgentWorkflow, file_path: str, content: str) -> None:
        """Check for cascading failure risks (MA-ORCH-008)."""
        # Deep workflows without error isolation
        if workflow.max_depth >= 3:
            isolation_patterns = ['circuit_breaker', 'try:', 'except:', 'catch', 'on_error', 'error_handler']
            has_isolation = sum(1 for p in isolation_patterns if p in content.lower()) >= 2

            if not has_isolation:
                rule = ORCHESTRATION_RULES["MA-ORCH-008"]
                self.findings.append(Finding(
                    rule_id="MA-ORCH-008",
                    title=rule["title"],
                    description=f"Workflow depth of {workflow.max_depth} without adequate error isolation. {rule['description']}",
                    severity=rule["severity"],
                    location=Location(file_path=file_path),
                    remediation=rule["remediation"],
                    cwe_id=rule["cwe_id"],
                    owasp_id=rule["owasp_id"],
                ))

    def _check_entry_validation(self, workflow: AgentWorkflow, file_path: str, content: str) -> None:
        """Check for entry point validation (MA-ORCH-009)."""
        entry_nodes = [n for n in workflow.nodes if n.is_entry_point or n.has_external_access]

        if entry_nodes:
            validation_patterns = ['validate', 'sanitize', 'schema', 'pydantic', 'validator']
            has_validation = any(p in content.lower() for p in validation_patterns)

            if not has_validation:
                rule = ORCHESTRATION_RULES["MA-ORCH-009"]
                self.findings.append(Finding(
                    rule_id="MA-ORCH-009",
                    title=rule["title"],
                    description=f"Entry points ({', '.join(n.node_id for n in entry_nodes)}) without apparent validation. {rule['description']}",
                    severity=rule["severity"],
                    location=Location(file_path=file_path),
                    remediation=rule["remediation"],
                    cwe_id=rule["cwe_id"],
                    owasp_id=rule["owasp_id"],
                ))

    def _check_sensitive_data(self, workflow: AgentWorkflow, file_path: str, content: str) -> None:
        """Check for sensitive data in workflow state (MA-ORCH-010)."""
        sensitive_patterns = [
            r'password', r'api_key', r'secret', r'token', r'credential',
            r'ssn', r'credit_card', r'social_security'
        ]
        encryption_patterns = ['encrypt', 'crypto', 'fernet', 'aes', 'kms']

        has_sensitive = any(re.search(p, content, re.IGNORECASE) for p in sensitive_patterns)
        has_encryption = any(p in content.lower() for p in encryption_patterns)

        if has_sensitive and not has_encryption and len(workflow.nodes) > 1:
            rule = ORCHESTRATION_RULES["MA-ORCH-010"]
            self.findings.append(Finding(
                rule_id="MA-ORCH-010",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))
