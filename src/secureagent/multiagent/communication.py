"""Multi-agent communication security analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any

from secureagent.core.models.finding import Finding, Location
from secureagent.core.models.severity import Severity


class MessageType(str, Enum):
    """Types of inter-agent messages."""
    TASK = "task"  # Task delegation
    RESULT = "result"  # Task completion result
    QUERY = "query"  # Information request
    RESPONSE = "response"  # Query response
    CONTROL = "control"  # Control signal
    DATA = "data"  # Data transfer
    ERROR = "error"  # Error notification
    HEARTBEAT = "heartbeat"  # Health check
    UNKNOWN = "unknown"


class ChannelSecurity(str, Enum):
    """Security level of communication channel."""
    ENCRYPTED = "encrypted"
    SIGNED = "signed"
    AUTHENTICATED = "authenticated"
    PLAINTEXT = "plaintext"
    UNKNOWN = "unknown"


@dataclass
class CommunicationThreat:
    """Represents a communication security threat."""
    threat_id: str
    threat_type: str
    severity: Severity
    description: str
    source_agent: str = ""
    target_agent: str = ""
    evidence: str = ""
    remediation: str = ""


@dataclass
class AgentMessage:
    """Represents an inter-agent message."""
    message_id: str
    source_agent: str
    target_agent: str
    message_type: MessageType = MessageType.UNKNOWN
    channel_security: ChannelSecurity = ChannelSecurity.UNKNOWN
    has_validation: bool = False
    has_sanitization: bool = False
    payload_types: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# Communication security rules
COMMUNICATION_RULES = {
    "MA-COMM-001": {
        "id": "MA-COMM-001",
        "title": "Unencrypted Agent Communication",
        "severity": Severity.HIGH,
        "description": "Inter-agent messages transmitted without encryption",
        "cwe_id": "CWE-319",
        "owasp_id": "LLM02",
        "remediation": "Implement TLS/encryption for all inter-agent communication",
    },
    "MA-COMM-002": {
        "id": "MA-COMM-002",
        "title": "Missing Message Authentication",
        "severity": Severity.HIGH,
        "description": "Messages between agents lack authentication, enabling spoofing",
        "cwe_id": "CWE-306",
        "owasp_id": "LLM08",
        "remediation": "Implement message signing or HMAC for agent-to-agent messages",
    },
    "MA-COMM-003": {
        "id": "MA-COMM-003",
        "title": "Message Injection Vulnerability",
        "severity": Severity.CRITICAL,
        "description": "Agent messages can be injected with malicious payloads",
        "cwe_id": "CWE-94",
        "owasp_id": "LLM01",
        "remediation": "Validate and sanitize all message content before processing",
    },
    "MA-COMM-004": {
        "id": "MA-COMM-004",
        "title": "Unrestricted Message Broadcast",
        "severity": Severity.MEDIUM,
        "description": "Agents can broadcast to all other agents without restrictions",
        "cwe_id": "CWE-284",
        "owasp_id": "LLM08",
        "remediation": "Implement message routing with access controls",
    },
    "MA-COMM-005": {
        "id": "MA-COMM-005",
        "title": "Message Replay Vulnerability",
        "severity": Severity.MEDIUM,
        "description": "No protection against message replay attacks",
        "cwe_id": "CWE-294",
        "owasp_id": "LLM08",
        "remediation": "Add nonces or timestamps to prevent message replay",
    },
    "MA-COMM-006": {
        "id": "MA-COMM-006",
        "title": "Sensitive Data in Messages",
        "severity": Severity.HIGH,
        "description": "Sensitive data transmitted in agent messages without protection",
        "cwe_id": "CWE-312",
        "owasp_id": "LLM02",
        "remediation": "Encrypt sensitive fields in messages or use secure channels",
    },
    "MA-COMM-007": {
        "id": "MA-COMM-007",
        "title": "Message Size Unlimited",
        "severity": Severity.MEDIUM,
        "description": "No limits on message size, enabling DoS attacks",
        "cwe_id": "CWE-770",
        "owasp_id": "LLM04",
        "remediation": "Implement message size limits and rate limiting",
    },
    "MA-COMM-008": {
        "id": "MA-COMM-008",
        "title": "Command Execution in Messages",
        "severity": Severity.CRITICAL,
        "description": "Message content can trigger command execution",
        "cwe_id": "CWE-78",
        "owasp_id": "LLM01",
        "remediation": "Never execute message content directly; use allowlisted actions",
    },
    "MA-COMM-009": {
        "id": "MA-COMM-009",
        "title": "Trust Without Verification",
        "severity": Severity.HIGH,
        "description": "Agent trusts messages from other agents without verification",
        "cwe_id": "CWE-346",
        "owasp_id": "LLM08",
        "remediation": "Implement zero-trust message verification",
    },
    "MA-COMM-010": {
        "id": "MA-COMM-010",
        "title": "Message Queue Poisoning",
        "severity": Severity.HIGH,
        "description": "Message queue vulnerable to injection of malicious messages",
        "cwe_id": "CWE-502",
        "owasp_id": "LLM01",
        "remediation": "Validate message schema and source before queue insertion",
    },
}


class CommunicationAnalyzer:
    """Analyzer for multi-agent communication security."""

    def __init__(self):
        self.findings: List[Finding] = []
        self.messages: List[AgentMessage] = []
        self.threats: List[CommunicationThreat] = []

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file for communication security issues."""
        self.findings = []

        try:
            content = file_path.read_text()
        except Exception:
            return self.findings

        # Detect communication patterns
        self._detect_communication_patterns(content, str(file_path))

        # Analyze for security issues
        self._check_encryption(content, str(file_path))
        self._check_authentication(content, str(file_path))
        self._check_message_injection(content, str(file_path))
        self._check_broadcast(content, str(file_path))
        self._check_replay_protection(content, str(file_path))
        self._check_sensitive_data(content, str(file_path))
        self._check_message_size(content, str(file_path))
        self._check_command_execution(content, str(file_path))
        self._check_trust_verification(content, str(file_path))
        self._check_queue_security(content, str(file_path))

        return self.findings

    def analyze_directory(self, dir_path: str) -> List[Finding]:
        """Analyze a directory for communication issues."""
        self.findings = []
        path = Path(dir_path)

        for file_path in path.rglob("*.py"):
            self.analyze_file(file_path)

        return self.findings

    def _detect_communication_patterns(self, content: str, file_path: str) -> None:
        """Detect inter-agent communication patterns."""
        # Common message passing patterns
        patterns = [
            (r'\.send\s*\(\s*(["\'][^"\']+["\']),', "send"),
            (r'\.receive\s*\(', "receive"),
            (r'\.publish\s*\(', "publish"),
            (r'\.subscribe\s*\(', "subscribe"),
            (r'message_queue', "queue"),
            (r'\.emit\s*\(', "emit"),
            (r'websocket', "websocket"),
            (r'grpc', "grpc"),
            (r'\.post\s*\(', "http_post"),
        ]

        for pattern, comm_type in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                msg = AgentMessage(
                    message_id=f"{file_path}:{match.start()}",
                    source_agent="unknown",
                    target_agent="unknown",
                )
                self.messages.append(msg)

    def _check_encryption(self, content: str, file_path: str) -> None:
        """Check for unencrypted communication (MA-COMM-001)."""
        # Has communication but no encryption
        comm_patterns = ['send(', 'receive(', 'publish(', 'subscribe(', 'message_queue']
        has_communication = any(p in content for p in comm_patterns)

        encryption_patterns = ['ssl', 'tls', 'encrypt', 'https', 'wss://', 'crypto']
        has_encryption = any(p in content.lower() for p in encryption_patterns)

        if has_communication and not has_encryption:
            rule = COMMUNICATION_RULES["MA-COMM-001"]
            self.findings.append(Finding(
                rule_id="MA-COMM-001",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_authentication(self, content: str, file_path: str) -> None:
        """Check for missing authentication (MA-COMM-002)."""
        comm_patterns = ['send(', 'receive(', 'publish(']
        has_communication = any(p in content for p in comm_patterns)

        auth_patterns = ['verify_signature', 'hmac', 'jwt', 'authenticate', 'bearer', 'api_key']
        has_auth = any(p in content.lower() for p in auth_patterns)

        if has_communication and not has_auth:
            rule = COMMUNICATION_RULES["MA-COMM-002"]
            self.findings.append(Finding(
                rule_id="MA-COMM-002",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_message_injection(self, content: str, file_path: str) -> None:
        """Check for message injection vulnerabilities (MA-COMM-003)."""
        # Look for dynamic message content without sanitization
        injection_patterns = [
            (r'send\s*\(\s*f["\']', "f-string in send"),
            (r'send\s*\(\s*["\'].*\{.*\}', "format string in send"),
            (r'\.format\s*\([^)]*user', "user input in format"),
            (r'message\s*=\s*.*input\s*\(', "user input in message"),
            (r'payload\s*=\s*request\.', "request data in payload"),
        ]

        for pattern, desc in injection_patterns:
            if re.search(pattern, content):
                # Check for sanitization
                sanitize_patterns = ['sanitize', 'escape', 'validate', 'clean']
                has_sanitize = any(s in content.lower() for s in sanitize_patterns)

                if not has_sanitize:
                    rule = COMMUNICATION_RULES["MA-COMM-003"]
                    self.findings.append(Finding(
                        rule_id="MA-COMM-003",
                        title=rule["title"],
                        description=f"Detected {desc}. {rule['description']}",
                        severity=rule["severity"],
                        location=Location(file_path=file_path),
                        remediation=rule["remediation"],
                        cwe_id=rule["cwe_id"],
                        owasp_id=rule["owasp_id"],
                    ))
                    break

    def _check_broadcast(self, content: str, file_path: str) -> None:
        """Check for unrestricted broadcast (MA-COMM-004)."""
        broadcast_patterns = ['broadcast(', 'send_all(', 'notify_all(', 'emit_all(']
        has_broadcast = any(p in content for p in broadcast_patterns)

        restrict_patterns = ['filter', 'recipients', 'allowed_agents', 'acl', 'permission']
        has_restrictions = any(r in content.lower() for r in restrict_patterns)

        if has_broadcast and not has_restrictions:
            rule = COMMUNICATION_RULES["MA-COMM-004"]
            self.findings.append(Finding(
                rule_id="MA-COMM-004",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_replay_protection(self, content: str, file_path: str) -> None:
        """Check for replay protection (MA-COMM-005)."""
        comm_patterns = ['send(', 'receive(', 'message']
        has_communication = any(p in content for p in comm_patterns)

        replay_patterns = ['nonce', 'timestamp', 'sequence_number', 'message_id', 'idempotency']
        has_replay_protection = any(p in content.lower() for p in replay_patterns)

        if has_communication and not has_replay_protection:
            rule = COMMUNICATION_RULES["MA-COMM-005"]
            self.findings.append(Finding(
                rule_id="MA-COMM-005",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_sensitive_data(self, content: str, file_path: str) -> None:
        """Check for sensitive data in messages (MA-COMM-006)."""
        # Message with sensitive data patterns
        message_patterns = [
            r'message.*password', r'send.*token', r'payload.*secret',
            r'message.*api_key', r'emit.*credential', r'publish.*ssn'
        ]

        has_sensitive_message = any(re.search(p, content, re.IGNORECASE) for p in message_patterns)

        encryption_patterns = ['encrypt', 'mask', 'redact', 'hash(']
        has_protection = any(p in content.lower() for p in encryption_patterns)

        if has_sensitive_message and not has_protection:
            rule = COMMUNICATION_RULES["MA-COMM-006"]
            self.findings.append(Finding(
                rule_id="MA-COMM-006",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_message_size(self, content: str, file_path: str) -> None:
        """Check for message size limits (MA-COMM-007)."""
        comm_patterns = ['send(', 'receive(', 'message_queue', 'publish(']
        has_communication = any(p in content for p in comm_patterns)

        limit_patterns = ['max_size', 'size_limit', 'max_length', 'max_bytes', 'limit=']
        has_limits = any(p in content.lower() for p in limit_patterns)

        if has_communication and not has_limits:
            rule = COMMUNICATION_RULES["MA-COMM-007"]
            self.findings.append(Finding(
                rule_id="MA-COMM-007",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_command_execution(self, content: str, file_path: str) -> None:
        """Check for command execution in messages (MA-COMM-008)."""
        # Message content used in execution
        dangerous_patterns = [
            r'exec\s*\(\s*message', r'eval\s*\(\s*message', r'subprocess.*message',
            r'os\.system\s*\(\s*.*message', r'shell=True.*message',
            r'message.*\)\s*\(\)', r'getattr.*message'
        ]

        for pattern in dangerous_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                line_num = content[:match.start()].count('\n') + 1
                rule = COMMUNICATION_RULES["MA-COMM-008"]
                self.findings.append(Finding(
                    rule_id="MA-COMM-008",
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    location=Location(file_path=file_path, line_number=line_num),
                    remediation=rule["remediation"],
                    cwe_id=rule["cwe_id"],
                    owasp_id=rule["owasp_id"],
                ))
                break

    def _check_trust_verification(self, content: str, file_path: str) -> None:
        """Check for trust without verification (MA-COMM-009)."""
        # Multiple agents and message handling without verification
        multi_agent = 'agent' in content.lower() and content.lower().count('agent') > 2
        has_messaging = any(p in content for p in ['receive(', 'on_message', 'handle_message'])

        verify_patterns = ['verify', 'validate_sender', 'check_source', 'authenticate', 'is_trusted']
        has_verification = any(p in content.lower() for p in verify_patterns)

        if multi_agent and has_messaging and not has_verification:
            rule = COMMUNICATION_RULES["MA-COMM-009"]
            self.findings.append(Finding(
                rule_id="MA-COMM-009",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))

    def _check_queue_security(self, content: str, file_path: str) -> None:
        """Check for message queue security (MA-COMM-010)."""
        queue_patterns = ['queue.put', 'queue.add', 'enqueue', 'push_message']
        has_queue = any(p in content for p in queue_patterns)

        validation_patterns = ['validate_message', 'schema', 'check_message', 'message_validator']
        has_validation = any(p in content.lower() for p in validation_patterns)

        if has_queue and not has_validation:
            rule = COMMUNICATION_RULES["MA-COMM-010"]
            self.findings.append(Finding(
                rule_id="MA-COMM-010",
                title=rule["title"],
                description=rule["description"],
                severity=rule["severity"],
                location=Location(file_path=file_path),
                remediation=rule["remediation"],
                cwe_id=rule["cwe_id"],
                owasp_id=rule["owasp_id"],
            ))
