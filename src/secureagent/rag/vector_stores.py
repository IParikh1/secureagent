"""Vector store security analysis for RAG systems.

Analyzes security configurations for popular vector databases:
- Pinecone
- Chroma
- Weaviate
- Qdrant
- Milvus
- PGVector
- Redis Vector
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

from ..core.models.finding import Finding, FindingDomain, Location
from ..core.models.severity import Severity


class VectorStoreType(Enum):
    """Supported vector store types."""

    PINECONE = "pinecone"
    CHROMA = "chroma"
    WEAVIATE = "weaviate"
    QDRANT = "qdrant"
    MILVUS = "milvus"
    PGVECTOR = "pgvector"
    REDIS = "redis"
    FAISS = "faiss"
    UNKNOWN = "unknown"


@dataclass
class VectorStoreConfig:
    """Parsed vector store configuration."""

    store_type: VectorStoreType
    source_file: str
    line_number: Optional[int] = None

    # Connection settings
    host: Optional[str] = None
    port: Optional[int] = None
    api_key: Optional[str] = None
    api_key_env_var: Optional[str] = None
    connection_string: Optional[str] = None

    # Security settings
    uses_tls: bool = False
    auth_enabled: bool = False
    auth_type: Optional[str] = None
    encryption_at_rest: Optional[bool] = None

    # Access control
    has_acl: bool = False
    namespace: Optional[str] = None
    collection: Optional[str] = None

    # Network exposure
    is_public: bool = False
    allowed_ips: List[str] = field(default_factory=list)

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


class VectorStoreSecurityAnalyzer:
    """Analyzes vector store configurations for security issues."""

    # Patterns for detecting vector stores in code
    DETECTION_PATTERNS = {
        VectorStoreType.PINECONE: [
            r"pinecone\.init\s*\(",
            r"from\s+pinecone\s+import",
            r"import\s+pinecone",
            r"Pinecone\s*\(",
            r"pinecone\.Index\s*\(",
            r"PINECONE_API_KEY",
        ],
        VectorStoreType.CHROMA: [
            r"chromadb\.Client\s*\(",
            r"chromadb\.PersistentClient\s*\(",
            r"chromadb\.HttpClient\s*\(",
            r"from\s+chromadb\s+import",
            r"import\s+chromadb",
            r"Chroma\s*\(",
            r"Chroma\.from_",
        ],
        VectorStoreType.WEAVIATE: [
            r"weaviate\.Client\s*\(",
            r"weaviate\.connect_to",
            r"from\s+weaviate\s+import",
            r"import\s+weaviate",
            r"WEAVIATE_URL",
            r"WEAVIATE_API_KEY",
        ],
        VectorStoreType.QDRANT: [
            r"QdrantClient\s*\(",
            r"qdrant_client\.QdrantClient",
            r"from\s+qdrant_client\s+import",
            r"QDRANT_HOST",
            r"QDRANT_API_KEY",
        ],
        VectorStoreType.MILVUS: [
            r"connections\.connect\s*\(",
            r"from\s+pymilvus\s+import",
            r"import\s+pymilvus",
            r"Milvus\s*\(",
            r"MILVUS_HOST",
        ],
        VectorStoreType.PGVECTOR: [
            r"pgvector",
            r"PGVector\s*\(",
            r"create\s+extension.*vector",
            r"vector\s*\(",
        ],
        VectorStoreType.REDIS: [
            r"Redis\s*\(.*vector",
            r"redis\..*vector",
            r"RediSearch",
            r"REDIS_URL",
        ],
        VectorStoreType.FAISS: [
            r"faiss\.IndexFlatL2",
            r"faiss\.IndexIVF",
            r"from\s+faiss\s+import",
            r"import\s+faiss",
            r"FAISS\s*\(",
        ],
    }

    # Sensitive patterns to detect
    SENSITIVE_PATTERNS = {
        "hardcoded_api_key": [
            (r'api[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9\-_]{20,}["\']', "Hardcoded API key"),
            (r'PINECONE_API_KEY\s*=\s*["\'][^"\']+["\']', "Hardcoded Pinecone API key"),
            (r'WEAVIATE_API_KEY\s*=\s*["\'][^"\']+["\']', "Hardcoded Weaviate API key"),
            (r'QDRANT_API_KEY\s*=\s*["\'][^"\']+["\']', "Hardcoded Qdrant API key"),
        ],
        "public_endpoint": [
            (r'host\s*[=:]\s*["\']0\.0\.0\.0["\']', "Binding to all interfaces"),
            (r'host\s*[=:]\s*["\']localhost["\']', "Local-only binding (may be intentional)"),
        ],
        "insecure_connection": [
            (r'http://', "Using HTTP instead of HTTPS"),
            (r'ssl\s*[=:]\s*(False|false|0)', "SSL/TLS disabled"),
            (r'verify\s*[=:]\s*(False|false|0)', "SSL verification disabled"),
            (r'tls\s*[=:]\s*(False|false|0)', "TLS disabled"),
        ],
        "no_auth": [
            (r'auth\s*[=:]\s*(None|null|False)', "Authentication disabled"),
            (r'anonymous\s*[=:]\s*(True|true|1)', "Anonymous access enabled"),
        ],
    }

    def __init__(self):
        """Initialize the analyzer."""
        self.findings: List[Finding] = []

    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file for vector store security issues.

        Args:
            file_path: Path to file to analyze

        Returns:
            List of security findings
        """
        self.findings = []
        file_path = Path(file_path)

        if not file_path.exists():
            return []

        try:
            content = file_path.read_text()
        except Exception:
            return []

        # Detect vector store type
        store_types = self._detect_vector_stores(content)

        if not store_types:
            return []

        # Analyze for each detected store type
        for store_type in store_types:
            self._analyze_store_security(content, str(file_path), store_type)

        # General security checks
        self._check_hardcoded_credentials(content, str(file_path))
        self._check_insecure_connections(content, str(file_path))
        self._check_access_controls(content, str(file_path))

        return self.findings

    def analyze_config(self, config: VectorStoreConfig) -> List[Finding]:
        """Analyze a parsed vector store configuration.

        Args:
            config: Parsed vector store configuration

        Returns:
            List of security findings
        """
        self.findings = []

        # Check for hardcoded API key
        if config.api_key and not config.api_key.startswith("${"):
            self._add_finding(
                rule_id="RAG-VS-001",
                title="Hardcoded Vector Store API Key",
                description=f"API key for {config.store_type.value} is hardcoded instead of using environment variables",
                severity=Severity.CRITICAL,
                file_path=config.source_file,
                line_number=config.line_number,
                remediation="Use environment variables or a secrets manager for API keys",
                cwe_id="CWE-798",
            )

        # Check TLS
        if not config.uses_tls and config.host and config.host not in ["localhost", "127.0.0.1"]:
            self._add_finding(
                rule_id="RAG-VS-002",
                title="Vector Store Connection Without TLS",
                description=f"Connection to {config.store_type.value} does not use TLS encryption",
                severity=Severity.HIGH,
                file_path=config.source_file,
                line_number=config.line_number,
                remediation="Enable TLS/SSL for all vector store connections",
                cwe_id="CWE-319",
            )

        # Check authentication
        if not config.auth_enabled:
            self._add_finding(
                rule_id="RAG-VS-003",
                title="Vector Store Without Authentication",
                description=f"{config.store_type.value} connection has no authentication configured",
                severity=Severity.HIGH,
                file_path=config.source_file,
                line_number=config.line_number,
                remediation="Enable authentication for the vector store",
                cwe_id="CWE-306",
            )

        # Check public exposure
        if config.is_public:
            self._add_finding(
                rule_id="RAG-VS-004",
                title="Publicly Exposed Vector Store",
                description=f"{config.store_type.value} is exposed to the public internet without IP restrictions",
                severity=Severity.CRITICAL,
                file_path=config.source_file,
                line_number=config.line_number,
                remediation="Restrict access to specific IP ranges or use private networking",
                cwe_id="CWE-284",
            )

        # Check encryption at rest
        if config.encryption_at_rest is False:
            self._add_finding(
                rule_id="RAG-VS-005",
                title="Vector Store Without Encryption at Rest",
                description=f"{config.store_type.value} does not have encryption at rest enabled",
                severity=Severity.MEDIUM,
                file_path=config.source_file,
                line_number=config.line_number,
                remediation="Enable encryption at rest for stored vectors and metadata",
                cwe_id="CWE-311",
            )

        # Check ACL
        if not config.has_acl:
            self._add_finding(
                rule_id="RAG-VS-006",
                title="No Access Control on Vector Store",
                description=f"{config.store_type.value} has no document-level access controls configured",
                severity=Severity.MEDIUM,
                file_path=config.source_file,
                line_number=config.line_number,
                remediation="Implement namespace or collection-level access controls",
                cwe_id="CWE-862",
            )

        return self.findings

    def _detect_vector_stores(self, content: str) -> List[VectorStoreType]:
        """Detect which vector stores are used in the content."""
        detected = []

        for store_type, patterns in self.DETECTION_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    if store_type not in detected:
                        detected.append(store_type)
                    break

        return detected

    def _analyze_store_security(
        self, content: str, file_path: str, store_type: VectorStoreType
    ) -> None:
        """Analyze security for a specific vector store type."""

        if store_type == VectorStoreType.PINECONE:
            self._analyze_pinecone(content, file_path)
        elif store_type == VectorStoreType.CHROMA:
            self._analyze_chroma(content, file_path)
        elif store_type == VectorStoreType.WEAVIATE:
            self._analyze_weaviate(content, file_path)
        elif store_type == VectorStoreType.QDRANT:
            self._analyze_qdrant(content, file_path)
        elif store_type == VectorStoreType.MILVUS:
            self._analyze_milvus(content, file_path)

    def _analyze_pinecone(self, content: str, file_path: str) -> None:
        """Analyze Pinecone-specific security issues."""
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            # Check for hardcoded API key in init
            if re.search(r'pinecone\.init\s*\(\s*api_key\s*=\s*["\'][^"\']+["\']', line):
                self._add_finding(
                    rule_id="RAG-PIN-001",
                    title="Hardcoded Pinecone API Key",
                    description="Pinecone API key is hardcoded in pinecone.init()",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=i,
                    remediation="Use environment variable: pinecone.init(api_key=os.environ['PINECONE_API_KEY'])",
                    cwe_id="CWE-798",
                )

            # Check for missing environment specification (can lead to data leakage)
            if re.search(r'pinecone\.init\s*\(', line) and "environment" not in line:
                self._add_finding(
                    rule_id="RAG-PIN-002",
                    title="Pinecone Environment Not Specified",
                    description="Pinecone environment not explicitly specified, may connect to wrong environment",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=i,
                    remediation="Explicitly specify the environment parameter",
                    cwe_id="CWE-1188",
                )

    def _analyze_chroma(self, content: str, file_path: str) -> None:
        """Analyze Chroma-specific security issues."""
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            # Check for HttpClient without auth
            if re.search(r'chromadb\.HttpClient\s*\(', line):
                # Check if SSL and auth are configured in nearby lines
                context = "\n".join(lines[max(0, i-3):min(len(lines), i+3)])
                if "ssl" not in context.lower() and "https" not in context.lower():
                    self._add_finding(
                        rule_id="RAG-CHR-001",
                        title="Chroma HTTP Client Without SSL",
                        description="Chroma HttpClient may not be using SSL/TLS",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        remediation="Use HTTPS URL or configure SSL settings",
                        cwe_id="CWE-319",
                    )

            # Check for persistent client in world-readable location
            if re.search(r'PersistentClient\s*\(\s*path\s*=\s*["\']/(tmp|var/tmp)', line):
                self._add_finding(
                    rule_id="RAG-CHR-002",
                    title="Chroma Persistent Storage in Temp Directory",
                    description="Chroma database stored in world-readable temp directory",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    remediation="Use a secure directory with proper permissions",
                    cwe_id="CWE-732",
                )

    def _analyze_weaviate(self, content: str, file_path: str) -> None:
        """Analyze Weaviate-specific security issues."""
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            # Check for anonymous access
            if re.search(r'auth_client_secret\s*=\s*None', line, re.IGNORECASE):
                self._add_finding(
                    rule_id="RAG-WEA-001",
                    title="Weaviate Anonymous Access",
                    description="Weaviate client configured without authentication",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    remediation="Configure API key or OIDC authentication",
                    cwe_id="CWE-306",
                )

            # Check for hardcoded API key
            if re.search(r'api_key\s*=\s*["\'][a-zA-Z0-9\-_]{20,}["\']', line):
                self._add_finding(
                    rule_id="RAG-WEA-002",
                    title="Hardcoded Weaviate API Key",
                    description="Weaviate API key is hardcoded",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=i,
                    remediation="Use environment variables for API keys",
                    cwe_id="CWE-798",
                )

    def _analyze_qdrant(self, content: str, file_path: str) -> None:
        """Analyze Qdrant-specific security issues."""
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            # Check for connection without API key
            if re.search(r'QdrantClient\s*\(', line):
                context = "\n".join(lines[max(0, i-2):min(len(lines), i+5)])
                if "api_key" not in context and "grpc_port" not in context:
                    # Check if it's a local connection
                    if "localhost" not in context and "127.0.0.1" not in context and ":memory:" not in context:
                        self._add_finding(
                            rule_id="RAG-QDR-001",
                            title="Qdrant Client Without API Key",
                            description="Qdrant client connecting to remote server without API key",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=i,
                            remediation="Configure API key for Qdrant connection",
                            cwe_id="CWE-306",
                        )

    def _analyze_milvus(self, content: str, file_path: str) -> None:
        """Analyze Milvus-specific security issues."""
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            # Check for connection without auth
            if re.search(r'connections\.connect\s*\(', line):
                context = "\n".join(lines[max(0, i-2):min(len(lines), i+5)])
                if "user" not in context and "password" not in context and "token" not in context:
                    self._add_finding(
                        rule_id="RAG-MIL-001",
                        title="Milvus Connection Without Authentication",
                        description="Milvus connection established without user authentication",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        remediation="Configure user/password or token authentication",
                        cwe_id="CWE-306",
                    )

            # Check for hardcoded password
            if re.search(r'password\s*=\s*["\'][^"\']+["\']', line):
                self._add_finding(
                    rule_id="RAG-MIL-002",
                    title="Hardcoded Milvus Password",
                    description="Milvus password is hardcoded in connection",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=i,
                    remediation="Use environment variables for credentials",
                    cwe_id="CWE-798",
                )

    def _check_hardcoded_credentials(self, content: str, file_path: str) -> None:
        """Check for hardcoded credentials."""
        lines = content.split("\n")

        for category, patterns in self.SENSITIVE_PATTERNS.items():
            if category != "hardcoded_api_key":
                continue

            for pattern, description in patterns:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        self._add_finding(
                            rule_id="RAG-CRED-001",
                            title="Hardcoded Vector Store Credential",
                            description=description,
                            severity=Severity.CRITICAL,
                            file_path=file_path,
                            line_number=i,
                            remediation="Use environment variables or a secrets manager",
                            cwe_id="CWE-798",
                        )

    def _check_insecure_connections(self, content: str, file_path: str) -> None:
        """Check for insecure connection configurations."""
        lines = content.split("\n")

        for pattern, description in self.SENSITIVE_PATTERNS.get("insecure_connection", []):
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip if it's localhost HTTP (often acceptable for dev)
                    if "http://" in line.lower() and ("localhost" in line or "127.0.0.1" in line):
                        continue

                    self._add_finding(
                        rule_id="RAG-CONN-001",
                        title="Insecure Vector Store Connection",
                        description=description,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        remediation="Use HTTPS/TLS and enable certificate verification",
                        cwe_id="CWE-319",
                    )

    def _check_access_controls(self, content: str, file_path: str) -> None:
        """Check for missing access controls."""
        lines = content.split("\n")

        for pattern, description in self.SENSITIVE_PATTERNS.get("no_auth", []):
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_finding(
                        rule_id="RAG-AUTH-001",
                        title="Vector Store Authentication Disabled",
                        description=description,
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        remediation="Enable authentication for the vector store",
                        cwe_id="CWE-306",
                    )

    def _add_finding(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        file_path: str,
        line_number: Optional[int] = None,
        remediation: str = "",
        cwe_id: Optional[str] = None,
    ) -> None:
        """Add a finding to the list."""
        self.findings.append(
            Finding(
                rule_id=rule_id,
                domain=FindingDomain.MCP,  # Using MCP domain for now, could add RAG domain
                title=title,
                description=description,
                severity=severity,
                location=Location(
                    file_path=file_path,
                    line_number=line_number,
                ),
                remediation=remediation,
                cwe_id=cwe_id,
                tags=["rag", "vector-store"],
            )
        )
