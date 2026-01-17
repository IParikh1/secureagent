"""Main RAG security scanner module.

Provides comprehensive security analysis for RAG systems including:
- Vector store configuration security
- Document ingestion security
- RAG poisoning detection
- Retrieval security analysis
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Generator
from datetime import datetime

from ..core.models.finding import Finding, FindingDomain, Location, ScanResult
from ..core.models.severity import Severity
from ..core.scanner.base import BaseScanner
from ..core.scanner.registry import register_scanner

from .vector_stores import VectorStoreSecurityAnalyzer, VectorStoreType
from .document_scanner import DocumentSecurityScanner, DocumentScanResult, DocumentRisk
from .poisoning import RAGPoisoningDetector, PoisoningAnalysisResult

logger = logging.getLogger(__name__)


@dataclass
class RAGSecurityReport:
    """Comprehensive RAG security analysis report."""

    # Summary
    overall_risk: str  # low, medium, high, critical
    risk_score: float  # 0.0 to 1.0
    total_findings: int

    # Component results
    vector_store_findings: List[Finding] = field(default_factory=list)
    document_scan_results: List[DocumentScanResult] = field(default_factory=list)
    poisoning_results: List[PoisoningAnalysisResult] = field(default_factory=list)

    # Findings by category
    findings_by_category: Dict[str, int] = field(default_factory=dict)

    # Recommendations
    recommendations: List[str] = field(default_factory=list)

    # Metadata
    scanned_files: int = 0
    scanned_documents: int = 0
    scan_duration_ms: float = 0.0
    scanned_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "summary": {
                "overall_risk": self.overall_risk,
                "risk_score": self.risk_score,
                "total_findings": self.total_findings,
                "scanned_files": self.scanned_files,
                "scanned_documents": self.scanned_documents,
            },
            "findings_by_category": self.findings_by_category,
            "vector_store_findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    "location": f.location.file_path if f.location else None,
                }
                for f in self.vector_store_findings
            ],
            "document_scan_results": [r.to_dict() for r in self.document_scan_results],
            "poisoning_results": [r.to_dict() for r in self.poisoning_results],
            "recommendations": self.recommendations,
            "scan_duration_ms": self.scan_duration_ms,
            "scanned_at": self.scanned_at.isoformat(),
        }


@register_scanner
class RAGSecurityScanner(BaseScanner):
    """Comprehensive scanner for RAG system security.

    Analyzes:
    - Vector store configurations (Pinecone, Chroma, Weaviate, etc.)
    - Document security before ingestion
    - RAG poisoning attempts
    - Retrieval security
    """

    name = "rag"
    description = "Scans RAG systems for security vulnerabilities"
    version = "1.0.0"

    # File patterns for vector store configs
    file_patterns = [
        "*.py",
        "*.js",
        "*.ts",
        "*.yaml",
        "*.yml",
        "*.json",
        "*.env",
        ".env*",
    ]

    supports_auto_discovery = True
    supports_remediation = True
    supports_risk_scoring = True

    def __init__(self, path=None, config=None, **kwargs):
        """Initialize the RAG security scanner."""
        super().__init__(path, config, **kwargs)

        # Initialize sub-analyzers
        self.vector_store_analyzer = VectorStoreSecurityAnalyzer()
        self.document_scanner = DocumentSecurityScanner(
            check_pii=self.config.get("check_pii", True),
            check_sensitive=self.config.get("check_sensitive", True),
        )
        self.poisoning_detector = RAGPoisoningDetector(
            sensitivity=self.config.get("poisoning_sensitivity", 1.0),
        )

    def scan(self, target: str = None, **kwargs) -> ScanResult:
        """Run comprehensive RAG security scan.

        Args:
            target: Path to scan (file or directory)
            **kwargs: Additional options:
                - scan_documents: List of documents to scan
                - check_poisoning: Whether to check for poisoning (default: True)

        Returns:
            ScanResult with findings
        """
        import time
        start_time = time.time()

        if target:
            self.path = Path(target)

        self.findings = []

        # Scan for vector store configurations
        logger.info(f"Scanning for vector store configurations in {self.path}")
        self._scan_vector_stores()

        # Scan documents if provided
        documents = kwargs.get("scan_documents", [])
        document_results = []
        poisoning_results = []

        if documents:
            logger.info(f"Scanning {len(documents)} documents")
            document_results = self._scan_documents(documents)

            if kwargs.get("check_poisoning", True):
                poisoning_results = self._check_poisoning(documents)

        # Generate scan result
        scan_duration = (time.time() - start_time) * 1000

        return ScanResult(
            findings=self.findings,
            scan_path=str(self.path),
            scanner_name=self.name,
            scan_duration_ms=int(scan_duration),
            metadata={
                "document_scan_results": [r.to_dict() for r in document_results],
                "poisoning_results": [r.to_dict() for r in poisoning_results],
            },
        )

    def scan_comprehensive(
        self,
        target: str = None,
        documents: Optional[List[Dict[str, Any]]] = None,
    ) -> RAGSecurityReport:
        """Run comprehensive RAG security analysis.

        Args:
            target: Path to scan for vector store configs
            documents: Documents to scan for security issues

        Returns:
            RAGSecurityReport with detailed findings
        """
        import time
        start_time = time.time()

        if target:
            self.path = Path(target)

        documents = documents or []

        # Scan vector stores
        logger.info(f"Scanning vector store configurations in {self.path}")
        vector_findings = self._scan_vector_stores()

        # Scan documents
        doc_results = []
        if documents:
            logger.info(f"Scanning {len(documents)} documents for security issues")
            doc_results = self._scan_documents(documents)

        # Check poisoning
        poisoning_results = []
        if documents:
            logger.info("Analyzing documents for poisoning attempts")
            poisoning_results = self._check_poisoning(documents)

        # Calculate overall risk
        risk_score, overall_risk = self._calculate_overall_risk(
            vector_findings, doc_results, poisoning_results
        )

        # Categorize findings
        findings_by_category = self._categorize_findings(
            vector_findings, doc_results, poisoning_results
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(
            vector_findings, doc_results, poisoning_results
        )

        scan_duration = (time.time() - start_time) * 1000

        return RAGSecurityReport(
            overall_risk=overall_risk,
            risk_score=risk_score,
            total_findings=len(vector_findings) + sum(r.threat_count for r in doc_results),
            vector_store_findings=vector_findings,
            document_scan_results=doc_results,
            poisoning_results=poisoning_results,
            findings_by_category=findings_by_category,
            recommendations=recommendations,
            scanned_files=self._count_scanned_files(),
            scanned_documents=len(documents),
            scan_duration_ms=scan_duration,
        )

    def discover_targets(self) -> Generator[Path, None, None]:
        """Discover files that may contain vector store configurations."""
        if self.path.is_file():
            yield self.path
            return

        for pattern in self.file_patterns:
            for file_path in self.path.glob(f"**/{pattern}"):
                if file_path.is_file() and not self._should_skip(file_path):
                    yield file_path

    def _should_skip(self, file_path: Path) -> bool:
        """Check if file should be skipped."""
        skip_dirs = ["node_modules", ".git", "__pycache__", ".venv", "venv", ".tox"]
        return any(skip in file_path.parts for skip in skip_dirs)

    def _scan_vector_stores(self) -> List[Finding]:
        """Scan for vector store security issues."""
        findings = []

        for file_path in self.discover_targets():
            try:
                file_findings = self.vector_store_analyzer.analyze_file(file_path)
                findings.extend(file_findings)
                self.findings.extend(file_findings)
            except Exception as e:
                logger.debug(f"Error scanning {file_path}: {e}")

        return findings

    def _scan_documents(
        self, documents: List[Dict[str, Any]]
    ) -> List[DocumentScanResult]:
        """Scan documents for security issues."""
        results = []

        for i, doc in enumerate(documents):
            content = doc.get("content", doc.get("page_content", ""))
            source = doc.get("metadata", {}).get("source", f"document_{i}")

            result = self.document_scanner.scan_text(content, source)
            results.append(result)

            # Convert document threats to findings
            for threat in result.threats:
                if threat.risk in [DocumentRisk.CRITICAL, DocumentRisk.HIGH]:
                    self.findings.append(Finding(
                        rule_id=f"RAG-DOC-{threat.category.value[:3].upper()}",
                        domain=FindingDomain.MCP,
                        title=f"Document Security Issue: {threat.category.value}",
                        description=threat.description,
                        severity=Severity.CRITICAL if threat.risk == DocumentRisk.CRITICAL else Severity.HIGH,
                        location=Location(
                            file_path=source,
                            line_number=threat.line_number,
                        ),
                        remediation=threat.remediation,
                        tags=["rag", "document", threat.category.value],
                    ))

        return results

    def _check_poisoning(
        self, documents: List[Dict[str, Any]]
    ) -> List[PoisoningAnalysisResult]:
        """Check documents for poisoning attempts."""
        results = []

        for i, doc in enumerate(documents):
            content = doc.get("content", doc.get("page_content", ""))
            doc_id = doc.get("id", doc.get("metadata", {}).get("source", f"document_{i}"))
            metadata = doc.get("metadata", {})

            result = self.poisoning_detector.analyze_document(content, doc_id, metadata)
            results.append(result)

            # Convert poisoning indicators to findings
            if result.is_poisoned:
                for indicator in result.indicators:
                    if indicator.confidence >= 0.7:
                        self.findings.append(Finding(
                            rule_id=f"RAG-POISON-{indicator.poisoning_type.value[:3].upper()}",
                            domain=FindingDomain.MCP,
                            title=f"RAG Poisoning: {indicator.poisoning_type.value}",
                            description=indicator.description,
                            severity=Severity.CRITICAL if indicator.severity.value == "critical" else Severity.HIGH,
                            location=Location(file_path=doc_id),
                            remediation=indicator.remediation,
                            tags=["rag", "poisoning", indicator.poisoning_type.value],
                        ))

        return results

    def _calculate_overall_risk(
        self,
        vector_findings: List[Finding],
        doc_results: List[DocumentScanResult],
        poisoning_results: List[PoisoningAnalysisResult],
    ) -> tuple[float, str]:
        """Calculate overall risk score and level."""
        scores = []

        # Vector store risk
        if vector_findings:
            critical = sum(1 for f in vector_findings if f.severity == Severity.CRITICAL)
            high = sum(1 for f in vector_findings if f.severity == Severity.HIGH)
            vector_score = min((critical * 0.3 + high * 0.15), 1.0)
            scores.append(vector_score)

        # Document risk
        for result in doc_results:
            if result.risk_level == DocumentRisk.CRITICAL:
                scores.append(1.0)
            elif result.risk_level == DocumentRisk.HIGH:
                scores.append(0.75)
            elif result.risk_level == DocumentRisk.MEDIUM:
                scores.append(0.5)

        # Poisoning risk
        for result in poisoning_results:
            scores.append(result.poisoning_score)

        if not scores:
            return 0.0, "low"

        avg_score = sum(scores) / len(scores)
        max_score = max(scores)

        # Use weighted combination
        risk_score = (avg_score * 0.4 + max_score * 0.6)

        if risk_score >= 0.8:
            return risk_score, "critical"
        elif risk_score >= 0.6:
            return risk_score, "high"
        elif risk_score >= 0.3:
            return risk_score, "medium"
        else:
            return risk_score, "low"

    def _categorize_findings(
        self,
        vector_findings: List[Finding],
        doc_results: List[DocumentScanResult],
        poisoning_results: List[PoisoningAnalysisResult],
    ) -> Dict[str, int]:
        """Categorize findings by type."""
        categories = {
            "vector_store_config": 0,
            "hardcoded_credentials": 0,
            "insecure_connection": 0,
            "document_injection": 0,
            "sensitive_data": 0,
            "pii_exposure": 0,
            "rag_poisoning": 0,
        }

        for f in vector_findings:
            if "CRED" in f.rule_id or "PIN" in f.rule_id or "WEA" in f.rule_id:
                categories["hardcoded_credentials"] += 1
            elif "CONN" in f.rule_id:
                categories["insecure_connection"] += 1
            else:
                categories["vector_store_config"] += 1

        for result in doc_results:
            for threat in result.threats:
                if "injection" in threat.category.value.lower():
                    categories["document_injection"] += 1
                elif "sensitive" in threat.category.value.lower():
                    categories["sensitive_data"] += 1
                elif "pii" in threat.category.value.lower():
                    categories["pii_exposure"] += 1

        for result in poisoning_results:
            categories["rag_poisoning"] += len(result.indicators)

        return {k: v for k, v in categories.items() if v > 0}

    def _generate_recommendations(
        self,
        vector_findings: List[Finding],
        doc_results: List[DocumentScanResult],
        poisoning_results: List[PoisoningAnalysisResult],
    ) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []

        # Vector store recommendations
        if vector_findings:
            cred_findings = [f for f in vector_findings if "CRED" in f.rule_id or "key" in f.title.lower()]
            if cred_findings:
                recommendations.append("Use environment variables or a secrets manager for vector store credentials")

            conn_findings = [f for f in vector_findings if "CONN" in f.rule_id or "tls" in f.title.lower()]
            if conn_findings:
                recommendations.append("Enable TLS/SSL for all vector store connections")

        # Document recommendations
        unsafe_docs = [r for r in doc_results if not r.is_safe]
        if unsafe_docs:
            recommendations.append(f"Review and sanitize {len(unsafe_docs)} documents before ingestion")

        injection_docs = [r for r in doc_results if any("injection" in t.category.value for t in r.threats)]
        if injection_docs:
            recommendations.append("Implement document sanitization pipeline to remove injection payloads")

        pii_docs = [r for r in doc_results if r.pii_detected]
        if pii_docs:
            recommendations.append(f"Consider PII redaction for {len(pii_docs)} documents")

        # Poisoning recommendations
        poisoned_docs = [r for r in poisoning_results if r.is_poisoned]
        if poisoned_docs:
            recommendations.append(f"CRITICAL: {len(poisoned_docs)} documents show signs of poisoning - manual review required")
            recommendations.append("Implement document provenance tracking and verification")

        # General recommendations
        if not recommendations:
            recommendations.append("RAG system security appears adequate - continue monitoring")
        else:
            recommendations.append("Implement regular security audits for RAG knowledge base")

        return recommendations

    def _count_scanned_files(self) -> int:
        """Count files that were scanned."""
        return sum(1 for _ in self.discover_targets())

    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all RAG security rules."""
        return [
            {
                "id": "RAG-VS-001",
                "title": "Hardcoded Vector Store API Key",
                "severity": "critical",
                "description": "API key is hardcoded instead of using environment variables",
                "cwe_id": "CWE-798",
            },
            {
                "id": "RAG-VS-002",
                "title": "Vector Store Connection Without TLS",
                "severity": "high",
                "description": "Connection does not use TLS encryption",
                "cwe_id": "CWE-319",
            },
            {
                "id": "RAG-VS-003",
                "title": "Vector Store Without Authentication",
                "severity": "high",
                "description": "No authentication configured for vector store",
                "cwe_id": "CWE-306",
            },
            {
                "id": "RAG-VS-004",
                "title": "Publicly Exposed Vector Store",
                "severity": "critical",
                "description": "Vector store exposed to public internet",
                "cwe_id": "CWE-284",
            },
            {
                "id": "RAG-DOC-001",
                "title": "Document Contains Injection Payload",
                "severity": "critical",
                "description": "Document contains potential prompt injection",
                "cwe_id": "CWE-94",
            },
            {
                "id": "RAG-POISON-001",
                "title": "RAG Poisoning Attempt Detected",
                "severity": "critical",
                "description": "Document appears to be attempting to poison the knowledge base",
                "cwe_id": "CWE-94",
            },
        ]
