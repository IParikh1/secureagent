"""Document ingestion security scanner for RAG systems.

Scans documents before ingestion into vector stores to detect:
- Hidden prompt injections
- Malicious content
- PII/sensitive data
- Adversarial content designed to poison the knowledge base
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime


class DocumentRisk(Enum):
    """Risk levels for document content."""

    CRITICAL = "critical"  # Definite malicious content
    HIGH = "high"  # Likely malicious content
    MEDIUM = "medium"  # Suspicious content
    LOW = "low"  # Minor concerns
    CLEAN = "clean"  # No issues detected


class ThreatCategory(Enum):
    """Categories of document threats."""

    INJECTION_PAYLOAD = "injection_payload"
    HIDDEN_INSTRUCTION = "hidden_instruction"
    INVISIBLE_TEXT = "invisible_text"
    ENCODING_ATTACK = "encoding_attack"
    PII_EXPOSURE = "pii_exposure"
    SENSITIVE_DATA = "sensitive_data"
    MALICIOUS_LINK = "malicious_link"
    DATA_EXFILTRATION = "data_exfiltration"
    JAILBREAK_CONTENT = "jailbreak_content"
    ADVERSARIAL_CONTENT = "adversarial_content"


@dataclass
class DocumentThreat:
    """A detected threat in a document."""

    category: ThreatCategory
    risk: DocumentRisk
    description: str
    matched_content: str
    position: Optional[int] = None
    line_number: Optional[int] = None
    remediation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DocumentScanResult:
    """Result of scanning a document."""

    document_path: str
    document_type: str
    risk_level: DocumentRisk
    threats: List[DocumentThreat] = field(default_factory=list)
    pii_detected: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    scan_time_ms: float = 0.0
    scanned_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def is_safe(self) -> bool:
        """Check if document is safe for ingestion."""
        return self.risk_level in [DocumentRisk.CLEAN, DocumentRisk.LOW]

    @property
    def threat_count(self) -> int:
        """Get total number of threats detected."""
        return len(self.threats)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "document_path": self.document_path,
            "document_type": self.document_type,
            "risk_level": self.risk_level.value,
            "is_safe": self.is_safe,
            "threat_count": self.threat_count,
            "threats": [
                {
                    "category": t.category.value,
                    "risk": t.risk.value,
                    "description": t.description,
                    "matched_content": t.matched_content[:100] + "..." if len(t.matched_content) > 100 else t.matched_content,
                    "line_number": t.line_number,
                }
                for t in self.threats
            ],
            "pii_detected": self.pii_detected,
            "recommendations": self.recommendations,
            "scan_time_ms": self.scan_time_ms,
            "scanned_at": self.scanned_at.isoformat(),
        }


class DocumentSecurityScanner:
    """Scans documents for security threats before RAG ingestion."""

    # Injection patterns - hidden instructions in documents
    INJECTION_PATTERNS = [
        # Direct instructions
        (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", ThreatCategory.INJECTION_PAYLOAD, DocumentRisk.CRITICAL),
        (r"(?i)disregard\s+(all\s+)?(previous|your)\s+(instructions?|rules?)", ThreatCategory.INJECTION_PAYLOAD, DocumentRisk.CRITICAL),
        (r"(?i)new\s+instructions?:\s*", ThreatCategory.INJECTION_PAYLOAD, DocumentRisk.HIGH),
        (r"(?i)system\s*:\s*you\s+(are|must|will|should)", ThreatCategory.INJECTION_PAYLOAD, DocumentRisk.HIGH),

        # Hidden in comments/markup
        (r"<!--\s*(?:INSTRUCTION|SYSTEM|INJECT|HIDDEN|IMPORTANT)\s*:", ThreatCategory.HIDDEN_INSTRUCTION, DocumentRisk.CRITICAL),
        (r"<!--[^>]*ignore\s+previous[^>]*-->", ThreatCategory.HIDDEN_INSTRUCTION, DocumentRisk.CRITICAL),
        (r"<!--[^>]*system\s*prompt[^>]*-->", ThreatCategory.HIDDEN_INSTRUCTION, DocumentRisk.CRITICAL),
        (r"\[comment\]:[^:]*:.*instruction", ThreatCategory.HIDDEN_INSTRUCTION, DocumentRisk.HIGH),

        # Markdown hidden
        (r"\[//\]:\s*#\s*\(.*instruction.*\)", ThreatCategory.HIDDEN_INSTRUCTION, DocumentRisk.HIGH),
        (r"\[hidden\]:\s*", ThreatCategory.HIDDEN_INSTRUCTION, DocumentRisk.HIGH),

        # Role manipulation
        (r"(?i)you\s+are\s+now\s+(a|an)\s+", ThreatCategory.JAILBREAK_CONTENT, DocumentRisk.HIGH),
        (r"(?i)act\s+as\s+(if\s+you\s+are\s+)?(a|an)\s+", ThreatCategory.JAILBREAK_CONTENT, DocumentRisk.MEDIUM),
        (r"(?i)pretend\s+(to\s+be|you\s+are)", ThreatCategory.JAILBREAK_CONTENT, DocumentRisk.MEDIUM),

        # Token manipulation
        (r"<\|im_start\|>|<\|im_end\|>", ThreatCategory.ENCODING_ATTACK, DocumentRisk.CRITICAL),
        (r"<\|endoftext\|>", ThreatCategory.ENCODING_ATTACK, DocumentRisk.CRITICAL),
        (r"\[INST\]|\[/INST\]", ThreatCategory.ENCODING_ATTACK, DocumentRisk.HIGH),
        (r"<<SYS>>|<</SYS>>", ThreatCategory.ENCODING_ATTACK, DocumentRisk.HIGH),

        # Data exfiltration
        (r"(?i)send\s+(this|the|all)\s+(data|information|content)\s+to", ThreatCategory.DATA_EXFILTRATION, DocumentRisk.CRITICAL),
        (r"(?i)forward\s+(everything|all)\s+to", ThreatCategory.DATA_EXFILTRATION, DocumentRisk.HIGH),
        (r"(?i)include\s+(in\s+)?your\s+response.*http", ThreatCategory.DATA_EXFILTRATION, DocumentRisk.HIGH),
    ]

    # Invisible/obfuscated text patterns
    INVISIBLE_TEXT_PATTERNS = [
        # Zero-width characters
        (r"[\u200b\u200c\u200d\u2060\ufeff]{3,}", ThreatCategory.INVISIBLE_TEXT, DocumentRisk.HIGH),
        # Right-to-left override
        (r"[\u202e\u202d\u202c]", ThreatCategory.INVISIBLE_TEXT, DocumentRisk.HIGH),
        # Homoglyph attacks (Cyrillic lookalikes in otherwise Latin text)
        (r"[a-zA-Z]+[\u0430\u0435\u043e\u0440\u0441\u0443\u0445]+[a-zA-Z]+", ThreatCategory.INVISIBLE_TEXT, DocumentRisk.MEDIUM),
        # White text (in HTML)
        (r"color:\s*white|color:\s*#fff|opacity:\s*0|font-size:\s*0", ThreatCategory.INVISIBLE_TEXT, DocumentRisk.HIGH),
    ]

    # PII patterns
    PII_PATTERNS = [
        (r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b", "potential_name"),  # Names
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email"),
        (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "phone_number"),
        (r"\b\d{3}[-]?\d{2}[-]?\d{4}\b", "ssn"),
        (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "credit_card"),
        (r"\b\d{1,5}\s+[A-Za-z]+\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd)\b", "address"),
        (r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b", "date_of_birth"),
    ]

    # Sensitive data patterns
    SENSITIVE_PATTERNS = [
        (r"(?i)password\s*[:=]\s*\S+", ThreatCategory.SENSITIVE_DATA, DocumentRisk.CRITICAL),
        (r"(?i)api[_-]?key\s*[:=]\s*[a-zA-Z0-9\-_]{16,}", ThreatCategory.SENSITIVE_DATA, DocumentRisk.CRITICAL),
        (r"(?i)secret\s*[:=]\s*\S+", ThreatCategory.SENSITIVE_DATA, DocumentRisk.HIGH),
        (r"(?i)token\s*[:=]\s*[a-zA-Z0-9\-_]{20,}", ThreatCategory.SENSITIVE_DATA, DocumentRisk.HIGH),
        (r"(?i)private[_-]?key", ThreatCategory.SENSITIVE_DATA, DocumentRisk.CRITICAL),
        (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", ThreatCategory.SENSITIVE_DATA, DocumentRisk.CRITICAL),
        (r"-----BEGIN\s+CERTIFICATE-----", ThreatCategory.SENSITIVE_DATA, DocumentRisk.HIGH),
        (r"(?i)aws[_-]?access[_-]?key", ThreatCategory.SENSITIVE_DATA, DocumentRisk.CRITICAL),
        (r"AKIA[0-9A-Z]{16}", ThreatCategory.SENSITIVE_DATA, DocumentRisk.CRITICAL),
    ]

    # Malicious URL patterns
    MALICIOUS_URL_PATTERNS = [
        (r"(?i)https?://[^\s]*\.(ru|cn|tk|ml|ga|cf)/", ThreatCategory.MALICIOUS_LINK, DocumentRisk.MEDIUM),
        (r"(?i)https?://\d+\.\d+\.\d+\.\d+[:/]", ThreatCategory.MALICIOUS_LINK, DocumentRisk.MEDIUM),
        (r"(?i)https?://[^\s]*/(phish|hack|malware|exploit)", ThreatCategory.MALICIOUS_LINK, DocumentRisk.HIGH),
    ]

    def __init__(
        self,
        check_pii: bool = True,
        check_sensitive: bool = True,
        custom_patterns: Optional[List[Tuple[str, ThreatCategory, DocumentRisk]]] = None,
    ):
        """Initialize the document scanner.

        Args:
            check_pii: Whether to scan for PII
            check_sensitive: Whether to scan for sensitive data
            custom_patterns: Additional custom patterns to check
        """
        self.check_pii = check_pii
        self.check_sensitive = check_sensitive
        self.custom_patterns = custom_patterns or []

    def scan_text(self, text: str, source: str = "unknown") -> DocumentScanResult:
        """Scan text content for security threats.

        Args:
            text: Text content to scan
            source: Source identifier for the text

        Returns:
            DocumentScanResult with findings
        """
        import time
        start_time = time.time()

        threats: List[DocumentThreat] = []
        pii_detected: List[str] = []

        # Check injection patterns
        for pattern, category, risk in self.INJECTION_PATTERNS:
            matches = list(re.finditer(pattern, text, re.MULTILINE | re.DOTALL))
            for match in matches:
                line_num = text[:match.start()].count('\n') + 1
                threats.append(DocumentThreat(
                    category=category,
                    risk=risk,
                    description=f"Detected {category.value} pattern",
                    matched_content=match.group(0),
                    position=match.start(),
                    line_number=line_num,
                    remediation=self._get_remediation(category),
                ))

        # Check invisible text patterns
        for pattern, category, risk in self.INVISIBLE_TEXT_PATTERNS:
            matches = list(re.finditer(pattern, text))
            for match in matches:
                line_num = text[:match.start()].count('\n') + 1
                threats.append(DocumentThreat(
                    category=category,
                    risk=risk,
                    description=f"Detected hidden/invisible text",
                    matched_content=repr(match.group(0)),
                    position=match.start(),
                    line_number=line_num,
                    remediation="Remove invisible characters and verify document source",
                ))

        # Check sensitive data patterns
        if self.check_sensitive:
            for pattern, category, risk in self.SENSITIVE_PATTERNS:
                matches = list(re.finditer(pattern, text))
                for match in matches:
                    line_num = text[:match.start()].count('\n') + 1
                    threats.append(DocumentThreat(
                        category=category,
                        risk=risk,
                        description=f"Detected sensitive data",
                        matched_content=self._mask_sensitive(match.group(0)),
                        position=match.start(),
                        line_number=line_num,
                        remediation="Remove or redact sensitive data before ingestion",
                    ))

        # Check PII patterns
        if self.check_pii:
            for pattern, pii_type in self.PII_PATTERNS:
                matches = list(re.finditer(pattern, text))
                if matches:
                    pii_detected.append(f"{pii_type}: {len(matches)} instances")

        # Check malicious URLs
        for pattern, category, risk in self.MALICIOUS_URL_PATTERNS:
            matches = list(re.finditer(pattern, text))
            for match in matches:
                line_num = text[:match.start()].count('\n') + 1
                threats.append(DocumentThreat(
                    category=category,
                    risk=risk,
                    description="Potentially malicious URL detected",
                    matched_content=match.group(0),
                    position=match.start(),
                    line_number=line_num,
                    remediation="Verify URL legitimacy before including in knowledge base",
                ))

        # Check custom patterns
        for pattern, category, risk in self.custom_patterns:
            matches = list(re.finditer(pattern, text))
            for match in matches:
                line_num = text[:match.start()].count('\n') + 1
                threats.append(DocumentThreat(
                    category=category,
                    risk=risk,
                    description=f"Custom pattern match: {category.value}",
                    matched_content=match.group(0),
                    position=match.start(),
                    line_number=line_num,
                ))

        # Determine overall risk level
        risk_level = self._calculate_risk_level(threats)

        # Generate recommendations
        recommendations = self._generate_recommendations(threats, pii_detected)

        scan_time = (time.time() - start_time) * 1000

        return DocumentScanResult(
            document_path=source,
            document_type=self._detect_document_type(source),
            risk_level=risk_level,
            threats=threats,
            pii_detected=pii_detected,
            recommendations=recommendations,
            scan_time_ms=scan_time,
        )

    def scan_file(self, file_path: Path) -> DocumentScanResult:
        """Scan a file for security threats.

        Args:
            file_path: Path to file to scan

        Returns:
            DocumentScanResult with findings
        """
        file_path = Path(file_path)

        if not file_path.exists():
            return DocumentScanResult(
                document_path=str(file_path),
                document_type="unknown",
                risk_level=DocumentRisk.MEDIUM,
                recommendations=["File not found"],
            )

        # Handle different file types
        suffix = file_path.suffix.lower()

        if suffix in [".txt", ".md", ".rst", ".csv", ".json", ".yaml", ".yml"]:
            content = file_path.read_text(errors='ignore')
        elif suffix == ".pdf":
            content = self._extract_pdf_text(file_path)
        elif suffix in [".doc", ".docx"]:
            content = self._extract_docx_text(file_path)
        elif suffix in [".html", ".htm"]:
            content = self._extract_html_text(file_path)
        else:
            # Try to read as text
            try:
                content = file_path.read_text(errors='ignore')
            except Exception:
                content = ""

        return self.scan_text(content, str(file_path))

    def scan_documents(self, documents: List[Dict[str, Any]]) -> List[DocumentScanResult]:
        """Scan multiple documents (LangChain Document format).

        Args:
            documents: List of documents with 'page_content' and 'metadata'

        Returns:
            List of DocumentScanResults
        """
        results = []

        for i, doc in enumerate(documents):
            content = doc.get("page_content", "")
            source = doc.get("metadata", {}).get("source", f"document_{i}")
            result = self.scan_text(content, source)
            results.append(result)

        return results

    def _extract_pdf_text(self, file_path: Path) -> str:
        """Extract text from PDF."""
        try:
            import pypdf
            reader = pypdf.PdfReader(file_path)
            text = ""
            for page in reader.pages:
                text += page.extract_text() or ""
            return text
        except ImportError:
            return "[PDF extraction requires pypdf: pip install pypdf]"
        except Exception as e:
            return f"[PDF extraction error: {e}]"

    def _extract_docx_text(self, file_path: Path) -> str:
        """Extract text from DOCX."""
        try:
            import docx
            doc = docx.Document(file_path)
            return "\n".join(para.text for para in doc.paragraphs)
        except ImportError:
            return "[DOCX extraction requires python-docx: pip install python-docx]"
        except Exception as e:
            return f"[DOCX extraction error: {e}]"

    def _extract_html_text(self, file_path: Path) -> str:
        """Extract text from HTML, preserving hidden content."""
        try:
            from bs4 import BeautifulSoup
            html = file_path.read_text()
            # Don't strip comments - we want to scan them for injections
            soup = BeautifulSoup(html, 'html.parser')
            # Get text but also include comments
            text = soup.get_text()
            # Also include comment content
            comments = soup.find_all(string=lambda t: isinstance(t, type(soup.new_string(''))) and t.parent.name is None)
            return text + "\n" + "\n".join(str(c) for c in comments)
        except ImportError:
            return file_path.read_text()
        except Exception:
            return file_path.read_text()

    def _detect_document_type(self, source: str) -> str:
        """Detect document type from source."""
        if "." in source:
            return source.split(".")[-1].lower()
        return "text"

    def _calculate_risk_level(self, threats: List[DocumentThreat]) -> DocumentRisk:
        """Calculate overall risk level from threats."""
        if not threats:
            return DocumentRisk.CLEAN

        # Get highest risk
        risk_priority = {
            DocumentRisk.CRITICAL: 4,
            DocumentRisk.HIGH: 3,
            DocumentRisk.MEDIUM: 2,
            DocumentRisk.LOW: 1,
            DocumentRisk.CLEAN: 0,
        }

        max_risk = max(t.risk for t in threats)

        # Escalate if multiple high risks
        high_count = sum(1 for t in threats if t.risk in [DocumentRisk.HIGH, DocumentRisk.CRITICAL])
        if high_count >= 3 and max_risk == DocumentRisk.HIGH:
            return DocumentRisk.CRITICAL

        return max_risk

    def _get_remediation(self, category: ThreatCategory) -> str:
        """Get remediation advice for a threat category."""
        remediations = {
            ThreatCategory.INJECTION_PAYLOAD: "Remove or sanitize the injection payload before ingestion",
            ThreatCategory.HIDDEN_INSTRUCTION: "Remove hidden instructions and verify document source",
            ThreatCategory.INVISIBLE_TEXT: "Remove invisible characters and scan document source",
            ThreatCategory.ENCODING_ATTACK: "Remove special tokens and verify document integrity",
            ThreatCategory.PII_EXPOSURE: "Redact PII before ingestion or implement access controls",
            ThreatCategory.SENSITIVE_DATA: "Remove sensitive data or use a secrets manager",
            ThreatCategory.MALICIOUS_LINK: "Verify and sanitize URLs before inclusion",
            ThreatCategory.DATA_EXFILTRATION: "Remove data exfiltration instructions",
            ThreatCategory.JAILBREAK_CONTENT: "Remove role manipulation content",
            ThreatCategory.ADVERSARIAL_CONTENT: "Review and sanitize adversarial content",
        }
        return remediations.get(category, "Review and sanitize content before ingestion")

    def _mask_sensitive(self, text: str) -> str:
        """Mask sensitive data for safe display."""
        if len(text) <= 10:
            return text[:3] + "***"
        return text[:6] + "***" + text[-3:]

    def _generate_recommendations(
        self,
        threats: List[DocumentThreat],
        pii_detected: List[str],
    ) -> List[str]:
        """Generate recommendations based on scan results."""
        recommendations = []

        if not threats and not pii_detected:
            recommendations.append("Document appears safe for ingestion")
            return recommendations

        # Critical threats
        critical_threats = [t for t in threats if t.risk == DocumentRisk.CRITICAL]
        if critical_threats:
            recommendations.append(f"BLOCK: {len(critical_threats)} critical threats detected - do not ingest")

        # High threats
        high_threats = [t for t in threats if t.risk == DocumentRisk.HIGH]
        if high_threats:
            recommendations.append(f"REVIEW: {len(high_threats)} high-risk issues require manual review")

        # Specific recommendations by category
        categories = set(t.category for t in threats)

        if ThreatCategory.INJECTION_PAYLOAD in categories:
            recommendations.append("Sanitize or remove detected injection payloads before ingestion")

        if ThreatCategory.HIDDEN_INSTRUCTION in categories:
            recommendations.append("Document contains hidden instructions - verify source and remove")

        if ThreatCategory.INVISIBLE_TEXT in categories:
            recommendations.append("Remove invisible/zero-width characters")

        if ThreatCategory.SENSITIVE_DATA in categories:
            recommendations.append("Remove credentials and sensitive data before ingestion")

        if pii_detected:
            recommendations.append(f"PII detected ({', '.join(pii_detected[:3])}) - consider redaction")

        return recommendations


class ChunkSecurityAnalyzer:
    """Analyzes chunking strategies for security implications."""

    def analyze_chunks(
        self,
        chunks: List[str],
        original_text: str,
    ) -> Dict[str, Any]:
        """Analyze chunks for security issues.

        Args:
            chunks: List of text chunks
            original_text: Original text before chunking

        Returns:
            Analysis results
        """
        issues = []

        # Check for split injection payloads
        injection_keywords = ["ignore", "instruction", "system", "disregard", "override"]
        for i, chunk in enumerate(chunks):
            chunk_lower = chunk.lower()
            for keyword in injection_keywords:
                if keyword in chunk_lower:
                    # Check if the full injection might be split across chunks
                    if i + 1 < len(chunks):
                        combined = chunk + " " + chunks[i + 1]
                        scanner = DocumentSecurityScanner()
                        result = scanner.scan_text(combined, "combined_chunks")
                        if result.threats:
                            issues.append({
                                "type": "split_injection",
                                "description": "Potential injection split across chunks",
                                "chunks": [i, i + 1],
                            })

        # Check chunk size variance (very small chunks might be adversarial)
        sizes = [len(c) for c in chunks]
        avg_size = sum(sizes) / len(sizes) if sizes else 0
        small_chunks = [i for i, s in enumerate(sizes) if s < avg_size * 0.1]
        if small_chunks:
            issues.append({
                "type": "suspicious_small_chunks",
                "description": "Unusually small chunks detected",
                "chunk_indices": small_chunks,
            })

        # Check for metadata injection in chunks
        for i, chunk in enumerate(chunks):
            if re.search(r'\{["\']?(metadata|source|author)["\']?\s*:', chunk):
                issues.append({
                    "type": "metadata_injection",
                    "description": "Chunk appears to contain injected metadata",
                    "chunk_index": i,
                })

        return {
            "total_chunks": len(chunks),
            "average_chunk_size": avg_size,
            "issues": issues,
            "is_safe": len(issues) == 0,
        }
