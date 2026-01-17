"""RAG poisoning detection for knowledge base security.

Detects attempts to poison RAG knowledge bases through:
- Adversarial document injection
- Embedding manipulation
- Retrieval hijacking
- Context confusion attacks
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime


class PoisoningType(Enum):
    """Types of RAG poisoning attacks."""

    # Document-level poisoning
    INSTRUCTION_INJECTION = "instruction_injection"
    CONTEXT_MANIPULATION = "context_manipulation"
    FACT_POLLUTION = "fact_pollution"
    AUTHORITY_SPOOFING = "authority_spoofing"

    # Retrieval-level poisoning
    EMBEDDING_MANIPULATION = "embedding_manipulation"
    RETRIEVAL_HIJACKING = "retrieval_hijacking"
    SEMANTIC_COLLISION = "semantic_collision"

    # System-level poisoning
    METADATA_INJECTION = "metadata_injection"
    SOURCE_SPOOFING = "source_spoofing"
    TIMESTAMP_MANIPULATION = "timestamp_manipulation"


class SeverityLevel(Enum):
    """Severity levels for poisoning attempts."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class PoisoningIndicator:
    """An indicator of a potential poisoning attempt."""

    poisoning_type: PoisoningType
    severity: SeverityLevel
    description: str
    evidence: str
    confidence: float  # 0.0 to 1.0
    affected_content: Optional[str] = None
    remediation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PoisoningAnalysisResult:
    """Result of poisoning analysis."""

    document_id: str
    is_poisoned: bool
    poisoning_score: float  # 0.0 to 1.0
    indicators: List[PoisoningIndicator] = field(default_factory=list)
    risk_summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    analyzed_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "document_id": self.document_id,
            "is_poisoned": self.is_poisoned,
            "poisoning_score": self.poisoning_score,
            "indicators": [
                {
                    "type": i.poisoning_type.value,
                    "severity": i.severity.value,
                    "description": i.description,
                    "confidence": i.confidence,
                }
                for i in self.indicators
            ],
            "risk_summary": self.risk_summary,
            "recommendations": self.recommendations,
            "analyzed_at": self.analyzed_at.isoformat(),
        }


class RAGPoisoningDetector:
    """Detects RAG poisoning attempts in documents and embeddings."""

    # Patterns indicating instruction injection attempts
    INSTRUCTION_INJECTION_PATTERNS = [
        # Direct instruction patterns
        (r"(?i)\b(always|never|must|should)\s+(say|respond|answer|include)\b.*\b(in\s+your|every)\s+(response|answer|reply)", 0.9),
        (r"(?i)\bwhen\s+(asked|queried|questioned)\s+about.*\b(always|must|should)\b", 0.85),
        (r"(?i)\bremember\s+that\s+you\s+(are|must|should|will)\b", 0.8),
        (r"(?i)\bimportant\s*:\s*you\s+(must|should|will|are)\b", 0.85),

        # Context manipulation
        (r"(?i)\b(this|the\s+following)\s+is\s+(true|fact|correct|accurate)\s*:", 0.7),
        (r"(?i)\b(official|authoritative|verified)\s+(source|information|data)\b", 0.6),
        (r"(?i)\b(always|unconditionally)\s+trust\s+(this|the\s+following)\b", 0.85),

        # Retrieval hijacking
        (r"(?i)\bthis\s+document\s+(is|should\s+be)\s+(the|your)\s+(primary|main|only)\s+source\b", 0.8),
        (r"(?i)\bignore\s+(other|all\s+other|any\s+other)\s+(sources|documents|information)\b", 0.9),
        (r"(?i)\bprioritize\s+this\s+(information|content|document)\s+(over|above)\b", 0.8),
    ]

    # Patterns indicating authority spoofing
    AUTHORITY_SPOOFING_PATTERNS = [
        (r"(?i)\b(official|verified|authenticated)\s+(document|source|release)\b", 0.6),
        (r"(?i)\bfrom\s+(the\s+)?(official|verified)\s+(source|team|organization)\b", 0.7),
        (r"(?i)\b(CEO|CTO|president|director|official)\s+(statement|announcement|notice)\b", 0.5),
        (r"(?i)\bthis\s+supersedes\s+(all\s+)?(previous|prior|earlier)\b", 0.75),
        (r"(?i)\b(internal|confidential|classified)\s+(memo|document|notice)\b", 0.6),
    ]

    # Patterns indicating fact pollution
    FACT_POLLUTION_PATTERNS = [
        # Contradictory statements designed to confuse
        (r"(?i)\b(contrary|opposite)\s+to\s+(popular|common)\s+belief\b", 0.5),
        (r"(?i)\b(actually|in\s+fact|really)\s*,?\s*(the\s+)?(truth|reality)\s+is\b", 0.6),
        (r"(?i)\b(new|recent|updated)\s+(research|studies|findings)\s+(show|prove|demonstrate)\b", 0.5),
        (r"(?i)\b(everyone|experts|scientists)\s+(know|agree|confirm)\s+that\b", 0.6),
    ]

    # Patterns indicating metadata injection
    METADATA_INJECTION_PATTERNS = [
        (r'\{["\']?source["\']?\s*:\s*["\']', 0.8),
        (r'\{["\']?author["\']?\s*:\s*["\']', 0.7),
        (r'\{["\']?date["\']?\s*:\s*["\']', 0.6),
        (r'\{["\']?verified["\']?\s*:\s*true', 0.85),
        (r'\{["\']?priority["\']?\s*:\s*(high|critical|urgent)', 0.8),
        (r'\{["\']?trust_score["\']?\s*:\s*[0-9.]+', 0.9),
    ]

    # Embedding manipulation patterns (text designed to create specific embeddings)
    EMBEDDING_MANIPULATION_PATTERNS = [
        # Keyword stuffing
        (r"(\b\w+\b)(\s+\1){5,}", 0.8),  # Same word repeated 5+ times
        # Semantic padding
        (r"(?i)(important|relevant|key|critical|essential)(\s*,?\s*(important|relevant|key|critical|essential)){3,}", 0.7),
    ]

    def __init__(
        self,
        sensitivity: float = 1.0,
        min_confidence: float = 0.5,
    ):
        """Initialize the poisoning detector.

        Args:
            sensitivity: Detection sensitivity multiplier
            min_confidence: Minimum confidence to report indicator
        """
        self.sensitivity = sensitivity
        self.min_confidence = min_confidence

    def analyze_document(
        self,
        content: str,
        document_id: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PoisoningAnalysisResult:
        """Analyze a document for poisoning attempts.

        Args:
            content: Document content
            document_id: Identifier for the document
            metadata: Optional document metadata

        Returns:
            PoisoningAnalysisResult
        """
        indicators: List[PoisoningIndicator] = []
        metadata = metadata or {}

        # Check instruction injection
        indicators.extend(
            self._check_patterns(
                content,
                self.INSTRUCTION_INJECTION_PATTERNS,
                PoisoningType.INSTRUCTION_INJECTION,
                SeverityLevel.CRITICAL,
            )
        )

        # Check authority spoofing
        indicators.extend(
            self._check_patterns(
                content,
                self.AUTHORITY_SPOOFING_PATTERNS,
                PoisoningType.AUTHORITY_SPOOFING,
                SeverityLevel.HIGH,
            )
        )

        # Check fact pollution
        indicators.extend(
            self._check_patterns(
                content,
                self.FACT_POLLUTION_PATTERNS,
                PoisoningType.FACT_POLLUTION,
                SeverityLevel.MEDIUM,
            )
        )

        # Check metadata injection
        indicators.extend(
            self._check_patterns(
                content,
                self.METADATA_INJECTION_PATTERNS,
                PoisoningType.METADATA_INJECTION,
                SeverityLevel.HIGH,
            )
        )

        # Check embedding manipulation
        indicators.extend(
            self._check_patterns(
                content,
                self.EMBEDDING_MANIPULATION_PATTERNS,
                PoisoningType.EMBEDDING_MANIPULATION,
                SeverityLevel.MEDIUM,
            )
        )

        # Check for context manipulation
        indicators.extend(self._check_context_manipulation(content))

        # Check metadata for suspicious patterns
        if metadata:
            indicators.extend(self._check_metadata(metadata))

        # Filter by minimum confidence
        indicators = [i for i in indicators if i.confidence >= self.min_confidence]

        # Calculate poisoning score
        poisoning_score = self._calculate_poisoning_score(indicators)

        # Determine if document is poisoned
        is_poisoned = poisoning_score >= 0.5 or any(
            i.severity == SeverityLevel.CRITICAL and i.confidence >= 0.8
            for i in indicators
        )

        # Generate risk summary
        risk_summary = self._generate_risk_summary(indicators, poisoning_score)

        # Generate recommendations
        recommendations = self._generate_recommendations(indicators)

        return PoisoningAnalysisResult(
            document_id=document_id,
            is_poisoned=is_poisoned,
            poisoning_score=poisoning_score,
            indicators=indicators,
            risk_summary=risk_summary,
            recommendations=recommendations,
        )

    def analyze_batch(
        self,
        documents: List[Dict[str, Any]],
    ) -> List[PoisoningAnalysisResult]:
        """Analyze multiple documents.

        Args:
            documents: List of documents with 'content', 'id', and optional 'metadata'

        Returns:
            List of PoisoningAnalysisResults
        """
        results = []
        for doc in documents:
            content = doc.get("content", doc.get("page_content", ""))
            doc_id = doc.get("id", doc.get("metadata", {}).get("source", "unknown"))
            metadata = doc.get("metadata", {})
            results.append(self.analyze_document(content, doc_id, metadata))
        return results

    def detect_retrieval_hijacking(
        self,
        query: str,
        retrieved_docs: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Detect retrieval hijacking in search results.

        Checks if retrieved documents appear to be trying to hijack
        the retrieval process with adversarial content.

        Args:
            query: The search query
            retrieved_docs: List of retrieved documents

        Returns:
            Analysis results
        """
        issues = []
        query_lower = query.lower()

        for i, doc in enumerate(retrieved_docs):
            content = doc.get("content", doc.get("page_content", ""))
            content_lower = content.lower()

            # Check for query keyword stuffing
            query_words = set(query_lower.split())
            for word in query_words:
                if len(word) > 3:  # Ignore short words
                    count = content_lower.count(word)
                    if count > 10:  # Suspicious repetition
                        issues.append({
                            "type": "keyword_stuffing",
                            "document_index": i,
                            "description": f"Query keyword '{word}' appears {count} times",
                            "severity": "medium",
                        })

            # Check for retrieval hijacking phrases
            hijacking_phrases = [
                "this is the most relevant",
                "this document should be prioritized",
                "ignore other search results",
                "this is the authoritative source",
            ]
            for phrase in hijacking_phrases:
                if phrase in content_lower:
                    issues.append({
                        "type": "retrieval_hijacking",
                        "document_index": i,
                        "description": f"Retrieval hijacking phrase detected: '{phrase}'",
                        "severity": "high",
                    })

            # Check for semantic collision attempts
            if self._detect_semantic_collision(query, content):
                issues.append({
                    "type": "semantic_collision",
                    "document_index": i,
                    "description": "Document may be crafted to match query semantics artificially",
                    "severity": "medium",
                })

        return {
            "query": query,
            "documents_analyzed": len(retrieved_docs),
            "issues_found": len(issues),
            "issues": issues,
            "is_safe": len(issues) == 0,
        }

    def _check_patterns(
        self,
        content: str,
        patterns: List[Tuple[str, float]],
        poisoning_type: PoisoningType,
        severity: SeverityLevel,
    ) -> List[PoisoningIndicator]:
        """Check content against a list of patterns."""
        indicators = []

        for pattern, base_confidence in patterns:
            matches = list(re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE))
            for match in matches:
                confidence = min(base_confidence * self.sensitivity, 1.0)
                indicators.append(PoisoningIndicator(
                    poisoning_type=poisoning_type,
                    severity=severity,
                    description=f"Detected {poisoning_type.value} pattern",
                    evidence=match.group(0)[:100],
                    confidence=confidence,
                    affected_content=match.group(0),
                    remediation=self._get_remediation(poisoning_type),
                ))

        return indicators

    def _check_context_manipulation(self, content: str) -> List[PoisoningIndicator]:
        """Check for context manipulation attempts."""
        indicators = []

        # Check for excessive emphasis on truthfulness/authority
        authority_words = ["true", "fact", "verified", "official", "authoritative", "confirmed"]
        authority_count = sum(content.lower().count(word) for word in authority_words)
        word_count = len(content.split())

        if word_count > 50 and authority_count / word_count > 0.02:  # >2% authority words
            indicators.append(PoisoningIndicator(
                poisoning_type=PoisoningType.CONTEXT_MANIPULATION,
                severity=SeverityLevel.MEDIUM,
                description="Excessive emphasis on authority/truthfulness",
                evidence=f"{authority_count} authority words in {word_count} word document",
                confidence=0.6 * self.sensitivity,
                remediation="Verify document source and claims independently",
            ))

        # Check for unusual structure that might confuse context
        if content.count("---") > 5 or content.count("===") > 5:
            indicators.append(PoisoningIndicator(
                poisoning_type=PoisoningType.CONTEXT_MANIPULATION,
                severity=SeverityLevel.LOW,
                description="Unusual document structure with many separators",
                evidence="Multiple separator lines detected",
                confidence=0.5 * self.sensitivity,
                remediation="Review document structure for intentional confusion",
            ))

        return indicators

    def _check_metadata(self, metadata: Dict[str, Any]) -> List[PoisoningIndicator]:
        """Check metadata for suspicious patterns."""
        indicators = []

        suspicious_keys = ["priority", "trust_score", "verified", "authoritative", "override"]
        for key in suspicious_keys:
            if key in metadata:
                indicators.append(PoisoningIndicator(
                    poisoning_type=PoisoningType.METADATA_INJECTION,
                    severity=SeverityLevel.HIGH,
                    description=f"Suspicious metadata key: {key}",
                    evidence=f"{key}: {metadata[key]}",
                    confidence=0.8 * self.sensitivity,
                    remediation="Remove or verify suspicious metadata fields",
                ))

        # Check for metadata that claims special status
        source = str(metadata.get("source", "")).lower()
        if any(word in source for word in ["official", "verified", "trusted", "authoritative"]):
            indicators.append(PoisoningIndicator(
                poisoning_type=PoisoningType.SOURCE_SPOOFING,
                severity=SeverityLevel.MEDIUM,
                description="Source claims special authority status",
                evidence=f"source: {metadata.get('source')}",
                confidence=0.6 * self.sensitivity,
                remediation="Verify source authenticity independently",
            ))

        return indicators

    def _detect_semantic_collision(self, query: str, content: str) -> bool:
        """Detect if content appears crafted for semantic collision."""
        # Simple heuristic: check if content repeats query terms unnaturally
        query_words = set(query.lower().split())
        content_words = content.lower().split()

        if len(content_words) < 20:
            return False

        # Calculate what percentage of content is query words
        query_word_count = sum(1 for w in content_words if w in query_words)
        ratio = query_word_count / len(content_words)

        # If >30% of content is query words, suspicious
        return ratio > 0.3

    def _calculate_poisoning_score(self, indicators: List[PoisoningIndicator]) -> float:
        """Calculate overall poisoning score."""
        if not indicators:
            return 0.0

        # Weight by severity
        severity_weights = {
            SeverityLevel.CRITICAL: 1.0,
            SeverityLevel.HIGH: 0.7,
            SeverityLevel.MEDIUM: 0.4,
            SeverityLevel.LOW: 0.2,
        }

        weighted_sum = sum(
            severity_weights[i.severity] * i.confidence
            for i in indicators
        )

        # Normalize to 0-1 range
        max_possible = len(indicators) * 1.0  # All critical, confidence 1.0
        normalized = weighted_sum / max_possible if max_possible > 0 else 0

        # Bonus for multiple indicators (indicates coordinated attack)
        if len(indicators) >= 3:
            normalized = min(normalized * 1.2, 1.0)
        if len(indicators) >= 5:
            normalized = min(normalized * 1.3, 1.0)

        return min(normalized, 1.0)

    def _generate_risk_summary(
        self,
        indicators: List[PoisoningIndicator],
        score: float,
    ) -> str:
        """Generate a human-readable risk summary."""
        if score < 0.2:
            return "Low risk - No significant poisoning indicators detected"
        elif score < 0.5:
            return f"Medium risk - {len(indicators)} potential poisoning indicators found"
        elif score < 0.8:
            return f"High risk - Document shows strong signs of poisoning ({len(indicators)} indicators)"
        else:
            return f"Critical risk - Document is likely poisoned ({len(indicators)} indicators, score: {score:.2f})"

    def _generate_recommendations(
        self,
        indicators: List[PoisoningIndicator],
    ) -> List[str]:
        """Generate recommendations based on indicators."""
        recommendations = []

        if not indicators:
            recommendations.append("Document appears safe - continue with normal ingestion")
            return recommendations

        # Group by type
        types = set(i.poisoning_type for i in indicators)

        if PoisoningType.INSTRUCTION_INJECTION in types:
            recommendations.append("BLOCK: Remove instruction injection patterns before ingestion")

        if PoisoningType.AUTHORITY_SPOOFING in types:
            recommendations.append("Verify document source and claimed authority independently")

        if PoisoningType.METADATA_INJECTION in types:
            recommendations.append("Strip suspicious metadata fields before ingestion")

        if PoisoningType.EMBEDDING_MANIPULATION in types:
            recommendations.append("Review for keyword stuffing and normalize content")

        if PoisoningType.FACT_POLLUTION in types:
            recommendations.append("Cross-reference claims with trusted sources")

        # General recommendations
        critical_count = sum(1 for i in indicators if i.severity == SeverityLevel.CRITICAL)
        if critical_count > 0:
            recommendations.insert(0, f"URGENT: {critical_count} critical indicators - manual review required")

        return recommendations

    def _get_remediation(self, poisoning_type: PoisoningType) -> str:
        """Get remediation advice for a poisoning type."""
        remediations = {
            PoisoningType.INSTRUCTION_INJECTION: "Remove or sanitize instruction patterns",
            PoisoningType.CONTEXT_MANIPULATION: "Verify claims and normalize emphasis",
            PoisoningType.FACT_POLLUTION: "Cross-reference with trusted sources",
            PoisoningType.AUTHORITY_SPOOFING: "Verify source authenticity",
            PoisoningType.EMBEDDING_MANIPULATION: "Normalize content and remove repetition",
            PoisoningType.RETRIEVAL_HIJACKING: "Remove retrieval manipulation phrases",
            PoisoningType.SEMANTIC_COLLISION: "Review for artificial query matching",
            PoisoningType.METADATA_INJECTION: "Strip suspicious metadata",
            PoisoningType.SOURCE_SPOOFING: "Verify source independently",
            PoisoningType.TIMESTAMP_MANIPULATION: "Verify document timestamps",
        }
        return remediations.get(poisoning_type, "Review and sanitize content")
