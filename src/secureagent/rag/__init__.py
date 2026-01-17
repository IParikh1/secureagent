"""RAG Security Analysis Module for SecureAgent.

Provides comprehensive security analysis for Retrieval-Augmented Generation systems:
- Vector store configuration security (Pinecone, Chroma, Weaviate, Qdrant, Milvus)
- Document ingestion security scanning
- RAG poisoning detection
- Retrieval security analysis
"""

from .vector_stores import (
    VectorStoreType,
    VectorStoreConfig,
    VectorStoreSecurityAnalyzer,
)
from .document_scanner import (
    DocumentRisk,
    ThreatCategory,
    DocumentThreat,
    DocumentScanResult,
    DocumentSecurityScanner,
    ChunkSecurityAnalyzer,
)
from .poisoning import (
    PoisoningType,
    SeverityLevel,
    PoisoningIndicator,
    PoisoningAnalysisResult,
    RAGPoisoningDetector,
)
from .scanner import (
    RAGSecurityReport,
    RAGSecurityScanner,
)

__all__ = [
    # Vector store analysis
    "VectorStoreType",
    "VectorStoreConfig",
    "VectorStoreSecurityAnalyzer",
    # Document scanning
    "DocumentRisk",
    "ThreatCategory",
    "DocumentThreat",
    "DocumentScanResult",
    "DocumentSecurityScanner",
    "ChunkSecurityAnalyzer",
    # Poisoning detection
    "PoisoningType",
    "SeverityLevel",
    "PoisoningIndicator",
    "PoisoningAnalysisResult",
    "RAGPoisoningDetector",
    # Main scanner
    "RAGSecurityReport",
    "RAGSecurityScanner",
]
