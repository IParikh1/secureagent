"""Jailbreak and threat detection module for SecureAgent."""

from .patterns import (
    JailbreakCategory,
    JailbreakPattern,
    JailbreakPatternLibrary,
    RiskLevel,
    get_pattern_library,
)
from .jailbreak_detector import (
    ConversationMonitor,
    DetectionReport,
    DetectionResult,
    JailbreakDetector,
    PatternMatch,
)

__all__ = [
    # Pattern library
    "JailbreakCategory",
    "JailbreakPattern",
    "JailbreakPatternLibrary",
    "RiskLevel",
    "get_pattern_library",
    # Detector
    "ConversationMonitor",
    "DetectionReport",
    "DetectionResult",
    "JailbreakDetector",
    "PatternMatch",
]
