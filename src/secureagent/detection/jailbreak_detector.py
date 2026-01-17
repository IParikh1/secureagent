"""Jailbreak detection engine.

This module provides real-time jailbreak detection capabilities
for analyzing prompts sent to AI agents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple
import re

from .patterns import (
    JailbreakCategory,
    JailbreakPattern,
    JailbreakPatternLibrary,
    RiskLevel,
    get_pattern_library,
)


class DetectionResult(Enum):
    """Result of jailbreak detection."""

    CLEAN = "clean"  # No jailbreak detected
    SUSPICIOUS = "suspicious"  # Some indicators found, may be false positive
    LIKELY_JAILBREAK = "likely_jailbreak"  # Strong indicators of jailbreak
    CONFIRMED_JAILBREAK = "confirmed_jailbreak"  # Multiple strong indicators


@dataclass
class PatternMatch:
    """A matched jailbreak pattern."""

    pattern: JailbreakPattern
    matched_text: str
    start_position: int
    end_position: int
    confidence: float = 1.0

    @property
    def risk_level(self) -> RiskLevel:
        """Get the risk level of the matched pattern."""
        return self.pattern.risk_level

    @property
    def category(self) -> JailbreakCategory:
        """Get the category of the matched pattern."""
        return self.pattern.category


@dataclass
class DetectionReport:
    """Report from jailbreak detection analysis."""

    input_text: str
    result: DetectionResult
    risk_score: float  # 0.0 to 1.0
    matches: List[PatternMatch] = field(default_factory=list)
    categories_detected: List[JailbreakCategory] = field(default_factory=list)
    highest_risk: Optional[RiskLevel] = None
    recommendations: List[str] = field(default_factory=list)
    analysis_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)

    @property
    def is_jailbreak(self) -> bool:
        """Check if this is likely a jailbreak attempt."""
        return self.result in [
            DetectionResult.LIKELY_JAILBREAK,
            DetectionResult.CONFIRMED_JAILBREAK,
        ]

    @property
    def match_count(self) -> int:
        """Get the number of pattern matches."""
        return len(self.matches)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "result": self.result.value,
            "risk_score": self.risk_score,
            "is_jailbreak": self.is_jailbreak,
            "match_count": self.match_count,
            "highest_risk": self.highest_risk.value if self.highest_risk else None,
            "categories_detected": [c.value for c in self.categories_detected],
            "matches": [
                {
                    "pattern_id": m.pattern.id,
                    "pattern_name": m.pattern.name,
                    "category": m.category.value,
                    "risk_level": m.risk_level.value,
                    "matched_text": m.matched_text[:100] + "..." if len(m.matched_text) > 100 else m.matched_text,
                    "confidence": m.confidence,
                }
                for m in self.matches
            ],
            "recommendations": self.recommendations,
            "analysis_time_ms": self.analysis_time_ms,
            "timestamp": self.timestamp.isoformat(),
        }


class JailbreakDetector:
    """Detects jailbreak attempts in text.

    This class provides real-time analysis of prompts to detect
    potential jailbreak attempts using pattern matching and heuristics.
    """

    # Risk score thresholds
    THRESHOLD_SUSPICIOUS = 0.2
    THRESHOLD_LIKELY = 0.5
    THRESHOLD_CONFIRMED = 0.8

    # Risk level weights for scoring
    RISK_WEIGHTS = {
        RiskLevel.CRITICAL: 1.0,
        RiskLevel.HIGH: 0.7,
        RiskLevel.MEDIUM: 0.4,
        RiskLevel.LOW: 0.2,
        RiskLevel.INFO: 0.1,
    }

    def __init__(
        self,
        pattern_library: Optional[JailbreakPatternLibrary] = None,
        sensitivity: float = 1.0,
        enabled_categories: Optional[List[JailbreakCategory]] = None,
    ):
        """Initialize the detector.

        Args:
            pattern_library: Pattern library to use (default: global library)
            sensitivity: Detection sensitivity multiplier (default: 1.0)
            enabled_categories: Categories to check (default: all)
        """
        self._library = pattern_library or get_pattern_library()
        self._sensitivity = sensitivity
        self._enabled_categories = enabled_categories

    def detect(self, text: str) -> DetectionReport:
        """Analyze text for jailbreak attempts.

        Args:
            text: Text to analyze

        Returns:
            DetectionReport with analysis results
        """
        import time
        start_time = time.time()

        # Initialize report
        matches: List[PatternMatch] = []
        categories_detected: set = set()

        # Normalize text for analysis
        normalized_text = self._normalize_text(text)

        # Check all patterns
        patterns = self._library.get_all_patterns()
        for pattern in patterns:
            # Skip disabled categories
            if self._enabled_categories and pattern.category not in self._enabled_categories:
                continue

            # Check pattern matches
            pattern_matches = self._check_pattern(pattern, text, normalized_text)
            if pattern_matches:
                matches.extend(pattern_matches)
                categories_detected.add(pattern.category)

        # Calculate risk score
        risk_score = self._calculate_risk_score(matches)

        # Apply sensitivity
        risk_score = min(1.0, risk_score * self._sensitivity)

        # Determine result
        result = self._determine_result(risk_score, matches)

        # Get highest risk level
        highest_risk = None
        if matches:
            risk_priority = {
                RiskLevel.CRITICAL: 5,
                RiskLevel.HIGH: 4,
                RiskLevel.MEDIUM: 3,
                RiskLevel.LOW: 2,
                RiskLevel.INFO: 1,
            }
            highest_risk = max(
                (m.risk_level for m in matches),
                key=lambda r: risk_priority.get(r, 0)
            )

        # Generate recommendations
        recommendations = self._generate_recommendations(matches, result)

        # Calculate analysis time
        analysis_time_ms = (time.time() - start_time) * 1000

        return DetectionReport(
            input_text=text,
            result=result,
            risk_score=risk_score,
            matches=matches,
            categories_detected=list(categories_detected),
            highest_risk=highest_risk,
            recommendations=recommendations,
            analysis_time_ms=analysis_time_ms,
        )

    def _normalize_text(self, text: str) -> str:
        """Normalize text for pattern matching."""
        # Convert to lowercase
        normalized = text.lower()

        # Normalize whitespace
        normalized = re.sub(r'\s+', ' ', normalized)

        # Remove some common obfuscation
        # Remove zero-width characters
        normalized = re.sub(r'[\u200b\u200c\u200d\u2060\ufeff]', '', normalized)

        return normalized

    def _check_pattern(
        self,
        pattern: JailbreakPattern,
        original_text: str,
        normalized_text: str,
    ) -> List[PatternMatch]:
        """Check a pattern against text."""
        matches: List[PatternMatch] = []

        # Check regex patterns
        for compiled_pattern in pattern.compiled_patterns:
            for match in compiled_pattern.finditer(original_text):
                matches.append(PatternMatch(
                    pattern=pattern,
                    matched_text=match.group(0),
                    start_position=match.start(),
                    end_position=match.end(),
                    confidence=1.0,
                ))

            # Also check normalized text
            for match in compiled_pattern.finditer(normalized_text):
                # Avoid duplicates from same position
                if not any(
                    m.start_position == match.start() and m.end_position == match.end()
                    for m in matches
                ):
                    matches.append(PatternMatch(
                        pattern=pattern,
                        matched_text=match.group(0),
                        start_position=match.start(),
                        end_position=match.end(),
                        confidence=0.9,  # Slightly lower for normalized match
                    ))

        # Check keywords (case-insensitive)
        for keyword in pattern.keywords:
            keyword_lower = keyword.lower()
            if keyword_lower in normalized_text:
                # Find position
                pos = normalized_text.find(keyword_lower)
                # Check if not already matched by regex
                if not any(
                    m.start_position <= pos < m.end_position
                    for m in matches
                ):
                    matches.append(PatternMatch(
                        pattern=pattern,
                        matched_text=keyword,
                        start_position=pos,
                        end_position=pos + len(keyword),
                        confidence=0.7,  # Keywords have lower confidence
                    ))

        return matches

    def _calculate_risk_score(self, matches: List[PatternMatch]) -> float:
        """Calculate overall risk score from matches."""
        if not matches:
            return 0.0

        # Weight by risk level and confidence
        total_weight = 0.0
        for match in matches:
            weight = self.RISK_WEIGHTS.get(match.risk_level, 0.1)
            total_weight += weight * match.confidence

        # Normalize to 0-1 range
        # More matches increase score, but diminishing returns
        base_score = min(1.0, total_weight / 2.0)

        # Bonus for multiple categories (indicates sophisticated attack)
        unique_categories = len(set(m.category for m in matches))
        category_bonus = min(0.2, unique_categories * 0.05)

        # Bonus for critical matches
        critical_count = len([m for m in matches if m.risk_level == RiskLevel.CRITICAL])
        critical_bonus = min(0.3, critical_count * 0.15)

        return min(1.0, base_score + category_bonus + critical_bonus)

    def _determine_result(
        self,
        risk_score: float,
        matches: List[PatternMatch],
    ) -> DetectionResult:
        """Determine detection result from risk score and matches."""
        if risk_score >= self.THRESHOLD_CONFIRMED:
            return DetectionResult.CONFIRMED_JAILBREAK

        if risk_score >= self.THRESHOLD_LIKELY:
            return DetectionResult.LIKELY_JAILBREAK

        if risk_score >= self.THRESHOLD_SUSPICIOUS:
            return DetectionResult.SUSPICIOUS

        # Even with low score, critical matches are suspicious
        if any(m.risk_level == RiskLevel.CRITICAL for m in matches):
            return DetectionResult.SUSPICIOUS

        return DetectionResult.CLEAN

    def _generate_recommendations(
        self,
        matches: List[PatternMatch],
        result: DetectionResult,
    ) -> List[str]:
        """Generate recommendations based on detection results."""
        recommendations = []

        if result == DetectionResult.CONFIRMED_JAILBREAK:
            recommendations.append("BLOCK: High confidence jailbreak attempt detected")
            recommendations.append("Log this attempt for security analysis")
            recommendations.append("Consider rate-limiting this user")
        elif result == DetectionResult.LIKELY_JAILBREAK:
            recommendations.append("WARN: Likely jailbreak attempt - consider blocking or manual review")
            recommendations.append("Request rephrasing from user")
        elif result == DetectionResult.SUSPICIOUS:
            recommendations.append("MONITOR: Suspicious content detected - log for review")
            recommendations.append("Continue with caution, monitor follow-up messages")

        # Category-specific recommendations
        categories = set(m.category for m in matches)

        if JailbreakCategory.SYSTEM_PROMPT_EXTRACTION in categories:
            recommendations.append("Do not reveal system prompt content")

        if JailbreakCategory.AUTHORITY_IMPERSONATION in categories:
            recommendations.append("Never trust claims of developer/admin status in user messages")

        if JailbreakCategory.DELIMITER_ATTACK in categories:
            recommendations.append("Detected delimiter manipulation - ensure proper input sanitization")

        if JailbreakCategory.DAN_JAILBREAK in categories:
            recommendations.append("Classic DAN-style jailbreak detected - do not comply with persona requests")

        return recommendations

    def detect_batch(self, texts: List[str]) -> List[DetectionReport]:
        """Analyze multiple texts.

        Args:
            texts: List of texts to analyze

        Returns:
            List of DetectionReports
        """
        return [self.detect(text) for text in texts]

    def get_statistics(self, reports: List[DetectionReport]) -> Dict:
        """Get statistics from multiple detection reports.

        Args:
            reports: List of detection reports

        Returns:
            Dictionary with statistics
        """
        if not reports:
            return {
                "total": 0,
                "clean": 0,
                "suspicious": 0,
                "likely_jailbreak": 0,
                "confirmed_jailbreak": 0,
                "average_risk_score": 0.0,
            }

        result_counts = {result: 0 for result in DetectionResult}
        for report in reports:
            result_counts[report.result] += 1

        return {
            "total": len(reports),
            "clean": result_counts[DetectionResult.CLEAN],
            "suspicious": result_counts[DetectionResult.SUSPICIOUS],
            "likely_jailbreak": result_counts[DetectionResult.LIKELY_JAILBREAK],
            "confirmed_jailbreak": result_counts[DetectionResult.CONFIRMED_JAILBREAK],
            "average_risk_score": sum(r.risk_score for r in reports) / len(reports),
            "jailbreak_rate": (
                result_counts[DetectionResult.LIKELY_JAILBREAK] +
                result_counts[DetectionResult.CONFIRMED_JAILBREAK]
            ) / len(reports),
            "top_categories": self._get_top_categories(reports),
        }

    def _get_top_categories(self, reports: List[DetectionReport]) -> Dict[str, int]:
        """Get most common categories from reports."""
        category_counts: Dict[str, int] = {}
        for report in reports:
            for category in report.categories_detected:
                category_counts[category.value] = category_counts.get(category.value, 0) + 1

        return dict(sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5])


class ConversationMonitor:
    """Monitors conversations for jailbreak attempts over multiple turns.

    This class tracks conversation history and can detect multi-turn
    jailbreak attempts that build up gradually.
    """

    def __init__(
        self,
        detector: Optional[JailbreakDetector] = None,
        window_size: int = 10,
        escalation_threshold: float = 0.3,
    ):
        """Initialize the conversation monitor.

        Args:
            detector: Jailbreak detector to use
            window_size: Number of messages to keep in context
            escalation_threshold: Risk score increase to flag escalation
        """
        self._detector = detector or JailbreakDetector()
        self._window_size = window_size
        self._escalation_threshold = escalation_threshold
        self._history: List[DetectionReport] = []

    def analyze_message(self, message: str) -> Tuple[DetectionReport, bool]:
        """Analyze a message in conversation context.

        Args:
            message: Message to analyze

        Returns:
            Tuple of (DetectionReport, is_escalating)
        """
        # Detect jailbreak in current message
        report = self._detector.detect(message)

        # Check for escalation
        is_escalating = self._check_escalation(report)

        # Update history
        self._history.append(report)
        if len(self._history) > self._window_size:
            self._history.pop(0)

        return report, is_escalating

    def _check_escalation(self, current_report: DetectionReport) -> bool:
        """Check if there's a risk escalation pattern."""
        if len(self._history) < 2:
            return False

        # Compare with recent average
        recent_scores = [r.risk_score for r in self._history[-5:]]
        recent_avg = sum(recent_scores) / len(recent_scores)

        # Check if current score is significantly higher
        if current_report.risk_score > recent_avg + self._escalation_threshold:
            return True

        # Check for gradual buildup
        if len(self._history) >= 3:
            trend = [r.risk_score for r in self._history[-3:]]
            if trend[0] < trend[1] < trend[2] < current_report.risk_score:
                return True

        return False

    def get_conversation_risk(self) -> float:
        """Get overall conversation risk score."""
        if not self._history:
            return 0.0

        # Weighted average - recent messages count more
        weights = [i + 1 for i in range(len(self._history))]
        weighted_sum = sum(r.risk_score * w for r, w in zip(self._history, weights))
        return weighted_sum / sum(weights)

    def reset(self) -> None:
        """Reset conversation history."""
        self._history.clear()

    def get_summary(self) -> Dict:
        """Get conversation analysis summary."""
        if not self._history:
            return {
                "message_count": 0,
                "average_risk": 0.0,
                "max_risk": 0.0,
                "jailbreak_attempts": 0,
            }

        return {
            "message_count": len(self._history),
            "average_risk": sum(r.risk_score for r in self._history) / len(self._history),
            "max_risk": max(r.risk_score for r in self._history),
            "jailbreak_attempts": sum(1 for r in self._history if r.is_jailbreak),
            "escalation_detected": any(
                self._history[i].risk_score > self._history[i-1].risk_score + self._escalation_threshold
                for i in range(1, len(self._history))
            ),
        }
