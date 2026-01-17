"""Risk scorer for SecureAgent."""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path

from ..core.models.finding import Finding
from ..core.models.severity import Severity
from .models import EnsembleModel, Prediction
from .features.base import FeatureExtractor

logger = logging.getLogger(__name__)


@dataclass
class RiskAssessment:
    """Complete risk assessment result."""

    overall_score: float
    risk_level: str
    confidence: float
    finding_scores: Dict[str, float] = field(default_factory=dict)
    risk_factors: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class RiskScorer:
    """Score security risks using ML and heuristics."""

    # Severity-based weights
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.8,
        Severity.MEDIUM: 0.5,
        Severity.LOW: 0.2,
        Severity.INFO: 0.05,
    }

    # Risk factor weights
    FACTOR_WEIGHTS = {
        "credential_exposure": 0.9,
        "command_injection": 0.85,
        "data_exposure": 0.8,
        "auth_bypass": 0.75,
        "privilege_escalation": 0.7,
        "network_exposure": 0.65,
        "encryption_missing": 0.6,
        "configuration_issue": 0.4,
        "information_disclosure": 0.3,
    }

    def __init__(
        self,
        model_path: Optional[Path] = None,
        use_ml: bool = True,
    ):
        """Initialize risk scorer."""
        self.use_ml = use_ml
        self.model: Optional[EnsembleModel] = None
        self.feature_extractors: List[FeatureExtractor] = []

        if model_path and use_ml:
            self.load_model(model_path)

    def load_model(self, path: Path) -> None:
        """Load ML model from file."""
        try:
            self.model = EnsembleModel()
            self.model.load(path)
            logger.info(f"ML model loaded from {path}")
        except Exception as e:
            logger.warning(f"Failed to load ML model: {e}")
            self.model = None

    def register_extractor(self, extractor: FeatureExtractor) -> None:
        """Register a feature extractor."""
        self.feature_extractors.append(extractor)

    def score_findings(self, findings: List[Finding]) -> RiskAssessment:
        """Score a list of findings."""
        if not findings:
            return RiskAssessment(
                overall_score=0.0,
                risk_level="low",
                confidence=1.0,
                recommendations=["No security findings detected."],
            )

        # Calculate individual finding scores
        finding_scores = {}
        for finding in findings:
            score = self._score_finding(finding)
            finding_scores[finding.id] = score

        # Calculate overall score
        overall_score = self._calculate_overall_score(findings, finding_scores)
        risk_level = self._score_to_level(overall_score)

        # Identify risk factors
        risk_factors = self._identify_risk_factors(findings)

        # Generate recommendations
        recommendations = self._generate_recommendations(findings, risk_factors)

        # Calculate confidence
        confidence = self._calculate_confidence(findings)

        return RiskAssessment(
            overall_score=overall_score,
            risk_level=risk_level,
            confidence=confidence,
            finding_scores=finding_scores,
            risk_factors=risk_factors,
            recommendations=recommendations,
        )

    def score_finding(self, finding: Finding) -> float:
        """Score a single finding."""
        return self._score_finding(finding)

    def score(self, finding: Finding) -> float:
        """Score a single finding (alias for score_finding)."""
        return self._score_finding(finding)

    def score_batch(self, findings: List[Finding]) -> List[float]:
        """Score multiple findings in batch.

        Args:
            findings: List of findings to score

        Returns:
            List of risk scores (0.0-1.0)
        """
        return [self._score_finding(f) for f in findings]

    def _score_finding(self, finding: Finding) -> float:
        """Calculate risk score for a finding."""
        # Base score from severity
        base_score = self.SEVERITY_WEIGHTS.get(finding.severity, 0.1)

        # Factor modifiers
        modifiers = []

        # Check rule ID patterns for risk factors
        rule_lower = finding.rule_id.lower()
        for factor, weight in self.FACTOR_WEIGHTS.items():
            factor_keywords = factor.replace("_", " ").split()
            if any(kw in rule_lower or kw in finding.title.lower() for kw in factor_keywords):
                modifiers.append(weight)

        # Apply ML prediction if available
        if self.model and self.use_ml:
            features = self._extract_features(finding)
            try:
                prediction = self.model.predict(features)
                modifiers.append(prediction.risk_score)
            except Exception as e:
                logger.debug(f"ML prediction failed: {e}")

        # Calculate final score
        if modifiers:
            modifier = sum(modifiers) / len(modifiers)
            score = (base_score + modifier) / 2
        else:
            score = base_score

        # Use finding's existing risk score if available
        if finding.risk_score is not None:
            score = (score + finding.risk_score) / 2

        return min(max(score, 0.0), 1.0)

    def _calculate_overall_score(
        self,
        findings: List[Finding],
        finding_scores: Dict[str, float],
    ) -> float:
        """Calculate overall risk score."""
        if not findings:
            return 0.0

        # Weight by severity for overall score
        weighted_sum = 0.0
        weight_total = 0.0

        for finding in findings:
            score = finding_scores.get(finding.id, 0.0)
            weight = self.SEVERITY_WEIGHTS.get(finding.severity, 0.1)
            weighted_sum += score * weight
            weight_total += weight

        if weight_total == 0:
            return 0.0

        # Normalize and apply count penalty
        base_score = weighted_sum / weight_total

        # More findings increase risk
        count_factor = min(1.0 + (len(findings) - 1) * 0.05, 1.5)

        # Critical findings heavily impact score
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        if critical_count > 0:
            count_factor += critical_count * 0.1

        return min(base_score * count_factor, 1.0)

    def _score_to_level(self, score: float) -> str:
        """Convert score to risk level."""
        if score >= 0.85:
            return "critical"
        elif score >= 0.65:
            return "high"
        elif score >= 0.40:
            return "medium"
        else:
            return "low"

    def _identify_risk_factors(
        self, findings: List[Finding]
    ) -> List[Dict[str, Any]]:
        """Identify key risk factors from findings."""
        factors = []

        # Count findings by category
        category_counts: Dict[str, int] = {}
        for finding in findings:
            # Extract category from rule ID
            parts = finding.rule_id.split("-")
            if len(parts) >= 2:
                category = parts[0]
            else:
                category = "general"
            category_counts[category] = category_counts.get(category, 0) + 1

        # Identify dominant categories
        for category, count in sorted(
            category_counts.items(), key=lambda x: x[1], reverse=True
        ):
            severity_list = [
                f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                for f in findings
                if f.rule_id.startswith(category)
            ]
            factors.append(
                {
                    "category": category,
                    "finding_count": count,
                    "severities": severity_list,
                    "impact": "high" if count >= 3 else "medium" if count >= 2 else "low",
                }
            )

        return factors[:5]  # Top 5 factors

    def _generate_recommendations(
        self,
        findings: List[Finding],
        risk_factors: List[Dict[str, Any]],
    ) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = []

        # Priority by severity
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        high_findings = [f for f in findings if f.severity == Severity.HIGH]

        if critical_findings:
            recommendations.append(
                f"URGENT: Address {len(critical_findings)} critical findings immediately"
            )
            # Add specific remediations
            for finding in critical_findings[:3]:
                if finding.remediation:
                    recommendations.append(f"  - {finding.remediation}")

        if high_findings:
            recommendations.append(
                f"HIGH PRIORITY: Review {len(high_findings)} high severity findings"
            )

        # Add factor-specific recommendations
        for factor in risk_factors:
            if factor["category"] == "MCP":
                recommendations.append(
                    "Review MCP server configurations for security best practices"
                )
            elif factor["category"] == "AWS":
                recommendations.append(
                    "Audit AWS resource permissions and encryption settings"
                )
            elif factor["category"] == "LC":
                recommendations.append(
                    "Review LangChain agent configurations for security issues"
                )

        return recommendations[:10]

    def _calculate_confidence(self, findings: List[Finding]) -> float:
        """Calculate confidence in the assessment."""
        if not findings:
            return 1.0

        # More findings with remediations = higher confidence
        with_remediation = sum(1 for f in findings if f.remediation)

        # More findings with CWE/OWASP = higher confidence
        with_refs = sum(1 for f in findings if f.cwe_id or f.owasp_id)

        confidence_factors = [
            min(len(findings) / 10, 1.0) * 0.3,  # Finding count
            (with_remediation / max(len(findings), 1)) * 0.4,  # Remediation coverage
            (with_refs / max(len(findings), 1)) * 0.3,  # Reference coverage
        ]

        return sum(confidence_factors)

    def _extract_features(self, finding: Finding) -> Dict[str, float]:
        """Extract features from a finding for ML prediction."""
        features = {
            "severity_critical": 1.0 if finding.severity == Severity.CRITICAL else 0.0,
            "severity_high": 1.0 if finding.severity == Severity.HIGH else 0.0,
            "severity_medium": 1.0 if finding.severity == Severity.MEDIUM else 0.0,
            "severity_low": 1.0 if finding.severity == Severity.LOW else 0.0,
            "has_remediation": 1.0 if finding.remediation else 0.0,
            "has_cwe": 1.0 if finding.cwe_id else 0.0,
            "has_owasp": 1.0 if finding.owasp_id else 0.0,
            "description_length": min(len(finding.description) / 500, 1.0),
        }

        # Add features from registered extractors
        for extractor in self.feature_extractors:
            try:
                extracted = extractor.extract(finding)
                features.update(extracted)
            except Exception as e:
                logger.debug(f"Feature extraction failed: {e}")

        return features
