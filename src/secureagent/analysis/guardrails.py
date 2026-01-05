"""Guardrail analysis for AI agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from secureagent.core.models.agent import AgentInventoryItem, Guardrail
from secureagent.core.models.severity import Severity


class GuardrailType(Enum):
    """Types of guardrails."""

    INPUT_VALIDATION = "input_validation"
    OUTPUT_FILTERING = "output_filtering"
    CONTENT_MODERATION = "content_moderation"
    PII_DETECTION = "pii_detection"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_DETECTION = "jailbreak_detection"
    RATE_LIMITING = "rate_limiting"
    COST_LIMITING = "cost_limiting"
    TOPIC_RESTRICTION = "topic_restriction"
    HALLUCINATION_DETECTION = "hallucination_detection"


class CoverageStatus(Enum):
    """Guardrail coverage status."""

    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"


@dataclass
class GuardrailCoverage:
    """Coverage assessment for a guardrail type."""

    guardrail_type: GuardrailType
    status: CoverageStatus
    implemented_guardrails: List[Guardrail] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class GuardrailReport:
    """Guardrail analysis report for an agent."""

    agent_id: str
    agent_name: str
    total_guardrails: int = 0
    active_guardrails: int = 0
    coverage: List[GuardrailCoverage] = field(default_factory=list)
    overall_coverage_score: float = 0.0
    missing_critical: List[GuardrailType] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    @property
    def has_full_coverage(self) -> bool:
        """Check if all guardrail types have full coverage."""
        return all(c.status == CoverageStatus.FULL for c in self.coverage)

    @property
    def uncovered_types(self) -> List[GuardrailType]:
        """Get guardrail types with no coverage."""
        return [c.guardrail_type for c in self.coverage if c.status == CoverageStatus.NONE]


# Required guardrails by risk profile
REQUIRED_GUARDRAILS = {
    "high_risk": [
        GuardrailType.INPUT_VALIDATION,
        GuardrailType.OUTPUT_FILTERING,
        GuardrailType.PROMPT_INJECTION,
        GuardrailType.PII_DETECTION,
        GuardrailType.RATE_LIMITING,
    ],
    "medium_risk": [
        GuardrailType.INPUT_VALIDATION,
        GuardrailType.OUTPUT_FILTERING,
        GuardrailType.CONTENT_MODERATION,
    ],
    "low_risk": [
        GuardrailType.INPUT_VALIDATION,
    ],
}


class GuardrailAnalyzer:
    """Analyzes guardrail coverage for AI agents."""

    # Mapping of guardrail name patterns to types
    GUARDRAIL_PATTERNS = {
        GuardrailType.INPUT_VALIDATION: ["input", "validate", "sanitize", "filter_input"],
        GuardrailType.OUTPUT_FILTERING: ["output", "response", "filter_output"],
        GuardrailType.CONTENT_MODERATION: ["moderation", "content", "toxic", "harmful"],
        GuardrailType.PII_DETECTION: ["pii", "personal", "sensitive", "redact"],
        GuardrailType.PROMPT_INJECTION: ["injection", "prompt_guard", "jailbreak"],
        GuardrailType.JAILBREAK_DETECTION: ["jailbreak", "bypass", "escape"],
        GuardrailType.RATE_LIMITING: ["rate", "limit", "throttle", "quota"],
        GuardrailType.COST_LIMITING: ["cost", "budget", "spending"],
        GuardrailType.TOPIC_RESTRICTION: ["topic", "allow", "deny", "restrict"],
        GuardrailType.HALLUCINATION_DETECTION: ["hallucination", "fact", "ground"],
    }

    def __init__(self):
        """Initialize the analyzer."""
        self._reports: Dict[str, GuardrailReport] = {}

    def analyze(
        self, agent: AgentInventoryItem, risk_profile: str = "medium_risk"
    ) -> GuardrailReport:
        """Analyze guardrail coverage for an agent.

        Args:
            agent: Agent to analyze
            risk_profile: Risk profile (high_risk, medium_risk, low_risk)

        Returns:
            GuardrailReport with analysis results
        """
        report = GuardrailReport(
            agent_id=agent.id,
            agent_name=agent.name,
            total_guardrails=len(agent.guardrails),
            active_guardrails=len([g for g in agent.guardrails if g.enabled]),
        )

        # Classify existing guardrails
        guardrail_by_type = self._classify_guardrails(agent.guardrails)

        # Get required guardrails for risk profile
        required = REQUIRED_GUARDRAILS.get(risk_profile, REQUIRED_GUARDRAILS["medium_risk"])

        # Assess coverage for each type
        for guardrail_type in GuardrailType:
            coverage = self._assess_coverage(
                guardrail_type,
                guardrail_by_type.get(guardrail_type, []),
                guardrail_type in required,
            )
            report.coverage.append(coverage)

            # Track missing critical guardrails
            if guardrail_type in required and coverage.status == CoverageStatus.NONE:
                report.missing_critical.append(guardrail_type)

        # Calculate overall score
        report.overall_coverage_score = self._calculate_coverage_score(report, required)

        # Generate recommendations
        report.recommendations = self._generate_recommendations(report, required)

        self._reports[agent.id] = report
        return report

    def _classify_guardrails(
        self, guardrails: List[Guardrail]
    ) -> Dict[GuardrailType, List[Guardrail]]:
        """Classify guardrails by type based on name patterns."""
        classified: Dict[GuardrailType, List[Guardrail]] = {}

        for guardrail in guardrails:
            guardrail_lower = guardrail.name.lower()

            for gtype, patterns in self.GUARDRAIL_PATTERNS.items():
                if any(p in guardrail_lower for p in patterns):
                    if gtype not in classified:
                        classified[gtype] = []
                    classified[gtype].append(guardrail)
                    break

        return classified

    def _assess_coverage(
        self,
        guardrail_type: GuardrailType,
        implemented: List[Guardrail],
        is_required: bool,
    ) -> GuardrailCoverage:
        """Assess coverage for a guardrail type."""
        coverage = GuardrailCoverage(
            guardrail_type=guardrail_type,
            implemented_guardrails=implemented,
        )

        if len(implemented) == 0:
            coverage.status = CoverageStatus.NONE
            coverage.gaps.append(f"No {guardrail_type.value} guardrails implemented")
            if is_required:
                coverage.recommendation = f"CRITICAL: Implement {guardrail_type.value} guardrails"
            else:
                coverage.recommendation = f"Consider implementing {guardrail_type.value}"
        elif all(g.enabled for g in implemented):
            coverage.status = CoverageStatus.FULL
            coverage.recommendation = "Coverage adequate"
        else:
            coverage.status = CoverageStatus.PARTIAL
            disabled = [g.name for g in implemented if not g.enabled]
            coverage.gaps.append(f"Disabled guardrails: {', '.join(disabled)}")
            coverage.recommendation = f"Enable disabled guardrails: {', '.join(disabled)}"

        return coverage

    def _calculate_coverage_score(
        self, report: GuardrailReport, required: List[GuardrailType]
    ) -> float:
        """Calculate overall coverage score."""
        if not required:
            return 1.0

        score_map = {
            CoverageStatus.FULL: 1.0,
            CoverageStatus.PARTIAL: 0.5,
            CoverageStatus.NONE: 0.0,
        }

        required_coverage = [c for c in report.coverage if c.guardrail_type in required]

        if not required_coverage:
            return 0.0

        total_score = sum(score_map[c.status] for c in required_coverage)
        return total_score / len(required_coverage)

    def _generate_recommendations(
        self, report: GuardrailReport, required: List[GuardrailType]
    ) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []

        # Critical missing guardrails
        for gtype in report.missing_critical:
            recommendations.append(
                f"CRITICAL: Implement {gtype.value} guardrails immediately"
            )

        # Partially covered
        for coverage in report.coverage:
            if coverage.status == CoverageStatus.PARTIAL:
                recommendations.append(coverage.recommendation)

        # Nice-to-have
        for coverage in report.coverage:
            if (
                coverage.status == CoverageStatus.NONE
                and coverage.guardrail_type not in required
            ):
                recommendations.append(f"Consider: {coverage.recommendation}")

        return recommendations

    def get_coverage_summary(
        self, agents: List[AgentInventoryItem], risk_profile: str = "medium_risk"
    ) -> Dict[str, any]:
        """Get coverage summary across multiple agents.

        Args:
            agents: List of agents
            risk_profile: Risk profile

        Returns:
            Summary statistics
        """
        reports = [self.analyze(a, risk_profile) for a in agents]

        return {
            "total_agents": len(agents),
            "fully_covered": len([r for r in reports if r.has_full_coverage]),
            "partially_covered": len(
                [r for r in reports if 0 < r.overall_coverage_score < 1]
            ),
            "no_coverage": len([r for r in reports if r.overall_coverage_score == 0]),
            "average_score": sum(r.overall_coverage_score for r in reports) / len(reports)
            if reports
            else 0,
            "most_common_gaps": self._find_common_gaps(reports),
        }

    def _find_common_gaps(
        self, reports: List[GuardrailReport]
    ) -> Dict[str, int]:
        """Find most common guardrail gaps."""
        gap_counts: Dict[str, int] = {}

        for report in reports:
            for gtype in report.uncovered_types:
                gap_counts[gtype.value] = gap_counts.get(gtype.value, 0) + 1

        return dict(sorted(gap_counts.items(), key=lambda x: x[1], reverse=True))
