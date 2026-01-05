"""Tests for ML risk scorer."""

import pytest
from pathlib import Path

from secureagent.ml.risk_scorer import RiskScorer, RiskAssessment
from secureagent.ml.models import EnsembleModel
from secureagent.core.models.finding import Finding, Location, FindingDomain
from secureagent.core.models.severity import Severity


class TestRiskScorer:
    """Tests for RiskScorer."""

    def test_scorer_initialization(self):
        """Test scorer initialization."""
        scorer = RiskScorer(use_ml=False)
        assert scorer is not None

    def test_score_single_finding(self, sample_finding):
        """Test scoring a single finding."""
        scorer = RiskScorer(use_ml=False)
        score = scorer.score_finding(sample_finding)

        assert 0.0 <= score <= 1.0
        # HIGH severity finding should have elevated score
        assert score >= 0.3

    def test_score_findings_list(self, sample_findings):
        """Test scoring multiple findings."""
        scorer = RiskScorer(use_ml=False)
        assessment = scorer.score_findings(sample_findings)

        assert isinstance(assessment, RiskAssessment)
        assert 0.0 <= assessment.overall_score <= 1.0
        assert assessment.risk_level in ["critical", "high", "medium", "low"]

    def test_score_empty_findings(self):
        """Test scoring empty list."""
        scorer = RiskScorer(use_ml=False)
        assessment = scorer.score_findings([])

        assert assessment.overall_score == 0.0
        assert assessment.risk_level == "low"

    def test_score_critical_finding(self):
        """Test that critical findings get high scores."""
        scorer = RiskScorer(use_ml=False)

        critical_finding = Finding(
            id="critical-001",
            rule_id="MCP-001",
            domain=FindingDomain.MCP,
            title="Hardcoded Credential",
            description="Critical security issue with exposed credentials.",
            severity=Severity.CRITICAL,
            location=Location(file_path="/config.json"),
            remediation="Use environment variables.",
            cwe_id="CWE-798",
        )

        score = scorer.score_finding(critical_finding)
        # Critical findings should score high
        assert score >= 0.7

    def test_score_info_finding(self):
        """Test that info findings get low scores."""
        scorer = RiskScorer(use_ml=False)

        info_finding = Finding(
            id="info-001",
            rule_id="MCP-006",
            domain=FindingDomain.MCP,
            title="Best Practice Suggestion",
            description="Consider improving configuration.",
            severity=Severity.INFO,
            location=Location(file_path="/config.json"),
            remediation="Review best practices.",
        )

        score = scorer.score_finding(info_finding)
        # Info findings should score low
        assert score <= 0.3

    def test_risk_factors_identified(self, sample_findings):
        """Test that risk factors are identified."""
        scorer = RiskScorer(use_ml=False)
        assessment = scorer.score_findings(sample_findings)

        assert isinstance(assessment.risk_factors, list)
        # Should identify MCP as a dominant category
        categories = [f.get("category") for f in assessment.risk_factors]
        assert "MCP" in categories

    def test_recommendations_generated(self, sample_findings):
        """Test that recommendations are generated."""
        scorer = RiskScorer(use_ml=False)
        assessment = scorer.score_findings(sample_findings)

        assert isinstance(assessment.recommendations, list)
        assert len(assessment.recommendations) > 0

    def test_confidence_calculation(self, sample_findings):
        """Test confidence calculation."""
        scorer = RiskScorer(use_ml=False)
        assessment = scorer.score_findings(sample_findings)

        assert 0.0 <= assessment.confidence <= 1.0

    def test_scorer_with_ml_model(self):
        """Test scorer with ML model (if model exists)."""
        model_path = Path(__file__).parent.parent.parent / "models" / "secureagent_risk_v1.pkl"

        if model_path.exists():
            scorer = RiskScorer(model_path=model_path, use_ml=True)
            assert scorer.model is not None

            # Create test finding
            finding = Finding(
                id="test-ml-001",
                rule_id="MCP-001",
                domain=FindingDomain.MCP,
                title="Test Finding for ML",
                description="Testing ML model prediction.",
                severity=Severity.HIGH,
                location=Location(file_path="/test.json"),
                remediation="Fix the issue.",
                cwe_id="CWE-798",
            )

            score = scorer.score_finding(finding)
            assert 0.0 <= score <= 1.0

    def test_severity_weights(self):
        """Test that severity weights are properly defined."""
        scorer = RiskScorer(use_ml=False)

        # Check all severities have weights
        for severity in Severity:
            assert severity in scorer.SEVERITY_WEIGHTS

        # Critical should have highest weight
        assert scorer.SEVERITY_WEIGHTS[Severity.CRITICAL] > scorer.SEVERITY_WEIGHTS[Severity.HIGH]
        assert scorer.SEVERITY_WEIGHTS[Severity.HIGH] > scorer.SEVERITY_WEIGHTS[Severity.MEDIUM]

    def test_finding_scores_in_assessment(self, sample_findings):
        """Test that individual finding scores are included."""
        scorer = RiskScorer(use_ml=False)
        assessment = scorer.score_findings(sample_findings)

        # Should have scores for each finding
        assert len(assessment.finding_scores) == len(sample_findings)

        for finding in sample_findings:
            assert finding.id in assessment.finding_scores
            assert 0.0 <= assessment.finding_scores[finding.id] <= 1.0


class TestEnsembleModel:
    """Tests for EnsembleModel."""

    def test_model_initialization(self):
        """Test model initialization."""
        model = EnsembleModel()
        assert model is not None
        assert not model._is_fitted

    @pytest.mark.skipif(
        not Path(__file__).parent.parent.parent.joinpath(
            "models", "secureagent_risk_v1.pkl"
        ).exists(),
        reason="Trained model not available",
    )
    def test_model_loading(self):
        """Test loading a trained model."""
        model_path = (
            Path(__file__).parent.parent.parent / "models" / "secureagent_risk_v1.pkl"
        )

        model = EnsembleModel()
        model.load(model_path)

        assert model._is_fitted
        assert len(model._models) > 0

    @pytest.mark.skipif(
        not Path(__file__).parent.parent.parent.joinpath(
            "models", "secureagent_risk_v1.pkl"
        ).exists(),
        reason="Trained model not available",
    )
    def test_model_prediction(self):
        """Test model prediction."""
        model_path = (
            Path(__file__).parent.parent.parent / "models" / "secureagent_risk_v1.pkl"
        )

        model = EnsembleModel()
        model.load(model_path)

        # Create test features
        features = {
            "severity_score": 0.8,
            "has_remediation": 1.0,
            "has_cwe": 1.0,
            "has_owasp": 1.0,
        }

        prediction = model.predict(features)

        assert prediction is not None
        assert 0.0 <= prediction.risk_score <= 1.0
        assert prediction.risk_level in ["critical", "high", "medium", "low"]
        assert 0.0 <= prediction.confidence <= 1.0

    @pytest.mark.skipif(
        not Path(__file__).parent.parent.parent.joinpath(
            "models", "secureagent_risk_v1.pkl"
        ).exists(),
        reason="Trained model not available",
    )
    def test_feature_importance(self):
        """Test getting feature importance."""
        model_path = (
            Path(__file__).parent.parent.parent / "models" / "secureagent_risk_v1.pkl"
        )

        model = EnsembleModel()
        model.load(model_path)

        importance = model.get_feature_importance()

        assert isinstance(importance, dict)
        assert len(importance) > 0
        # severity_score should be important
        assert "severity_score" in importance


class TestRiskAssessment:
    """Tests for RiskAssessment dataclass."""

    def test_assessment_creation(self):
        """Test creating a risk assessment."""
        assessment = RiskAssessment(
            overall_score=0.75,
            risk_level="high",
            confidence=0.85,
            finding_scores={"f1": 0.8, "f2": 0.7},
            risk_factors=[{"category": "MCP", "finding_count": 2}],
            recommendations=["Fix critical issues first"],
        )

        assert assessment.overall_score == 0.75
        assert assessment.risk_level == "high"
        assert assessment.confidence == 0.85
        assert len(assessment.finding_scores) == 2
        assert len(assessment.risk_factors) == 1
        assert len(assessment.recommendations) == 1
