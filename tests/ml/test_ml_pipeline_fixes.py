"""Tests for ML pipeline fixes (Fixes 1-8)."""

import pytest
from pathlib import Path

from secureagent.ml.risk_scorer import RiskScorer, RiskAssessment
from secureagent.ml.models import EnsembleModel
from secureagent.ml.trainer import ModelTrainer, SyntheticDataGenerator
from secureagent.ml.features.base import CompositeFeatureExtractor
from secureagent.ml.features.mcp_features import MCPFeatureExtractor
from secureagent.ml.features.cloud_features import CloudFeatureExtractor
from secureagent.ml.features.agent_features import AgentFeatureExtractor
from secureagent.core.models.finding import Finding, Location, FindingDomain
from secureagent.core.models.severity import Severity


MODEL_PATH = Path(__file__).parent.parent.parent / "models" / "secureagent_risk_v1.pkl"


class TestFix1RiskScoreFlag:
    """Tests for Fix 1: --risk-score flag wiring into scan pipeline."""

    def test_risk_scorer_with_extractors(self):
        """Test RiskScorer with registered feature extractors produces scores."""
        scorer = RiskScorer(use_ml=False)
        scorer.register_extractor(MCPFeatureExtractor())
        scorer.register_extractor(CloudFeatureExtractor())
        scorer.register_extractor(AgentFeatureExtractor())

        findings = [
            Finding(
                rule_id="MCP-001", domain=FindingDomain.MCP,
                title="Hardcoded Credential", description="API key in config",
                severity=Severity.CRITICAL, location=Location(file_path="/config.json"),
                remediation="Use env vars", cwe_id="CWE-798",
            ),
        ]
        assessment = scorer.score_findings(findings)

        assert isinstance(assessment, RiskAssessment)
        assert assessment.overall_score > 0.0
        assert assessment.risk_level in ["critical", "high", "medium", "low"]
        assert len(assessment.finding_scores) == 1

    def test_risk_scorer_heuristic_fallback(self):
        """Test that scoring works without ML model (heuristic only)."""
        scorer = RiskScorer(use_ml=False)
        finding = Finding(
            rule_id="MCP-002", domain=FindingDomain.MCP,
            title="Command Injection", description="Shell access without validation",
            severity=Severity.HIGH, location=Location(file_path="/config.json"),
            remediation="Validate inputs",
        )
        score = scorer.score_finding(finding)
        assert 0.0 <= score <= 1.0

    @pytest.mark.skipif(not MODEL_PATH.exists(), reason="Trained model not available")
    def test_risk_scorer_with_ml_model(self):
        """Test RiskScorer with ML model produces scores."""
        scorer = RiskScorer(model_path=MODEL_PATH, use_ml=True)
        scorer.register_extractor(MCPFeatureExtractor())
        scorer.register_extractor(CloudFeatureExtractor())
        scorer.register_extractor(AgentFeatureExtractor())

        findings = [
            Finding(
                rule_id="MCP-001", domain=FindingDomain.MCP,
                title="Hardcoded API Key", description="Found credential in config",
                severity=Severity.CRITICAL, location=Location(file_path="/config.json"),
                remediation="Use env vars", cwe_id="CWE-798",
            ),
            Finding(
                rule_id="MCP-006", domain=FindingDomain.MCP,
                title="Best Practice", description="Minor config suggestion",
                severity=Severity.INFO, location=Location(file_path="/config.json"),
                remediation="Review docs",
            ),
        ]

        assessment = scorer.score_findings(findings)
        assert assessment.overall_score > 0.0
        assert len(assessment.finding_scores) == 2

        # CRITICAL finding should score higher than INFO
        scores = list(assessment.finding_scores.values())
        assert max(scores) > min(scores)

    def test_scan_without_risk_score_has_no_scores(self, sample_findings):
        """Test that findings without --risk-score have no risk_score."""
        for finding in sample_findings:
            assert finding.risk_score is None


class TestFix2ModelFeatureSchema:
    """Tests for Fix 2: Model feature schema matches CompositeFeatureExtractor."""

    @pytest.mark.skipif(not MODEL_PATH.exists(), reason="Trained model not available")
    def test_model_loads_and_predicts(self):
        """Test that the shipped model loads and produces predictions."""
        model = EnsembleModel()
        model.load(MODEL_PATH)

        assert model._is_fitted
        assert len(model._feature_names) > 0

    @pytest.mark.skipif(not MODEL_PATH.exists(), reason="Trained model not available")
    def test_model_features_match_extractors(self):
        """Test that model feature names match CompositeFeatureExtractor output."""
        model = EnsembleModel()
        model.load(MODEL_PATH)

        extractor = CompositeFeatureExtractor([
            MCPFeatureExtractor(), CloudFeatureExtractor(), AgentFeatureExtractor()
        ])

        # Get features from a sample finding
        finding = Finding(
            rule_id="MCP-001", domain=FindingDomain.MCP,
            title="Test", description="Test finding",
            severity=Severity.HIGH, location=Location(file_path="/test.json"),
            remediation="Fix it",
        )
        extracted = extractor.extract(finding)
        # Add base features
        extracted.update({
            "severity_score": 0.8,
            "has_remediation": 1.0,
            "has_cwe": 0.0,
            "has_owasp": 0.0,
        })

        # All model feature names should be present in extracted features
        for name in model._feature_names:
            assert name in extracted, f"Model expects feature '{name}' not in extractor output"

    @pytest.mark.skipif(not MODEL_PATH.exists(), reason="Trained model not available")
    def test_model_produces_nonzero_predictions(self):
        """Test model produces non-zero, meaningful predictions."""
        model = EnsembleModel()
        model.load(MODEL_PATH)

        extractor = CompositeFeatureExtractor([
            MCPFeatureExtractor(), CloudFeatureExtractor(), AgentFeatureExtractor()
        ])

        # Critical finding should produce high risk score
        critical = Finding(
            rule_id="MCP-001", domain=FindingDomain.MCP,
            title="Hardcoded API Key", description="Found hardcoded credentials",
            severity=Severity.CRITICAL, location=Location(file_path="/config.json"),
            remediation="Use env vars", cwe_id="CWE-798",
        )
        features = extractor.extract(critical)
        features.update({
            "severity_score": 1.0, "has_remediation": 1.0,
            "has_cwe": 1.0, "has_owasp": 0.0,
        })
        pred = model.predict(features)
        assert pred.risk_score > 0.7, f"CRITICAL finding scored {pred.risk_score}, expected > 0.7"

        # INFO finding should produce low risk score
        info = Finding(
            rule_id="MCP-006", domain=FindingDomain.MCP,
            title="Config Notice", description="Minor improvement suggested",
            severity=Severity.INFO, location=Location(file_path="/config.json"),
            remediation="Review docs",
        )
        features = extractor.extract(info)
        features.update({
            "severity_score": 0.1, "has_remediation": 1.0,
            "has_cwe": 0.0, "has_owasp": 0.0,
        })
        pred = model.predict(features)
        assert pred.risk_score < 0.3, f"INFO finding scored {pred.risk_score}, expected < 0.3"

    @pytest.mark.skipif(not MODEL_PATH.exists(), reason="Trained model not available")
    def test_model_metadata_matches(self):
        """Test model_metadata.json matches the actual model."""
        import json
        metadata_path = MODEL_PATH.parent / "model_metadata.json"
        assert metadata_path.exists()

        metadata = json.loads(metadata_path.read_text())

        model = EnsembleModel()
        model.load(MODEL_PATH)

        # Feature count should match
        assert metadata["features"] == len(model._feature_names)

        # Classes should be binary
        assert metadata["classes"] == ["low_risk", "high_risk"]

        # Feature names should match
        assert metadata["feature_names"] == model._feature_names


class TestFix4SyntheticDataDomains:
    """Tests for Fix 4: Synthetic data covers all 9 scanner domains."""

    def test_all_domains_when_none(self):
        """Test that domains=None generates findings for all domains."""
        gen = SyntheticDataGenerator(seed=42)
        findings, labels = gen.generate(count=2000, domains=None)

        domains_found = set()
        for f in findings:
            dom = f.domain if isinstance(f.domain, str) else f.domain.value
            domains_found.add(dom)

        # Should have at least these domains
        expected = {"mcp", "aws", "langchain", "azure", "terraform", "openai", "autogpt"}
        assert expected.issubset(domains_found), (
            f"Missing domains: {expected - domains_found}"
        )

    def test_domain_filtering(self):
        """Test that domain filtering works for each domain."""
        gen = SyntheticDataGenerator(seed=42)

        for domain_name in ["mcp", "aws", "langchain", "azure", "terraform", "openai", "autogpt"]:
            findings, labels = gen.generate(count=100, domains=[domain_name])
            assert len(findings) > 0, f"No findings for domain '{domain_name}'"

    def test_azure_templates_exist(self):
        """Test Azure templates are present."""
        gen = SyntheticDataGenerator()
        assert hasattr(gen, 'AZURE_TEMPLATES')
        assert len(gen.AZURE_TEMPLATES) >= 4

    def test_terraform_templates_exist(self):
        """Test Terraform templates are present."""
        gen = SyntheticDataGenerator()
        assert hasattr(gen, 'TERRAFORM_TEMPLATES')
        assert len(gen.TERRAFORM_TEMPLATES) >= 5

    def test_openai_templates_exist(self):
        """Test OpenAI templates are present."""
        gen = SyntheticDataGenerator()
        assert hasattr(gen, 'OPENAI_TEMPLATES')
        assert len(gen.OPENAI_TEMPLATES) >= 5

    def test_autogpt_templates_exist(self):
        """Test AutoGPT/CrewAI templates are present."""
        gen = SyntheticDataGenerator()
        assert hasattr(gen, 'AUTOGPT_TEMPLATES')
        assert len(gen.AUTOGPT_TEMPLATES) >= 7

    def test_multiagent_templates_exist(self):
        """Test Multi-Agent templates are present."""
        gen = SyntheticDataGenerator()
        assert hasattr(gen, 'MULTIAGENT_TEMPLATES')
        assert len(gen.MULTIAGENT_TEMPLATES) >= 6

    def test_rag_templates_exist(self):
        """Test RAG templates are present."""
        gen = SyntheticDataGenerator()
        assert hasattr(gen, 'RAG_TEMPLATES')
        assert len(gen.RAG_TEMPLATES) >= 5

    def test_generated_findings_are_valid(self):
        """Test all generated findings have required fields."""
        gen = SyntheticDataGenerator(seed=42)
        findings, labels = gen.generate(count=500)

        for finding in findings:
            assert finding.rule_id
            assert finding.title
            assert finding.description
            assert finding.remediation
            assert finding.location is not None


class TestFix5CrossValidation:
    """Tests for Fix 5: cross_validate uses actual ensemble."""

    def test_cross_validate_returns_metrics(self):
        """Test cross_validate returns expected metric keys."""
        gen = SyntheticDataGenerator(seed=42)
        findings, labels = gen.generate(count=200)
        for f, l in zip(findings, labels):
            f.risk_score = float(l)

        trainer = ModelTrainer()
        results = trainer.cross_validate(findings, folds=3)

        assert "accuracy_mean" in results
        assert "accuracy_std" in results
        assert "f1_mean" in results
        assert "f1_std" in results
        assert "roc_auc_mean" in results
        assert "roc_auc_std" in results

    def test_cross_validate_metrics_are_reasonable(self):
        """Test CV metrics are within reasonable range."""
        gen = SyntheticDataGenerator(seed=42)
        findings, labels = gen.generate(count=500)
        for f, l in zip(findings, labels):
            f.risk_score = float(l)

        trainer = ModelTrainer()
        results = trainer.cross_validate(findings, folds=5)

        # With synthetic data, accuracy should be reasonable
        assert results["accuracy_mean"] > 0.5
        assert results["f1_mean"] > 0.5
        assert 0.0 <= results["accuracy_std"] <= 0.5


class TestFix6TuneHyperparameters:
    """Tests for Fix 6: tune_hyperparameters tunes actual ensemble."""

    def test_tune_returns_per_model_results(self):
        """Test tuning returns results for each model in ensemble."""
        gen = SyntheticDataGenerator(seed=42)
        findings, labels = gen.generate(count=200)
        for f, l in zip(findings, labels):
            f.risk_score = float(l)

        trainer = ModelTrainer()
        # Use small grids for fast testing
        param_grids = {
            "random_forest": {"model__n_estimators": [50, 100]},
            "gradient_boosting": {"model__n_estimators": [50, 100]},
            "logistic_regression": {"model__C": [0.1, 1.0]},
        }
        results = trainer.tune_hyperparameters(findings, param_grids=param_grids, cv_folds=3)

        assert "random_forest" in results
        assert "gradient_boosting" in results
        assert "logistic_regression" in results

        for model_name in results:
            assert "best_params" in results[model_name]
            assert "best_score" in results[model_name]
            assert results[model_name]["best_score"] > 0.0


class TestFix7RetrainingStrategies:
    """Tests for Fix 7: Retraining strategy cleanup."""

    def test_only_implemented_strategies_exist(self):
        """Test that only FULL_RETRAIN and ENSEMBLE_BLEND strategies exist."""
        from secureagent.ml.model_manager import RetrainingStrategy

        strategies = list(RetrainingStrategy)
        strategy_values = [s.value for s in strategies]

        assert "full_retrain" in strategy_values
        assert "ensemble_blend" in strategy_values
        assert "transfer_learning" not in strategy_values
        assert "feedback_loop" not in strategy_values
        assert "active_learning" not in strategy_values

    def test_presets_use_valid_strategies(self):
        """Test all presets use implemented strategies."""
        from secureagent.ml.model_manager import RETRAINING_PRESETS, RetrainingStrategy

        for name, config in RETRAINING_PRESETS.items():
            assert config.strategy in RetrainingStrategy, (
                f"Preset '{name}' uses invalid strategy: {config.strategy}"
            )

    def test_removed_presets_not_present(self):
        """Test that removed presets are gone."""
        from secureagent.ml.model_manager import RETRAINING_PRESETS

        removed = ["healthcare", "finance", "government", "aws_heavy",
                    "azure_heavy", "multi_cloud", "feedback_driven", "active_learning"]
        for name in removed:
            assert name not in RETRAINING_PRESETS, f"Preset '{name}' should be removed"


class TestFix8UnifiedScoring:
    """Tests for Fix 8: Unified risk scoring paths."""

    def test_risk_analyzer_accepts_scorer(self):
        """Test RiskAnalyzer can be initialized with RiskScorer."""
        from secureagent.analysis.risk_analyzer import RiskAnalyzer

        scorer = RiskScorer(use_ml=False)
        analyzer = RiskAnalyzer(risk_scorer=scorer)
        assert analyzer._risk_scorer is scorer

    def test_risk_analyzer_without_scorer(self, sample_agent):
        """Test RiskAnalyzer works without scorer (backwards compatible)."""
        from secureagent.analysis.risk_analyzer import RiskAnalyzer

        analyzer = RiskAnalyzer()
        report = analyzer.analyze(sample_agent)

        assert report.overall_risk_score > 0.0
        assert report.agent_id == sample_agent.id

    def test_risk_analyzer_with_scorer_and_findings(self, sample_agent, sample_findings):
        """Test RiskAnalyzer blends ML scores with heuristic scores."""
        from secureagent.analysis.risk_analyzer import RiskAnalyzer

        # Without ML
        analyzer_no_ml = RiskAnalyzer()
        report_no_ml = analyzer_no_ml.analyze(sample_agent)

        # With ML
        scorer = RiskScorer(use_ml=False)
        analyzer_ml = RiskAnalyzer(risk_scorer=scorer)
        report_ml = analyzer_ml.analyze(sample_agent, findings=sample_findings)

        # Both should produce valid reports
        assert report_no_ml.overall_risk_score > 0.0
        assert report_ml.overall_risk_score > 0.0

        # ML-enhanced report may differ from heuristic-only
        # (scores are blended 70/30, so they won't be identical)
        assert report_ml.risk_level is not None


class TestAgentFeatureExtractorBugfix:
    """Test the agent feature extractor bug fix (all(any(...)) -> and)."""

    def test_agent_features_returned_for_agent_findings(self):
        """Test AgentFeatureExtractor returns features for AG-prefixed findings."""
        extractor = AgentFeatureExtractor()

        finding = Finding(
            rule_id="AG-003", domain=FindingDomain.AUTOGPT,
            title="Dangerous Tool Access",
            description="Agent has access to shell_executor tool",
            severity=Severity.CRITICAL, location=Location(file_path="/config.json"),
            remediation="Remove dangerous tool",
        )

        features = extractor.extract(finding)
        assert features["is_agent_finding"] == 1.0
        assert features["is_autogpt_crewai"] == 1.0
        assert features["agent_dangerous_capability"] == 1.0
        assert len(features) == 12

    def test_agent_features_returned_for_non_agent_findings(self):
        """Test AgentFeatureExtractor returns zero features for non-agent findings."""
        extractor = AgentFeatureExtractor()

        finding = Finding(
            rule_id="MCP-001", domain=FindingDomain.MCP,
            title="Test", description="Non-agent finding",
            severity=Severity.HIGH, location=Location(file_path="/config.json"),
            remediation="Fix it",
        )

        features = extractor.extract(finding)
        assert features["is_agent_finding"] == 0.0
        assert len(features) == 12

    def test_prompt_injection_detection(self):
        """Test prompt injection detection works correctly."""
        extractor = AgentFeatureExtractor()

        finding = Finding(
            rule_id="LC-002", domain=FindingDomain.LANGCHAIN,
            title="Prompt Injection Vulnerability",
            description="Agent prompt includes unsanitized user input",
            severity=Severity.HIGH, location=Location(file_path="/agent.py"),
            remediation="Sanitize inputs",
        )

        features = extractor.extract(finding)
        assert features["is_agent_finding"] == 1.0
        assert features["agent_prompt_injection"] == 1.0
