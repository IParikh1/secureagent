"""Performance tests for ML components."""

import time
import pytest
from pathlib import Path
from typing import List

from secureagent.core.models.finding import Finding, FindingDomain, Location
from secureagent.core.models.severity import Severity


class TestMLTrainingPerformance:
    """Performance tests for ML training operations."""

    @pytest.fixture
    def large_training_dataset(self) -> List[Finding]:
        """Create a large dataset for training tests."""
        findings = []

        # Generate 5000 diverse training samples
        for i in range(5000):
            is_high_risk = i % 3 == 0

            finding = Finding(
                rule_id=f"MCP-{(i % 7) + 1:03d}",
                domain=FindingDomain.MCP,
                title=f"Training Sample {i}",
                description=f"{'High risk' if is_high_risk else 'Low risk'} training sample with {'multiple' if is_high_risk else 'no'} security issues",
                severity=Severity.CRITICAL if is_high_risk else Severity.LOW,
                location=Location(
                    file_path=f"/train/sample_{i}.json",
                    line_number=(i % 100) + 1,
                    snippet=f"{'sk-proj-hardcoded' if is_high_risk else 'safe_config'}: value{i}",
                ),
                remediation="Apply security fix",
                risk_score=0.9 if is_high_risk else 0.1,
            )
            findings.append(finding)

        return findings

    @pytest.mark.skipif(
        not pytest.importorskip("sklearn", reason="sklearn required"),
        reason="sklearn not available"
    )
    def test_feature_extraction_performance(self, large_training_dataset):
        """Test feature extraction performance."""
        try:
            from secureagent.ml.features.base import CompositeFeatureExtractor
            from secureagent.ml.features.mcp_features import MCPFeatureExtractor
            from secureagent.ml.features.cloud_features import CloudFeatureExtractor
            from secureagent.ml.features.agent_features import AgentFeatureExtractor
        except ImportError:
            pytest.skip("ML dependencies not available")

        # Use concrete CompositeFeatureExtractor
        extractor = CompositeFeatureExtractor([
            MCPFeatureExtractor(),
            CloudFeatureExtractor(),
            AgentFeatureExtractor(),
        ])

        start_time = time.perf_counter()
        features = [extractor.extract(f) for f in large_training_dataset]
        elapsed = time.perf_counter() - start_time

        # Should extract features for 5000 samples in under 5 seconds
        assert elapsed < 5.0, f"Feature extraction too slow: {elapsed:.2f}s"

        # Check throughput
        samples_per_second = 5000 / elapsed
        assert samples_per_second > 1000, f"Throughput too low: {samples_per_second:.0f} samples/sec"

    @pytest.mark.skipif(
        not pytest.importorskip("sklearn", reason="sklearn required"),
        reason="sklearn not available"
    )
    def test_model_training_performance(self, large_training_dataset, tmp_path):
        """Test model training performance."""
        try:
            from secureagent.ml.trainer import ModelTrainer
        except ImportError:
            pytest.skip("ML trainer not available")

        trainer = ModelTrainer(
            output_dir=tmp_path / "models",
            model_name="perf_test_model",
        )

        start_time = time.perf_counter()
        result = trainer.train(large_training_dataset, validation_split=0.2)
        elapsed = time.perf_counter() - start_time

        # Should train on 5000 samples in under 30 seconds
        assert elapsed < 30.0, f"Model training too slow: {elapsed:.2f}s"

        # Model should have reasonable accuracy
        assert result.metrics.accuracy > 0.6

    @pytest.mark.skipif(
        not pytest.importorskip("sklearn", reason="sklearn required"),
        reason="sklearn not available"
    )
    def test_synthetic_data_generation_performance(self):
        """Test synthetic data generation performance."""
        try:
            from secureagent.ml.trainer import SyntheticDataGenerator
        except ImportError:
            pytest.skip("SyntheticDataGenerator not available")

        generator = SyntheticDataGenerator()

        start_time = time.perf_counter()
        findings, labels = generator.generate(count=10000)
        elapsed = time.perf_counter() - start_time

        # Should generate 10000 samples in under 5 seconds
        assert elapsed < 5.0, f"Synthetic generation too slow: {elapsed:.2f}s"
        assert len(findings) == 10000
        assert len(labels) == 10000


class TestMLInferencePerformance:
    """Performance tests for ML inference operations."""

    @pytest.fixture
    def test_findings(self) -> List[Finding]:
        """Create findings for inference testing."""
        findings = []

        for i in range(1000):
            finding = Finding(
                rule_id=f"MCP-{(i % 7) + 1:03d}",
                domain=FindingDomain.MCP,
                title=f"Test Finding {i}",
                description=f"Security finding for inference testing {i}",
                severity=[Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW][i % 4],
                location=Location(
                    file_path=f"/test/config_{i % 50}.json",
                    line_number=(i % 100) + 1,
                ),
                remediation="Fix the security issue",
            )
            findings.append(finding)

        return findings

    @pytest.mark.skipif(
        not pytest.importorskip("sklearn", reason="sklearn required"),
        reason="sklearn not available"
    )
    def test_risk_scoring_performance(self, test_findings):
        """Test risk scoring inference performance."""
        try:
            from secureagent.ml.risk_scorer import RiskScorer
        except ImportError:
            pytest.skip("RiskScorer not available")

        scorer = RiskScorer()

        start_time = time.perf_counter()
        for finding in test_findings:
            score = scorer.score(finding)
        elapsed = time.perf_counter() - start_time

        # Should score 1000 findings in under 2 seconds
        assert elapsed < 2.0, f"Risk scoring too slow: {elapsed:.2f}s"

        # Check throughput
        findings_per_second = 1000 / elapsed
        assert findings_per_second > 500, f"Throughput too low: {findings_per_second:.0f} findings/sec"

    @pytest.mark.skipif(
        not pytest.importorskip("sklearn", reason="sklearn required"),
        reason="sklearn not available"
    )
    def test_batch_scoring_performance(self, test_findings):
        """Test batch risk scoring performance."""
        try:
            from secureagent.ml.risk_scorer import RiskScorer
        except ImportError:
            pytest.skip("RiskScorer not available")

        scorer = RiskScorer()

        start_time = time.perf_counter()
        scores = scorer.score_batch(test_findings)
        elapsed = time.perf_counter() - start_time

        # Batch scoring should be faster than individual
        assert elapsed < 1.0, f"Batch scoring too slow: {elapsed:.2f}s"
        assert len(scores) == 1000


class TestCrossValidationPerformance:
    """Performance tests for cross-validation."""

    @pytest.mark.skipif(
        not pytest.importorskip("sklearn", reason="sklearn required"),
        reason="sklearn not available"
    )
    def test_cross_validation_performance(self, tmp_path):
        """Test cross-validation performance."""
        try:
            from secureagent.ml.trainer import ModelTrainer, SyntheticDataGenerator
        except ImportError:
            pytest.skip("ML trainer not available")

        # Generate training data
        generator = SyntheticDataGenerator()
        findings, labels = generator.generate(count=2000)

        for finding, label in zip(findings, labels):
            finding.risk_score = float(label)

        trainer = ModelTrainer(output_dir=tmp_path / "models")

        start_time = time.perf_counter()
        results = trainer.cross_validate(findings, folds=5)
        elapsed = time.perf_counter() - start_time

        # 5-fold CV on 2000 samples should complete in under 60 seconds
        assert elapsed < 60.0, f"Cross-validation too slow: {elapsed:.2f}s"

        # Should have results
        assert "accuracy_mean" in results
        assert results["accuracy_mean"] > 0.5


class TestModelPersistencePerformance:
    """Performance tests for model save/load operations."""

    @pytest.mark.skipif(
        not pytest.importorskip("sklearn", reason="sklearn required"),
        reason="sklearn not available"
    )
    def test_model_save_load_performance(self, tmp_path):
        """Test model save and load performance."""
        try:
            from secureagent.ml.trainer import ModelTrainer, SyntheticDataGenerator
        except ImportError:
            pytest.skip("ML trainer not available")

        # Train a model
        generator = SyntheticDataGenerator()
        findings, labels = generator.generate(count=1000)

        for finding, label in zip(findings, labels):
            finding.risk_score = float(label)

        trainer = ModelTrainer(
            output_dir=tmp_path / "models",
            model_name="persistence_test",
        )
        trainer.train(findings)

        # Test model loading performance
        model_path = tmp_path / "models" / "persistence_test.pkl"
        if not model_path.exists():
            pytest.skip("Model file not created")

        load_times = []
        for _ in range(10):
            start_time = time.perf_counter()
            trainer.load_model(model_path)
            load_times.append(time.perf_counter() - start_time)

        avg_load_time = sum(load_times) / len(load_times)

        # Model should load in under 0.5 seconds
        assert avg_load_time < 0.5, f"Model loading too slow: {avg_load_time:.3f}s average"
