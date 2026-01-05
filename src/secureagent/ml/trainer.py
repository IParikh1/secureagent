"""ML model trainer for SecureAgent."""

import logging
from typing import List, Tuple, Optional, Dict, Any
from pathlib import Path
from dataclasses import dataclass
import json

from ..core.models.finding import Finding
from ..core.models.severity import Severity
from .models import EnsembleModel, ModelMetrics
from .features.base import FeatureExtractor, CompositeFeatureExtractor
from .features.mcp_features import MCPFeatureExtractor
from .features.cloud_features import CloudFeatureExtractor
from .features.agent_features import AgentFeatureExtractor

logger = logging.getLogger(__name__)


@dataclass
class TrainingData:
    """Training data for ML model."""

    findings: List[Finding]
    labels: List[int]  # 0 = low risk, 1 = high risk


@dataclass
class TrainingResult:
    """Result of model training."""

    metrics: ModelMetrics
    model_path: Path
    feature_importance: Dict[str, float]


class ModelTrainer:
    """Train and evaluate ML models for risk prediction."""

    def __init__(
        self,
        output_dir: Path = Path("models"),
        model_name: str = "secureagent_risk_v1",
    ):
        """Initialize trainer."""
        self.output_dir = Path(output_dir)
        self.model_name = model_name
        self.feature_extractor = self._create_feature_extractor()
        self._np = None

    def _ensure_deps(self):
        """Ensure ML dependencies are available."""
        if self._np is None:
            try:
                import numpy as np

                self._np = np
            except ImportError:
                raise ImportError(
                    "numpy is required for training. "
                    "Install with: pip install secureagent[ml]"
                )

    def _create_feature_extractor(self) -> CompositeFeatureExtractor:
        """Create composite feature extractor."""
        return CompositeFeatureExtractor(
            [
                MCPFeatureExtractor(),
                CloudFeatureExtractor(),
                AgentFeatureExtractor(),
            ]
        )

    def prepare_data(
        self,
        findings: List[Finding],
        risk_threshold: float = 0.65,
    ) -> Tuple[Any, Any, List[str]]:
        """Prepare training data from findings."""
        self._ensure_deps()
        np = self._np

        features_list = []
        labels = []

        for finding in findings:
            # Extract features
            features = self.feature_extractor.extract(finding)

            # Add base features
            features.update(
                {
                    "severity_score": self._severity_to_score(finding.severity),
                    "has_remediation": 1.0 if finding.remediation else 0.0,
                    "has_cwe": 1.0 if finding.cwe_id else 0.0,
                    "has_owasp": 1.0 if finding.owasp_id else 0.0,
                }
            )

            features_list.append(features)

            # Determine label
            if finding.risk_score is not None:
                label = 1 if finding.risk_score >= risk_threshold else 0
            else:
                label = 1 if finding.severity in (Severity.CRITICAL, Severity.HIGH) else 0

            labels.append(label)

        # Convert to arrays
        feature_names = list(features_list[0].keys()) if features_list else []
        X = np.array(
            [[f.get(name, 0.0) for name in feature_names] for f in features_list]
        )
        y = np.array(labels)

        return X, y, feature_names

    def train(
        self,
        findings: List[Finding],
        validation_split: float = 0.2,
    ) -> TrainingResult:
        """Train model on findings."""
        self._ensure_deps()
        np = self._np

        from sklearn.model_selection import train_test_split

        logger.info(f"Preparing training data from {len(findings)} findings")

        # Prepare data
        X, y, feature_names = self.prepare_data(findings)

        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=validation_split, random_state=42, stratify=y
        )

        logger.info(f"Training set: {len(X_train)}, Validation set: {len(X_val)}")

        # Train model
        model = EnsembleModel()
        metrics = model.fit(X_train, y_train, feature_names)

        # Evaluate on validation set
        val_predictions = []
        for x in X_val:
            features_dict = dict(zip(feature_names, x))
            pred = model.predict(features_dict)
            val_predictions.append(pred.risk_score)

        val_predictions = np.array(val_predictions)
        val_pred_labels = (val_predictions >= 0.5).astype(int)

        from sklearn.metrics import accuracy_score, f1_score

        val_accuracy = accuracy_score(y_val, val_pred_labels)
        val_f1 = f1_score(y_val, val_pred_labels, average="weighted")

        logger.info(f"Validation accuracy: {val_accuracy:.4f}, F1: {val_f1:.4f}")

        # Save model
        self.output_dir.mkdir(parents=True, exist_ok=True)
        model_path = self.output_dir / f"{self.model_name}.pkl"
        model.save(model_path)

        # Get feature importance
        feature_importance = model.get_feature_importance()

        return TrainingResult(
            metrics=metrics,
            model_path=model_path,
            feature_importance=feature_importance,
        )

    def cross_validate(
        self,
        findings: List[Finding],
        folds: int = 5,
    ) -> Dict[str, float]:
        """Perform cross-validation."""
        self._ensure_deps()
        np = self._np

        from sklearn.model_selection import cross_val_score
        from sklearn.ensemble import RandomForestClassifier

        X, y, feature_names = self.prepare_data(findings)

        model = RandomForestClassifier(n_estimators=100, random_state=42)

        scores = {
            "accuracy": cross_val_score(model, X, y, cv=folds, scoring="accuracy"),
            "f1": cross_val_score(model, X, y, cv=folds, scoring="f1_weighted"),
            "roc_auc": cross_val_score(model, X, y, cv=folds, scoring="roc_auc"),
        }

        return {
            "accuracy_mean": float(np.mean(scores["accuracy"])),
            "accuracy_std": float(np.std(scores["accuracy"])),
            "f1_mean": float(np.mean(scores["f1"])),
            "f1_std": float(np.std(scores["f1"])),
            "roc_auc_mean": float(np.mean(scores["roc_auc"])),
            "roc_auc_std": float(np.std(scores["roc_auc"])),
        }

    def generate_training_data(
        self,
        findings: List[Finding],
        output_path: Path,
    ) -> None:
        """Generate training data file from findings."""
        X, y, feature_names = self.prepare_data(findings)

        data = {
            "feature_names": feature_names,
            "samples": [
                {
                    "features": dict(zip(feature_names, x.tolist())),
                    "label": int(label),
                    "finding_id": findings[i].id if i < len(findings) else None,
                }
                for i, (x, label) in enumerate(zip(X, y))
            ],
        }

        output_path = Path(output_path)
        output_path.write_text(json.dumps(data, indent=2))
        logger.info(f"Training data saved to {output_path}")

    def load_training_data(
        self, data_path: Path
    ) -> Tuple[Any, Any, List[str]]:
        """Load training data from file."""
        self._ensure_deps()
        np = self._np

        data_path = Path(data_path)
        data = json.loads(data_path.read_text())

        feature_names = data["feature_names"]
        X = np.array(
            [
                [sample["features"].get(name, 0.0) for name in feature_names]
                for sample in data["samples"]
            ]
        )
        y = np.array([sample["label"] for sample in data["samples"]])

        return X, y, feature_names

    def _severity_to_score(self, severity: Severity) -> float:
        """Convert severity to numeric score."""
        scores = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.2,
            Severity.INFO: 0.1,
        }
        return scores.get(severity, 0.0)
