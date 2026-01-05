"""ML models for SecureAgent risk prediction."""

import logging
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import pickle

logger = logging.getLogger(__name__)


@dataclass
class ModelMetrics:
    """Model performance metrics."""

    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: float


@dataclass
class Prediction:
    """Model prediction result."""

    risk_score: float
    risk_level: str  # "critical", "high", "medium", "low"
    confidence: float
    contributing_factors: List[Tuple[str, float]] = field(default_factory=list)


class EnsembleModel:
    """Ensemble model combining multiple classifiers for risk prediction."""

    RISK_THRESHOLDS = {
        "critical": 0.85,
        "high": 0.65,
        "medium": 0.40,
        "low": 0.0,
    }

    def __init__(self, model_path: Optional[Path] = None):
        """Initialize ensemble model."""
        self.model_path = model_path
        self._models: Dict[str, Any] = {}
        self._feature_names: List[str] = []
        self._scaler = None
        self._is_fitted = False
        self._np = None
        self._sklearn = None

    def _ensure_deps(self):
        """Ensure ML dependencies are available."""
        if self._np is None:
            try:
                import numpy as np
                import sklearn

                self._np = np
                self._sklearn = sklearn
            except ImportError:
                raise ImportError(
                    "numpy and scikit-learn are required for ML features. "
                    "Install with: pip install secureagent[ml]"
                )

    def fit(
        self,
        X: Any,
        y: Any,
        feature_names: Optional[List[str]] = None,
    ) -> ModelMetrics:
        """Train the ensemble model."""
        self._ensure_deps()
        np = self._np

        from sklearn.ensemble import (
            RandomForestClassifier,
            GradientBoostingClassifier,
        )
        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler
        from sklearn.model_selection import cross_val_score
        from sklearn.metrics import (
            accuracy_score,
            precision_score,
            recall_score,
            f1_score,
            roc_auc_score,
        )

        X = np.array(X)
        y = np.array(y)

        self._feature_names = feature_names or [f"feature_{i}" for i in range(X.shape[1])]

        # Scale features
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Train base models
        self._models = {
            "random_forest": RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
            ),
            "gradient_boosting": GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                random_state=42,
            ),
            "logistic_regression": LogisticRegression(
                max_iter=1000,
                random_state=42,
            ),
        }

        for name, model in self._models.items():
            model.fit(X_scaled, y)
            logger.info(f"Trained {name}")

        self._is_fitted = True

        # Calculate metrics using cross-validation
        y_pred = self._predict_ensemble(X_scaled)
        y_proba = self._predict_proba_ensemble(X_scaled)

        metrics = ModelMetrics(
            accuracy=accuracy_score(y, y_pred),
            precision=precision_score(y, y_pred, average="weighted"),
            recall=recall_score(y, y_pred, average="weighted"),
            f1_score=f1_score(y, y_pred, average="weighted"),
            auc_roc=roc_auc_score(y, y_proba) if len(np.unique(y)) == 2 else 0.0,
        )

        logger.info(f"Model trained with accuracy: {metrics.accuracy:.4f}")
        return metrics

    def predict(self, features: Dict[str, float]) -> Prediction:
        """Predict risk score for a single sample."""
        self._ensure_deps()
        np = self._np

        if not self._is_fitted:
            raise RuntimeError("Model must be fitted before prediction")

        # Convert features dict to array
        X = np.array([[features.get(name, 0.0) for name in self._feature_names]])
        X_scaled = self._scaler.transform(X)

        # Get ensemble prediction
        risk_score = self._predict_proba_ensemble(X_scaled)[0]
        confidence = self._calculate_confidence(X_scaled)
        risk_level = self._score_to_level(risk_score)

        # Get feature importances
        contributing_factors = self._get_contributing_factors(features)

        return Prediction(
            risk_score=risk_score,
            risk_level=risk_level,
            confidence=confidence,
            contributing_factors=contributing_factors,
        )

    def predict_batch(
        self, features_list: List[Dict[str, float]]
    ) -> List[Prediction]:
        """Predict risk scores for multiple samples."""
        return [self.predict(features) for features in features_list]

    def _predict_ensemble(self, X_scaled: Any) -> Any:
        """Get ensemble class predictions."""
        np = self._np

        predictions = []
        for model in self._models.values():
            predictions.append(model.predict(X_scaled))

        # Majority voting
        predictions = np.array(predictions)
        return np.apply_along_axis(
            lambda x: np.bincount(x.astype(int)).argmax(),
            axis=0,
            arr=predictions,
        )

    def _predict_proba_ensemble(self, X_scaled: Any) -> Any:
        """Get ensemble probability predictions."""
        np = self._np

        probas = []
        for model in self._models.values():
            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(X_scaled)
                if proba.shape[1] > 1:
                    probas.append(proba[:, 1])
                else:
                    probas.append(proba[:, 0])

        # Average probabilities
        return np.mean(probas, axis=0)

    def _calculate_confidence(self, X_scaled: Any) -> float:
        """Calculate prediction confidence based on model agreement."""
        np = self._np

        probas = []
        for model in self._models.values():
            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(X_scaled)
                if proba.shape[1] > 1:
                    probas.append(proba[0, 1])

        # Lower variance = higher confidence
        variance = np.var(probas) if probas else 0.0
        confidence = max(0.0, 1.0 - variance * 4)
        return min(confidence, 1.0)

    def _score_to_level(self, score: float) -> str:
        """Convert risk score to risk level."""
        for level, threshold in self.RISK_THRESHOLDS.items():
            if score >= threshold:
                return level
        return "low"

    def _get_contributing_factors(
        self, features: Dict[str, float]
    ) -> List[Tuple[str, float]]:
        """Get features contributing most to the prediction."""
        if "random_forest" not in self._models:
            return []

        rf = self._models["random_forest"]
        importances = rf.feature_importances_

        # Get top contributing features
        factors = []
        for i, importance in enumerate(importances):
            if i < len(self._feature_names):
                feature_name = self._feature_names[i]
                feature_value = features.get(feature_name, 0.0)
                if feature_value > 0 and importance > 0.01:
                    factors.append((feature_name, importance * feature_value))

        # Sort by contribution
        factors.sort(key=lambda x: x[1], reverse=True)
        return factors[:10]

    def save(self, path: Path) -> None:
        """Save model to file."""
        path = Path(path)
        model_data = {
            "models": self._models,
            "feature_names": self._feature_names,
            "scaler": self._scaler,
            "is_fitted": self._is_fitted,
        }
        with open(path, "wb") as f:
            pickle.dump(model_data, f)
        logger.info(f"Model saved to {path}")

    def load(self, path: Path) -> None:
        """Load model from file."""
        path = Path(path)
        with open(path, "rb") as f:
            model_data = pickle.load(f)

        self._models = model_data["models"]
        self._feature_names = model_data["feature_names"]
        self._scaler = model_data["scaler"]
        self._is_fitted = model_data["is_fitted"]
        logger.info(f"Model loaded from {path}")

    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from the ensemble."""
        self._ensure_deps()
        np = self._np

        if not self._is_fitted:
            return {}

        # Average importance across models
        importances = {}
        for name in self._feature_names:
            importances[name] = 0.0

        model_count = 0
        for model_name, model in self._models.items():
            if hasattr(model, "feature_importances_"):
                for i, imp in enumerate(model.feature_importances_):
                    if i < len(self._feature_names):
                        importances[self._feature_names[i]] += imp
                model_count += 1

        if model_count > 0:
            for name in importances:
                importances[name] /= model_count

        return dict(sorted(importances.items(), key=lambda x: x[1], reverse=True))
