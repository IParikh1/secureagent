#!/usr/bin/env python3
"""Train the SecureAgent ML risk model with synthetic data.

Uses the actual SyntheticDataGenerator and ModelTrainer pipeline
so that the trained model's feature schema matches what production
code (CompositeFeatureExtractor) produces.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from secureagent.ml.trainer import ModelTrainer, SyntheticDataGenerator
from secureagent.ml.models import EnsembleModel


def main():
    """Train and save the ML model."""
    print("=" * 60)
    print("SecureAgent ML Model Training")
    print("=" * 60)

    output_dir = Path(__file__).parent.parent / "models"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: Generate synthetic training data using SyntheticDataGenerator
    # This ensures features match what CompositeFeatureExtractor produces
    print("\n[1/5] Generating synthetic training data...")
    generator = SyntheticDataGenerator(seed=42)
    findings, labels = generator.generate(count=2000, high_risk_ratio=0.4)

    # Set risk scores on findings so ModelTrainer.prepare_data() labels correctly
    for finding, label in zip(findings, labels):
        finding.risk_score = float(label)

    # Count severity and domain distribution
    severity_counts = {}
    domain_counts = {}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        dom = f.domain.value if hasattr(f.domain, 'value') else str(f.domain)
        domain_counts[dom] = domain_counts.get(dom, 0) + 1

    print(f"  Generated {len(findings)} findings:")
    print(f"  Severity distribution:")
    for sev, count in sorted(severity_counts.items()):
        print(f"    - {sev}: {count}")
    print(f"  Domain distribution:")
    for dom, count in sorted(domain_counts.items()):
        print(f"    - {dom}: {count}")
    print(f"  High risk: {sum(labels)}, Low risk: {len(labels) - sum(labels)}")

    # Step 2: Initialize trainer with CompositeFeatureExtractor
    print("\n[2/5] Initializing model trainer...")
    trainer = ModelTrainer(
        output_dir=output_dir,
        model_name="secureagent_risk_v1",
    )

    # Step 3: Prepare data to inspect feature names
    print("\n[3/5] Extracting features...")
    X, y, feature_names = trainer.prepare_data(findings)
    print(f"  Feature count: {len(feature_names)}")
    print(f"  Feature names: {feature_names}")
    print(f"  Data shape: X={X.shape}, y={y.shape}")
    print(f"  Label distribution: 0={sum(y == 0)}, 1={sum(y == 1)}")

    # Step 4: Train the model
    print("\n[4/5] Training final model...")
    result = trainer.train(findings, validation_split=0.2)

    print(f"\n  Model training complete!")
    print(f"  Metrics:")
    print(f"    - Accuracy:  {result.metrics.accuracy:.4f}")
    print(f"    - Precision: {result.metrics.precision:.4f}")
    print(f"    - Recall:    {result.metrics.recall:.4f}")
    print(f"    - F1 Score:  {result.metrics.f1_score:.4f}")
    print(f"    - AUC-ROC:   {result.metrics.auc_roc:.4f}")

    print(f"\n  Top feature importances:")
    for feature, importance in list(result.feature_importance.items())[:15]:
        print(f"    - {feature}: {importance:.4f}")

    print(f"\n  Model saved to: {result.model_path}")

    # Step 5: Generate accurate model_metadata.json
    print("\n[5/5] Generating model metadata...")
    metadata = {
        "version": f"v2.0.0_{datetime.now().strftime('%Y%m%d')}",
        "created_at": datetime.now().isoformat(),
        "model_type": "Ensemble (RandomForest + GradientBoosting + LogisticRegression)",
        "training_samples": len(findings),
        "test_samples": int(len(findings) * 0.2),
        "features": len(feature_names),
        "feature_names": feature_names,
        "classes": ["low_risk", "high_risk"],
        "metrics": {
            "accuracy": round(result.metrics.accuracy, 4),
            "precision": round(result.metrics.precision, 4),
            "recall": round(result.metrics.recall, 4),
            "f1_score": round(result.metrics.f1_score, 4),
            "auc_roc": round(result.metrics.auc_roc, 4),
        },
        "feature_importance": {
            k: round(v, 4) for k, v in list(result.feature_importance.items())[:20]
        },
        "hyperparameters": {
            "random_forest": {
                "n_estimators": 100,
                "max_depth": 10,
                "random_state": 42,
            },
            "gradient_boosting": {
                "n_estimators": 100,
                "max_depth": 5,
                "random_state": 42,
            },
            "logistic_regression": {
                "max_iter": 1000,
                "random_state": 42,
            },
            "scaler": "StandardScaler",
            "ensemble_method": "average_predict_proba",
        },
        "training_domains": sorted(domain_counts.keys()),
    }

    metadata_path = output_dir / "model_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2))
    print(f"  Metadata saved to: {metadata_path}")

    # Clean up stale artifact
    stale_model = output_dir / "mcp_risk_model_latest.pkl"
    if stale_model.exists():
        stale_model.unlink()
        print(f"  Removed stale artifact: {stale_model}")

    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
