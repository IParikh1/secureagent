"""Model manager for baseline and custom ML models."""

import hashlib
import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class ModelType(str, Enum):
    """Types of models supported."""
    BASELINE = "baseline"  # Ships with package
    CUSTOM = "custom"  # Client-trained
    FINE_TUNED = "fine_tuned"  # Fine-tuned from baseline
    INDUSTRY = "industry"  # Industry-specific (healthcare, finance, etc.)


class RetrainingStrategy(str, Enum):
    """Strategies for model retraining."""
    TRANSFER_LEARNING = "transfer_learning"  # Fine-tune baseline on new data
    FEEDBACK_LOOP = "feedback_loop"  # Learn from user accept/dismiss
    FULL_RETRAIN = "full_retrain"  # Train from scratch on client data
    ACTIVE_LEARNING = "active_learning"  # Model requests labels for uncertain samples
    ENSEMBLE_BLEND = "ensemble_blend"  # Combine baseline with custom model


@dataclass
class ModelMetadata:
    """Metadata for a trained model."""
    model_id: str
    model_type: ModelType
    version: str
    created_at: str
    description: str
    checksum: str
    metrics: Dict[str, float] = field(default_factory=dict)
    training_config: Dict[str, Any] = field(default_factory=dict)
    use_case: Optional[str] = None
    industry: Optional[str] = None
    organization: Optional[str] = None
    parent_model: Optional[str] = None  # For fine-tuned models
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "model_type": self.model_type.value,
            "version": self.version,
            "created_at": self.created_at,
            "description": self.description,
            "checksum": self.checksum,
            "metrics": self.metrics,
            "training_config": self.training_config,
            "use_case": self.use_case,
            "industry": self.industry,
            "organization": self.organization,
            "parent_model": self.parent_model,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ModelMetadata":
        return cls(
            model_id=data["model_id"],
            model_type=ModelType(data["model_type"]),
            version=data["version"],
            created_at=data["created_at"],
            description=data["description"],
            checksum=data["checksum"],
            metrics=data.get("metrics", {}),
            training_config=data.get("training_config", {}),
            use_case=data.get("use_case"),
            industry=data.get("industry"),
            organization=data.get("organization"),
            parent_model=data.get("parent_model"),
            tags=data.get("tags", []),
        )


@dataclass
class RetrainingConfig:
    """Configuration for model retraining."""
    strategy: RetrainingStrategy
    use_case: str
    description: str

    # Data configuration
    min_samples: int = 500
    validation_split: float = 0.2
    include_baseline_data: bool = True  # Mix with baseline training data

    # Training parameters
    learning_rate: Optional[float] = None
    epochs: Optional[int] = None
    early_stopping: bool = True

    # Fine-tuning specific
    freeze_layers: Optional[int] = None  # For transfer learning
    blend_weight: float = 0.5  # For ensemble blending (0=baseline, 1=custom)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy": self.strategy.value,
            "use_case": self.use_case,
            "description": self.description,
            "min_samples": self.min_samples,
            "validation_split": self.validation_split,
            "include_baseline_data": self.include_baseline_data,
            "learning_rate": self.learning_rate,
            "epochs": self.epochs,
            "early_stopping": self.early_stopping,
            "freeze_layers": self.freeze_layers,
            "blend_weight": self.blend_weight,
        }


# Predefined retraining configurations for common use cases
RETRAINING_PRESETS: Dict[str, RetrainingConfig] = {
    # Industry-specific presets
    "healthcare": RetrainingConfig(
        strategy=RetrainingStrategy.TRANSFER_LEARNING,
        use_case="healthcare",
        description="Healthcare/HIPAA-focused risk scoring with emphasis on PHI protection",
        min_samples=1000,
        include_baseline_data=True,
    ),
    "finance": RetrainingConfig(
        strategy=RetrainingStrategy.TRANSFER_LEARNING,
        use_case="finance",
        description="Financial services with PCI-DSS and SOX compliance focus",
        min_samples=1000,
        include_baseline_data=True,
    ),
    "government": RetrainingConfig(
        strategy=RetrainingStrategy.TRANSFER_LEARNING,
        use_case="government",
        description="Government/FedRAMP compliance with strict security controls",
        min_samples=800,
        include_baseline_data=True,
    ),

    # Risk tolerance presets
    "high_security": RetrainingConfig(
        strategy=RetrainingStrategy.ENSEMBLE_BLEND,
        use_case="high_security",
        description="Conservative scoring - flags more potential issues",
        blend_weight=0.3,  # More weight to baseline (stricter)
        include_baseline_data=True,
    ),
    "balanced": RetrainingConfig(
        strategy=RetrainingStrategy.ENSEMBLE_BLEND,
        use_case="balanced",
        description="Balanced approach between security and usability",
        blend_weight=0.5,
        include_baseline_data=True,
    ),
    "low_friction": RetrainingConfig(
        strategy=RetrainingStrategy.ENSEMBLE_BLEND,
        use_case="low_friction",
        description="Permissive scoring - reduces false positives",
        blend_weight=0.7,  # More weight to custom (permissive)
        include_baseline_data=True,
    ),

    # Tech stack presets
    "aws_heavy": RetrainingConfig(
        strategy=RetrainingStrategy.TRANSFER_LEARNING,
        use_case="aws_heavy",
        description="Optimized for AWS-centric infrastructure",
        min_samples=500,
        include_baseline_data=True,
    ),
    "azure_heavy": RetrainingConfig(
        strategy=RetrainingStrategy.TRANSFER_LEARNING,
        use_case="azure_heavy",
        description="Optimized for Azure-centric infrastructure",
        min_samples=500,
        include_baseline_data=True,
    ),
    "multi_cloud": RetrainingConfig(
        strategy=RetrainingStrategy.TRANSFER_LEARNING,
        use_case="multi_cloud",
        description="Multi-cloud environment scoring",
        min_samples=800,
        include_baseline_data=True,
    ),

    # Workflow presets
    "feedback_driven": RetrainingConfig(
        strategy=RetrainingStrategy.FEEDBACK_LOOP,
        use_case="feedback_driven",
        description="Learns from user accept/dismiss decisions over time",
        min_samples=200,
        include_baseline_data=True,
    ),
    "active_learning": RetrainingConfig(
        strategy=RetrainingStrategy.ACTIVE_LEARNING,
        use_case="active_learning",
        description="Model requests labels for uncertain predictions",
        min_samples=100,
        include_baseline_data=True,
    ),

    # Custom framework presets
    "custom_agents": RetrainingConfig(
        strategy=RetrainingStrategy.FULL_RETRAIN,
        use_case="custom_agents",
        description="For organizations with proprietary agent frameworks",
        min_samples=1500,
        include_baseline_data=False,  # Fully custom
    ),
}


class ModelManager:
    """Manages baseline and custom ML models."""

    BASELINE_MODEL_NAME = "secureagent_risk_v1.pkl"
    METADATA_FILE = "model_registry.json"

    def __init__(
        self,
        models_dir: Optional[Path] = None,
        cache_dir: Optional[Path] = None,
    ):
        """Initialize the model manager.

        Args:
            models_dir: Directory containing model files
            cache_dir: Directory for caching downloaded models
        """
        # Default paths
        self.models_dir = models_dir or self._get_default_models_dir()
        self.cache_dir = cache_dir or Path.home() / ".secureagent" / "models"

        # Ensure directories exist
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Model registry
        self._registry: Dict[str, ModelMetadata] = {}
        self._load_registry()

    def _get_default_models_dir(self) -> Path:
        """Get the default models directory."""
        # Check package models directory
        pkg_models = Path(__file__).parent.parent.parent.parent / "models"
        if pkg_models.exists():
            return pkg_models

        # Fall back to current directory
        return Path("models")

    def _load_registry(self) -> None:
        """Load model registry from disk."""
        registry_path = self.cache_dir / self.METADATA_FILE

        if registry_path.exists():
            try:
                data = json.loads(registry_path.read_text())
                for model_id, metadata in data.items():
                    self._registry[model_id] = ModelMetadata.from_dict(metadata)
            except Exception as e:
                logger.warning(f"Failed to load model registry: {e}")

        # Always register baseline model if it exists
        self._register_baseline()

    def _save_registry(self) -> None:
        """Save model registry to disk."""
        registry_path = self.cache_dir / self.METADATA_FILE
        data = {
            model_id: metadata.to_dict()
            for model_id, metadata in self._registry.items()
        }
        registry_path.write_text(json.dumps(data, indent=2))

    def _register_baseline(self) -> None:
        """Register the baseline model."""
        baseline_path = self.models_dir / self.BASELINE_MODEL_NAME

        if baseline_path.exists():
            checksum = self._compute_checksum(baseline_path)

            # Load existing metadata if available
            metadata_path = self.models_dir / "model_metadata.json"
            metrics = {}
            if metadata_path.exists():
                try:
                    meta = json.loads(metadata_path.read_text())
                    metrics = meta.get("metrics", {})
                except Exception:
                    pass

            self._registry["baseline"] = ModelMetadata(
                model_id="baseline",
                model_type=ModelType.BASELINE,
                version="1.0.0",
                created_at=datetime.now().isoformat(),
                description="SecureAgent baseline risk scoring model",
                checksum=checksum,
                metrics=metrics,
                tags=["baseline", "default"],
            )

    def _compute_checksum(self, path: Path) -> str:
        """Compute SHA256 checksum of a file."""
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def get_model_path(self, model_id: str = "baseline") -> Optional[Path]:
        """Get the path to a model file.

        Args:
            model_id: Model identifier (default: "baseline")

        Returns:
            Path to the model file, or None if not found
        """
        if model_id == "baseline":
            baseline_path = self.models_dir / self.BASELINE_MODEL_NAME
            if baseline_path.exists():
                return baseline_path

            # Check alternative name
            alt_path = self.models_dir / "mcp_risk_model_latest.pkl"
            if alt_path.exists():
                return alt_path

        # Check cache for custom models
        cached_path = self.cache_dir / f"{model_id}.pkl"
        if cached_path.exists():
            return cached_path

        # Check models directory
        model_path = self.models_dir / f"{model_id}.pkl"
        if model_path.exists():
            return model_path

        return None

    def list_models(self) -> List[ModelMetadata]:
        """List all registered models."""
        return list(self._registry.values())

    def get_model_metadata(self, model_id: str) -> Optional[ModelMetadata]:
        """Get metadata for a model."""
        return self._registry.get(model_id)

    def register_model(
        self,
        model_path: Path,
        model_id: str,
        model_type: ModelType,
        description: str,
        metrics: Optional[Dict[str, float]] = None,
        training_config: Optional[Dict[str, Any]] = None,
        use_case: Optional[str] = None,
        industry: Optional[str] = None,
        organization: Optional[str] = None,
        parent_model: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> ModelMetadata:
        """Register a new model.

        Args:
            model_path: Path to the model file
            model_id: Unique identifier for the model
            model_type: Type of model
            description: Human-readable description
            metrics: Training/evaluation metrics
            training_config: Configuration used for training
            use_case: Use case this model is optimized for
            industry: Industry this model targets
            organization: Organization that owns this model
            parent_model: ID of parent model (for fine-tuned models)
            tags: Tags for categorization

        Returns:
            ModelMetadata for the registered model
        """
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        # Copy to cache directory
        dest_path = self.cache_dir / f"{model_id}.pkl"
        shutil.copy2(model_path, dest_path)

        # Compute checksum
        checksum = self._compute_checksum(dest_path)

        # Create metadata
        metadata = ModelMetadata(
            model_id=model_id,
            model_type=model_type,
            version="1.0.0",
            created_at=datetime.now().isoformat(),
            description=description,
            checksum=checksum,
            metrics=metrics or {},
            training_config=training_config or {},
            use_case=use_case,
            industry=industry,
            organization=organization,
            parent_model=parent_model,
            tags=tags or [],
        )

        self._registry[model_id] = metadata
        self._save_registry()

        logger.info(f"Registered model: {model_id}")
        return metadata

    def delete_model(self, model_id: str) -> bool:
        """Delete a registered model.

        Args:
            model_id: Model identifier

        Returns:
            True if deleted, False if not found
        """
        if model_id == "baseline":
            raise ValueError("Cannot delete baseline model")

        if model_id not in self._registry:
            return False

        # Remove file
        model_path = self.cache_dir / f"{model_id}.pkl"
        if model_path.exists():
            model_path.unlink()

        # Remove from registry
        del self._registry[model_id]
        self._save_registry()

        logger.info(f"Deleted model: {model_id}")
        return True

    def verify_model(self, model_id: str) -> bool:
        """Verify model integrity using checksum.

        Args:
            model_id: Model identifier

        Returns:
            True if checksum matches, False otherwise
        """
        metadata = self._registry.get(model_id)
        if not metadata:
            return False

        model_path = self.get_model_path(model_id)
        if not model_path:
            return False

        actual_checksum = self._compute_checksum(model_path)
        return actual_checksum == metadata.checksum

    def get_retraining_preset(self, preset_name: str) -> Optional[RetrainingConfig]:
        """Get a predefined retraining configuration.

        Args:
            preset_name: Name of the preset

        Returns:
            RetrainingConfig or None if not found
        """
        return RETRAINING_PRESETS.get(preset_name)

    def list_retraining_presets(self) -> Dict[str, RetrainingConfig]:
        """List all available retraining presets."""
        return RETRAINING_PRESETS.copy()

    def get_recommended_preset(
        self,
        industry: Optional[str] = None,
        use_case: Optional[str] = None,
        sample_count: int = 0,
    ) -> str:
        """Get recommended retraining preset based on context.

        Args:
            industry: Industry vertical
            use_case: Specific use case
            sample_count: Number of training samples available

        Returns:
            Name of recommended preset
        """
        # Industry-specific recommendations
        if industry:
            industry_lower = industry.lower()
            if "health" in industry_lower or "hipaa" in industry_lower:
                return "healthcare"
            if "financ" in industry_lower or "bank" in industry_lower:
                return "finance"
            if "gov" in industry_lower or "fed" in industry_lower:
                return "government"

        # Sample count recommendations
        if sample_count < 200:
            return "active_learning"
        if sample_count < 500:
            return "feedback_driven"

        # Default
        return "balanced"

    def export_model(self, model_id: str, dest_path: Path) -> bool:
        """Export a model to a specified location.

        Args:
            model_id: Model identifier
            dest_path: Destination path

        Returns:
            True if exported successfully
        """
        model_path = self.get_model_path(model_id)
        if not model_path:
            return False

        # Copy model file
        shutil.copy2(model_path, dest_path)

        # Export metadata alongside
        metadata = self._registry.get(model_id)
        if metadata:
            meta_path = dest_path.with_suffix(".meta.json")
            meta_path.write_text(json.dumps(metadata.to_dict(), indent=2))

        return True

    def import_model(self, model_path: Path, model_id: Optional[str] = None) -> ModelMetadata:
        """Import a model from a file.

        Args:
            model_path: Path to the model file
            model_id: Optional model ID (derived from filename if not provided)

        Returns:
            ModelMetadata for the imported model
        """
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")

        # Derive model ID from filename if not provided
        if not model_id:
            model_id = model_path.stem

        # Check for accompanying metadata
        meta_path = model_path.with_suffix(".meta.json")
        if meta_path.exists():
            meta_data = json.loads(meta_path.read_text())
            return self.register_model(
                model_path=model_path,
                model_id=model_id,
                model_type=ModelType(meta_data.get("model_type", "custom")),
                description=meta_data.get("description", "Imported model"),
                metrics=meta_data.get("metrics"),
                training_config=meta_data.get("training_config"),
                use_case=meta_data.get("use_case"),
                industry=meta_data.get("industry"),
                organization=meta_data.get("organization"),
                parent_model=meta_data.get("parent_model"),
                tags=meta_data.get("tags"),
            )

        # Register with minimal metadata
        return self.register_model(
            model_path=model_path,
            model_id=model_id,
            model_type=ModelType.CUSTOM,
            description="Imported custom model",
        )
