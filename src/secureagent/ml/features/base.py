"""Base feature extractor for SecureAgent ML."""

from abc import ABC, abstractmethod
from typing import Dict, Any, List

from ...core.models.finding import Finding


class FeatureExtractor(ABC):
    """Base class for feature extractors."""

    @abstractmethod
    def extract(self, finding: Finding) -> Dict[str, float]:
        """Extract features from a finding."""
        pass

    @property
    @abstractmethod
    def feature_names(self) -> List[str]:
        """Get list of feature names produced by this extractor."""
        pass


class CompositeFeatureExtractor(FeatureExtractor):
    """Combine multiple feature extractors."""

    def __init__(self, extractors: List[FeatureExtractor]):
        """Initialize with list of extractors."""
        self.extractors = extractors

    def extract(self, finding: Finding) -> Dict[str, float]:
        """Extract features from all extractors."""
        features = {}
        for extractor in self.extractors:
            try:
                extracted = extractor.extract(finding)
                features.update(extracted)
            except Exception:
                # Skip failed extractors
                pass
        return features

    @property
    def feature_names(self) -> List[str]:
        """Get combined feature names."""
        names = []
        for extractor in self.extractors:
            names.extend(extractor.feature_names)
        return names


class TextFeatureExtractor(FeatureExtractor):
    """Extract text-based features."""

    KEYWORDS = {
        "credential": ["credential", "password", "secret", "api_key", "token", "key"],
        "injection": ["injection", "command", "sql", "xss", "script"],
        "exposure": ["exposure", "public", "open", "accessible", "leak"],
        "auth": ["auth", "authentication", "authorization", "access", "permission"],
        "encryption": ["encryption", "encrypt", "ssl", "tls", "https"],
        "network": ["network", "firewall", "port", "ingress", "egress"],
    }

    def extract(self, finding: Finding) -> Dict[str, float]:
        """Extract text features from finding."""
        features = {}
        text = f"{finding.title} {finding.description}".lower()

        for category, keywords in self.KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in text) / len(keywords)
            features[f"text_{category}"] = score

        # Text length features
        features["title_length"] = min(len(finding.title) / 100, 1.0)
        features["desc_length"] = min(len(finding.description) / 500, 1.0)

        return features

    @property
    def feature_names(self) -> List[str]:
        """Get feature names."""
        names = [f"text_{cat}" for cat in self.KEYWORDS.keys()]
        names.extend(["title_length", "desc_length"])
        return names


class LocationFeatureExtractor(FeatureExtractor):
    """Extract location-based features."""

    SENSITIVE_PATHS = [
        "config", "secret", "credential", "env", ".env",
        "key", "auth", "password", "token",
    ]

    SENSITIVE_EXTENSIONS = [
        ".env", ".pem", ".key", ".json", ".yml", ".yaml",
    ]

    def extract(self, finding: Finding) -> Dict[str, float]:
        """Extract location features from finding."""
        features = {
            "has_location": 0.0,
            "has_line_number": 0.0,
            "sensitive_path": 0.0,
            "sensitive_extension": 0.0,
            "is_cloud_resource": 0.0,
        }

        if not finding.location:
            return features

        features["has_location"] = 1.0
        loc = finding.location

        if loc.file_path:
            path_lower = loc.file_path.lower()

            if loc.line_number:
                features["has_line_number"] = 1.0

            # Check for sensitive paths
            for sensitive in self.SENSITIVE_PATHS:
                if sensitive in path_lower:
                    features["sensitive_path"] = 1.0
                    break

            # Check for sensitive extensions
            for ext in self.SENSITIVE_EXTENSIONS:
                if path_lower.endswith(ext):
                    features["sensitive_extension"] = 1.0
                    break

        if loc.resource_type:
            features["is_cloud_resource"] = 1.0

        return features

    @property
    def feature_names(self) -> List[str]:
        """Get feature names."""
        return [
            "has_location",
            "has_line_number",
            "sensitive_path",
            "sensitive_extension",
            "is_cloud_resource",
        ]
