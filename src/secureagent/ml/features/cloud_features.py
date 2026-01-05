"""Cloud-specific feature extractor for SecureAgent ML."""

from typing import Dict, List

from ...core.models.finding import Finding
from .base import FeatureExtractor


class CloudFeatureExtractor(FeatureExtractor):
    """Extract cloud-specific features from findings."""

    # Cloud rule prefixes
    CLOUD_PREFIXES = ["AWS", "AZURE", "GCP", "TF"]

    # Cloud service categories
    AWS_SERVICES = {
        "s3": ["S3", "bucket"],
        "iam": ["IAM", "policy", "role", "user"],
        "ec2": ["EC2", "instance", "security-group", "sg"],
        "rds": ["RDS", "database"],
        "lambda": ["Lambda", "function"],
        "kms": ["KMS", "key", "encryption"],
    }

    # High-risk cloud patterns
    HIGH_RISK_PATTERNS = [
        "public", "open", "0.0.0.0", "::/0",
        "wildcard", "*", "admin", "root",
        "unencrypted", "no-encryption", "plain",
    ]

    # Resource exposure patterns
    EXPOSURE_PATTERNS = [
        "public-access", "public-read", "public-write",
        "internet-facing", "external", "open-to-world",
    ]

    def extract(self, finding: Finding) -> Dict[str, float]:
        """Extract cloud features from finding."""
        features = {
            "is_cloud_finding": 0.0,
            "is_aws": 0.0,
            "is_azure": 0.0,
            "is_terraform": 0.0,
            "cloud_s3_risk": 0.0,
            "cloud_iam_risk": 0.0,
            "cloud_ec2_risk": 0.0,
            "cloud_rds_risk": 0.0,
            "cloud_lambda_risk": 0.0,
            "cloud_kms_risk": 0.0,
            "cloud_high_risk_pattern": 0.0,
            "cloud_exposure_risk": 0.0,
            "cloud_encryption_issue": 0.0,
            "cloud_permission_issue": 0.0,
        }

        # Check if this is a cloud finding
        rule_prefix = finding.rule_id.split("-")[0] if "-" in finding.rule_id else ""
        if rule_prefix not in self.CLOUD_PREFIXES:
            return features

        features["is_cloud_finding"] = 1.0

        # Identify cloud provider
        if rule_prefix == "AWS" or finding.rule_id.startswith("AWS"):
            features["is_aws"] = 1.0
        elif rule_prefix == "AZURE" or "Azure" in finding.title:
            features["is_azure"] = 1.0
        elif rule_prefix == "TF":
            features["is_terraform"] = 1.0

        # Identify AWS service
        text = f"{finding.rule_id} {finding.title} {finding.description}".lower()
        for service, keywords in self.AWS_SERVICES.items():
            if any(kw.lower() in text for kw in keywords):
                features[f"cloud_{service}_risk"] = 1.0

        # Check for high-risk patterns
        for pattern in self.HIGH_RISK_PATTERNS:
            if pattern.lower() in text:
                features["cloud_high_risk_pattern"] = 1.0
                break

        # Check for exposure patterns
        for pattern in self.EXPOSURE_PATTERNS:
            if pattern.lower() in text:
                features["cloud_exposure_risk"] = 1.0
                break

        # Check for encryption issues
        encryption_keywords = ["encrypt", "kms", "ssl", "tls"]
        if any(kw in text for kw in encryption_keywords):
            if any(neg in text for neg in ["no", "not", "missing", "without", "disabled"]):
                features["cloud_encryption_issue"] = 1.0

        # Check for permission issues
        permission_keywords = ["permission", "policy", "role", "access", "iam"]
        if any(kw in text for kw in permission_keywords):
            if any(risk in text for risk in ["admin", "root", "*", "wildcard", "overly"]):
                features["cloud_permission_issue"] = 1.0

        return features

    @property
    def feature_names(self) -> List[str]:
        """Get feature names."""
        return [
            "is_cloud_finding",
            "is_aws",
            "is_azure",
            "is_terraform",
            "cloud_s3_risk",
            "cloud_iam_risk",
            "cloud_ec2_risk",
            "cloud_rds_risk",
            "cloud_lambda_risk",
            "cloud_kms_risk",
            "cloud_high_risk_pattern",
            "cloud_exposure_risk",
            "cloud_encryption_issue",
            "cloud_permission_issue",
        ]
