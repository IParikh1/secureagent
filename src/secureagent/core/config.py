"""Unified configuration management for SecureAgent."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class AWSConfig:
    """AWS configuration settings."""

    region: str = "us-east-1"
    profile: Optional[str] = None
    sns_topic_arn: Optional[str] = None
    cloudtrail_bucket: Optional[str] = None

    # Scanning options
    scan_s3: bool = True
    scan_iam: bool = True
    scan_ec2: bool = True
    scan_lambda: bool = True

    @classmethod
    def from_env(cls) -> "AWSConfig":
        """Create config from environment variables."""
        return cls(
            region=os.getenv("AWS_REGION", "us-east-1"),
            profile=os.getenv("AWS_PROFILE"),
            sns_topic_arn=os.getenv("AWS_SNS_TOPIC_ARN"),
            cloudtrail_bucket=os.getenv("AWS_CLOUDTRAIL_BUCKET"),
            scan_s3=os.getenv("SCAN_S3", "true").lower() == "true",
            scan_iam=os.getenv("SCAN_IAM", "true").lower() == "true",
            scan_ec2=os.getenv("SCAN_EC2", "true").lower() == "true",
            scan_lambda=os.getenv("SCAN_LAMBDA", "true").lower() == "true",
        )


@dataclass
class AzureConfig:
    """Azure configuration settings."""

    subscription_id: Optional[str] = None
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None

    # Scanning options
    scan_storage: bool = True
    scan_keyvault: bool = True

    @classmethod
    def from_env(cls) -> "AzureConfig":
        """Create config from environment variables."""
        return cls(
            subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID"),
            tenant_id=os.getenv("AZURE_TENANT_ID"),
            client_id=os.getenv("AZURE_CLIENT_ID"),
            scan_storage=os.getenv("SCAN_AZURE_STORAGE", "true").lower() == "true",
        )


@dataclass
class AlertConfig:
    """Alerting configuration settings."""

    slack_webhook_url: Optional[str] = None
    slack_channel: Optional[str] = None
    enable_sns: bool = False
    enable_slack: bool = False
    enable_webhook: bool = False
    webhook_url: Optional[str] = None

    # Alert filtering
    min_severity: str = "medium"

    @classmethod
    def from_env(cls) -> "AlertConfig":
        """Create config from environment variables."""
        return cls(
            slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL"),
            slack_channel=os.getenv("SLACK_CHANNEL"),
            enable_sns=os.getenv("ENABLE_SNS_ALERTS", "false").lower() == "true",
            enable_slack=os.getenv("ENABLE_SLACK_ALERTS", "false").lower() == "true",
            enable_webhook=os.getenv("ENABLE_WEBHOOK_ALERTS", "false").lower() == "true",
            webhook_url=os.getenv("WEBHOOK_URL"),
            min_severity=os.getenv("ALERT_MIN_SEVERITY", "medium"),
        )


@dataclass
class ScanConfig:
    """Scanning configuration settings."""

    # General
    max_file_size_mb: int = 10
    timeout_seconds: int = 300
    parallel_scans: int = 4

    # Output
    output_format: str = "console"  # console, json, sarif, html
    output_file: Optional[str] = None

    # Filtering
    min_severity: str = "info"
    include_suppressed: bool = False
    fail_on_severity: Optional[str] = None  # For CI mode

    # Risk scoring
    enable_risk_scoring: bool = True
    enable_graph_analysis: bool = False

    @classmethod
    def from_env(cls) -> "ScanConfig":
        """Create config from environment variables."""
        return cls(
            max_file_size_mb=int(os.getenv("MAX_FILE_SIZE_MB", "10")),
            timeout_seconds=int(os.getenv("SCAN_TIMEOUT", "300")),
            parallel_scans=int(os.getenv("PARALLEL_SCANS", "4")),
            output_format=os.getenv("OUTPUT_FORMAT", "console"),
            output_file=os.getenv("OUTPUT_FILE"),
            min_severity=os.getenv("MIN_SEVERITY", "info"),
            fail_on_severity=os.getenv("FAIL_ON_SEVERITY"),
            enable_risk_scoring=os.getenv("ENABLE_RISK_SCORING", "true").lower() == "true",
        )


@dataclass
class MLConfig:
    """Machine learning configuration settings."""

    model_path: Optional[str] = None
    enable_ml_scoring: bool = True
    confidence_threshold: float = 0.7

    @classmethod
    def from_env(cls) -> "MLConfig":
        """Create config from environment variables."""
        return cls(
            model_path=os.getenv("ML_MODEL_PATH"),
            enable_ml_scoring=os.getenv("ENABLE_ML_SCORING", "true").lower() == "true",
            confidence_threshold=float(os.getenv("ML_CONFIDENCE_THRESHOLD", "0.7")),
        )


@dataclass
class GitHubConfig:
    """GitHub integration configuration."""

    token: Optional[str] = None
    app_id: Optional[str] = None
    app_private_key: Optional[str] = None

    # PR integration
    post_pr_comments: bool = True
    create_issues: bool = False
    fail_pr_on_severity: Optional[str] = "high"

    @classmethod
    def from_env(cls) -> "GitHubConfig":
        """Create config from environment variables."""
        return cls(
            token=os.getenv("GITHUB_TOKEN"),
            app_id=os.getenv("GITHUB_APP_ID"),
            app_private_key=os.getenv("GITHUB_APP_PRIVATE_KEY"),
            post_pr_comments=os.getenv("GITHUB_POST_PR_COMMENTS", "true").lower() == "true",
            create_issues=os.getenv("GITHUB_CREATE_ISSUES", "false").lower() == "true",
            fail_pr_on_severity=os.getenv("GITHUB_FAIL_PR_SEVERITY", "high"),
        )


@dataclass
class SlackConfig:
    """Slack bot configuration."""

    bot_token: Optional[str] = None
    app_token: Optional[str] = None
    signing_secret: Optional[str] = None
    default_channel: Optional[str] = None

    @classmethod
    def from_env(cls) -> "SlackConfig":
        """Create config from environment variables."""
        return cls(
            bot_token=os.getenv("SLACK_BOT_TOKEN"),
            app_token=os.getenv("SLACK_APP_TOKEN"),
            signing_secret=os.getenv("SLACK_SIGNING_SECRET"),
            default_channel=os.getenv("SLACK_DEFAULT_CHANNEL"),
        )


@dataclass
class Config:
    """Main configuration class combining all settings."""

    # Sub-configurations
    aws: AWSConfig = field(default_factory=AWSConfig)
    azure: AzureConfig = field(default_factory=AzureConfig)
    alert: AlertConfig = field(default_factory=AlertConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    github: GitHubConfig = field(default_factory=GitHubConfig)
    slack: SlackConfig = field(default_factory=SlackConfig)

    # Global settings
    log_level: str = "INFO"
    debug: bool = False

    # Paths
    config_file: Optional[str] = None
    cache_dir: Optional[str] = None

    # Scanner selection
    enabled_scanners: List[str] = field(default_factory=lambda: ["mcp", "aws", "terraform"])
    disabled_scanners: List[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "Config":
        """Create config from environment variables."""
        return cls(
            aws=AWSConfig.from_env(),
            azure=AzureConfig.from_env(),
            alert=AlertConfig.from_env(),
            scan=ScanConfig.from_env(),
            ml=MLConfig.from_env(),
            github=GitHubConfig.from_env(),
            slack=SlackConfig.from_env(),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            debug=os.getenv("DEBUG", "false").lower() == "true",
            cache_dir=os.getenv("SECUREAGENT_CACHE_DIR"),
        )

    @classmethod
    def from_file(cls, path: str) -> "Config":
        """Load config from YAML file.

        Args:
            path: Path to YAML config file

        Returns:
            Config instance
        """
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(config_path) as f:
            data = yaml.safe_load(f) or {}

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Create config from dictionary.

        Args:
            data: Configuration dictionary

        Returns:
            Config instance
        """
        config = cls()

        if "aws" in data:
            config.aws = AWSConfig(**data["aws"])
        if "azure" in data:
            config.azure = AzureConfig(**data["azure"])
        if "alert" in data:
            config.alert = AlertConfig(**data["alert"])
        if "scan" in data:
            config.scan = ScanConfig(**data["scan"])
        if "ml" in data:
            config.ml = MLConfig(**data["ml"])
        if "github" in data:
            config.github = GitHubConfig(**data["github"])
        if "slack" in data:
            config.slack = SlackConfig(**data["slack"])

        # Global settings
        config.log_level = data.get("log_level", config.log_level)
        config.debug = data.get("debug", config.debug)
        config.enabled_scanners = data.get("enabled_scanners", config.enabled_scanners)
        config.disabled_scanners = data.get("disabled_scanners", config.disabled_scanners)

        return config

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary.

        Returns:
            Configuration dictionary
        """
        return {
            "aws": {
                "region": self.aws.region,
                "profile": self.aws.profile,
                "scan_s3": self.aws.scan_s3,
                "scan_iam": self.aws.scan_iam,
                "scan_ec2": self.aws.scan_ec2,
            },
            "azure": {
                "subscription_id": self.azure.subscription_id,
                "scan_storage": self.azure.scan_storage,
            },
            "alert": {
                "enable_slack": self.alert.enable_slack,
                "enable_sns": self.alert.enable_sns,
                "min_severity": self.alert.min_severity,
            },
            "scan": {
                "output_format": self.scan.output_format,
                "min_severity": self.scan.min_severity,
                "enable_risk_scoring": self.scan.enable_risk_scoring,
            },
            "log_level": self.log_level,
            "debug": self.debug,
            "enabled_scanners": self.enabled_scanners,
        }

    def validate(self) -> List[str]:
        """Validate configuration and return warnings.

        Returns:
            List of warning messages
        """
        warnings = []

        # AWS warnings
        if self.aws.scan_s3 and not self.aws.region:
            warnings.append("AWS region not set; using default us-east-1")

        # SNS warnings
        if self.alert.enable_sns and not self.aws.sns_topic_arn:
            warnings.append("SNS alerts enabled but no topic ARN configured")

        # Slack warnings
        if self.alert.enable_slack and not self.alert.slack_webhook_url:
            warnings.append("Slack alerts enabled but no webhook URL configured")

        # Azure warnings
        if self.azure.scan_storage and not self.azure.subscription_id:
            warnings.append("Azure scanning enabled but subscription ID not set")

        # GitHub warnings
        if self.github.post_pr_comments and not self.github.token:
            warnings.append("GitHub PR comments enabled but no token configured")

        return warnings


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance.

    Returns:
        Global Config instance
    """
    global _config
    if _config is None:
        _config = Config.from_env()
    return _config


def set_config(config: Config) -> None:
    """Set the global configuration instance.

    Args:
        config: Config instance to set
    """
    global _config
    _config = config


def load_config(path: Optional[str] = None) -> Config:
    """Load configuration from file or environment.

    Args:
        path: Optional path to config file

    Returns:
        Loaded Config instance
    """
    global _config

    if path:
        _config = Config.from_file(path)
    else:
        # Try default config locations
        default_paths = [
            ".secureagent.yaml",
            ".secureagent.yml",
            "secureagent.yaml",
            "secureagent.yml",
            Path.home() / ".config" / "secureagent" / "config.yaml",
        ]

        for default_path in default_paths:
            if Path(default_path).exists():
                _config = Config.from_file(str(default_path))
                break
        else:
            # Fall back to environment
            _config = Config.from_env()

    return _config
