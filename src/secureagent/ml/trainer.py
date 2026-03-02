"""ML model trainer for SecureAgent.

Provides training pipeline for risk prediction models including:
- Synthetic data generation for bootstrapping
- Feature extraction and preparation
- Model training with cross-validation
- Hyperparameter tuning
- Model evaluation and reporting
"""

import logging
import random
from typing import List, Tuple, Optional, Dict, Any
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
import json

from ..core.models.finding import Finding, FindingDomain, Location
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
    training_samples: int = 0
    validation_samples: int = 0
    training_time_seconds: float = 0.0


@dataclass
class EvaluationReport:
    """Model evaluation report."""

    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: float
    confusion_matrix: List[List[int]] = field(default_factory=list)
    classification_report: str = ""
    feature_importance: Dict[str, float] = field(default_factory=dict)
    generated_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "auc_roc": self.auc_roc,
            "confusion_matrix": self.confusion_matrix,
            "classification_report": self.classification_report,
            "feature_importance": self.feature_importance,
            "generated_at": self.generated_at,
        }


class SyntheticDataGenerator:
    """Generate synthetic training data for bootstrapping.

    Creates realistic security findings with known risk labels
    to train the model when real labeled data is scarce.
    """

    # Templates for synthetic findings
    MCP_TEMPLATES = [
        # High risk findings
        {
            "rule_id": "MCP-002",
            "title": "Hardcoded API Key",
            "description": "Found hardcoded {key_type} in MCP configuration",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": ["OpenAI API key", "Anthropic API key", "GitHub token", "AWS credentials"],
        },
        {
            "rule_id": "MCP-001",
            "title": "No Authentication Configured",
            "description": "Remote MCP server '{server}' has no authentication",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": ["api-server", "data-server", "file-server", "exec-server"],
        },
        {
            "rule_id": "MCP-003",
            "title": "Command Injection Risk",
            "description": "Server '{server}' contains {pattern} in command",
            "severity": Severity.HIGH,
            "risk": 1,
            "variations": [("shell", "pipe operator"), ("exec", "command chaining"), ("runner", "backticks")],
        },
        # Medium risk findings
        {
            "rule_id": "MCP-005",
            "title": "Path Traversal Risk",
            "description": "Server references {path_type}",
            "severity": Severity.MEDIUM,
            "risk": 0,
            "variations": ["absolute system path", "parent directory traversal", "sensitive directory"],
        },
        {
            "rule_id": "MCP-007",
            "title": "Dangerous Tool Configuration",
            "description": "Server provides {tool} capabilities",
            "severity": Severity.MEDIUM,
            "risk": 0,
            "variations": ["shell execution", "file write", "system command", "admin access"],
        },
        # Low risk findings
        {
            "rule_id": "MCP-INFO",
            "title": "Configuration Notice",
            "description": "MCP server {notice}",
            "severity": Severity.LOW,
            "risk": 0,
            "variations": ["uses default settings", "missing optional field", "deprecated format"],
        },
    ]

    AWS_TEMPLATES = [
        # High risk
        {
            "rule_id": "AWS-S3-001",
            "title": "Public S3 Bucket",
            "description": "S3 bucket '{bucket}' allows public access",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": ["data-bucket", "backup-bucket", "logs-bucket", "assets-bucket"],
        },
        {
            "rule_id": "AWS-IAM-001",
            "title": "Wildcard IAM Permissions",
            "description": "IAM policy grants {permission} on all resources",
            "severity": Severity.HIGH,
            "risk": 1,
            "variations": ["s3:*", "ec2:*", "iam:*", "*:*"],
        },
        # Medium risk
        {
            "rule_id": "AWS-S3-002",
            "title": "S3 Bucket Without Encryption",
            "description": "S3 bucket '{bucket}' does not have encryption enabled",
            "severity": Severity.MEDIUM,
            "risk": 0,
            "variations": ["storage-bucket", "archive-bucket", "temp-bucket"],
        },
        # Low risk
        {
            "rule_id": "AWS-S3-003",
            "title": "S3 Versioning Disabled",
            "description": "S3 bucket does not have versioning enabled",
            "severity": Severity.LOW,
            "risk": 0,
            "variations": [],
        },
    ]

    LANGCHAIN_TEMPLATES = [
        # High risk
        {
            "rule_id": "LC-001",
            "title": "Arbitrary Code Execution",
            "description": "LangChain agent can execute arbitrary {code_type}",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": ["Python code", "shell commands", "system calls"],
        },
        {
            "rule_id": "LC-002",
            "title": "Prompt Injection Vulnerability",
            "description": "Agent prompt includes unsanitized {input_type}",
            "severity": Severity.HIGH,
            "risk": 1,
            "variations": ["user input", "external data", "database content"],
        },
        # Medium risk
        {
            "rule_id": "LC-003",
            "title": "Excessive Tool Permissions",
            "description": "Agent has access to {tool_count} tools including sensitive ones",
            "severity": Severity.MEDIUM,
            "risk": 0,
            "variations": ["15+", "20+", "many"],
        },
    ]

    AZURE_TEMPLATES = [
        {
            "rule_id": "AZURE-STORAGE-001",
            "title": "Public Storage Container",
            "description": "Azure storage container '{container}' allows public access",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": ["data-container", "backup-container", "uploads-container", "assets-container"],
        },
        {
            "rule_id": "AZURE-STORAGE-002",
            "title": "Missing Encryption at Rest",
            "description": "Azure storage account '{account}' missing encryption at rest",
            "severity": Severity.HIGH,
            "risk": 1,
            "variations": ["storageaccount01", "proddata", "logstorage", "archivestore"],
        },
        {
            "rule_id": "AZURE-STORAGE-003",
            "title": "Missing Network Restrictions",
            "description": "Azure storage account has no network restrictions configured",
            "severity": Severity.MEDIUM,
            "risk": 0,
            "variations": [],
        },
        {
            "rule_id": "AZURE-STORAGE-004",
            "title": "Missing Access Logging",
            "description": "Azure storage account '{account}' does not have access logging enabled",
            "severity": Severity.LOW,
            "risk": 0,
            "variations": ["storageaccount01", "proddata", "logstorage"],
        },
    ]

    TERRAFORM_TEMPLATES = [
        {
            "rule_id": "TF-SG-001",
            "title": "Open Security Group",
            "description": "Security group allows unrestricted access from {cidr}",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": ["0.0.0.0/0", "::/0", "any source"],
        },
        {
            "rule_id": "TF-S3-001",
            "title": "Public S3 Bucket in Terraform",
            "description": "Terraform creates S3 bucket '{bucket}' with public access",
            "severity": Severity.HIGH,
            "risk": 1,
            "variations": ["data-bucket", "public-assets", "web-bucket"],
        },
        {
            "rule_id": "TF-RDS-001",
            "title": "Unencrypted RDS Instance",
            "description": "RDS instance '{instance}' does not have storage encryption enabled",
            "severity": Severity.HIGH,
            "risk": 1,
            "variations": ["prod-db", "main-database", "analytics-rds"],
        },
        {
            "rule_id": "TF-EC2-001",
            "title": "Unencrypted EBS Volume",
            "description": "EBS volume attached to instance has no encryption",
            "severity": Severity.MEDIUM,
            "risk": 0,
            "variations": [],
        },
        {
            "rule_id": "TF-RDS-002",
            "title": "Public RDS Instance",
            "description": "RDS instance is publicly accessible",
            "severity": Severity.MEDIUM,
            "risk": 0,
            "variations": [],
        },
    ]

    OPENAI_TEMPLATES = [
        {
            "rule_id": "OAI-001",
            "title": "Hardcoded API Key",
            "description": "OpenAI API key hardcoded in {location}",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": ["assistant configuration", "source code", "environment file", "config.json"],
        },
        {
            "rule_id": "OAI-002",
            "title": "Code Interpreter Without Restrictions",
            "description": "OpenAI Assistant has code_interpreter enabled without execution restrictions",
            "severity": Severity.HIGH,
            "risk": 1,
            "variations": [],
        },
        {
            "rule_id": "OAI-003",
            "title": "File Search With Sensitive Data",
            "description": "OpenAI Assistant file_search tool has access to {data_type}",
            "severity": Severity.HIGH,
            "risk": 1,
            "variations": ["sensitive documents", "PII data files", "internal reports", "credentials files"],
        },
        {
            "rule_id": "OAI-004",
            "title": "Dangerous Function Definition",
            "description": "OpenAI Assistant defines dangerous function: {function}",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": ["execute_shell_command", "run_system_command", "delete_files", "modify_permissions"],
        },
        {
            "rule_id": "OAI-005",
            "title": "Missing Assistant Guardrails",
            "description": "OpenAI Assistant has no instruction guardrails configured",
            "severity": Severity.MEDIUM,
            "risk": 0,
            "variations": [],
        },
    ]

    AUTOGPT_TEMPLATES = [
        {
            "rule_id": "AG-001",
            "title": "Hardcoded API Keys in Agent Config",
            "description": "API keys hardcoded in {framework} agent configuration",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": ["AutoGPT", "CrewAI", "autonomous agent"],
        },
        {
            "rule_id": "AG-002",
            "title": "Unrestricted Agent Autonomy",
            "description": "Agent has unrestricted autonomy with no human-in-the-loop controls",
            "severity": Severity.HIGH,
            "risk": 1,
            "variations": [],
        },
        {
            "rule_id": "AG-003",
            "title": "Dangerous Tool Access",
            "description": "Agent has access to dangerous tool: {tool}",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": ["shell_executor", "file_system_write", "code_execution", "system_admin"],
        },
        {
            "rule_id": "AG-004",
            "title": "Inter-Agent Trust Without Verification",
            "description": "Agent trusts other agents without verification or authentication",
            "severity": Severity.HIGH,
            "risk": 1,
            "variations": [],
        },
        {
            "rule_id": "AG-005",
            "title": "No Memory Limits Configured",
            "description": "Agent has no memory limits configured for {memory_type}",
            "severity": Severity.MEDIUM,
            "risk": 0,
            "variations": ["context window", "vector store", "conversation history"],
        },
        {
            "rule_id": "AG-006",
            "title": "Unconstrained Task Delegation",
            "description": "Agent can delegate tasks without scope restrictions",
            "severity": Severity.MEDIUM,
            "risk": 0,
            "variations": [],
        },
        {
            "rule_id": "AG-009",
            "title": "No Iteration Limits",
            "description": "Agent has no iteration or recursion limits configured",
            "severity": Severity.LOW,
            "risk": 0,
            "variations": [],
        },
    ]

    MULTIAGENT_TEMPLATES = [
        {
            "rule_id": "MA-ORCH-001",
            "title": "Workflow Cycle Detected",
            "description": "Orchestration workflow contains a cycle that could cause infinite loops",
            "severity": Severity.HIGH,
            "risk": 1,
            "variations": [],
        },
        {
            "rule_id": "MA-ORCH-003",
            "title": "Privilege Escalation Path",
            "description": "Privilege escalation path detected in orchestration from {source} to {target}",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": [("reader agent", "admin agent"), ("worker", "orchestrator"), ("guest", "system")],
        },
        {
            "rule_id": "MA-COMM-001",
            "title": "Unencrypted Agent Communication",
            "description": "Agent communication channel uses unencrypted transport",
            "severity": Severity.HIGH,
            "risk": 1,
            "variations": [],
        },
        {
            "rule_id": "MA-COMM-003",
            "title": "Message Injection Vulnerability",
            "description": "Agent messaging system vulnerable to message injection attacks",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": [],
        },
        {
            "rule_id": "MA-DEL-001",
            "title": "Circular Delegation Chain",
            "description": "Circular delegation chain detected between agents",
            "severity": Severity.MEDIUM,
            "risk": 0,
            "variations": [],
        },
        {
            "rule_id": "MA-DEL-003",
            "title": "Unauthorized Delegation",
            "description": "Agent delegates tasks to unauthorized recipient agents",
            "severity": Severity.HIGH,
            "risk": 1,
            "variations": [],
        },
    ]

    RAG_TEMPLATES = [
        {
            "rule_id": "RAG-VS-001",
            "title": "Vector Store No Access Controls",
            "description": "Vector store '{store}' has no access controls configured",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": ["main-index", "document-store", "knowledge-base", "embeddings-db"],
        },
        {
            "rule_id": "RAG-VS-003",
            "title": "Vector Store Network Exposure",
            "description": "Vector store is exposed to network without authentication",
            "severity": Severity.HIGH,
            "risk": 1,
            "variations": [],
        },
        {
            "rule_id": "RAG-DOC-001",
            "title": "Malicious Document Ingestion",
            "description": "RAG pipeline ingests documents without validation or sanitization",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": [],
        },
        {
            "rule_id": "RAG-POISON-001",
            "title": "Knowledge Base Poisoning",
            "description": "Knowledge base poisoning detected via {vector}",
            "severity": Severity.CRITICAL,
            "risk": 1,
            "variations": ["adversarial embeddings", "corrupted documents", "injected content"],
        },
        {
            "rule_id": "RAG-VS-005",
            "title": "Missing Vector Store Encryption",
            "description": "Vector store data is not encrypted at rest",
            "severity": Severity.MEDIUM,
            "risk": 0,
            "variations": [],
        },
    ]

    def __init__(self, seed: int = 42):
        """Initialize with random seed for reproducibility."""
        self.seed = seed
        random.seed(seed)

    def generate(
        self,
        count: int = 1000,
        high_risk_ratio: float = 0.4,
        domains: Optional[List[str]] = None,
    ) -> Tuple[List[Finding], List[int]]:
        """Generate synthetic training data.

        Args:
            count: Number of findings to generate
            high_risk_ratio: Ratio of high-risk findings (0.0-1.0)
            domains: List of domains to include (None = all)

        Returns:
            Tuple of (findings, labels)
        """
        findings = []
        labels = []

        # Collect templates
        templates = []
        if domains is None or "mcp" in domains:
            templates.extend([(t, FindingDomain.MCP) for t in self.MCP_TEMPLATES])
        if domains is None or "aws" in domains:
            templates.extend([(t, FindingDomain.AWS) for t in self.AWS_TEMPLATES])
        if domains is None or "langchain" in domains:
            templates.extend([(t, FindingDomain.LANGCHAIN) for t in self.LANGCHAIN_TEMPLATES])
        if domains is None or "azure" in domains:
            templates.extend([(t, FindingDomain.AZURE) for t in self.AZURE_TEMPLATES])
        if domains is None or "terraform" in domains:
            templates.extend([(t, FindingDomain.TERRAFORM) for t in self.TERRAFORM_TEMPLATES])
        if domains is None or "openai" in domains:
            templates.extend([(t, FindingDomain.OPENAI) for t in self.OPENAI_TEMPLATES])
        if domains is None or "autogpt" in domains:
            templates.extend([(t, FindingDomain.AUTOGPT) for t in self.AUTOGPT_TEMPLATES])
        if domains is None or "multiagent" in domains:
            templates.extend([(t, FindingDomain.MCP) for t in self.MULTIAGENT_TEMPLATES])
        if domains is None or "rag" in domains:
            templates.extend([(t, FindingDomain.MCP) for t in self.RAG_TEMPLATES])

        if not templates:
            return [], []

        # Separate high and low risk templates
        high_risk_templates = [(t, d) for t, d in templates if t["risk"] == 1]
        low_risk_templates = [(t, d) for t, d in templates if t["risk"] == 0]

        # Generate findings
        high_risk_count = int(count * high_risk_ratio)
        low_risk_count = count - high_risk_count

        for _ in range(high_risk_count):
            if high_risk_templates:
                template, domain = random.choice(high_risk_templates)
                finding = self._generate_from_template(template, domain)
                findings.append(finding)
                labels.append(1)

        for _ in range(low_risk_count):
            if low_risk_templates:
                template, domain = random.choice(low_risk_templates)
                finding = self._generate_from_template(template, domain)
                findings.append(finding)
                labels.append(0)

        # Shuffle
        combined = list(zip(findings, labels))
        random.shuffle(combined)
        findings, labels = zip(*combined) if combined else ([], [])

        return list(findings), list(labels)

    def _generate_from_template(
        self,
        template: Dict[str, Any],
        domain: FindingDomain,
    ) -> Finding:
        """Generate a finding from a template."""
        variations = template.get("variations", [])

        # Fill in template variations
        description = template["description"]
        if variations:
            variation = random.choice(variations)
            if isinstance(variation, tuple):
                # Multiple placeholders
                for i, v in enumerate(variation):
                    placeholder = list(set(
                        p.strip("{}") for p in description.split()
                        if p.startswith("{") and p.endswith("}")
                    ))
                    if i < len(placeholder):
                        description = description.replace("{" + placeholder[i] + "}", v)
            else:
                # Single placeholder - find and replace
                import re
                placeholders = re.findall(r'\{(\w+)\}', description)
                if placeholders:
                    description = description.replace("{" + placeholders[0] + "}", str(variation))

        # Generate random file path
        file_paths = [
            "/app/config/mcp.json",
            "/home/user/.mcp/config.json",
            "/etc/mcp/servers.json",
            "./mcp.json",
            "/app/terraform/main.tf",
            "/infra/aws/iam.tf",
        ]

        return Finding(
            rule_id=template["rule_id"],
            domain=domain,
            title=template["title"],
            description=description,
            severity=template["severity"],
            location=Location(
                file_path=random.choice(file_paths),
                line_number=random.randint(1, 100),
            ),
            remediation=f"Fix the {template['title'].lower()} issue",
            cwe_id=f"CWE-{random.randint(1, 999)}" if random.random() > 0.3 else None,
            owasp_id=f"LLM{random.randint(1, 10):02d}" if random.random() > 0.4 else None,
        )


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
        """Perform cross-validation using the actual ensemble model.

        Uses KFold to train an EnsembleModel on each fold, collecting
        predictions and computing metrics that reflect the production
        model architecture (RF + GradientBoosting + LogisticRegression).
        """
        self._ensure_deps()
        np = self._np

        from sklearn.model_selection import KFold
        from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

        X, y, feature_names = self.prepare_data(findings)

        kf = KFold(n_splits=folds, shuffle=True, random_state=42)

        accuracy_scores = []
        f1_scores = []
        roc_auc_scores = []

        for train_idx, val_idx in kf.split(X):
            X_train, X_val = X[train_idx], X[val_idx]
            y_train, y_val = y[train_idx], y[val_idx]

            # Train ensemble model on this fold
            model = EnsembleModel()
            model.fit(X_train, y_train, feature_names)

            # Get predictions
            y_pred = []
            y_proba = []
            for x in X_val:
                features_dict = dict(zip(feature_names, x))
                pred = model.predict(features_dict)
                y_pred.append(1 if pred.risk_score >= 0.5 else 0)
                y_proba.append(pred.risk_score)

            y_pred = np.array(y_pred)
            y_proba = np.array(y_proba)

            accuracy_scores.append(accuracy_score(y_val, y_pred))
            f1_scores.append(f1_score(y_val, y_pred, average="weighted"))
            if len(np.unique(y_val)) > 1:
                roc_auc_scores.append(roc_auc_score(y_val, y_proba))

        return {
            "accuracy_mean": float(np.mean(accuracy_scores)),
            "accuracy_std": float(np.std(accuracy_scores)),
            "f1_mean": float(np.mean(f1_scores)),
            "f1_std": float(np.std(f1_scores)),
            "roc_auc_mean": float(np.mean(roc_auc_scores)) if roc_auc_scores else 0.0,
            "roc_auc_std": float(np.std(roc_auc_scores)) if roc_auc_scores else 0.0,
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

    def load_model(self, model_path: Path) -> EnsembleModel:
        """Load a trained model from disk.

        Args:
            model_path: Path to the saved model file

        Returns:
            Loaded EnsembleModel instance
        """
        model = EnsembleModel()
        model.load(model_path)
        logger.info(f"Model loaded from {model_path}")
        return model

    def train_from_synthetic(
        self,
        sample_count: int = 1000,
        high_risk_ratio: float = 0.4,
        validation_split: float = 0.2,
    ) -> TrainingResult:
        """Train model using synthetic data.

        Useful for bootstrapping when no labeled data is available.

        Args:
            sample_count: Number of synthetic samples to generate
            high_risk_ratio: Ratio of high-risk samples
            validation_split: Validation set ratio

        Returns:
            TrainingResult with model and metrics
        """
        logger.info(f"Generating {sample_count} synthetic training samples")

        generator = SyntheticDataGenerator()
        findings, labels = generator.generate(
            count=sample_count,
            high_risk_ratio=high_risk_ratio,
        )

        # Convert labels to findings with risk scores
        for finding, label in zip(findings, labels):
            finding.risk_score = float(label)

        return self.train(findings, validation_split=validation_split)

    def evaluate(
        self,
        findings: List[Finding],
        model_path: Optional[Path] = None,
    ) -> EvaluationReport:
        """Evaluate a trained model on test data.

        Args:
            findings: Test findings with known risk labels
            model_path: Path to model to evaluate (uses latest if None)

        Returns:
            EvaluationReport with detailed metrics
        """
        self._ensure_deps()
        np = self._np

        from sklearn.metrics import (
            accuracy_score,
            precision_score,
            recall_score,
            f1_score,
            roc_auc_score,
            confusion_matrix,
            classification_report,
        )

        # Load model
        model = EnsembleModel()
        if model_path:
            model.load(model_path)
        else:
            default_path = self.output_dir / f"{self.model_name}.pkl"
            if default_path.exists():
                model.load(default_path)
            else:
                raise ValueError("No model found to evaluate")

        # Prepare data
        X, y_true, feature_names = self.prepare_data(findings)

        # Get predictions
        y_pred = []
        y_proba = []
        for x in X:
            features_dict = dict(zip(feature_names, x))
            pred = model.predict(features_dict)
            y_pred.append(1 if pred.risk_score >= 0.5 else 0)
            y_proba.append(pred.risk_score)

        y_pred = np.array(y_pred)
        y_proba = np.array(y_proba)

        # Calculate metrics
        report = EvaluationReport(
            accuracy=float(accuracy_score(y_true, y_pred)),
            precision=float(precision_score(y_true, y_pred, average="weighted", zero_division=0)),
            recall=float(recall_score(y_true, y_pred, average="weighted", zero_division=0)),
            f1_score=float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
            auc_roc=float(roc_auc_score(y_true, y_proba)) if len(np.unique(y_true)) > 1 else 0.0,
            confusion_matrix=confusion_matrix(y_true, y_pred).tolist(),
            classification_report=classification_report(y_true, y_pred, zero_division=0),
            feature_importance=model.get_feature_importance(),
            generated_at=datetime.utcnow().isoformat(),
        )

        return report

    def tune_hyperparameters(
        self,
        findings: List[Finding],
        param_grids: Optional[Dict[str, Dict[str, List[Any]]]] = None,
        cv_folds: int = 5,
    ) -> Dict[str, Any]:
        """Tune hyperparameters for each model in the ensemble separately.

        Runs GridSearchCV for RandomForest, GradientBoosting, and
        LogisticRegression with their respective parameter grids.

        Args:
            findings: Training findings
            param_grids: Dict of model_name -> param_grid (uses defaults if None)
            cv_folds: Number of cross-validation folds

        Returns:
            Dictionary with best parameters per model and scores
        """
        self._ensure_deps()
        np = self._np

        from sklearn.model_selection import GridSearchCV
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline

        # Prepare data
        X, y, feature_names = self.prepare_data(findings)

        # Default parameter grids per model
        if param_grids is None:
            param_grids = {
                "random_forest": {
                    "model__n_estimators": [50, 100, 200],
                    "model__max_depth": [5, 10, 15],
                    "model__min_samples_split": [2, 5, 10],
                },
                "gradient_boosting": {
                    "model__n_estimators": [50, 100, 200],
                    "model__max_depth": [3, 5, 7],
                    "model__learning_rate": [0.01, 0.1, 0.2],
                },
                "logistic_regression": {
                    "model__C": [0.1, 1.0, 10.0],
                    "model__max_iter": [500, 1000],
                },
            }

        models = {
            "random_forest": RandomForestClassifier(random_state=42),
            "gradient_boosting": GradientBoostingClassifier(random_state=42),
            "logistic_regression": LogisticRegression(random_state=42),
        }

        results = {}
        for model_name, model in models.items():
            if model_name not in param_grids:
                continue

            pipeline = Pipeline([
                ("scaler", StandardScaler()),
                ("model", model),
            ])

            grid_search = GridSearchCV(
                pipeline,
                param_grids[model_name],
                cv=cv_folds,
                scoring="f1_weighted",
                n_jobs=-1,
            )

            logger.info(f"Tuning {model_name}...")
            grid_search.fit(X, y)

            # Strip 'model__' prefix from param names for cleaner output
            best_params = {
                k.replace("model__", ""): v
                for k, v in grid_search.best_params_.items()
            }

            results[model_name] = {
                "best_params": best_params,
                "best_score": float(grid_search.best_score_),
            }
            logger.info(f"{model_name} best params: {best_params}, score: {grid_search.best_score_:.4f}")

        return results

    def export_model_info(self, output_path: Optional[Path] = None) -> Dict[str, Any]:
        """Export model information for documentation.

        Args:
            output_path: Path to write JSON file (optional)

        Returns:
            Model information dictionary
        """
        model_path = self.output_dir / f"{self.model_name}.pkl"

        info = {
            "model_name": self.model_name,
            "model_path": str(model_path),
            "model_exists": model_path.exists(),
            "feature_extractors": [
                type(e).__name__ for e in self.feature_extractor.extractors
            ],
            "feature_names": self.feature_extractor.feature_names,
            "created_at": datetime.utcnow().isoformat(),
        }

        if model_path.exists():
            try:
                model = EnsembleModel()
                model.load(model_path)
                info["feature_importance"] = model.get_feature_importance()
            except Exception as e:
                info["load_error"] = str(e)

        if output_path:
            output_path = Path(output_path)
            output_path.write_text(json.dumps(info, indent=2))
            logger.info(f"Model info exported to {output_path}")

        return info
