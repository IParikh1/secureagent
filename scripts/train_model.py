#!/usr/bin/env python3
"""Train the SecureAgent ML risk model with synthetic data."""

import sys
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import random
from typing import List

from secureagent.core.models.finding import Finding, Location, FindingDomain
from secureagent.core.models.severity import Severity
from secureagent.ml.trainer import ModelTrainer


def generate_synthetic_findings(n_samples: int = 1000) -> List[Finding]:
    """Generate synthetic security findings for training."""
    findings = []

    # Define realistic finding patterns
    finding_patterns = [
        # Critical findings - credential exposure
        {
            "rule_id": "MCP-001",
            "domain": FindingDomain.MCP,
            "title": "Hardcoded API Key in Configuration",
            "description": "API key is hardcoded in the MCP server configuration.",
            "severity": Severity.CRITICAL,
            "cwe_id": "CWE-798",
            "owasp_id": "LLM06",
            "remediation": "Use environment variables or a secrets manager.",
            "risk_score": 0.95,
        },
        {
            "rule_id": "AWS-IAM-001",
            "domain": FindingDomain.AWS,
            "title": "AWS Credentials in Environment",
            "description": "AWS access keys found in environment variables.",
            "severity": Severity.CRITICAL,
            "cwe_id": "CWE-798",
            "owasp_id": None,
            "remediation": "Use IAM roles instead of hardcoded credentials.",
            "risk_score": 0.92,
        },
        {
            "rule_id": "LC-001",
            "domain": FindingDomain.LANGCHAIN,
            "title": "Exposed OpenAI API Key",
            "description": "OpenAI API key found in LangChain configuration.",
            "severity": Severity.CRITICAL,
            "cwe_id": "CWE-798",
            "owasp_id": "LLM06",
            "remediation": "Store API keys in environment variables.",
            "risk_score": 0.90,
        },
        # Critical findings - command injection
        {
            "rule_id": "MCP-002",
            "domain": FindingDomain.MCP,
            "title": "Shell Command Injection Risk",
            "description": "MCP server has shell access without input sanitization.",
            "severity": Severity.CRITICAL,
            "cwe_id": "CWE-78",
            "owasp_id": "LLM03",
            "remediation": "Add input validation and sandboxing.",
            "risk_score": 0.88,
        },
        {
            "rule_id": "LC-002",
            "domain": FindingDomain.LANGCHAIN,
            "title": "Unrestricted Shell Tool",
            "description": "LangChain agent has unrestricted ShellTool access.",
            "severity": Severity.CRITICAL,
            "cwe_id": "CWE-78",
            "owasp_id": "LLM03",
            "remediation": "Remove ShellTool or add strict sandboxing.",
            "risk_score": 0.91,
        },
        # High findings - data exposure
        {
            "rule_id": "AWS-S3-001",
            "domain": FindingDomain.AWS,
            "title": "Public S3 Bucket",
            "description": "S3 bucket allows public access.",
            "severity": Severity.HIGH,
            "cwe_id": "CWE-732",
            "owasp_id": None,
            "remediation": "Configure bucket ACLs to restrict access.",
            "risk_score": 0.75,
        },
        {
            "rule_id": "TF-001",
            "domain": FindingDomain.TERRAFORM,
            "title": "Public S3 Bucket in Terraform",
            "description": "Terraform configuration creates public S3 bucket.",
            "severity": Severity.HIGH,
            "cwe_id": "CWE-732",
            "owasp_id": None,
            "remediation": "Set acl to private.",
            "risk_score": 0.72,
        },
        {
            "rule_id": "MCP-003",
            "domain": FindingDomain.MCP,
            "title": "Unrestricted File Access",
            "description": "MCP server can access files without path restrictions.",
            "severity": Severity.HIGH,
            "cwe_id": "CWE-22",
            "owasp_id": "LLM03",
            "remediation": "Implement path validation and sandboxing.",
            "risk_score": 0.78,
        },
        {
            "rule_id": "OPENAI-001",
            "domain": FindingDomain.OPENAI,
            "title": "Code Interpreter Enabled",
            "description": "OpenAI Assistant has code_interpreter tool enabled.",
            "severity": Severity.HIGH,
            "cwe_id": "CWE-94",
            "owasp_id": "LLM03",
            "remediation": "Disable code_interpreter if not required.",
            "risk_score": 0.70,
        },
        # Medium findings
        {
            "rule_id": "AWS-EC2-001",
            "domain": FindingDomain.AWS,
            "title": "Open Security Group",
            "description": "Security group allows unrestricted SSH access.",
            "severity": Severity.MEDIUM,
            "cwe_id": "CWE-732",
            "owasp_id": None,
            "remediation": "Restrict CIDR blocks to known IPs.",
            "risk_score": 0.55,
        },
        {
            "rule_id": "TF-002",
            "domain": FindingDomain.TERRAFORM,
            "title": "Missing S3 Encryption",
            "description": "S3 bucket lacks server-side encryption.",
            "severity": Severity.MEDIUM,
            "cwe_id": "CWE-311",
            "owasp_id": None,
            "remediation": "Enable default encryption.",
            "risk_score": 0.50,
        },
        {
            "rule_id": "MCP-004",
            "domain": FindingDomain.MCP,
            "title": "Missing Rate Limiting",
            "description": "MCP server lacks rate limiting configuration.",
            "severity": Severity.MEDIUM,
            "cwe_id": "CWE-770",
            "owasp_id": "LLM04",
            "remediation": "Implement rate limiting.",
            "risk_score": 0.45,
        },
        {
            "rule_id": "LC-003",
            "domain": FindingDomain.LANGCHAIN,
            "title": "Verbose Logging Enabled",
            "description": "LangChain agent has verbose logging which may expose data.",
            "severity": Severity.MEDIUM,
            "cwe_id": "CWE-532",
            "owasp_id": "LLM06",
            "remediation": "Disable verbose logging in production.",
            "risk_score": 0.40,
        },
        # Low findings
        {
            "rule_id": "AWS-S3-002",
            "domain": FindingDomain.AWS,
            "title": "Missing S3 Versioning",
            "description": "S3 bucket versioning is not enabled.",
            "severity": Severity.LOW,
            "cwe_id": None,
            "owasp_id": None,
            "remediation": "Enable versioning for data protection.",
            "risk_score": 0.25,
        },
        {
            "rule_id": "MCP-005",
            "domain": FindingDomain.MCP,
            "title": "Debug Mode Enabled",
            "description": "MCP server running in debug mode.",
            "severity": Severity.LOW,
            "cwe_id": "CWE-489",
            "owasp_id": None,
            "remediation": "Disable debug mode in production.",
            "risk_score": 0.20,
        },
        {
            "rule_id": "TF-003",
            "domain": FindingDomain.TERRAFORM,
            "title": "Missing Tags",
            "description": "Terraform resource missing required tags.",
            "severity": Severity.LOW,
            "cwe_id": None,
            "owasp_id": None,
            "remediation": "Add required tags for resource tracking.",
            "risk_score": 0.15,
        },
        # Info findings
        {
            "rule_id": "MCP-006",
            "domain": FindingDomain.MCP,
            "title": "Configuration Best Practice",
            "description": "MCP configuration could benefit from improvements.",
            "severity": Severity.INFO,
            "cwe_id": None,
            "owasp_id": None,
            "remediation": "Review MCP best practices documentation.",
            "risk_score": 0.05,
        },
        {
            "rule_id": "AWS-INFO-001",
            "domain": FindingDomain.AWS,
            "title": "Resource Naming Convention",
            "description": "AWS resource does not follow naming convention.",
            "severity": Severity.INFO,
            "cwe_id": None,
            "owasp_id": None,
            "remediation": "Follow organization naming conventions.",
            "risk_score": 0.03,
        },
    ]

    for i in range(n_samples):
        # Select a pattern with some variation
        pattern = random.choice(finding_patterns)

        # Add some noise to risk score
        risk_noise = random.uniform(-0.1, 0.1)
        risk_score = max(0.0, min(1.0, pattern["risk_score"] + risk_noise))

        finding = Finding(
            id=f"finding-{i:04d}",
            rule_id=pattern["rule_id"],
            domain=pattern["domain"],
            title=pattern["title"],
            description=pattern["description"],
            severity=pattern["severity"],
            location=Location(
                file_path=f"/path/to/config-{i % 10}.json",
                line_number=random.randint(1, 100),
            ),
            remediation=pattern["remediation"],
            cwe_id=pattern.get("cwe_id"),
            owasp_id=pattern.get("owasp_id"),
            risk_score=risk_score,
        )
        findings.append(finding)

    return findings


def main():
    """Train and save the ML model."""
    print("=" * 60)
    print("SecureAgent ML Model Training")
    print("=" * 60)

    # Generate synthetic training data
    print("\n[1/4] Generating synthetic training data...")
    findings = generate_synthetic_findings(n_samples=2000)

    # Count severity distribution
    severity_counts = {}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"  Generated {len(findings)} findings:")
    for sev, count in sorted(severity_counts.items()):
        print(f"    - {sev}: {count}")

    # Initialize trainer
    print("\n[2/4] Initializing model trainer...")
    output_dir = Path(__file__).parent.parent / "models"
    trainer = ModelTrainer(
        output_dir=output_dir,
        model_name="secureagent_risk_v1",
    )

    # Cross-validate
    print("\n[3/4] Cross-validating model...")
    cv_results = trainer.cross_validate(findings, folds=5)
    print(f"  Cross-validation results:")
    print(f"    - Accuracy: {cv_results['accuracy_mean']:.4f} (+/- {cv_results['accuracy_std']:.4f})")
    print(f"    - F1 Score: {cv_results['f1_mean']:.4f} (+/- {cv_results['f1_std']:.4f})")
    print(f"    - ROC AUC:  {cv_results['roc_auc_mean']:.4f} (+/- {cv_results['roc_auc_std']:.4f})")

    # Train final model
    print("\n[4/4] Training final model...")
    result = trainer.train(findings, validation_split=0.2)

    print(f"\n  Model training complete!")
    print(f"  Metrics:")
    print(f"    - Accuracy:  {result.metrics.accuracy:.4f}")
    print(f"    - Precision: {result.metrics.precision:.4f}")
    print(f"    - Recall:    {result.metrics.recall:.4f}")
    print(f"    - F1 Score:  {result.metrics.f1_score:.4f}")

    print(f"\n  Top feature importances:")
    for feature, importance in list(result.feature_importance.items())[:10]:
        print(f"    - {feature}: {importance:.4f}")

    print(f"\n  Model saved to: {result.model_path}")
    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
