"""OWASP LLM Top 10 compliance framework."""

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class OWASPControl:
    """OWASP control definition."""

    id: str
    title: str
    description: str
    risk_summary: str
    prevention: List[str] = field(default_factory=list)
    related_cwe: List[str] = field(default_factory=list)


OWASP_LLM_TOP_10: Dict[str, OWASPControl] = {
    "LLM01": OWASPControl(
        id="LLM01",
        title="Prompt Injection",
        description="Manipulating LLMs via crafted inputs to override instructions or execute unintended actions.",
        risk_summary="Attackers can bypass safety measures, access sensitive data, or perform unauthorized actions.",
        prevention=[
            "Implement strict input validation",
            "Use parameterized prompts",
            "Apply principle of least privilege to LLM actions",
            "Implement human-in-the-loop for sensitive operations",
        ],
        related_cwe=["CWE-74", "CWE-20"],
    ),
    "LLM02": OWASPControl(
        id="LLM02",
        title="Insecure Output Handling",
        description="Trusting LLM outputs without validation, leading to XSS, SSRF, or code execution.",
        risk_summary="Unvalidated outputs can be exploited for injection attacks in downstream systems.",
        prevention=[
            "Treat LLM output as untrusted",
            "Apply output encoding/escaping",
            "Validate outputs before use",
            "Implement content security policies",
        ],
        related_cwe=["CWE-79", "CWE-918", "CWE-94"],
    ),
    "LLM03": OWASPControl(
        id="LLM03",
        title="Training Data Poisoning",
        description="Manipulation of training data or fine-tuning to introduce vulnerabilities.",
        risk_summary="Compromised training data can lead to biased, incorrect, or malicious model behavior.",
        prevention=[
            "Verify training data sources",
            "Implement data validation pipelines",
            "Monitor model behavior for anomalies",
            "Use secure fine-tuning practices",
        ],
        related_cwe=["CWE-20", "CWE-502"],
    ),
    "LLM04": OWASPControl(
        id="LLM04",
        title="Model Denial of Service",
        description="Resource-intensive operations causing service degradation or excessive costs.",
        risk_summary="Attackers can cause service outages or financial damage through resource exhaustion.",
        prevention=[
            "Implement rate limiting",
            "Set input size limits",
            "Monitor resource usage",
            "Implement cost controls",
        ],
        related_cwe=["CWE-400", "CWE-770"],
    ),
    "LLM05": OWASPControl(
        id="LLM05",
        title="Supply Chain Vulnerabilities",
        description="Vulnerabilities in third-party components, plugins, or pre-trained models.",
        risk_summary="Compromised dependencies can introduce backdoors or vulnerabilities.",
        prevention=[
            "Audit third-party components",
            "Verify model integrity",
            "Use pinned versions",
            "Implement security scanning",
        ],
        related_cwe=["CWE-829", "CWE-494"],
    ),
    "LLM06": OWASPControl(
        id="LLM06",
        title="Sensitive Information Disclosure",
        description="LLMs revealing sensitive information through responses.",
        risk_summary="Confidential data, PII, or system details can be leaked through model outputs.",
        prevention=[
            "Implement output filtering",
            "Train models to avoid sensitive data",
            "Use data classification",
            "Apply access controls",
        ],
        related_cwe=["CWE-200", "CWE-212"],
    ),
    "LLM07": OWASPControl(
        id="LLM07",
        title="Insecure Plugin Design",
        description="Plugins with excessive permissions or insufficient input validation.",
        risk_summary="Vulnerable plugins can be exploited to perform unauthorized actions.",
        prevention=[
            "Apply least privilege to plugins",
            "Validate plugin inputs",
            "Implement plugin sandboxing",
            "Review plugin permissions",
        ],
        related_cwe=["CWE-250", "CWE-732"],
    ),
    "LLM08": OWASPControl(
        id="LLM08",
        title="Excessive Agency",
        description="LLMs with too much autonomy performing harmful actions.",
        risk_summary="Over-privileged agents can cause damage without human oversight.",
        prevention=[
            "Limit agent capabilities",
            "Implement human-in-the-loop",
            "Apply action rate limiting",
            "Log all agent actions",
        ],
        related_cwe=["CWE-250", "CWE-284"],
    ),
    "LLM09": OWASPControl(
        id="LLM09",
        title="Overreliance",
        description="Trusting LLM outputs without verification.",
        risk_summary="Incorrect or misleading outputs can lead to poor decisions.",
        prevention=[
            "Implement human review",
            "Use confidence thresholds",
            "Verify critical outputs",
            "Provide uncertainty indicators",
        ],
        related_cwe=["CWE-1188"],
    ),
    "LLM10": OWASPControl(
        id="LLM10",
        title="Model Theft",
        description="Unauthorized access to or extraction of proprietary models.",
        risk_summary="Model theft can lead to IP loss and competitive disadvantage.",
        prevention=[
            "Implement access controls",
            "Monitor for extraction attempts",
            "Use model watermarking",
            "Limit API query rates",
        ],
        related_cwe=["CWE-284", "CWE-522"],
    ),
}


def get_control(control_id: str) -> OWASPControl:
    """Get OWASP LLM control by ID."""
    return OWASP_LLM_TOP_10.get(control_id)


def get_all_controls() -> List[OWASPControl]:
    """Get all OWASP LLM controls."""
    return list(OWASP_LLM_TOP_10.values())
