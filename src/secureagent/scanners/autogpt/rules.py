"""Security rules for AutoGPT/CrewAI scanner."""

from secureagent.core.models.severity import Severity

AUTOGPT_RULES = {
    "AG-001": {
        "id": "AG-001",
        "title": "Hardcoded API Keys",
        "severity": Severity.CRITICAL,
        "description": "Hardcoded API keys in agent configuration",
        "cwe_id": "CWE-798",
        "owasp_id": "LLM02",
        "references": [
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        "remediation": "Use environment variables or secure secret management.",
    },
    "AG-002": {
        "id": "AG-002",
        "title": "Unrestricted Agent Autonomy",
        "severity": Severity.HIGH,
        "description": "Agent configured with full autonomy without human oversight",
        "cwe_id": "CWE-284",
        "owasp_id": "LLM08",
        "references": [
            "https://docs.crewai.com/core-concepts/Agents/",
            "https://cwe.mitre.org/data/definitions/284.html",
        ],
        "remediation": "Implement human-in-the-loop controls for critical actions.",
    },
    "AG-003": {
        "id": "AG-003",
        "title": "Dangerous Tool Access",
        "severity": Severity.HIGH,
        "description": "Agent has access to shell, file system, or code execution tools",
        "cwe_id": "CWE-78",
        "owasp_id": "LLM05",
        "references": [
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
        "remediation": "Restrict tool access. Implement sandboxing and input validation.",
    },
    "AG-004": {
        "id": "AG-004",
        "title": "Inter-Agent Trust",
        "severity": Severity.MEDIUM,
        "description": "Agents configured to trust each other without validation",
        "cwe_id": "CWE-346",
        "owasp_id": "LLM08",
        "references": [
            "https://cwe.mitre.org/data/definitions/346.html",
        ],
        "remediation": "Implement message validation between agents.",
    },
    "AG-005": {
        "id": "AG-005",
        "title": "No Memory Limits",
        "severity": Severity.MEDIUM,
        "description": "Agent memory without size limits or cleanup policies",
        "cwe_id": "CWE-770",
        "owasp_id": "LLM04",
        "references": [
            "https://cwe.mitre.org/data/definitions/770.html",
        ],
        "remediation": "Set memory limits and implement periodic cleanup.",
    },
    "AG-006": {
        "id": "AG-006",
        "title": "Unconstrained Task Delegation",
        "severity": Severity.MEDIUM,
        "description": "Agent can delegate tasks without restrictions",
        "cwe_id": "CWE-863",
        "owasp_id": "LLM08",
        "references": [
            "https://docs.crewai.com/core-concepts/Tasks/",
            "https://cwe.mitre.org/data/definitions/863.html",
        ],
        "remediation": "Implement delegation policies and task approval workflows.",
    },
    "AG-007": {
        "id": "AG-007",
        "title": "Web Browsing Without Filters",
        "severity": Severity.MEDIUM,
        "description": "Agent has web browsing capability without URL filtering",
        "cwe_id": "CWE-918",
        "owasp_id": "LLM05",
        "references": [
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
        "remediation": "Implement URL allowlists and content filtering.",
    },
    "AG-008": {
        "id": "AG-008",
        "title": "Verbose Logging Enabled",
        "severity": Severity.LOW,
        "description": "Verbose logging may expose sensitive information",
        "cwe_id": "CWE-532",
        "owasp_id": "LLM02",
        "references": [
            "https://cwe.mitre.org/data/definitions/532.html",
        ],
        "remediation": "Disable verbose logging in production. Sanitize log output.",
    },
    "AG-009": {
        "id": "AG-009",
        "title": "No Iteration Limits",
        "severity": Severity.MEDIUM,
        "description": "Agent loops without maximum iteration limits",
        "cwe_id": "CWE-835",
        "owasp_id": "LLM04",
        "references": [
            "https://cwe.mitre.org/data/definitions/835.html",
        ],
        "remediation": "Set max_iterations and timeout limits on agents.",
    },
    "AG-010": {
        "id": "AG-010",
        "title": "External Data Without Validation",
        "severity": Severity.MEDIUM,
        "description": "Agent processes external data without sanitization",
        "cwe_id": "CWE-20",
        "owasp_id": "LLM03",
        "references": [
            "https://cwe.mitre.org/data/definitions/20.html",
        ],
        "remediation": "Validate and sanitize all external inputs before processing.",
    },
}


def get_rule(rule_id: str) -> dict:
    """Get rule definition by ID."""
    return AUTOGPT_RULES.get(rule_id, {})


def get_all_rules() -> list:
    """Get all rule definitions as a list."""
    return list(AUTOGPT_RULES.values())
