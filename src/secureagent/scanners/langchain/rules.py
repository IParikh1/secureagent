"""Security rules for LangChain scanner."""

from secureagent.core.models.severity import Severity

LANGCHAIN_RULES = {
    "LC-001": {
        "id": "LC-001",
        "title": "Hardcoded API Keys",
        "severity": Severity.CRITICAL,
        "description": "Hardcoded API keys in LangChain configuration or code",
        "cwe_id": "CWE-798",
        "owasp_id": "LLM02",
        "references": [
            "https://python.langchain.com/docs/security",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        "remediation": "Use environment variables or secure secret management for API keys.",
    },
    "LC-002": {
        "id": "LC-002",
        "title": "Unsafe Tool Configuration",
        "severity": Severity.HIGH,
        "description": "Tools with shell execution or file system access without restrictions",
        "cwe_id": "CWE-78",
        "owasp_id": "LLM05",
        "references": [
            "https://python.langchain.com/docs/security",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
        "remediation": "Restrict tool capabilities and implement input validation.",
    },
    "LC-003": {
        "id": "LC-003",
        "title": "Prompt Injection Vulnerability",
        "severity": Severity.HIGH,
        "description": "User input directly concatenated into prompts without sanitization",
        "cwe_id": "CWE-74",
        "owasp_id": "LLM01",
        "references": [
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "https://cwe.mitre.org/data/definitions/74.html",
        ],
        "remediation": "Use parameterized prompts and input validation.",
    },
    "LC-004": {
        "id": "LC-004",
        "title": "Insecure Memory Configuration",
        "severity": Severity.MEDIUM,
        "description": "Agent memory storing sensitive data without encryption",
        "cwe_id": "CWE-312",
        "owasp_id": "LLM02",
        "references": [
            "https://python.langchain.com/docs/modules/memory/",
            "https://cwe.mitre.org/data/definitions/312.html",
        ],
        "remediation": "Use encrypted memory backends for sensitive conversations.",
    },
    "LC-005": {
        "id": "LC-005",
        "title": "Unrestricted Agent Loops",
        "severity": Severity.MEDIUM,
        "description": "Agent configured without iteration limits allowing infinite loops",
        "cwe_id": "CWE-835",
        "owasp_id": "LLM04",
        "references": [
            "https://python.langchain.com/docs/modules/agents/",
            "https://cwe.mitre.org/data/definitions/835.html",
        ],
        "remediation": "Set max_iterations and max_execution_time on agents.",
    },
    "LC-006": {
        "id": "LC-006",
        "title": "Unsafe Python Execution",
        "severity": Severity.CRITICAL,
        "description": "PythonREPL or exec() used without sandboxing",
        "cwe_id": "CWE-94",
        "owasp_id": "LLM05",
        "references": [
            "https://python.langchain.com/docs/security",
            "https://cwe.mitre.org/data/definitions/94.html",
        ],
        "remediation": "Use sandboxed execution environments or remove Python execution tools.",
    },
    "LC-007": {
        "id": "LC-007",
        "title": "SQL Injection Risk",
        "severity": Severity.HIGH,
        "description": "SQL queries constructed with user input without parameterization",
        "cwe_id": "CWE-89",
        "owasp_id": "LLM05",
        "references": [
            "https://python.langchain.com/docs/modules/chains/popular/sqlite",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
        "remediation": "Use parameterized queries and restrict database permissions.",
    },
    "LC-008": {
        "id": "LC-008",
        "title": "Verbose Error Exposure",
        "severity": Severity.LOW,
        "description": "Verbose mode enabled exposing internal prompts and errors",
        "cwe_id": "CWE-209",
        "owasp_id": "LLM02",
        "references": [
            "https://cwe.mitre.org/data/definitions/209.html",
        ],
        "remediation": "Disable verbose mode in production environments.",
    },
    "LC-009": {
        "id": "LC-009",
        "title": "Unsafe Web Browsing",
        "severity": Severity.MEDIUM,
        "description": "Web browsing tool without URL filtering or content restrictions",
        "cwe_id": "CWE-918",
        "owasp_id": "LLM05",
        "references": [
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
        "remediation": "Implement URL allowlists and content filtering for web tools.",
    },
    "LC-010": {
        "id": "LC-010",
        "title": "Unvalidated External Data",
        "severity": Severity.MEDIUM,
        "description": "External data sources loaded without validation",
        "cwe_id": "CWE-20",
        "owasp_id": "LLM03",
        "references": [
            "https://cwe.mitre.org/data/definitions/20.html",
        ],
        "remediation": "Validate and sanitize all external data before use.",
    },
}


def get_rule(rule_id: str) -> dict:
    """Get rule definition by ID."""
    return LANGCHAIN_RULES.get(rule_id, {})


def get_all_rules() -> list:
    """Get all rule definitions as a list."""
    return list(LANGCHAIN_RULES.values())
