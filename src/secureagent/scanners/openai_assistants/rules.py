"""Security rules for OpenAI Assistants scanner."""

from secureagent.core.models.severity import Severity

OPENAI_RULES = {
    "OAI-001": {
        "id": "OAI-001",
        "title": "Hardcoded API Key",
        "severity": Severity.CRITICAL,
        "description": "OpenAI API key hardcoded in source code",
        "cwe_id": "CWE-798",
        "owasp_id": "LLM02",
        "references": [
            "https://platform.openai.com/docs/api-reference/authentication",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        "remediation": "Use environment variables (OPENAI_API_KEY) instead of hardcoding.",
    },
    "OAI-002": {
        "id": "OAI-002",
        "title": "Code Interpreter Enabled",
        "severity": Severity.HIGH,
        "description": "Assistant has code interpreter tool enabled allowing arbitrary code execution",
        "cwe_id": "CWE-94",
        "owasp_id": "LLM05",
        "references": [
            "https://platform.openai.com/docs/assistants/tools/code-interpreter",
            "https://cwe.mitre.org/data/definitions/94.html",
        ],
        "remediation": "Only enable code interpreter when necessary. Review assistant instructions for prompt injection risks.",
    },
    "OAI-003": {
        "id": "OAI-003",
        "title": "File Search on Sensitive Data",
        "severity": Severity.MEDIUM,
        "description": "Assistant has retrieval/file search enabled which may expose sensitive documents",
        "cwe_id": "CWE-200",
        "owasp_id": "LLM06",
        "references": [
            "https://platform.openai.com/docs/assistants/tools/file-search",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
        "remediation": "Review files attached to assistant. Ensure no sensitive data is exposed via retrieval.",
    },
    "OAI-004": {
        "id": "OAI-004",
        "title": "Function Calling Without Validation",
        "severity": Severity.HIGH,
        "description": "Function calling enabled without apparent input validation",
        "cwe_id": "CWE-20",
        "owasp_id": "LLM05",
        "references": [
            "https://platform.openai.com/docs/assistants/tools/function-calling",
            "https://cwe.mitre.org/data/definitions/20.html",
        ],
        "remediation": "Implement strict input validation for all function parameters before execution.",
    },
    "OAI-005": {
        "id": "OAI-005",
        "title": "Dangerous Function Definition",
        "severity": Severity.HIGH,
        "description": "Function with potentially dangerous capabilities (shell, file, network)",
        "cwe_id": "CWE-78",
        "owasp_id": "LLM05",
        "references": [
            "https://platform.openai.com/docs/guides/function-calling",
            "https://cwe.mitre.org/data/definitions/78.html",
        ],
        "remediation": "Restrict function capabilities. Implement strict sandboxing for dangerous operations.",
    },
    "OAI-006": {
        "id": "OAI-006",
        "title": "No Instructions Set",
        "severity": Severity.MEDIUM,
        "description": "Assistant created without system instructions",
        "cwe_id": "CWE-1188",
        "owasp_id": "LLM01",
        "references": [
            "https://platform.openai.com/docs/assistants/how-it-works",
        ],
        "remediation": "Set clear system instructions to define assistant behavior and boundaries.",
    },
    "OAI-007": {
        "id": "OAI-007",
        "title": "Verbose Error Handling",
        "severity": Severity.LOW,
        "description": "Error messages may expose internal details",
        "cwe_id": "CWE-209",
        "owasp_id": "LLM02",
        "references": [
            "https://cwe.mitre.org/data/definitions/209.html",
        ],
        "remediation": "Implement generic error messages that don't expose internal details.",
    },
    "OAI-008": {
        "id": "OAI-008",
        "title": "Thread Data Persistence",
        "severity": Severity.MEDIUM,
        "description": "Thread messages may persist sensitive conversation data",
        "cwe_id": "CWE-312",
        "owasp_id": "LLM02",
        "references": [
            "https://platform.openai.com/docs/assistants/how-it-works/managing-threads-and-messages",
            "https://cwe.mitre.org/data/definitions/312.html",
        ],
        "remediation": "Implement thread cleanup policies. Review data retention requirements.",
    },
}


def get_rule(rule_id: str) -> dict:
    """Get rule definition by ID."""
    return OPENAI_RULES.get(rule_id, {})


def get_all_rules() -> list:
    """Get all rule definitions as a list."""
    return list(OPENAI_RULES.values())
