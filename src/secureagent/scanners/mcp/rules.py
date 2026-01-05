"""Security rules for MCP scanner."""

from secureagent.core.models.severity import Severity

# Rule definitions with metadata for documentation and reporting
MCP_RULES = {
    "MCP-001": {
        "id": "MCP-001",
        "title": "No Authentication Configured",
        "severity": Severity.CRITICAL,
        "description": "Remote MCP server has no authentication configured",
        "cwe_id": "CWE-306",
        "owasp_id": "LLM06",
        "references": [
            "https://modelcontextprotocol.io/specification/draft/basic/security_best_practices",
            "https://cwe.mitre.org/data/definitions/306.html",
        ],
        "remediation": "Configure authentication for the MCP server using OAuth 2.0, API keys, or other mechanisms.",
    },
    "MCP-002": {
        "id": "MCP-002",
        "title": "Hardcoded Credentials",
        "severity": Severity.CRITICAL,
        "description": "Hardcoded API keys, tokens, or passwords in configuration",
        "cwe_id": "CWE-798",
        "owasp_id": "LLM02",
        "references": [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        "remediation": "Use environment variables instead of hardcoding credentials. Use ${VAR} syntax.",
    },
    "MCP-003": {
        "id": "MCP-003",
        "title": "Command Injection Risk",
        "severity": Severity.HIGH,
        "description": "Shell metacharacters or command chaining in server configuration",
        "cwe_id": "CWE-78",
        "owasp_id": "LLM05",
        "references": [
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://owasp.org/www-community/attacks/Command_Injection",
        ],
        "remediation": "Avoid shell metacharacters in commands. Use parameterized arguments and validate inputs.",
    },
    "MCP-004": {
        "id": "MCP-004",
        "title": "SSRF Risk",
        "severity": Severity.HIGH,
        "description": "Internal or private URLs that could enable SSRF attacks",
        "cwe_id": "CWE-918",
        "owasp_id": "LLM05",
        "references": [
            "https://cwe.mitre.org/data/definitions/918.html",
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        ],
        "remediation": "Avoid hardcoding internal URLs. Use allowlists for permitted URLs.",
    },
    "MCP-005": {
        "id": "MCP-005",
        "title": "Path Traversal",
        "severity": Severity.MEDIUM,
        "description": "Path traversal sequences or absolute paths outside safe directories",
        "cwe_id": "CWE-22",
        "owasp_id": "LLM05",
        "references": [
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
        "remediation": "Use relative paths within allowed directories. Implement path validation.",
    },
    "MCP-006": {
        "id": "MCP-006",
        "title": "Sensitive Data Exposure",
        "severity": Severity.HIGH,
        "description": "Sensitive environment variables with hardcoded values",
        "cwe_id": "CWE-312",
        "owasp_id": "LLM02",
        "references": [
            "https://cwe.mitre.org/data/definitions/312.html",
        ],
        "remediation": "Use environment variable references instead of hardcoded values.",
    },
    "MCP-007": {
        "id": "MCP-007",
        "title": "Dangerous Tool Configuration",
        "severity": Severity.MEDIUM,
        "description": "Tools with potentially dangerous capabilities (shell, exec, etc.)",
        "cwe_id": "CWE-250",
        "owasp_id": "LLM06",
        "references": [
            "https://modelcontextprotocol.io/specification/draft/basic/security_best_practices",
            "https://cwe.mitre.org/data/definitions/250.html",
        ],
        "remediation": "Ensure dangerous tools are properly sandboxed. Implement input validation and principle of least privilege.",
    },
}


def get_rule(rule_id: str) -> dict:
    """Get rule definition by ID."""
    return MCP_RULES.get(rule_id, {})


def get_all_rules() -> list:
    """Get all rule definitions as a list."""
    return list(MCP_RULES.values())
