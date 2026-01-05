"""OWASP MCP Top 10 compliance framework."""

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class MCPControl:
    """MCP control definition."""

    id: str
    title: str
    description: str
    risk_summary: str
    prevention: List[str] = field(default_factory=list)
    related_cwe: List[str] = field(default_factory=list)


OWASP_MCP_TOP_10: Dict[str, MCPControl] = {
    "MCP01": MCPControl(
        id="MCP01",
        title="Server Spoofing",
        description="Attacker impersonates a legitimate MCP server to intercept or manipulate communications.",
        risk_summary="Compromised communications can lead to data theft or malicious command injection.",
        prevention=[
            "Implement server authentication",
            "Use TLS for all connections",
            "Verify server certificates",
            "Use allowlists for approved servers",
        ],
        related_cwe=["CWE-290", "CWE-295"],
    ),
    "MCP02": MCPControl(
        id="MCP02",
        title="Tool Poisoning",
        description="Malicious tools injected into MCP server configuration.",
        risk_summary="Poisoned tools can execute malicious code when invoked by agents.",
        prevention=[
            "Validate tool sources",
            "Implement tool signing",
            "Review tool capabilities",
            "Use allowlists for approved tools",
        ],
        related_cwe=["CWE-494", "CWE-829"],
    ),
    "MCP03": MCPControl(
        id="MCP03",
        title="Credential Exposure",
        description="API keys and secrets exposed in MCP configuration files.",
        risk_summary="Exposed credentials can be used for unauthorized access.",
        prevention=[
            "Use environment variables",
            "Never hardcode secrets",
            "Implement secret scanning",
            "Use secure secret management",
        ],
        related_cwe=["CWE-798", "CWE-312"],
    ),
    "MCP04": MCPControl(
        id="MCP04",
        title="Command Injection",
        description="Unsanitized inputs allow command injection through MCP tools.",
        risk_summary="Attackers can execute arbitrary commands on the host system.",
        prevention=[
            "Validate all inputs",
            "Use parameterized commands",
            "Implement command allowlists",
            "Sandbox command execution",
        ],
        related_cwe=["CWE-78", "CWE-77"],
    ),
    "MCP05": MCPControl(
        id="MCP05",
        title="Insufficient Access Control",
        description="MCP servers without proper authentication or authorization.",
        risk_summary="Unauthorized users can access sensitive tools and data.",
        prevention=[
            "Implement authentication",
            "Use OAuth 2.0 or API keys",
            "Apply role-based access control",
            "Log all access attempts",
        ],
        related_cwe=["CWE-306", "CWE-284"],
    ),
    "MCP06": MCPControl(
        id="MCP06",
        title="Insecure Transport",
        description="MCP communications over unencrypted channels.",
        risk_summary="Data in transit can be intercepted and modified.",
        prevention=[
            "Use TLS for all connections",
            "Verify certificate chains",
            "Disable insecure protocols",
            "Implement certificate pinning",
        ],
        related_cwe=["CWE-319", "CWE-295"],
    ),
    "MCP07": MCPControl(
        id="MCP07",
        title="Path Traversal",
        description="MCP tools accessing files outside allowed directories.",
        risk_summary="Attackers can read or write sensitive files.",
        prevention=[
            "Validate file paths",
            "Use path canonicalization",
            "Implement directory jails",
            "Apply file access controls",
        ],
        related_cwe=["CWE-22", "CWE-73"],
    ),
    "MCP08": MCPControl(
        id="MCP08",
        title="Overprivileged Tools",
        description="MCP tools with excessive capabilities beyond requirements.",
        risk_summary="Compromised tools can cause extensive damage.",
        prevention=[
            "Apply least privilege",
            "Review tool permissions",
            "Implement capability-based security",
            "Sandbox dangerous tools",
        ],
        related_cwe=["CWE-250", "CWE-732"],
    ),
    "MCP09": MCPControl(
        id="MCP09",
        title="SSRF via MCP",
        description="MCP servers making requests to internal resources.",
        risk_summary="Attackers can access internal services and cloud metadata.",
        prevention=[
            "Implement URL allowlists",
            "Block private IP ranges",
            "Validate request destinations",
            "Monitor outbound requests",
        ],
        related_cwe=["CWE-918"],
    ),
    "MCP10": MCPControl(
        id="MCP10",
        title="Logging and Monitoring Gaps",
        description="Insufficient logging of MCP tool invocations and errors.",
        risk_summary="Security incidents may go undetected.",
        prevention=[
            "Log all tool invocations",
            "Implement centralized logging",
            "Set up alerting",
            "Retain logs for analysis",
        ],
        related_cwe=["CWE-778", "CWE-223"],
    ),
}


def get_control(control_id: str) -> MCPControl:
    """Get OWASP MCP control by ID."""
    return OWASP_MCP_TOP_10.get(control_id)


def get_all_controls() -> List[MCPControl]:
    """Get all OWASP MCP controls."""
    return list(OWASP_MCP_TOP_10.values())
