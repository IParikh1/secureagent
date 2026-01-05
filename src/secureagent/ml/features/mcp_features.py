"""MCP-specific feature extractor for SecureAgent ML."""

from typing import Dict, List

from ...core.models.finding import Finding
from .base import FeatureExtractor


class MCPFeatureExtractor(FeatureExtractor):
    """Extract MCP-specific features from findings."""

    # MCP rule categories
    MCP_CATEGORIES = {
        "credential": ["MCP-001", "MCP-005"],
        "injection": ["MCP-002"],
        "traversal": ["MCP-003"],
        "ssrf": ["MCP-004"],
        "auth": ["MCP-006"],
        "permission": ["MCP-007"],
    }

    # High-risk MCP tool patterns
    HIGH_RISK_TOOLS = [
        "bash", "shell", "exec", "run_command", "execute",
        "file_write", "file_delete", "rm", "delete",
        "sql", "database", "query",
        "http", "fetch", "request", "curl", "wget",
    ]

    # Sensitive environment variable patterns
    SENSITIVE_ENV_PATTERNS = [
        "api_key", "secret", "password", "token", "credential",
        "private_key", "auth", "bearer", "jwt",
    ]

    def extract(self, finding: Finding) -> Dict[str, float]:
        """Extract MCP features from finding."""
        features = {
            "is_mcp_finding": 0.0,
            "mcp_credential_risk": 0.0,
            "mcp_injection_risk": 0.0,
            "mcp_traversal_risk": 0.0,
            "mcp_ssrf_risk": 0.0,
            "mcp_auth_risk": 0.0,
            "mcp_permission_risk": 0.0,
            "mcp_high_risk_tool": 0.0,
            "mcp_sensitive_env": 0.0,
            "mcp_server_count": 0.0,
            "mcp_tool_count": 0.0,
        }

        # Check if this is an MCP finding
        if not finding.rule_id.startswith("MCP"):
            return features

        features["is_mcp_finding"] = 1.0

        # Categorize by rule
        for category, rules in self.MCP_CATEGORIES.items():
            if finding.rule_id in rules:
                features[f"mcp_{category}_risk"] = 1.0

        # Check for high-risk tool patterns
        text = f"{finding.title} {finding.description}".lower()
        for tool in self.HIGH_RISK_TOOLS:
            if tool in text:
                features["mcp_high_risk_tool"] = 1.0
                break

        # Check for sensitive environment patterns
        for pattern in self.SENSITIVE_ENV_PATTERNS:
            if pattern in text:
                features["mcp_sensitive_env"] = 1.0
                break

        # Extract counts from metadata
        if finding.metadata:
            if "server_count" in finding.metadata:
                features["mcp_server_count"] = min(
                    finding.metadata["server_count"] / 10, 1.0
                )
            if "tool_count" in finding.metadata:
                features["mcp_tool_count"] = min(
                    finding.metadata["tool_count"] / 20, 1.0
                )

        return features

    @property
    def feature_names(self) -> List[str]:
        """Get feature names."""
        return [
            "is_mcp_finding",
            "mcp_credential_risk",
            "mcp_injection_risk",
            "mcp_traversal_risk",
            "mcp_ssrf_risk",
            "mcp_auth_risk",
            "mcp_permission_risk",
            "mcp_high_risk_tool",
            "mcp_sensitive_env",
            "mcp_server_count",
            "mcp_tool_count",
        ]
