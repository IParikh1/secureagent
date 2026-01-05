"""AI Agent-specific feature extractor for SecureAgent ML."""

from typing import Dict, List

from ...core.models.finding import Finding
from .base import FeatureExtractor


class AgentFeatureExtractor(FeatureExtractor):
    """Extract AI agent-specific features from findings."""

    # Agent framework prefixes
    AGENT_PREFIXES = ["LC", "OAI", "AG"]

    # Dangerous capabilities
    DANGEROUS_CAPABILITIES = [
        "shell", "bash", "command", "exec", "system",
        "file_write", "file_delete", "code_execution",
        "python_repl", "sql_execute", "eval",
    ]

    # Agent framework patterns
    FRAMEWORK_PATTERNS = {
        "langchain": ["langchain", "agent", "chain", "tool", "callback"],
        "openai": ["openai", "assistant", "function_calling", "code_interpreter"],
        "autogpt": ["autogpt", "crewai", "autonomous", "multi-agent"],
    }

    # Risk indicators
    RISK_INDICATORS = {
        "high_autonomy": ["autonomous", "unlimited", "no_limit", "unrestricted"],
        "memory_risk": ["memory", "context", "persistent", "vector_store"],
        "delegation": ["delegate", "sub-agent", "inter-agent", "trust"],
        "external_access": ["http", "api", "web", "fetch", "request"],
    }

    def extract(self, finding: Finding) -> Dict[str, float]:
        """Extract AI agent features from finding."""
        features = {
            "is_agent_finding": 0.0,
            "is_langchain": 0.0,
            "is_openai_assistant": 0.0,
            "is_autogpt_crewai": 0.0,
            "agent_dangerous_capability": 0.0,
            "agent_high_autonomy": 0.0,
            "agent_memory_risk": 0.0,
            "agent_delegation_risk": 0.0,
            "agent_external_access": 0.0,
            "agent_prompt_injection": 0.0,
            "agent_excessive_agency": 0.0,
            "agent_tool_count": 0.0,
        }

        # Check if this is an agent finding
        rule_prefix = finding.rule_id.split("-")[0] if "-" in finding.rule_id else ""
        if rule_prefix not in self.AGENT_PREFIXES:
            return features

        features["is_agent_finding"] = 1.0

        # Identify framework
        text = f"{finding.rule_id} {finding.title} {finding.description}".lower()

        if rule_prefix == "LC" or "langchain" in text:
            features["is_langchain"] = 1.0
        elif rule_prefix == "OAI" or "openai" in text or "assistant" in text:
            features["is_openai_assistant"] = 1.0
        elif rule_prefix == "AG" or any(p in text for p in ["autogpt", "crewai"]):
            features["is_autogpt_crewai"] = 1.0

        # Check for dangerous capabilities
        for capability in self.DANGEROUS_CAPABILITIES:
            if capability in text:
                features["agent_dangerous_capability"] = 1.0
                break

        # Check risk indicators
        for indicator, patterns in self.RISK_INDICATORS.items():
            if any(p in text for p in patterns):
                features[f"agent_{indicator}"] = 1.0

        # Check for prompt injection risks
        prompt_patterns = ["prompt", "injection", "jailbreak", "input"]
        if all(any(p in text for p in [prompt_patterns[0], prompt_patterns[1]])):
            features["agent_prompt_injection"] = 1.0

        # Check for excessive agency
        agency_patterns = ["agency", "excessive", "overprivileged", "unrestricted"]
        if any(p in text for p in agency_patterns):
            features["agent_excessive_agency"] = 1.0

        # Extract tool count from metadata
        if finding.metadata:
            if "tool_count" in finding.metadata:
                features["agent_tool_count"] = min(
                    finding.metadata["tool_count"] / 10, 1.0
                )

        return features

    @property
    def feature_names(self) -> List[str]:
        """Get feature names."""
        return [
            "is_agent_finding",
            "is_langchain",
            "is_openai_assistant",
            "is_autogpt_crewai",
            "agent_dangerous_capability",
            "agent_high_autonomy",
            "agent_memory_risk",
            "agent_delegation_risk",
            "agent_external_access",
            "agent_prompt_injection",
            "agent_excessive_agency",
            "agent_tool_count",
        ]
