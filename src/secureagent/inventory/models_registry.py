"""LLM Model Registry for tracking which models agents use."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set


@dataclass
class ModelInfo:
    """Information about an LLM model."""

    provider: str
    model_id: str
    display_name: Optional[str] = None
    context_window: Optional[int] = None
    max_output_tokens: Optional[int] = None
    supports_function_calling: bool = False
    supports_vision: bool = False
    cost_per_1k_input: Optional[float] = None
    cost_per_1k_output: Optional[float] = None
    risk_notes: List[str] = field(default_factory=list)

    @property
    def full_id(self) -> str:
        """Get full model identifier."""
        return f"{self.provider}/{self.model_id}"


@dataclass
class ModelUsage:
    """Tracks how a model is used by agents."""

    model: ModelInfo
    agent_ids: Set[str] = field(default_factory=set)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


# Known model information
KNOWN_MODELS: Dict[str, ModelInfo] = {
    "openai/gpt-4": ModelInfo(
        provider="openai",
        model_id="gpt-4",
        display_name="GPT-4",
        context_window=8192,
        max_output_tokens=8192,
        supports_function_calling=True,
        cost_per_1k_input=0.03,
        cost_per_1k_output=0.06,
    ),
    "openai/gpt-4-turbo": ModelInfo(
        provider="openai",
        model_id="gpt-4-turbo",
        display_name="GPT-4 Turbo",
        context_window=128000,
        max_output_tokens=4096,
        supports_function_calling=True,
        supports_vision=True,
        cost_per_1k_input=0.01,
        cost_per_1k_output=0.03,
    ),
    "openai/gpt-4o": ModelInfo(
        provider="openai",
        model_id="gpt-4o",
        display_name="GPT-4o",
        context_window=128000,
        max_output_tokens=16384,
        supports_function_calling=True,
        supports_vision=True,
        cost_per_1k_input=0.005,
        cost_per_1k_output=0.015,
    ),
    "openai/gpt-3.5-turbo": ModelInfo(
        provider="openai",
        model_id="gpt-3.5-turbo",
        display_name="GPT-3.5 Turbo",
        context_window=16385,
        max_output_tokens=4096,
        supports_function_calling=True,
        cost_per_1k_input=0.0005,
        cost_per_1k_output=0.0015,
    ),
    "anthropic/claude-3-opus": ModelInfo(
        provider="anthropic",
        model_id="claude-3-opus-20240229",
        display_name="Claude 3 Opus",
        context_window=200000,
        max_output_tokens=4096,
        supports_function_calling=True,
        supports_vision=True,
        cost_per_1k_input=0.015,
        cost_per_1k_output=0.075,
    ),
    "anthropic/claude-3-sonnet": ModelInfo(
        provider="anthropic",
        model_id="claude-3-sonnet-20240229",
        display_name="Claude 3 Sonnet",
        context_window=200000,
        max_output_tokens=4096,
        supports_function_calling=True,
        supports_vision=True,
        cost_per_1k_input=0.003,
        cost_per_1k_output=0.015,
    ),
    "anthropic/claude-3.5-sonnet": ModelInfo(
        provider="anthropic",
        model_id="claude-3-5-sonnet-20241022",
        display_name="Claude 3.5 Sonnet",
        context_window=200000,
        max_output_tokens=8192,
        supports_function_calling=True,
        supports_vision=True,
        cost_per_1k_input=0.003,
        cost_per_1k_output=0.015,
    ),
}


class ModelRegistry:
    """Registry for tracking LLM models used by agents."""

    def __init__(self):
        """Initialize the registry."""
        self._usage: Dict[str, ModelUsage] = {}
        self._custom_models: Dict[str, ModelInfo] = {}

    def register_usage(self, provider: str, model_id: str, agent_id: str) -> None:
        """Register that an agent uses a model.

        Args:
            provider: Model provider
            model_id: Model identifier
            agent_id: Agent using the model
        """
        full_id = f"{provider}/{model_id}"
        now = datetime.now()

        if full_id not in self._usage:
            model_info = self._get_model_info(provider, model_id)
            self._usage[full_id] = ModelUsage(
                model=model_info,
                first_seen=now,
            )

        self._usage[full_id].agent_ids.add(agent_id)
        self._usage[full_id].last_seen = now

    def _get_model_info(self, provider: str, model_id: str) -> ModelInfo:
        """Get model information."""
        full_id = f"{provider}/{model_id}"

        # Check known models
        if full_id in KNOWN_MODELS:
            return KNOWN_MODELS[full_id]

        # Check custom models
        if full_id in self._custom_models:
            return self._custom_models[full_id]

        # Create basic info for unknown model
        return ModelInfo(provider=provider, model_id=model_id)

    def add_custom_model(self, model: ModelInfo) -> None:
        """Add a custom model definition.

        Args:
            model: Model information
        """
        self._custom_models[model.full_id] = model

    def get_model(self, provider: str, model_id: str) -> Optional[ModelInfo]:
        """Get model information.

        Args:
            provider: Model provider
            model_id: Model identifier

        Returns:
            ModelInfo if found
        """
        full_id = f"{provider}/{model_id}"

        if full_id in self._usage:
            return self._usage[full_id].model

        return self._get_model_info(provider, model_id)

    def get_all_usage(self) -> List[ModelUsage]:
        """Get all model usage records.

        Returns:
            List of ModelUsage objects
        """
        return list(self._usage.values())

    def get_agents_using_model(self, provider: str, model_id: str) -> Set[str]:
        """Get all agents using a specific model.

        Args:
            provider: Model provider
            model_id: Model identifier

        Returns:
            Set of agent IDs
        """
        full_id = f"{provider}/{model_id}"
        if full_id in self._usage:
            return self._usage[full_id].agent_ids
        return set()

    def get_models_by_agent(self, agent_id: str) -> List[ModelInfo]:
        """Get all models used by an agent.

        Args:
            agent_id: Agent ID

        Returns:
            List of models used by the agent
        """
        models = []
        for usage in self._usage.values():
            if agent_id in usage.agent_ids:
                models.append(usage.model)
        return models

    def get_stats(self) -> Dict[str, any]:
        """Get registry statistics.

        Returns:
            Dictionary of statistics
        """
        total_models = len(self._usage)
        total_agents = len(
            set(aid for usage in self._usage.values() for aid in usage.agent_ids)
        )

        by_provider: Dict[str, int] = {}
        for usage in self._usage.values():
            provider = usage.model.provider
            by_provider[provider] = by_provider.get(provider, 0) + 1

        return {
            "total_models": total_models,
            "total_agents_using_models": total_agents,
            "by_provider": by_provider,
            "most_used": sorted(
                self._usage.values(),
                key=lambda u: len(u.agent_ids),
                reverse=True,
            )[:5],
        }
