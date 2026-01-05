"""Agent catalog management."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from secureagent.core.models.agent import AgentInventoryItem, AgentFramework


def _get_framework_value(framework) -> str:
    """Get string value from framework, handling both enum and string."""
    if hasattr(framework, 'value'):
        return framework.value
    return str(framework)


@dataclass
class CatalogStats:
    """Statistics about the agent catalog."""

    total_agents: int = 0
    by_framework: Dict[str, int] = field(default_factory=dict)
    total_tools: int = 0
    total_models: int = 0
    high_risk_agents: int = 0
    last_updated: Optional[datetime] = None


class AgentCatalog:
    """Manages a catalog of discovered AI agents."""

    def __init__(self, catalog_path: Optional[Path] = None):
        """Initialize the catalog.

        Args:
            catalog_path: Optional path to persist the catalog
        """
        self.catalog_path = catalog_path
        self._agents: Dict[str, AgentInventoryItem] = {}
        self._load_catalog()

    def _load_catalog(self) -> None:
        """Load catalog from disk if exists."""
        if self.catalog_path and self.catalog_path.exists():
            try:
                data = json.loads(self.catalog_path.read_text())
                for agent_data in data.get("agents", []):
                    agent = self._deserialize_agent(agent_data)
                    self._agents[agent.id] = agent
            except Exception:
                pass

    def _save_catalog(self) -> None:
        """Save catalog to disk."""
        if self.catalog_path:
            data = {
                "agents": [self._serialize_agent(a) for a in self._agents.values()],
                "last_updated": datetime.now().isoformat(),
            }
            self.catalog_path.parent.mkdir(parents=True, exist_ok=True)
            self.catalog_path.write_text(json.dumps(data, indent=2))

    def _serialize_agent(self, agent: AgentInventoryItem) -> Dict[str, Any]:
        """Serialize agent to dictionary."""
        return {
            "id": agent.id,
            "name": agent.name,
            "framework": _get_framework_value(agent.framework),
            "models": [
                {"provider": m.provider, "model_id": m.model_id}
                for m in agent.models
            ],
            "tools": [
                {"name": t.name, "tool_type": t.tool_type}
                for t in agent.tools
            ],
            "data_sources": [
                {"name": ds.name, "source_type": ds.source_type, "access_type": ds.access_type}
                for ds in agent.data_sources
            ],
            "permissions": [
                {"action": p.action, "resource": p.resource, "granted": p.granted}
                for p in agent.permissions
            ],
            "risk_score": agent.risk_score,
            "discovered_at": agent.discovered_at.isoformat() if agent.discovered_at else None,
            "config_path": agent.config_path,
        }

    def _deserialize_agent(self, data: Dict[str, Any]) -> AgentInventoryItem:
        """Deserialize agent from dictionary."""
        from secureagent.core.models.agent import (
            ModelReference,
            ToolReference,
            DataSource,
            Permission,
        )

        return AgentInventoryItem(
            id=data["id"],
            name=data["name"],
            framework=AgentFramework(data["framework"]),
            models=[
                ModelReference(provider=m["provider"], model_id=m["model_id"])
                for m in data.get("models", [])
            ],
            tools=[
                ToolReference(name=t["name"], tool_type=t["tool_type"])
                for t in data.get("tools", [])
            ],
            data_sources=[
                DataSource(
                    name=ds["name"],
                    source_type=ds["source_type"],
                    access_type=ds["access_type"],
                )
                for ds in data.get("data_sources", [])
            ],
            permissions=[
                Permission(
                    action=p["action"],
                    resource=p["resource"],
                    granted=p["granted"],
                )
                for p in data.get("permissions", [])
            ],
            risk_score=data.get("risk_score", 0.0),
            discovered_at=datetime.fromisoformat(data["discovered_at"])
            if data.get("discovered_at")
            else None,
            config_path=data.get("config_path"),
        )

    def add(self, agent: AgentInventoryItem) -> None:
        """Add an agent to the catalog.

        Args:
            agent: Agent to add
        """
        self._agents[agent.id] = agent
        self._save_catalog()

    def add_many(self, agents: List[AgentInventoryItem]) -> None:
        """Add multiple agents to the catalog.

        Args:
            agents: List of agents to add
        """
        for agent in agents:
            self._agents[agent.id] = agent
        self._save_catalog()

    def get(self, agent_id: str) -> Optional[AgentInventoryItem]:
        """Get an agent by ID.

        Args:
            agent_id: Agent ID

        Returns:
            Agent if found, None otherwise
        """
        return self._agents.get(agent_id)

    def remove(self, agent_id: str) -> bool:
        """Remove an agent from the catalog.

        Args:
            agent_id: Agent ID

        Returns:
            True if removed, False if not found
        """
        if agent_id in self._agents:
            del self._agents[agent_id]
            self._save_catalog()
            return True
        return False

    def list_all(self) -> List[AgentInventoryItem]:
        """Get all agents in the catalog.

        Returns:
            List of all agents
        """
        return list(self._agents.values())

    def filter_by_framework(
        self, framework: AgentFramework
    ) -> List[AgentInventoryItem]:
        """Filter agents by framework.

        Args:
            framework: Framework to filter by

        Returns:
            List of matching agents
        """
        return [a for a in self._agents.values() if a.framework == framework]

    def filter_by_risk(
        self, min_risk: float = 0.0, max_risk: float = 1.0
    ) -> List[AgentInventoryItem]:
        """Filter agents by risk score.

        Args:
            min_risk: Minimum risk score
            max_risk: Maximum risk score

        Returns:
            List of matching agents
        """
        return [
            a
            for a in self._agents.values()
            if min_risk <= a.risk_score <= max_risk
        ]

    def search(self, query: str) -> List[AgentInventoryItem]:
        """Search agents by name or ID.

        Args:
            query: Search query

        Returns:
            List of matching agents
        """
        query_lower = query.lower()
        return [
            a
            for a in self._agents.values()
            if query_lower in a.name.lower() or query_lower in a.id.lower()
        ]

    def get_stats(self) -> CatalogStats:
        """Get catalog statistics.

        Returns:
            CatalogStats object
        """
        stats = CatalogStats()
        stats.total_agents = len(self._agents)

        for agent in self._agents.values():
            framework = _get_framework_value(agent.framework)
            stats.by_framework[framework] = stats.by_framework.get(framework, 0) + 1
            stats.total_tools += len(agent.tools)
            stats.total_models += len(agent.models)
            if agent.risk_score >= 0.7:
                stats.high_risk_agents += 1

        return stats

    def export(self, format: str = "json") -> str:
        """Export catalog to string.

        Args:
            format: Export format (json, csv)

        Returns:
            Exported data as string
        """
        if format == "json":
            return json.dumps(
                {
                    "agents": [self._serialize_agent(a) for a in self._agents.values()],
                    "stats": {
                        "total": len(self._agents),
                        "exported_at": datetime.now().isoformat(),
                    },
                },
                indent=2,
            )
        elif format == "csv":
            lines = ["id,name,framework,tools,models,risk_score"]
            for agent in self._agents.values():
                lines.append(
                    f'"{agent.id}","{agent.name}","{_get_framework_value(agent.framework)}",'
                    f'{len(agent.tools)},{len(agent.models)},{agent.risk_score}'
                )
            return "\n".join(lines)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def sync(self, discovered_agents: List[AgentInventoryItem]) -> Dict[str, int]:
        """Sync catalog with newly discovered agents.

        Args:
            discovered_agents: List of discovered agents

        Returns:
            Dict with counts of added, updated, removed agents
        """
        result = {"added": 0, "updated": 0, "removed": 0}

        discovered_ids = {a.id for a in discovered_agents}
        existing_ids = set(self._agents.keys())

        # Add new agents
        for agent in discovered_agents:
            if agent.id not in existing_ids:
                self._agents[agent.id] = agent
                result["added"] += 1
            else:
                # Update existing agent
                self._agents[agent.id] = agent
                result["updated"] += 1

        # Remove agents no longer discovered
        for agent_id in existing_ids - discovered_ids:
            del self._agents[agent_id]
            result["removed"] += 1

        self._save_catalog()
        return result
