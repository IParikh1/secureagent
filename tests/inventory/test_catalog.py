"""Tests for agent catalog."""

import pytest
from pathlib import Path

from secureagent.inventory.catalog import AgentCatalog, CatalogStats
from secureagent.core.models.agent import AgentInventoryItem, AgentFramework


class TestAgentCatalog:
    """Tests for AgentCatalog."""

    def test_catalog_initialization(self):
        """Test catalog initialization."""
        catalog = AgentCatalog()
        assert catalog is not None
        assert len(catalog.list_all()) == 0

    def test_add_agent(self, sample_agent):
        """Test adding an agent to catalog."""
        catalog = AgentCatalog()
        catalog.add(sample_agent)

        assert len(catalog.list_all()) == 1
        assert catalog.get(sample_agent.id) is not None

    def test_remove_agent(self, sample_agent):
        """Test removing an agent from catalog."""
        catalog = AgentCatalog()
        catalog.add(sample_agent)

        result = catalog.remove(sample_agent.id)
        assert result is True
        assert len(catalog.list_all()) == 0
        assert catalog.get(sample_agent.id) is None

    def test_remove_nonexistent_agent(self):
        """Test removing a non-existent agent."""
        catalog = AgentCatalog()
        result = catalog.remove("nonexistent-id")
        assert result is False

    def test_get_agents_by_framework(self):
        """Test filtering agents by framework."""
        catalog = AgentCatalog()

        agent1 = AgentInventoryItem(
            id="agent-001",
            name="LangChain Agent",
            framework=AgentFramework.LANGCHAIN,
        )
        agent2 = AgentInventoryItem(
            id="agent-002",
            name="MCP Agent",
            framework=AgentFramework.MCP,
        )

        catalog.add(agent1)
        catalog.add(agent2)

        langchain_agents = catalog.filter_by_framework(AgentFramework.LANGCHAIN)
        assert len(langchain_agents) == 1
        assert langchain_agents[0].id == "agent-001"

        mcp_agents = catalog.filter_by_framework(AgentFramework.MCP)
        assert len(mcp_agents) == 1
        assert mcp_agents[0].id == "agent-002"

    def test_search_agents(self):
        """Test searching agents."""
        catalog = AgentCatalog()

        agent1 = AgentInventoryItem(
            id="agent-001",
            name="Production Agent",
            framework=AgentFramework.LANGCHAIN,
            description="Handles production tasks",
        )
        agent2 = AgentInventoryItem(
            id="agent-002",
            name="Dev Agent",
            framework=AgentFramework.MCP,
            description="For development",
        )

        catalog.add(agent1)
        catalog.add(agent2)

        results = catalog.search("Production")
        assert len(results) == 1
        assert results[0].id == "agent-001"

        results = catalog.search("dev")
        assert len(results) == 1
        assert results[0].id == "agent-002"

    def test_get_high_risk_agents(self):
        """Test getting high risk agents using filter_by_risk."""
        catalog = AgentCatalog()

        agent1 = AgentInventoryItem(
            id="agent-001",
            name="High Risk Agent",
            framework=AgentFramework.LANGCHAIN,
            risk_score=0.9,
        )
        agent2 = AgentInventoryItem(
            id="agent-002",
            name="Low Risk Agent",
            framework=AgentFramework.MCP,
            risk_score=0.2,
        )

        catalog.add(agent1)
        catalog.add(agent2)

        high_risk = catalog.filter_by_risk(min_risk=0.7)
        assert len(high_risk) == 1
        assert high_risk[0].id == "agent-001"

        low_risk = catalog.filter_by_risk(max_risk=0.5)
        assert len(low_risk) == 1
        assert low_risk[0].id == "agent-002"

    def test_catalog_persistence(self, temp_dir):
        """Test saving and loading catalog."""
        catalog_path = temp_dir / "catalog.json"

        # Create catalog and add agent
        catalog = AgentCatalog(catalog_path=catalog_path)

        agent = AgentInventoryItem(
            id="agent-001",
            name="Test Agent",
            framework=AgentFramework.LANGCHAIN,
        )
        catalog.add(agent)

        # Create new catalog instance and verify persistence
        catalog2 = AgentCatalog(catalog_path=catalog_path)
        assert len(catalog2.list_all()) == 1
        assert catalog2.get("agent-001") is not None

    def test_add_many_agents(self):
        """Test adding multiple agents at once."""
        catalog = AgentCatalog()

        agents = [
            AgentInventoryItem(
                id="agent-001",
                name="Agent 1",
                framework=AgentFramework.LANGCHAIN,
            ),
            AgentInventoryItem(
                id="agent-002",
                name="Agent 2",
                framework=AgentFramework.MCP,
            ),
        ]

        catalog.add_many(agents)
        assert len(catalog.list_all()) == 2

    def test_get_stats(self):
        """Test getting catalog statistics."""
        catalog = AgentCatalog()

        agent1 = AgentInventoryItem(
            id="agent-001",
            name="Agent 1",
            framework=AgentFramework.LANGCHAIN,
            risk_score=0.8,
        )
        agent2 = AgentInventoryItem(
            id="agent-002",
            name="Agent 2",
            framework=AgentFramework.MCP,
            risk_score=0.3,
        )

        catalog.add_many([agent1, agent2])

        stats = catalog.get_stats()
        assert isinstance(stats, CatalogStats)
        assert stats.total_agents == 2
        assert stats.high_risk_agents == 1  # agent1 has risk >= 0.7
        assert "langchain" in stats.by_framework
        assert "mcp" in stats.by_framework

    def test_export_json(self):
        """Test exporting catalog to JSON."""
        catalog = AgentCatalog()

        agent = AgentInventoryItem(
            id="agent-001",
            name="Test Agent",
            framework=AgentFramework.LANGCHAIN,
        )
        catalog.add(agent)

        export = catalog.export(format="json")
        assert isinstance(export, str)
        assert "agent-001" in export
        assert "Test Agent" in export

    def test_export_csv(self):
        """Test exporting catalog to CSV."""
        catalog = AgentCatalog()

        agent = AgentInventoryItem(
            id="agent-001",
            name="Test Agent",
            framework=AgentFramework.LANGCHAIN,
        )
        catalog.add(agent)

        export = catalog.export(format="csv")
        assert isinstance(export, str)
        assert "agent-001" in export
        assert "Test Agent" in export
        # CSV should have header row
        assert "id,name,framework" in export

    def test_sync_agents(self):
        """Test syncing catalog with discovered agents."""
        catalog = AgentCatalog()

        # Add initial agent
        agent1 = AgentInventoryItem(
            id="agent-001",
            name="Agent 1",
            framework=AgentFramework.LANGCHAIN,
        )
        catalog.add(agent1)

        # Sync with new set of agents
        new_agents = [
            AgentInventoryItem(
                id="agent-001",
                name="Agent 1 Updated",
                framework=AgentFramework.LANGCHAIN,
            ),
            AgentInventoryItem(
                id="agent-002",
                name="Agent 2",
                framework=AgentFramework.MCP,
            ),
        ]

        result = catalog.sync(new_agents)
        assert result["added"] == 1  # agent-002 is new
        assert result["updated"] == 1  # agent-001 was updated
        assert result["removed"] == 0  # nothing removed since agent-001 is in new list
