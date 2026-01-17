"""Tests for AutoGPT/CrewAI multi-agent scanner."""

import tempfile
from pathlib import Path

import pytest

from secureagent.scanners.autogpt.scanner import AutoGPTScanner
from secureagent.scanners.autogpt.models import AgentFramework


class TestAutoGPTScanner:
    """Tests for AutoGPT scanner functionality."""

    def test_scanner_initialization(self):
        """Test scanner can be initialized."""
        scanner = AutoGPTScanner(path=".")
        assert scanner.name == "autogpt"
        assert scanner.version == "1.0.0"

    def test_detect_crewai_framework(self):
        """Test detection of CrewAI framework."""
        crewai_code = '''
from crewai import Agent, Crew, Task

researcher = Agent(
    role="Researcher",
    goal="Research the topic",
    verbose=True
)
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "crew.py"
            file_path.write_text(crewai_code)

            scanner = AutoGPTScanner(path=tmpdir)
            config = scanner._analyze_file(file_path)

            assert config is not None
            assert config.framework == AgentFramework.CREWAI

    def test_detect_autogpt_framework(self):
        """Test detection of AutoGPT framework."""
        autogpt_yaml = '''
# AutoGPT configuration file
ai_name: TestAgent
ai_role: Assistant
ai_goals:
  - Help users with tasks
  - Be helpful and accurate
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "autogpt.yaml"
            file_path.write_text(autogpt_yaml)

            scanner = AutoGPTScanner(path=tmpdir)
            config = scanner._analyze_file(file_path)

            assert config is not None
            assert config.framework == AgentFramework.AUTOGPT

    def test_hardcoded_api_key_detection(self):
        """Test AG-001: Hardcoded API Keys detection."""
        code_with_key = '''
from crewai import Agent

api_key = "sk-proj-1234567890abcdefghijklmnop"

agent = Agent(
    role="Researcher",
    goal="Research"
)
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "agent.py"
            file_path.write_text(code_with_key)

            scanner = AutoGPTScanner(path=tmpdir)
            findings = scanner.scan()

            ag001_findings = [f for f in findings if f.rule_id == "AG-001"]
            assert len(ag001_findings) >= 1
            assert ag001_findings[0].severity == "critical"

    def test_unrestricted_autonomy_detection(self):
        """Test AG-002: Unrestricted Agent Autonomy detection."""
        hierarchical_crew = '''
from crewai import Agent, Crew

manager = Agent(role="Manager", goal="Manage team")
worker = Agent(role="Worker", goal="Do work")

crew = Crew(
    agents=[manager, worker],
    process="hierarchical"
)
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "crew.py"
            file_path.write_text(hierarchical_crew)

            scanner = AutoGPTScanner(path=tmpdir)
            findings = scanner.scan()

            ag002_findings = [f for f in findings if f.rule_id == "AG-002"]
            assert len(ag002_findings) >= 1

    def test_dangerous_tool_detection(self):
        """Test AG-003: Dangerous Tool Access detection."""
        agent_with_shell = '''
from crewai import Agent

hacker = Agent(
    role="Executor",
    goal="Execute commands",
    tools=[shell, execute_shell, terminal]
)
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "agent.py"
            file_path.write_text(agent_with_shell)

            scanner = AutoGPTScanner(path=tmpdir)
            findings = scanner.scan()

            ag003_findings = [f for f in findings if f.rule_id == "AG-003"]
            assert len(ag003_findings) >= 1
            assert ag003_findings[0].severity == "high"

    def test_inter_agent_trust_detection(self):
        """Test AG-004: Inter-Agent Trust detection."""
        multi_agent_delegation = '''
from crewai import Agent

agent1 = Agent(
    role="Delegator",
    goal="Delegate tasks",
    allow_delegation=True
)

agent2 = Agent(
    role="Worker",
    goal="Do delegated work",
    allow_delegation=True
)
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "agents.py"
            file_path.write_text(multi_agent_delegation)

            scanner = AutoGPTScanner(path=tmpdir)
            findings = scanner.scan()

            ag004_findings = [f for f in findings if f.rule_id == "AG-004"]
            assert len(ag004_findings) >= 1

    def test_memory_limits_detection(self):
        """Test AG-005: No Memory Limits detection."""
        agent_with_memory = '''
from crewai import Agent

agent = Agent(
    role="Rememberer",
    goal="Remember things",
    memory=True
)
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "agent.py"
            file_path.write_text(agent_with_memory)

            scanner = AutoGPTScanner(path=tmpdir)
            findings = scanner.scan()

            ag005_findings = [f for f in findings if f.rule_id == "AG-005"]
            assert len(ag005_findings) >= 1

    def test_unconstrained_delegation_detection(self):
        """Test AG-006: Unconstrained Task Delegation detection."""
        delegating_agent = '''
from crewai import Agent

manager = Agent(
    role="Manager",
    goal="Manage work",
    allow_delegation=True
)
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "agent.py"
            file_path.write_text(delegating_agent)

            scanner = AutoGPTScanner(path=tmpdir)
            findings = scanner.scan()

            ag006_findings = [f for f in findings if f.rule_id == "AG-006"]
            assert len(ag006_findings) >= 1

    def test_web_access_detection(self):
        """Test AG-007: Web Browsing Without Filters detection."""
        agent_with_browser = '''
from crewai import Agent

researcher = Agent(
    role="Web Researcher",
    goal="Research the web",
    tools=[browser, web_search]
)
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "agent.py"
            file_path.write_text(agent_with_browser)

            scanner = AutoGPTScanner(path=tmpdir)
            findings = scanner.scan()

            ag007_findings = [f for f in findings if f.rule_id == "AG-007"]
            assert len(ag007_findings) >= 1

    def test_verbose_mode_detection(self):
        """Test AG-008: Verbose Logging detection."""
        verbose_agent = '''
from crewai import Agent

agent = Agent(
    role="Talker",
    goal="Talk a lot",
    verbose=True
)
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "agent.py"
            file_path.write_text(verbose_agent)

            scanner = AutoGPTScanner(path=tmpdir)
            findings = scanner.scan()

            ag008_findings = [f for f in findings if f.rule_id == "AG-008"]
            assert len(ag008_findings) >= 1

    def test_no_iteration_limits_detection(self):
        """Test AG-009: No Iteration Limits detection."""
        unlimited_agent = '''
from crewai import Agent

agent = Agent(
    role="Looper",
    goal="Loop forever"
)
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "agent.py"
            file_path.write_text(unlimited_agent)

            scanner = AutoGPTScanner(path=tmpdir)
            findings = scanner.scan()

            ag009_findings = [f for f in findings if f.rule_id == "AG-009"]
            assert len(ag009_findings) >= 1

    def test_safe_agent_no_findings(self):
        """Test that a safely configured agent produces fewer findings."""
        safe_agent = '''
import os
from crewai import Agent

agent = Agent(
    role="Safe Worker",
    goal="Work safely",
    max_iter=10,
    allow_delegation=False,
    verbose=False
)
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "safe_agent.py"
            file_path.write_text(safe_agent)

            scanner = AutoGPTScanner(path=tmpdir)
            findings = scanner.scan()

            # Should not have delegation, verbose, or dangerous tool findings
            assert not any(f.rule_id == "AG-006" for f in findings)
            assert not any(f.rule_id == "AG-008" for f in findings)
            assert not any(f.rule_id == "AG-003" for f in findings)

    def test_complex_crew_configuration(self):
        """Test scanning a complex crew configuration."""
        complex_crew = '''
from crewai import Agent, Crew, Task

researcher = Agent(
    role="Senior Researcher",
    goal="Find accurate information",
    verbose=True,
    allow_delegation=True,
    tools=[web_search, browser],
    memory=True
)

writer = Agent(
    role="Technical Writer",
    goal="Write clear documentation",
    verbose=True,
    allow_delegation=True
)

reviewer = Agent(
    role="Quality Reviewer",
    goal="Review and approve content",
    verbose=True
)

crew = Crew(
    agents=[researcher, writer, reviewer],
    process="hierarchical",
    verbose=True,
    memory=True
)

api_key = "sk-proj-supersecretapikey123456789"
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "complex_crew.py"
            file_path.write_text(complex_crew)

            scanner = AutoGPTScanner(path=tmpdir)
            findings = scanner.scan()

            # Should detect multiple issues
            rule_ids = {f.rule_id for f in findings}
            assert "AG-001" in rule_ids  # API key
            assert "AG-002" in rule_ids  # Hierarchical without oversight
            assert "AG-004" in rule_ids  # Inter-agent trust
            assert "AG-005" in rule_ids  # Memory without limits
            assert "AG-006" in rule_ids  # Unconstrained delegation
            assert "AG-007" in rule_ids  # Web access
            assert "AG-008" in rule_ids  # Verbose logging

    def test_file_discovery(self):
        """Test that scanner discovers relevant files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create Python file with crewai import
            py_file = Path(tmpdir) / "crew.py"
            py_file.write_text("from crewai import Agent")

            # Create YAML file with autogpt config
            yaml_file = Path(tmpdir) / "config.yaml"
            yaml_file.write_text("ai_role: autogpt\nai_goals: []")

            # Create unrelated file
            other_file = Path(tmpdir) / "readme.txt"
            other_file.write_text("Just a readme")

            scanner = AutoGPTScanner(path=tmpdir)
            targets = list(scanner.discover_targets())

            assert len(targets) >= 1
            target_names = [t.name for t in targets]
            assert "crew.py" in target_names

    def test_scan_single_file(self):
        """Test scanning a single file directly."""
        code = '''
from crewai import Agent
agent = Agent(role="Test", goal="Test", verbose=True)
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "single.py"
            file_path.write_text(code)

            scanner = AutoGPTScanner(path=str(file_path))
            findings = scanner.scan()

            assert len(findings) >= 1


class TestAutoGPTModels:
    """Tests for AutoGPT data models."""

    def test_multi_agent_config(self):
        """Test MultiAgentConfig model."""
        from secureagent.scanners.autogpt.models import MultiAgentConfig

        config = MultiAgentConfig(
            file_path="/test/path.py",
            raw_content="test content"
        )

        assert config.file_path == "/test/path.py"
        assert config.framework == AgentFramework.UNKNOWN
        assert config.agents == []
        assert not config.has_errors

    def test_multi_agent_model(self):
        """Test MultiAgent model."""
        from secureagent.scanners.autogpt.models import MultiAgent

        agent = MultiAgent(
            name="TestAgent",
            role="Tester",
            goal="Test things",
            allow_delegation=True,
            memory=True,
            max_iterations=10,
        )

        assert agent.name == "TestAgent"
        assert agent.allow_delegation is True
        assert agent.has_iteration_limits is True

    def test_multi_agent_tool(self):
        """Test MultiAgentTool model."""
        from secureagent.scanners.autogpt.models import MultiAgentTool

        tool = MultiAgentTool(
            name="shell",
            tool_type="shell",
            is_dangerous=True,
            has_shell_access=True,
        )

        assert tool.is_dangerous is True
        assert tool.has_shell_access is True

    def test_multi_agent_crew(self):
        """Test MultiAgentCrew model."""
        from secureagent.scanners.autogpt.models import MultiAgentCrew

        crew = MultiAgentCrew(
            process="hierarchical",
            verbose=True,
            memory=True,
        )

        assert crew.process == "hierarchical"
        assert crew.verbose is True


class TestAutoGPTRules:
    """Tests for AutoGPT security rules."""

    def test_get_rule(self):
        """Test getting a single rule."""
        from secureagent.scanners.autogpt.rules import get_rule

        rule = get_rule("AG-001")
        assert rule["id"] == "AG-001"
        assert rule["title"] == "Hardcoded API Keys"
        assert rule["severity"] == "critical"

    def test_get_all_rules(self):
        """Test getting all rules."""
        from secureagent.scanners.autogpt.rules import get_all_rules

        rules = get_all_rules()
        assert len(rules) == 10

        rule_ids = {r["id"] for r in rules}
        expected_ids = {f"AG-{i:03d}" for i in range(1, 11)}
        assert rule_ids == expected_ids

    def test_rule_has_required_fields(self):
        """Test that all rules have required fields."""
        from secureagent.scanners.autogpt.rules import get_all_rules

        required_fields = ["id", "title", "severity", "description", "cwe_id", "remediation"]

        for rule in get_all_rules():
            for field in required_fields:
                assert field in rule, f"Rule {rule.get('id')} missing {field}"
