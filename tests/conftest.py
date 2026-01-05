"""Pytest configuration and fixtures for SecureAgent tests."""

import json
import os
import tempfile
from pathlib import Path
from typing import Dict, Any, List

import pytest

from secureagent.core.models.finding import Finding, Location, FindingDomain
from secureagent.core.models.severity import Severity
from secureagent.core.models.agent import (
    AgentInventoryItem,
    AgentFramework,
    ModelReference,
    ToolReference,
)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding for tests."""
    return Finding(
        id="test-001",
        rule_id="MCP-001",
        domain=FindingDomain.MCP,
        title="Test Finding",
        description="This is a test finding description.",
        severity=Severity.HIGH,
        location=Location(
            file_path="/path/to/config.json",
            line_number=10,
        ),
        remediation="Fix the issue by doing X.",
        cwe_id="CWE-798",
        owasp_id="LLM06",
    )


@pytest.fixture
def sample_findings() -> List[Finding]:
    """Create a list of sample findings for tests."""
    return [
        Finding(
            id="test-001",
            rule_id="MCP-001",
            domain=FindingDomain.MCP,
            title="Hardcoded Credential",
            description="API key found in configuration.",
            severity=Severity.CRITICAL,
            location=Location(file_path="/config.json", line_number=5),
            remediation="Use environment variables.",
            cwe_id="CWE-798",
        ),
        Finding(
            id="test-002",
            rule_id="MCP-002",
            domain=FindingDomain.MCP,
            title="Command Injection Risk",
            description="Shell tool without input validation.",
            severity=Severity.HIGH,
            location=Location(file_path="/config.json", line_number=15),
            remediation="Validate inputs.",
            cwe_id="CWE-78",
        ),
        Finding(
            id="test-003",
            rule_id="MCP-003",
            domain=FindingDomain.MCP,
            title="Path Traversal",
            description="File access without path validation.",
            severity=Severity.MEDIUM,
            location=Location(file_path="/config.json", line_number=25),
            remediation="Validate file paths.",
            cwe_id="CWE-22",
        ),
        Finding(
            id="test-004",
            rule_id="MCP-006",
            domain=FindingDomain.MCP,
            title="Missing Authentication",
            description="Server lacks authentication.",
            severity=Severity.LOW,
            location=Location(file_path="/config.json", line_number=1),
            remediation="Implement authentication.",
        ),
    ]


@pytest.fixture
def mcp_config() -> Dict[str, Any]:
    """Create a sample MCP configuration."""
    return {
        "mcpServers": {
            "test-server": {
                "command": "node",
                "args": ["server.js"],
                "env": {
                    "API_KEY": "sk-test-12345",
                    "DEBUG": "true",
                },
            },
            "shell-server": {
                "command": "bash",
                "args": ["-c", "echo hello"],
            },
        }
    }


@pytest.fixture
def mcp_config_file(temp_dir, mcp_config) -> Path:
    """Create a sample MCP configuration file."""
    config_path = temp_dir / "mcp_config.json"
    config_path.write_text(json.dumps(mcp_config, indent=2))
    return config_path


@pytest.fixture
def terraform_config() -> str:
    """Create sample Terraform configuration."""
    return '''
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "test" {
  name = "test-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "test" {
  identifier        = "test-db"
  publicly_accessible = true
  storage_encrypted   = false
}
'''


@pytest.fixture
def terraform_file(temp_dir, terraform_config) -> Path:
    """Create a sample Terraform file."""
    tf_path = temp_dir / "main.tf"
    tf_path.write_text(terraform_config)
    return tf_path


@pytest.fixture
def python_code_with_langchain() -> str:
    """Create sample Python code with LangChain usage."""
    return '''
from langchain.agents import create_react_agent
from langchain.tools import ShellTool
from langchain_openai import ChatOpenAI

# Hardcoded API key (bad practice)
api_key = "sk-proj-1234567890abcdef"

llm = ChatOpenAI(api_key=api_key, verbose=True)

# Using dangerous shell tool
shell_tool = ShellTool()
tools = [shell_tool]

agent = create_react_agent(llm, tools, prompt)
'''


@pytest.fixture
def python_file_langchain(temp_dir, python_code_with_langchain) -> Path:
    """Create a sample Python file with LangChain."""
    py_path = temp_dir / "agent.py"
    py_path.write_text(python_code_with_langchain)
    return py_path


@pytest.fixture
def sample_agent() -> AgentInventoryItem:
    """Create a sample agent inventory item."""
    return AgentInventoryItem(
        id="agent-001",
        name="Test Agent",
        framework=AgentFramework.LANGCHAIN,
        description="A test agent for unit tests",
        config_path="/path/to/config.json",
        models=[
            ModelReference(
                provider="openai",
                model_id="gpt-4",
            )
        ],
        tools=[
            ToolReference(
                name="shell",
                type="shell_execution",
                can_execute_code=True,
                risk_level=Severity.HIGH,
            ),
            ToolReference(
                name="file_reader",
                type="file_access",
                can_read_files=True,
                risk_level=Severity.MEDIUM,
            ),
        ],
        risk_score=0.7,
    )


@pytest.fixture
def aws_resources() -> List[Dict[str, Any]]:
    """Create sample AWS resource data."""
    return [
        {
            "type": "s3_bucket",
            "id": "test-bucket",
            "name": "test-bucket",
            "region": "us-east-1",
            "properties": {
                "public_access": True,
                "versioning": False,
                "encryption": False,
            },
        },
        {
            "type": "iam_policy",
            "id": "arn:aws:iam::123456789:policy/AdminAccess",
            "name": "AdminAccess",
            "region": "global",
            "properties": {
                "actions": ["*"],
                "resources": ["*"],
            },
        },
    ]


# Environment variable fixtures
@pytest.fixture(autouse=True)
def clean_env():
    """Clean up environment variables before each test."""
    env_vars = [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "SLACK_WEBHOOK_URL",
        "SECUREAGENT_CONFIG_DIR",
    ]
    old_values = {}
    for var in env_vars:
        old_values[var] = os.environ.get(var)
        if var in os.environ:
            del os.environ[var]

    yield

    # Restore old values
    for var, value in old_values.items():
        if value is not None:
            os.environ[var] = value
        elif var in os.environ:
            del os.environ[var]
