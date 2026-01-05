"""Tests for OpenAI Assistants scanner."""

import pytest
from pathlib import Path

from secureagent.scanners.openai_assistants.scanner import OpenAIAssistantsScanner
from secureagent.core.models.severity import Severity


class TestOpenAIAssistantsScanner:
    """Tests for OpenAI Assistants scanner."""

    def test_scanner_initialization(self, temp_dir):
        """Test scanner initialization."""
        scanner = OpenAIAssistantsScanner(path=temp_dir)
        assert scanner is not None
        assert scanner.name == "openai_assistants"

    def test_scan_hardcoded_api_key(self, temp_dir):
        """Test detecting hardcoded API keys."""
        code = '''
import openai

openai.api_key = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
'''
        code_path = temp_dir / "assistant.py"
        code_path.write_text(code)

        scanner = OpenAIAssistantsScanner(path=code_path)
        findings = scanner.scan()

        # Should detect hardcoded API key
        key_findings = [
            f for f in findings
            if "key" in f.title.lower() or "credential" in f.title.lower()
        ]
        assert len(key_findings) > 0

    def test_scan_code_interpreter(self, temp_dir):
        """Test detecting code interpreter usage."""
        code = '''
from openai import OpenAI

client = OpenAI()
assistant = client.beta.assistants.create(
    name="Code Assistant",
    tools=[{"type": "code_interpreter"}],
    model="gpt-4"
)
'''
        code_path = temp_dir / "assistant.py"
        code_path.write_text(code)

        scanner = OpenAIAssistantsScanner(path=code_path)
        findings = scanner.scan()

        # Should detect code interpreter
        code_findings = [
            f for f in findings
            if "code" in f.title.lower() or "interpreter" in f.title.lower()
        ]
        assert len(code_findings) > 0

    def test_scan_file_search(self, temp_dir):
        """Test detecting file search capabilities."""
        code = '''
from openai import OpenAI

client = OpenAI()
assistant = client.beta.assistants.create(
    name="File Assistant",
    tools=[{"type": "file_search"}],
    model="gpt-4"
)
'''
        code_path = temp_dir / "assistant.py"
        code_path.write_text(code)

        scanner = OpenAIAssistantsScanner(path=code_path)
        findings = scanner.scan()

        # Should detect file search
        file_findings = [
            f for f in findings if "file" in f.title.lower()
        ]
        assert len(file_findings) > 0

    def test_scan_dangerous_function(self, temp_dir):
        """Test detecting dangerous function definitions."""
        code = '''
from openai import OpenAI

client = OpenAI()
tools = [
    {
        "type": "function",
        "function": {
            "name": "execute_shell_command",
            "description": "Execute a shell command",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"}
                }
            }
        }
    }
]
assistant = client.beta.assistants.create(
    name="Shell Assistant",
    tools=tools,
    model="gpt-4"
)
'''
        code_path = temp_dir / "assistant.py"
        code_path.write_text(code)

        scanner = OpenAIAssistantsScanner(path=code_path)
        findings = scanner.scan()

        # Should detect dangerous function
        dangerous_findings = [
            f for f in findings
            if f.severity in [Severity.HIGH, Severity.CRITICAL]
        ]
        assert len(dangerous_findings) > 0

    def test_scan_clean_code(self, temp_dir):
        """Test scanning clean code without issues."""
        code = '''
import os
from openai import OpenAI

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}]
)
'''
        code_path = temp_dir / "assistant.py"
        code_path.write_text(code)

        scanner = OpenAIAssistantsScanner(path=code_path)
        findings = scanner.scan()

        # Should have minimal critical findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0

    def test_scan_multiple_tools(self, temp_dir):
        """Test scanning assistant with multiple tools."""
        code = '''
from openai import OpenAI

client = OpenAI()
assistant = client.beta.assistants.create(
    name="Multi-Tool Assistant",
    tools=[
        {"type": "code_interpreter"},
        {"type": "file_search"},
        {
            "type": "function",
            "function": {
                "name": "send_email",
                "description": "Send an email"
            }
        }
    ],
    model="gpt-4"
)
'''
        code_path = temp_dir / "assistant.py"
        code_path.write_text(code)

        scanner = OpenAIAssistantsScanner(path=code_path)
        findings = scanner.scan()

        # Should find multiple issues
        assert len(findings) >= 2

    def test_scan_directory(self, temp_dir):
        """Test scanning a directory with multiple Python files."""
        code1 = '''
from openai import OpenAI
client = OpenAI()
assistant = client.beta.assistants.create(
    tools=[{"type": "code_interpreter"}],
    model="gpt-4"
)
'''
        code2 = '''
import openai
openai.api_key = "sk-1234567890abcdefghijklmnop"
'''
        (temp_dir / "assistant1.py").write_text(code1)
        (temp_dir / "assistant2.py").write_text(code2)

        scanner = OpenAIAssistantsScanner(path=temp_dir)
        findings = scanner.scan()

        assert isinstance(findings, list)
        assert len(findings) >= 2

    def test_discover_targets(self, temp_dir):
        """Test target discovery."""
        openai_code = '''
from openai import OpenAI
'''
        non_openai_code = '''
import os
print("hello")
'''
        (temp_dir / "with_openai.py").write_text(openai_code)
        (temp_dir / "without_openai.py").write_text(non_openai_code)

        scanner = OpenAIAssistantsScanner(path=temp_dir)
        targets = list(scanner.discover_targets())

        # Should find the file with OpenAI imports
        target_names = [t.name for t in targets]
        assert "with_openai.py" in target_names

    def test_finding_has_location(self, temp_dir):
        """Test that findings include location information."""
        code = '''
from openai import OpenAI
client = OpenAI()
assistant = client.beta.assistants.create(
    tools=[{"type": "code_interpreter"}],
    model="gpt-4"
)
'''
        code_path = temp_dir / "assistant.py"
        code_path.write_text(code)

        scanner = OpenAIAssistantsScanner(path=code_path)
        findings = scanner.scan()

        for finding in findings:
            assert finding.location is not None
            assert finding.location.file_path is not None

    def test_scan_missing_instructions(self, temp_dir):
        """Test detecting assistant without instructions."""
        code = '''
from openai import OpenAI

client = OpenAI()
assistant = client.beta.assistants.create(
    name="No Instructions",
    tools=[{"type": "code_interpreter"}],
    model="gpt-4"
)
'''
        code_path = temp_dir / "assistant.py"
        code_path.write_text(code)

        scanner = OpenAIAssistantsScanner(path=code_path)
        findings = scanner.scan()

        # Should detect missing instructions
        instruction_findings = [
            f for f in findings if "instruction" in f.title.lower()
        ]
        assert len(instruction_findings) > 0
