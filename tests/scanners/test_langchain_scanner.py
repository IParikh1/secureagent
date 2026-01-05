"""Tests for LangChain scanner."""

import pytest
from pathlib import Path

from secureagent.scanners.langchain.scanner import LangChainScanner
from secureagent.core.models.severity import Severity


class TestLangChainScanner:
    """Tests for LangChain scanner."""

    def test_scanner_initialization(self, temp_dir):
        """Test scanner initialization."""
        scanner = LangChainScanner(path=temp_dir)
        assert scanner is not None
        assert scanner.name == "langchain"

    def test_scan_python_with_shell_tool(self, temp_dir):
        """Test detecting ShellTool usage."""
        code = '''
from langchain.tools import ShellTool
from langchain.agents import initialize_agent

shell_tool = ShellTool()
tools = [shell_tool]
agent = initialize_agent(tools, llm)
'''
        code_path = temp_dir / "agent.py"
        code_path.write_text(code)

        scanner = LangChainScanner(path=code_path)
        findings = scanner.scan()

        # Should detect dangerous shell tool
        dangerous_findings = [
            f for f in findings
            if "tool" in f.title.lower() or "shell" in f.title.lower()
        ]
        assert len(dangerous_findings) > 0

    def test_scan_python_with_python_repl(self, temp_dir):
        """Test detecting PythonREPL usage."""
        code = '''
from langchain.tools import PythonREPLTool
from langchain.agents import AgentExecutor

python_repl = PythonREPLTool()
'''
        code_path = temp_dir / "agent.py"
        code_path.write_text(code)

        scanner = LangChainScanner(path=code_path)
        findings = scanner.scan()

        # Should detect code execution risk
        code_findings = [
            f for f in findings
            if "python" in f.title.lower() or "execution" in f.title.lower() or "code" in f.title.lower()
        ]
        assert len(code_findings) > 0

    def test_scan_hardcoded_api_key(self, temp_dir):
        """Test detecting hardcoded API keys."""
        code = '''
from langchain_openai import ChatOpenAI

# Hardcoded API key - bad practice
llm = ChatOpenAI(openai_api_key="sk-proj-1234567890abcdefghijklmnopqrstuv")
'''
        code_path = temp_dir / "agent.py"
        code_path.write_text(code)

        scanner = LangChainScanner(path=code_path)
        findings = scanner.scan()

        # Should detect hardcoded API key
        key_findings = [
            f for f in findings
            if "key" in f.title.lower() or "credential" in f.title.lower()
        ]
        assert len(key_findings) > 0

    def test_scan_verbose_mode(self, temp_dir):
        """Test detecting verbose mode enabled."""
        code = '''
from langchain.agents import initialize_agent

agent = initialize_agent(tools, llm, verbose=True)
'''
        code_path = temp_dir / "agent.py"
        code_path.write_text(code)

        scanner = LangChainScanner(path=code_path)
        findings = scanner.scan()

        # Should detect verbose mode
        verbose_findings = [
            f for f in findings if "verbose" in f.title.lower()
        ]
        assert len(verbose_findings) > 0

    def test_scan_clean_code(self, temp_dir):
        """Test scanning clean code without issues."""
        code = '''
import os
from langchain_openai import ChatOpenAI
from langchain.tools import Tool

# Using environment variable for API key (good practice)
llm = ChatOpenAI(openai_api_key=os.environ.get("OPENAI_API_KEY"))

def calculator(input_str):
    """A simple calculator that only adds two numbers."""
    try:
        a, b = input_str.split("+")
        return float(a.strip()) + float(b.strip())
    except:
        return "Invalid input"

calculator_tool = Tool(
    name="Calculator",
    func=calculator,
    description="Useful for addition"
)
'''
        code_path = temp_dir / "agent.py"
        code_path.write_text(code)

        scanner = LangChainScanner(path=code_path)
        findings = scanner.scan()

        # Should have minimal critical findings for this simple code
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0

    def test_scan_sql_database(self, temp_dir):
        """Test detecting SQL database usage."""
        code = '''
from langchain.sql_database import SQLDatabase
from langchain.agents import create_sql_agent

db = SQLDatabase.from_uri("sqlite:///./db.sqlite")
agent = create_sql_agent(llm, db)
'''
        code_path = temp_dir / "agent.py"
        code_path.write_text(code)

        scanner = LangChainScanner(path=code_path)
        findings = scanner.scan()

        # Should detect SQL-related findings
        sql_findings = [
            f for f in findings if "sql" in f.title.lower()
        ]
        assert len(sql_findings) > 0

    def test_scan_memory_without_encryption(self, temp_dir):
        """Test detecting unencrypted memory usage."""
        code = '''
from langchain.memory import ConversationBufferMemory

memory = ConversationBufferMemory()
'''
        code_path = temp_dir / "agent.py"
        code_path.write_text(code)

        scanner = LangChainScanner(path=code_path)
        findings = scanner.scan()

        # Should detect memory configuration
        memory_findings = [
            f for f in findings if "memory" in f.title.lower()
        ]
        assert len(memory_findings) > 0

    def test_scan_directory(self, temp_dir):
        """Test scanning a directory with multiple Python files."""
        # Create multiple files
        code1 = '''
from langchain.tools import ShellTool
shell = ShellTool()
'''
        code2 = '''
from langchain_openai import ChatOpenAI
llm = ChatOpenAI(api_key="sk-test123456789012345678901234567890")
'''
        (temp_dir / "agent1.py").write_text(code1)
        (temp_dir / "agent2.py").write_text(code2)

        scanner = LangChainScanner(path=temp_dir)
        findings = scanner.scan()

        assert isinstance(findings, list)
        # Should find issues in both files
        assert len(findings) >= 2

    def test_discover_targets(self, temp_dir):
        """Test target discovery."""
        # Create Python files with and without LangChain imports
        langchain_code = '''
from langchain.agents import initialize_agent
'''
        non_langchain_code = '''
import os
print("hello")
'''
        (temp_dir / "with_langchain.py").write_text(langchain_code)
        (temp_dir / "without_langchain.py").write_text(non_langchain_code)

        scanner = LangChainScanner(path=temp_dir)
        targets = list(scanner.discover_targets())

        # Should find the file with LangChain imports
        target_names = [t.name for t in targets]
        assert "with_langchain.py" in target_names

    def test_scan_file_tools(self, temp_dir):
        """Test detecting file management tools."""
        code = '''
from langchain.tools.file_management import ReadFileTool, WriteFileTool

read_tool = ReadFileTool()
write_tool = WriteFileTool()
'''
        code_path = temp_dir / "file_agent.py"
        code_path.write_text(code)

        scanner = LangChainScanner(path=code_path)
        findings = scanner.scan()

        # Should detect file access tools
        file_findings = [
            f for f in findings
            if "file" in f.title.lower() or "tool" in f.title.lower()
        ]
        assert len(file_findings) > 0

    def test_finding_has_location(self, temp_dir):
        """Test that findings include location information."""
        code = '''
from langchain.tools import ShellTool
shell = ShellTool()
'''
        code_path = temp_dir / "agent.py"
        code_path.write_text(code)

        scanner = LangChainScanner(path=code_path)
        findings = scanner.scan()

        for finding in findings:
            assert finding.location is not None
            assert finding.location.file_path is not None
