"""OpenAI Assistants configuration models."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class OpenAIToolType(Enum):
    """Types of OpenAI Assistant tools."""
    CODE_INTERPRETER = "code_interpreter"
    FILE_SEARCH = "file_search"
    RETRIEVAL = "retrieval"  # Legacy name
    FUNCTION = "function"


@dataclass
class OpenAIFunction:
    """Represents a function tool definition."""

    name: str
    description: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    is_dangerous: bool = False
    raw_config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OpenAIAssistant:
    """Represents an OpenAI Assistant configuration."""

    assistant_id: Optional[str] = None
    name: Optional[str] = None
    model: str = "gpt-4"
    instructions: Optional[str] = None
    tools: List[OpenAIToolType] = field(default_factory=list)
    functions: List[OpenAIFunction] = field(default_factory=list)
    file_ids: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_config: Dict[str, Any] = field(default_factory=dict)

    @property
    def has_code_interpreter(self) -> bool:
        """Check if code interpreter is enabled."""
        return OpenAIToolType.CODE_INTERPRETER in self.tools

    @property
    def has_file_search(self) -> bool:
        """Check if file search/retrieval is enabled."""
        return OpenAIToolType.FILE_SEARCH in self.tools or OpenAIToolType.RETRIEVAL in self.tools

    @property
    def has_functions(self) -> bool:
        """Check if function calling is enabled."""
        return OpenAIToolType.FUNCTION in self.tools or len(self.functions) > 0

    @property
    def has_instructions(self) -> bool:
        """Check if instructions are set."""
        return self.instructions is not None and len(self.instructions.strip()) > 0


@dataclass
class OpenAIConfig:
    """Parsed OpenAI configuration from code analysis."""

    file_path: str
    assistants: List[OpenAIAssistant] = field(default_factory=list)
    functions: List[OpenAIFunction] = field(default_factory=list)
    api_keys_found: List[str] = field(default_factory=list)
    raw_content: str = ""
    parse_errors: List[str] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """Check if there were parsing errors."""
        return len(self.parse_errors) > 0

    @property
    def assistant_count(self) -> int:
        """Get number of assistants found."""
        return len(self.assistants)
