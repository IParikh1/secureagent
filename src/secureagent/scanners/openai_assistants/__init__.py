"""OpenAI Assistants scanner."""

from secureagent.scanners.openai_assistants.scanner import OpenAIAssistantsScanner
from secureagent.scanners.openai_assistants.rules import OPENAI_RULES

__all__ = ["OpenAIAssistantsScanner", "OPENAI_RULES"]
