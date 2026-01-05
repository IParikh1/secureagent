"""AutoGPT and CrewAI multi-agent scanner."""

from secureagent.scanners.autogpt.scanner import AutoGPTScanner
from secureagent.scanners.autogpt.rules import AUTOGPT_RULES

__all__ = ["AutoGPTScanner", "AUTOGPT_RULES"]
