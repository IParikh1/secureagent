"""LangChain agent scanner."""

from secureagent.scanners.langchain.scanner import LangChainScanner
from secureagent.scanners.langchain.rules import LANGCHAIN_RULES

__all__ = ["LangChainScanner", "LANGCHAIN_RULES"]
