"""Security scanners for SecureAgent."""

# Import scanners to register them with the registry
from secureagent.scanners.mcp import MCPScanner
from secureagent.scanners.langchain import LangChainScanner
from secureagent.scanners.openai_assistants import OpenAIAssistantsScanner
from secureagent.scanners.autogpt import AutoGPTScanner

# Cloud scanners - imported with try/except for optional dependencies
try:
    from secureagent.scanners.aws import AWSScanner
except ImportError:
    AWSScanner = None

try:
    from secureagent.scanners.azure import AzureScanner
except ImportError:
    AzureScanner = None

try:
    from secureagent.scanners.terraform import TerraformScanner
except ImportError:
    TerraformScanner = None

__all__ = [
    "MCPScanner",
    "LangChainScanner",
    "OpenAIAssistantsScanner",
    "AutoGPTScanner",
    "AWSScanner",
    "AzureScanner",
    "TerraformScanner",
]
