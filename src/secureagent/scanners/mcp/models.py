"""MCP configuration models."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MCPServer:
    """Represents an MCP server configuration."""

    name: str
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    url: Optional[str] = None
    raw_config: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_remote(self) -> bool:
        """Check if this is a remote server (has URL)."""
        return self.url is not None

    @property
    def is_local(self) -> bool:
        """Check if this is a local server (has command)."""
        return self.command is not None


@dataclass
class MCPConfig:
    """Parsed MCP configuration file."""

    file_path: str
    servers: Dict[str, MCPServer] = field(default_factory=dict)
    raw_content: str = ""
    parse_errors: List[str] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """Check if there were parsing errors."""
        return len(self.parse_errors) > 0

    @property
    def server_count(self) -> int:
        """Get number of configured servers."""
        return len(self.servers)

    @property
    def remote_servers(self) -> List[MCPServer]:
        """Get list of remote servers."""
        return [s for s in self.servers.values() if s.is_remote]

    @property
    def local_servers(self) -> List[MCPServer]:
        """Get list of local servers."""
        return [s for s in self.servers.values() if s.is_local]
