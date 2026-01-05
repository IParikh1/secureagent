"""Base scanner interface that all scanners must implement."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from secureagent.core.models.finding import Finding, ScanResult


class BaseScanner(ABC):
    """Abstract base class for all security scanners.

    All scanner implementations (MCP, LangChain, OpenAI, AWS, etc.) must
    inherit from this class and implement the required methods.
    """

    # Scanner metadata - override in subclasses
    name: str = "base"
    description: str = "Base scanner"
    version: str = "1.0.0"

    # Supported file patterns for auto-discovery
    file_patterns: List[str] = []

    # Scanner capabilities
    supports_auto_discovery: bool = False
    supports_remediation: bool = False
    supports_risk_scoring: bool = False

    def __init__(
        self,
        path: Optional[Path] = None,
        config: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """Initialize scanner with optional configuration.

        Args:
            path: Path to file/directory to scan
            config: Scanner-specific configuration dictionary
            **kwargs: Additional scanner-specific options
        """
        self.path = Path(path) if path else Path(".")
        self.config = config or {}
        self.findings: List[Finding] = []
        self._initialized = False

    def initialize(self) -> None:
        """Initialize scanner resources.

        Called before scanning begins. Override to set up connections,
        load models, etc.
        """
        self._initialized = True

    def cleanup(self) -> None:
        """Clean up scanner resources.

        Called after scanning completes. Override to close connections,
        release resources, etc.
        """
        self._initialized = False

    @abstractmethod
    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Scan a target for security issues.

        Args:
            target: Path to file/directory, URL, or resource identifier
            **kwargs: Scanner-specific options

        Returns:
            ScanResult containing all findings
        """
        pass

    def scan_file(self, file_path: Path, **kwargs: Any) -> ScanResult:
        """Scan a single file.

        Args:
            file_path: Path to the file to scan
            **kwargs: Scanner-specific options

        Returns:
            ScanResult for this file
        """
        return self.scan(str(file_path), **kwargs)

    def scan_directory(
        self,
        directory: Path,
        recursive: bool = True,
        **kwargs: Any
    ) -> ScanResult:
        """Scan a directory for matching files.

        Args:
            directory: Path to directory
            recursive: Whether to scan subdirectories
            **kwargs: Scanner-specific options

        Returns:
            Combined ScanResult for all files
        """
        all_findings: List[Finding] = []

        # Find matching files
        targets = self.discover_targets(directory, recursive)

        for target in targets:
            result = self.scan_file(Path(target), **kwargs)
            all_findings.extend(result.findings)

        return ScanResult(
            findings=all_findings,
            scan_path=str(directory),
            scanner_name=self.name,
        )

    def discover_targets(
        self,
        directory: Path,
        recursive: bool = True
    ) -> List[str]:
        """Discover scan targets in a directory.

        Args:
            directory: Directory to search
            recursive: Whether to search recursively

        Returns:
            List of file paths to scan
        """
        targets: List[str] = []

        if not self.file_patterns:
            return targets

        for pattern in self.file_patterns:
            if recursive:
                matches = directory.rglob(pattern)
            else:
                matches = directory.glob(pattern)

            for match in matches:
                if match.is_file():
                    targets.append(str(match))

        return sorted(set(targets))

    def get_rules(self) -> List[Dict[str, Any]]:
        """Get list of security rules this scanner checks.

        Returns:
            List of rule definitions with id, title, severity, etc.
        """
        return []

    def validate_target(self, target: str) -> bool:
        """Validate that target can be scanned.

        Args:
            target: Target path or identifier

        Returns:
            True if target is valid for this scanner
        """
        return True

    def get_supported_formats(self) -> Set[str]:
        """Get file formats/types this scanner supports.

        Returns:
            Set of supported format identifiers
        """
        return set()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name}, version={self.version})>"


class CloudScanner(BaseScanner):
    """Base class for cloud infrastructure scanners (AWS, Azure, GCP)."""

    # Cloud-specific attributes
    provider: str = "unknown"
    requires_credentials: bool = True

    def __init__(
        self,
        path: Optional[Path] = None,
        config: Optional[Dict[str, Any]] = None,
        region: Optional[str] = None,
        profile: Optional[str] = None,
        **kwargs
    ):
        """Initialize cloud scanner.

        Args:
            path: Path for configuration files
            config: Scanner configuration
            region: Cloud region to scan
            profile: Credential profile name
            **kwargs: Additional options
        """
        super().__init__(path=path, config=config, **kwargs)
        self.region = region
        self.profile = profile

    @abstractmethod
    def list_resources(self, resource_type: str) -> List[Dict[str, Any]]:
        """List cloud resources of a given type.

        Args:
            resource_type: Type of resource to list

        Returns:
            List of resource dictionaries
        """
        pass

    def check_credentials(self) -> bool:
        """Verify cloud credentials are available.

        Returns:
            True if credentials are valid
        """
        return False


class AgentScanner(BaseScanner):
    """Base class for AI agent scanners (MCP, LangChain, OpenAI, etc.)."""

    # Agent-specific attributes
    framework: str = "unknown"
    supports_inventory: bool = True
    supports_data_flow: bool = True

    @abstractmethod
    def extract_agent_info(self, target: str) -> Dict[str, Any]:
        """Extract agent information from configuration.

        Args:
            target: Path to agent configuration

        Returns:
            Dictionary of agent information
        """
        pass

    @abstractmethod
    def analyze_permissions(self, target: str) -> List[Dict[str, Any]]:
        """Analyze permissions/capabilities of an agent.

        Args:
            target: Path to agent configuration

        Returns:
            List of permission dictionaries
        """
        pass

    def analyze_data_flow(self, target: str) -> List[Dict[str, Any]]:
        """Analyze data flow through an agent.

        Args:
            target: Path to agent configuration

        Returns:
            List of data flow dictionaries
        """
        return []
