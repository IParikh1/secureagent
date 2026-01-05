"""Scanner registry for plugin-style scanner management."""

from typing import Any, Dict, List, Optional, Type

from secureagent.core.scanner.base import BaseScanner


class ScannerRegistry:
    """Registry for managing scanner plugins.

    Scanners register themselves with this registry, allowing dynamic
    discovery and instantiation based on target type or explicit selection.
    """

    def __init__(self) -> None:
        """Initialize the scanner registry."""
        self._scanners: Dict[str, Type[BaseScanner]] = {}
        self._instances: Dict[str, BaseScanner] = {}

    def register(
        self,
        name: str,
        scanner_class: Type[BaseScanner],
        override: bool = False
    ) -> None:
        """Register a scanner class.

        Args:
            name: Unique scanner name
            scanner_class: Scanner class (not instance)
            override: Whether to override existing registration

        Raises:
            ValueError: If scanner already registered and override=False
        """
        if name in self._scanners and not override:
            raise ValueError(f"Scanner '{name}' is already registered")

        self._scanners[name] = scanner_class

    def unregister(self, name: str) -> None:
        """Unregister a scanner.

        Args:
            name: Scanner name to unregister
        """
        self._scanners.pop(name, None)
        self._instances.pop(name, None)

    def get(
        self,
        name: str,
        config: Optional[Dict[str, Any]] = None,
        cached: bool = True
    ) -> Optional[BaseScanner]:
        """Get a scanner instance by name.

        Args:
            name: Scanner name
            config: Configuration to pass to scanner
            cached: Whether to return cached instance

        Returns:
            Scanner instance or None if not found
        """
        if name not in self._scanners:
            return None

        # Return cached instance if available and requested
        if cached and name in self._instances:
            return self._instances[name]

        # Create new instance
        scanner_class = self._scanners[name]
        instance = scanner_class(config=config)

        # Cache if requested
        if cached:
            self._instances[name] = instance

        return instance

    def get_all(self) -> List[str]:
        """Get all registered scanner names.

        Returns:
            List of scanner names
        """
        return list(self._scanners.keys())

    def get_by_domain(self, domain: str) -> List[str]:
        """Get scanners for a specific domain.

        Args:
            domain: Domain name (mcp, langchain, aws, etc.)

        Returns:
            List of scanner names for that domain
        """
        matching = []
        for name, scanner_class in self._scanners.items():
            # Check if scanner handles this domain
            scanner_name = getattr(scanner_class, 'name', name)
            if scanner_name.startswith(domain) or domain in scanner_name:
                matching.append(name)
        return matching

    def get_for_target(self, target: str) -> List[str]:
        """Get scanners that can handle a target.

        Args:
            target: Target path or identifier

        Returns:
            List of scanner names that can handle the target
        """
        matching = []
        for name, scanner_class in self._scanners.items():
            instance = scanner_class()
            if instance.validate_target(target):
                matching.append(name)
        return matching

    def list_scanners(self) -> List[Dict[str, Any]]:
        """Get detailed info about all registered scanners.

        Returns:
            List of scanner info dictionaries
        """
        scanners = []
        for name, scanner_class in self._scanners.items():
            scanners.append({
                "name": name,
                "class": scanner_class.__name__,
                "description": getattr(scanner_class, 'description', ''),
                "version": getattr(scanner_class, 'version', '1.0.0'),
                "file_patterns": getattr(scanner_class, 'file_patterns', []),
                "supports_auto_discovery": getattr(scanner_class, 'supports_auto_discovery', False),
                "supports_remediation": getattr(scanner_class, 'supports_remediation', False),
            })
        return scanners

    def clear(self) -> None:
        """Clear all registered scanners."""
        self._scanners.clear()
        self._instances.clear()

    def __contains__(self, name: str) -> bool:
        """Check if scanner is registered."""
        return name in self._scanners

    def __len__(self) -> int:
        """Get number of registered scanners."""
        return len(self._scanners)


# Global scanner registry instance
scanner_registry = ScannerRegistry()


def register_scanner(name_or_cls=None):
    """Decorator to register a scanner class.

    Usage:
        @register_scanner("mcp")
        class MCPScanner(BaseScanner):
            ...

        # Or use class name:
        @register_scanner()
        class MCPScanner(BaseScanner):
            ...

        # Or without parentheses:
        @register_scanner
        class MCPScanner(BaseScanner):
            ...
    """
    def decorator(cls: Type[BaseScanner]) -> Type[BaseScanner]:
        scanner_name = getattr(cls, 'name', cls.__name__.lower())
        scanner_registry.register(scanner_name, cls, override=True)
        return cls

    # Handle @register_scanner without parentheses
    if isinstance(name_or_cls, type):
        # Called without parentheses - name_or_cls is actually the class
        return decorator(name_or_cls)

    # Handle @register_scanner() or @register_scanner("name")
    if name_or_cls is not None:
        # Called with a custom name
        def name_decorator(cls: Type[BaseScanner]) -> Type[BaseScanner]:
            scanner_registry.register(name_or_cls, cls, override=True)
            return cls
        return name_decorator

    # Called with empty parentheses @register_scanner()
    return decorator
