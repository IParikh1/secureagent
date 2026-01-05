"""Data Source Registry for tracking agent data access."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set


class DataSourceType(Enum):
    """Types of data sources."""

    FILE_SYSTEM = "file_system"
    DATABASE = "database"
    API = "api"
    VECTOR_STORE = "vector_store"
    MEMORY = "memory"
    WEB = "web"
    MESSAGE_QUEUE = "message_queue"
    CACHE = "cache"
    BLOB_STORAGE = "blob_storage"
    OTHER = "other"


class AccessType(Enum):
    """Types of data access."""

    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"
    DELETE = "delete"
    ADMIN = "admin"


class DataSensitivity(Enum):
    """Data sensitivity levels."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PII = "pii"
    PHI = "phi"  # Protected Health Information
    PCI = "pci"  # Payment Card Industry data


@dataclass
class DataSourceInfo:
    """Information about a data source."""

    name: str
    source_type: DataSourceType
    access_type: AccessType = AccessType.READ
    sensitivity: DataSensitivity = DataSensitivity.INTERNAL
    description: Optional[str] = None
    location: Optional[str] = None  # Path, URL, connection string pattern
    contains_pii: bool = False
    contains_credentials: bool = False
    encrypted: bool = False
    access_controls: List[str] = field(default_factory=list)
    compliance_tags: List[str] = field(default_factory=list)  # GDPR, HIPAA, etc.

    @property
    def is_sensitive(self) -> bool:
        """Check if data source is sensitive."""
        return self.sensitivity in [
            DataSensitivity.CONFIDENTIAL,
            DataSensitivity.RESTRICTED,
            DataSensitivity.PII,
            DataSensitivity.PHI,
            DataSensitivity.PCI,
        ]

    @property
    def has_write_access(self) -> bool:
        """Check if source has write access."""
        return self.access_type in [
            AccessType.WRITE,
            AccessType.READ_WRITE,
            AccessType.DELETE,
            AccessType.ADMIN,
        ]


@dataclass
class DataSourceUsage:
    """Tracks how a data source is used by agents."""

    source: DataSourceInfo
    agent_ids: Set[str] = field(default_factory=set)
    access_patterns: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class DataSourceRegistry:
    """Registry for tracking data sources accessed by agents."""

    def __init__(self):
        """Initialize the registry."""
        self._usage: Dict[str, DataSourceUsage] = {}
        self._custom_sources: Dict[str, DataSourceInfo] = {}

    def register_usage(
        self,
        name: str,
        source_type: DataSourceType,
        access_type: AccessType,
        agent_id: str,
        location: Optional[str] = None,
    ) -> None:
        """Register that an agent accesses a data source.

        Args:
            name: Name of the data source
            source_type: Type of data source
            access_type: Type of access
            agent_id: Agent accessing the source
            location: Optional location/path
        """
        key = f"{source_type.value}/{name}"
        now = datetime.now()

        if key not in self._usage:
            source_info = self._get_source_info(name, source_type, access_type, location)
            self._usage[key] = DataSourceUsage(
                source=source_info,
                first_seen=now,
            )

        self._usage[key].agent_ids.add(agent_id)
        self._usage[key].last_seen = now

    def _get_source_info(
        self,
        name: str,
        source_type: DataSourceType,
        access_type: AccessType,
        location: Optional[str],
    ) -> DataSourceInfo:
        """Get or create data source information."""
        key = f"{source_type.value}/{name}"

        if key in self._custom_sources:
            return self._custom_sources[key]

        # Create info with inferred properties
        source = DataSourceInfo(
            name=name,
            source_type=source_type,
            access_type=access_type,
            location=location,
            sensitivity=self._infer_sensitivity(name, location),
            contains_pii=self._infer_pii(name, location),
            contains_credentials=self._infer_credentials(name, location),
        )

        return source

    def _infer_sensitivity(
        self, name: str, location: Optional[str]
    ) -> DataSensitivity:
        """Infer data sensitivity from name/location."""
        name_lower = name.lower()
        loc_lower = (location or "").lower()

        pii_patterns = ["user", "customer", "personal", "profile", "account"]
        phi_patterns = ["health", "medical", "patient", "diagnosis"]
        pci_patterns = ["payment", "card", "credit", "billing"]
        restricted_patterns = ["secret", "password", "credential", "key", "token"]

        combined = name_lower + loc_lower

        if any(p in combined for p in restricted_patterns):
            return DataSensitivity.RESTRICTED
        if any(p in combined for p in phi_patterns):
            return DataSensitivity.PHI
        if any(p in combined for p in pci_patterns):
            return DataSensitivity.PCI
        if any(p in combined for p in pii_patterns):
            return DataSensitivity.PII

        return DataSensitivity.INTERNAL

    def _infer_pii(self, name: str, location: Optional[str]) -> bool:
        """Infer if source contains PII."""
        combined = (name + (location or "")).lower()
        pii_patterns = [
            "user",
            "customer",
            "personal",
            "email",
            "phone",
            "address",
            "name",
            "ssn",
            "social",
        ]
        return any(p in combined for p in pii_patterns)

    def _infer_credentials(self, name: str, location: Optional[str]) -> bool:
        """Infer if source contains credentials."""
        combined = (name + (location or "")).lower()
        cred_patterns = ["password", "credential", "secret", "key", "token", "auth"]
        return any(p in combined for p in cred_patterns)

    def add_custom_source(self, source: DataSourceInfo) -> None:
        """Add a custom data source definition.

        Args:
            source: Data source information
        """
        key = f"{source.source_type.value}/{source.name}"
        self._custom_sources[key] = source

    def get_source(
        self, name: str, source_type: DataSourceType
    ) -> Optional[DataSourceInfo]:
        """Get data source information.

        Args:
            name: Name of the source
            source_type: Type of source

        Returns:
            DataSourceInfo if found
        """
        key = f"{source_type.value}/{name}"
        if key in self._usage:
            return self._usage[key].source
        return None

    def get_all_usage(self) -> List[DataSourceUsage]:
        """Get all data source usage records.

        Returns:
            List of DataSourceUsage objects
        """
        return list(self._usage.values())

    def get_sensitive_sources(self) -> List[DataSourceUsage]:
        """Get all sensitive data sources in use.

        Returns:
            List of sensitive data source usage records
        """
        return [u for u in self._usage.values() if u.source.is_sensitive]

    def get_pii_sources(self) -> List[DataSourceUsage]:
        """Get all sources containing PII.

        Returns:
            List of PII source usage records
        """
        return [u for u in self._usage.values() if u.source.contains_pii]

    def get_write_sources(self) -> List[DataSourceUsage]:
        """Get all sources with write access.

        Returns:
            List of write source usage records
        """
        return [u for u in self._usage.values() if u.source.has_write_access]

    def get_sources_by_agent(self, agent_id: str) -> List[DataSourceInfo]:
        """Get all data sources accessed by an agent.

        Args:
            agent_id: Agent ID

        Returns:
            List of data sources
        """
        sources = []
        for usage in self._usage.values():
            if agent_id in usage.agent_ids:
                sources.append(usage.source)
        return sources

    def get_agents_accessing_source(
        self, name: str, source_type: DataSourceType
    ) -> Set[str]:
        """Get all agents accessing a specific source.

        Args:
            name: Name of the source
            source_type: Type of source

        Returns:
            Set of agent IDs
        """
        key = f"{source_type.value}/{name}"
        if key in self._usage:
            return self._usage[key].agent_ids
        return set()

    def get_sources_by_type(self, source_type: DataSourceType) -> List[DataSourceUsage]:
        """Get sources by type.

        Args:
            source_type: Source type

        Returns:
            List of matching usage records
        """
        return [
            u for u in self._usage.values() if u.source.source_type == source_type
        ]

    def get_sources_by_sensitivity(
        self, sensitivity: DataSensitivity
    ) -> List[DataSourceUsage]:
        """Get sources by sensitivity level.

        Args:
            sensitivity: Sensitivity level

        Returns:
            List of matching usage records
        """
        return [
            u for u in self._usage.values() if u.source.sensitivity == sensitivity
        ]

    def get_compliance_sources(self, tag: str) -> List[DataSourceUsage]:
        """Get sources with a compliance tag.

        Args:
            tag: Compliance tag (GDPR, HIPAA, etc.)

        Returns:
            List of matching usage records
        """
        return [
            u
            for u in self._usage.values()
            if tag.upper() in [t.upper() for t in u.source.compliance_tags]
        ]

    def get_stats(self) -> Dict[str, any]:
        """Get registry statistics.

        Returns:
            Dictionary of statistics
        """
        total_sources = len(self._usage)
        sensitive_sources = len(self.get_sensitive_sources())
        pii_sources = len(self.get_pii_sources())
        write_sources = len(self.get_write_sources())

        by_type: Dict[str, int] = {}
        by_sensitivity: Dict[str, int] = {}

        for usage in self._usage.values():
            stype = usage.source.source_type.value
            sens = usage.source.sensitivity.value
            by_type[stype] = by_type.get(stype, 0) + 1
            by_sensitivity[sens] = by_sensitivity.get(sens, 0) + 1

        return {
            "total_sources": total_sources,
            "sensitive_sources": sensitive_sources,
            "pii_sources": pii_sources,
            "write_sources": write_sources,
            "by_type": by_type,
            "by_sensitivity": by_sensitivity,
        }
