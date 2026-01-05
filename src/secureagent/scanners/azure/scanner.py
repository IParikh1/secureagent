"""Azure Security Scanner implementation."""

from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional

from secureagent.core.models.finding import Finding, Location
from secureagent.core.models.severity import Severity
from secureagent.core.scanner.base import CloudScanner
from secureagent.core.scanner.registry import register_scanner

logger = logging.getLogger(__name__)


@register_scanner
class AzureScanner(CloudScanner):
    """Scanner for Azure cloud resources."""

    name = "azure"
    description = "Scans Azure resources for security misconfigurations"
    version = "1.0.0"
    provider = "azure"

    def __init__(self, path=None, subscription_id: Optional[str] = None):
        """Initialize the Azure scanner."""
        super().__init__(path)
        self.subscription_id = subscription_id
        self._credential = None
        self._storage_client = None
        self._keyvault_client = None

    @property
    def credential(self):
        """Lazy load Azure credentials."""
        if self._credential is None:
            try:
                from azure.identity import DefaultAzureCredential
                self._credential = DefaultAzureCredential()
            except ImportError:
                raise ImportError(
                    "azure-identity is required for Azure scanning. "
                    "Install with: pip install secureagent[azure]"
                )
        return self._credential

    @property
    def storage_client(self):
        """Lazy load Storage management client."""
        if self._storage_client is None:
            try:
                from azure.mgmt.storage import StorageManagementClient
                self._storage_client = StorageManagementClient(
                    self.credential, self.subscription_id
                )
            except ImportError:
                raise ImportError(
                    "azure-mgmt-storage is required for Azure scanning. "
                    "Install with: pip install secureagent[azure]"
                )
        return self._storage_client

    def scan(self) -> List[Finding]:
        """Run all Azure security scans."""
        logger.info("Starting Azure security scan...")
        self.findings = []

        if not self.subscription_id:
            logger.warning("No subscription ID provided, skipping Azure scan")
            return self.findings

        self.scan_storage_accounts()

        logger.info(f"Azure scan complete. Found {len(self.findings)} issues.")
        return self.findings

    def scan_storage_accounts(self) -> List[Finding]:
        """Scan Azure Storage accounts for misconfigurations."""
        logger.info("Scanning Azure Storage accounts...")
        storage_findings = []

        try:
            for account in self.storage_client.storage_accounts.list():
                account_name = account.name
                resource_group = account.id.split('/')[4]

                # Check HTTPS only
                if not account.enable_https_traffic_only:
                    storage_findings.append(Finding(
                        rule_id="AZURE-STORAGE-001",
                        title="Storage Account Allows HTTP Traffic",
                        description=f"Storage account {account_name} allows non-HTTPS traffic",
                        severity=Severity.HIGH,
                        location=Location(
                            resource_id=account.id,
                            resource_type="Microsoft.Storage/storageAccounts"
                        ),
                        remediation="Enable 'Secure transfer required' in storage account settings",
                        cwe_id="CWE-319",
                    ))

                # Check public blob access
                if account.allow_blob_public_access:
                    storage_findings.append(Finding(
                        rule_id="AZURE-STORAGE-002",
                        title="Storage Account Allows Public Blob Access",
                        description=f"Storage account {account_name} allows public blob access",
                        severity=Severity.HIGH,
                        location=Location(
                            resource_id=account.id,
                            resource_type="Microsoft.Storage/storageAccounts"
                        ),
                        remediation="Disable 'Allow Blob public access' in storage account settings",
                        cwe_id="CWE-284",
                    ))

                # Check network rules
                if account.network_rule_set:
                    if account.network_rule_set.default_action == "Allow":
                        storage_findings.append(Finding(
                            rule_id="AZURE-STORAGE-003",
                            title="Storage Account Allows All Network Access",
                            description=f"Storage account {account_name} allows access from all networks",
                            severity=Severity.MEDIUM,
                            location=Location(
                                resource_id=account.id,
                                resource_type="Microsoft.Storage/storageAccounts"
                            ),
                            remediation="Configure network rules to restrict access to specific VNets/IPs",
                            cwe_id="CWE-284",
                        ))

                # Check minimum TLS version
                min_tls = getattr(account, 'minimum_tls_version', None)
                if min_tls and min_tls != "TLS1_2":
                    storage_findings.append(Finding(
                        rule_id="AZURE-STORAGE-004",
                        title="Storage Account Uses Outdated TLS",
                        description=f"Storage account {account_name} allows TLS versions older than 1.2",
                        severity=Severity.MEDIUM,
                        location=Location(
                            resource_id=account.id,
                            resource_type="Microsoft.Storage/storageAccounts"
                        ),
                        remediation="Set minimum TLS version to TLS 1.2",
                        cwe_id="CWE-326",
                    ))

        except Exception as e:
            logger.error(f"Error scanning storage accounts: {e}")

        self.findings.extend(storage_findings)
        return storage_findings
