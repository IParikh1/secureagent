"""Terraform Security Scanner implementation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Dict, Any, Union, Generator

from secureagent.core.models.finding import Finding, FindingDomain, Location
from secureagent.core.models.severity import Severity
from secureagent.core.scanner.base import BaseScanner
from secureagent.core.scanner.registry import register_scanner

logger = logging.getLogger(__name__)


@register_scanner
class TerraformScanner(BaseScanner):
    """Scanner for Terraform IaC files."""

    name = "terraform"
    description = "Scans Terraform files for security misconfigurations"
    version = "1.0.0"

    def __init__(self, path=None):
        """Initialize the Terraform scanner."""
        super().__init__(path)
        self._hcl2 = None

    @property
    def hcl2(self):
        """Lazy load hcl2 parser."""
        if self._hcl2 is None:
            try:
                import hcl2
                self._hcl2 = hcl2
            except ImportError:
                raise ImportError(
                    "python-hcl2 is required for Terraform scanning. "
                    "Install with: pip install secureagent[iac]"
                )
        return self._hcl2

    def discover_targets(self) -> Generator[Path, None, None]:
        """Discover Terraform files."""
        if self.path.is_file() and self.path.suffix == '.tf':
            yield self.path
            return

        for tf_file in self.path.glob("**/*.tf"):
            if tf_file.is_file():
                yield tf_file

    def scan(self) -> List[Finding]:
        """Run Terraform security scan."""
        logger.info("Starting Terraform security scan...")
        self.findings = []

        for tf_file in self.discover_targets():
            self._scan_file(tf_file)

        logger.info(f"Terraform scan complete. Found {len(self.findings)} issues.")
        return self.findings

    def _scan_file(self, file_path: Path) -> None:
        """Scan a single Terraform file."""
        try:
            with open(file_path, 'r') as f:
                config = self.hcl2.load(f)

            source = str(file_path)
            self._check_security_groups(config, source)
            self._check_s3_buckets(config, source)
            self._check_rds_instances(config, source)
            self._check_ec2_instances(config, source)

        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")

    def _check_security_groups(self, config: Dict, source: str) -> None:
        """Check for overly permissive security group rules."""
        resources = config.get('resource', [])
        if isinstance(resources, dict):
            resources = [resources]

        for resource_block in resources:
            for sg_name, sg_configs in resource_block.get('aws_security_group', {}).items():
                if isinstance(sg_configs, list):
                    sg_configs = sg_configs[0] if sg_configs else {}

                ingress_rules = sg_configs.get('ingress', [])
                if isinstance(ingress_rules, dict):
                    ingress_rules = [ingress_rules]

                for rule in ingress_rules:
                    if not isinstance(rule, dict):
                        continue

                    cidr_blocks = rule.get('cidr_blocks', [])
                    from_port = rule.get('from_port', 0)
                    to_port = rule.get('to_port', 65535)
                    protocol = rule.get('protocol', '-1')

                    if '0.0.0.0/0' in cidr_blocks:
                        if protocol == '-1':
                            self.findings.append(Finding(rule_id="TF-SG-001",
                                domain=FindingDomain.TERRAFORM,
                                title="Security Group Allows All Inbound Traffic",
                                description=f"Security group '{sg_name}' allows all traffic from any IP",
                                severity=Severity.CRITICAL,
                                location=Location(file_path=source, resource_id=sg_name),
                                remediation="Restrict ingress rules to specific IPs and ports",
                                cwe_id="CWE-284",
                            ))

                        if from_port <= 22 <= to_port:
                            self.findings.append(Finding(rule_id="TF-SG-002",
                                domain=FindingDomain.TERRAFORM,
                                title="Security Group Exposes SSH to Internet",
                                description=f"Security group '{sg_name}' allows SSH (port 22) from any IP",
                                severity=Severity.CRITICAL,
                                location=Location(file_path=source, resource_id=sg_name),
                                remediation="Restrict SSH access to specific IP ranges or use a bastion host",
                                cwe_id="CWE-284",
                            ))

                        if from_port <= 3389 <= to_port:
                            self.findings.append(Finding(rule_id="TF-SG-003",
                                domain=FindingDomain.TERRAFORM,
                                title="Security Group Exposes RDP to Internet",
                                description=f"Security group '{sg_name}' allows RDP (port 3389) from any IP",
                                severity=Severity.CRITICAL,
                                location=Location(file_path=source, resource_id=sg_name),
                                remediation="Restrict RDP access to specific IP ranges",
                                cwe_id="CWE-284",
                            ))

                        db_ports = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB"}
                        for port, db_name in db_ports.items():
                            if from_port <= port <= to_port:
                                self.findings.append(Finding(
                                    rule_id=f"TF-SG-DB-{port}",
                                    domain=FindingDomain.TERRAFORM,
                                    title=f"Security Group Exposes {db_name} to Internet",
                                    description=f"Security group '{sg_name}' allows {db_name} (port {port}) from any IP",
                                    severity=Severity.HIGH,
                                    location=Location(file_path=source, resource_id=sg_name),
                                    remediation=f"Restrict {db_name} access to application subnets only",
                                    cwe_id="CWE-284",
                                ))

    def _check_s3_buckets(self, config: Dict, source: str) -> None:
        """Check for insecure S3 bucket configurations."""
        resources = config.get('resource', [])
        if isinstance(resources, dict):
            resources = [resources]

        for resource_block in resources:
            for bucket_name, bucket_configs in resource_block.get('aws_s3_bucket', {}).items():
                if isinstance(bucket_configs, list):
                    bucket_configs = bucket_configs[0] if bucket_configs else {}

                acl = bucket_configs.get('acl', 'private')
                if acl in ['public-read', 'public-read-write']:
                    self.findings.append(Finding(rule_id="TF-S3-001",
                                domain=FindingDomain.TERRAFORM,
                                title="S3 Bucket Has Public ACL",
                        description=f"S3 bucket '{bucket_name}' has a public ACL ({acl})",
                        severity=Severity.CRITICAL,
                        location=Location(file_path=source, resource_id=bucket_name),
                        remediation="Remove public ACL and use bucket policies with specific principals",
                        cwe_id="CWE-284",
                    ))

            for block_name, block_configs in resource_block.get('aws_s3_bucket_public_access_block', {}).items():
                if isinstance(block_configs, list):
                    block_configs = block_configs[0] if block_configs else {}

                checks = ['block_public_acls', 'block_public_policy', 'ignore_public_acls', 'restrict_public_buckets']
                for check in checks:
                    if not block_configs.get(check, True):
                        self.findings.append(Finding(rule_id="TF-S3-002",
                                domain=FindingDomain.TERRAFORM,
                                title=f"S3 Block Public Access: {check} Disabled",
                            description=f"Public access block '{block_name}' has {check} disabled",
                            severity=Severity.MEDIUM,
                            location=Location(file_path=source, resource_id=block_name),
                            remediation=f"Set {check} = true",
                        ))

    def _check_rds_instances(self, config: Dict, source: str) -> None:
        """Check for insecure RDS configurations."""
        resources = config.get('resource', [])
        if isinstance(resources, dict):
            resources = [resources]

        for resource_block in resources:
            for rds_name, rds_configs in resource_block.get('aws_db_instance', {}).items():
                if isinstance(rds_configs, list):
                    rds_configs = rds_configs[0] if rds_configs else {}

                if rds_configs.get('publicly_accessible', False):
                    self.findings.append(Finding(rule_id="TF-RDS-001",
                                domain=FindingDomain.TERRAFORM,
                                title="RDS Instance Publicly Accessible",
                        description=f"RDS instance '{rds_name}' is publicly accessible",
                        severity=Severity.CRITICAL,
                        location=Location(file_path=source, resource_id=rds_name),
                        remediation="Set publicly_accessible = false and use VPC private subnets",
                        cwe_id="CWE-284",
                    ))

                if not rds_configs.get('storage_encrypted', False):
                    self.findings.append(Finding(rule_id="TF-RDS-002",
                                domain=FindingDomain.TERRAFORM,
                                title="RDS Instance Not Encrypted",
                        description=f"RDS instance '{rds_name}' does not have storage encryption enabled",
                        severity=Severity.HIGH,
                        location=Location(file_path=source, resource_id=rds_name),
                        remediation="Set storage_encrypted = true and specify a KMS key",
                        cwe_id="CWE-311",
                    ))

                if rds_configs.get('backup_retention_period', 0) == 0:
                    self.findings.append(Finding(rule_id="TF-RDS-003",
                                domain=FindingDomain.TERRAFORM,
                                title="RDS Instance Has No Backup Retention",
                        description=f"RDS instance '{rds_name}' has backup retention disabled",
                        severity=Severity.MEDIUM,
                        location=Location(file_path=source, resource_id=rds_name),
                        remediation="Set backup_retention_period to at least 7 days",
                    ))

    def _check_ec2_instances(self, config: Dict, source: str) -> None:
        """Check for insecure EC2 configurations."""
        resources = config.get('resource', [])
        if isinstance(resources, dict):
            resources = [resources]

        for resource_block in resources:
            for instance_name, instance_configs in resource_block.get('aws_instance', {}).items():
                if isinstance(instance_configs, list):
                    instance_configs = instance_configs[0] if instance_configs else {}

                metadata_options = instance_configs.get('metadata_options', {})
                if isinstance(metadata_options, list):
                    metadata_options = metadata_options[0] if metadata_options else {}

                if metadata_options.get('http_tokens', 'optional') != 'required':
                    self.findings.append(Finding(rule_id="TF-EC2-001",
                                domain=FindingDomain.TERRAFORM,
                                title="EC2 Instance Does Not Require IMDSv2",
                        description=f"EC2 instance '{instance_name}' does not enforce IMDSv2",
                        severity=Severity.MEDIUM,
                        location=Location(file_path=source, resource_id=instance_name),
                        remediation="Set metadata_options.http_tokens = 'required'",
                        cwe_id="CWE-918",
                    ))

                root_block = instance_configs.get('root_block_device', {})
                if isinstance(root_block, list):
                    root_block = root_block[0] if root_block else {}

                if not root_block.get('encrypted', False):
                    self.findings.append(Finding(rule_id="TF-EC2-002",
                                domain=FindingDomain.TERRAFORM,
                                title="EC2 Root Volume Not Encrypted",
                        description=f"EC2 instance '{instance_name}' root volume is not encrypted",
                        severity=Severity.MEDIUM,
                        location=Location(file_path=source, resource_id=instance_name),
                        remediation="Set root_block_device.encrypted = true",
                        cwe_id="CWE-311",
                    ))
