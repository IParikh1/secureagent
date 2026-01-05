"""AWS Security Scanner implementation."""

from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional

from secureagent.core.models.finding import Finding, FindingDomain, Location
from secureagent.core.models.severity import Severity
from secureagent.core.scanner.base import CloudScanner
from secureagent.core.scanner.registry import register_scanner

logger = logging.getLogger(__name__)


@register_scanner
class AWSScanner(CloudScanner):
    """Scanner for AWS cloud resources."""

    name = "aws"
    description = "Scans AWS resources for security misconfigurations"
    version = "1.0.0"
    provider = "aws"

    SENSITIVE_PORTS = {
        22: ("SSH", Severity.CRITICAL),
        3389: ("RDP", Severity.CRITICAL),
        3306: ("MySQL", Severity.HIGH),
        5432: ("PostgreSQL", Severity.HIGH),
        1433: ("MSSQL", Severity.HIGH),
        27017: ("MongoDB", Severity.HIGH),
        6379: ("Redis", Severity.HIGH),
        9200: ("Elasticsearch", Severity.HIGH),
        23: ("Telnet", Severity.CRITICAL),
        21: ("FTP", Severity.HIGH),
    }

    def __init__(self, path=None, boto3_client=None, **kwargs):
        """Initialize the AWS scanner."""
        super().__init__(path=path, **kwargs)
        self._boto3 = boto3_client
        self._s3_client = None
        self._iam_client = None
        self._ec2_client = None

    @property
    def boto3(self):
        """Lazy load boto3."""
        if self._boto3 is None:
            try:
                import boto3
                self._boto3 = boto3
            except ImportError:
                raise ImportError(
                    "boto3 is required for AWS scanning. Install with: pip install secureagent[aws]"
                )
        return self._boto3

    @property
    def s3_client(self):
        """Lazy load S3 client."""
        if self._s3_client is None:
            self._s3_client = self.boto3.client('s3')
        return self._s3_client

    @property
    def iam_client(self):
        """Lazy load IAM client."""
        if self._iam_client is None:
            self._iam_client = self.boto3.client('iam')
        return self._iam_client

    @property
    def ec2_client(self):
        """Lazy load EC2 client."""
        if self._ec2_client is None:
            self._ec2_client = self.boto3.client('ec2')
        return self._ec2_client

    def scan(self) -> List[Finding]:
        """Run all AWS security scans."""
        logger.info("Starting AWS security scan...")
        self.findings = []

        self.scan_s3_buckets()
        self.scan_iam_policies()
        self.scan_security_groups()

        logger.info(f"AWS scan complete. Found {len(self.findings)} issues.")
        return self.findings

    def scan_s3_buckets(self) -> List[Finding]:
        """Scan S3 buckets for public access."""
        logger.info("Scanning S3 buckets...")
        s3_findings = []

        try:
            response = self.s3_client.list_buckets()

            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']

                # Check bucket ACL
                try:
                    acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        uri = grant.get('Grantee', {}).get('URI', '')

                        if 'AllUsers' in uri:
                            s3_findings.append(Finding(
                                rule_id="AWS-S3-001",
                                domain=FindingDomain.AWS,
                                title="S3 Bucket Publicly Accessible",
                                description=f"Bucket {bucket_name} has public access via ACL (AllUsers grant)",
                                severity=Severity.CRITICAL,
                                location=Location(resource_id=bucket_name, resource_type="AWS::S3::Bucket"),
                                remediation="Remove public ACL grants and enable S3 Block Public Access",
                                cwe_id="CWE-284",
                                metadata={"grant_permission": grant.get('Permission')},
                            ))
                        elif 'AuthenticatedUsers' in uri:
                            s3_findings.append(Finding(
                                rule_id="AWS-S3-002",
                                domain=FindingDomain.AWS,
                                title="S3 Bucket Accessible to All AWS Users",
                                description=f"Bucket {bucket_name} grants access to any authenticated AWS user",
                                severity=Severity.HIGH,
                                location=Location(resource_id=bucket_name, resource_type="AWS::S3::Bucket"),
                                remediation="Remove AuthenticatedUsers grant and restrict access",
                                cwe_id="CWE-284",
                            ))
                except Exception as e:
                    logger.debug(f"Could not check ACL for {bucket_name}: {e}")

                # Check Public Access Block
                try:
                    pab = self.s3_client.get_public_access_block(Bucket=bucket_name)
                    config = pab.get('PublicAccessBlockConfiguration', {})

                    if not all([
                        config.get('BlockPublicAcls', False),
                        config.get('IgnorePublicAcls', False),
                        config.get('BlockPublicPolicy', False),
                        config.get('RestrictPublicBuckets', False)
                    ]):
                        s3_findings.append(Finding(
                            rule_id="AWS-S3-003",
                                domain=FindingDomain.AWS,
                                title="S3 Block Public Access Not Fully Enabled",
                            description=f"Bucket {bucket_name} does not have all Block Public Access settings enabled",
                            severity=Severity.MEDIUM,
                            location=Location(resource_id=bucket_name, resource_type="AWS::S3::Bucket"),
                            remediation="Enable all S3 Block Public Access settings",
                            metadata={"public_access_block": config},
                        ))
                except Exception:
                    s3_findings.append(Finding(
                        rule_id="AWS-S3-004",
                                domain=FindingDomain.AWS,
                                title="S3 Block Public Access Not Configured",
                        description=f"Bucket {bucket_name} has no Block Public Access configuration",
                        severity=Severity.MEDIUM,
                        location=Location(resource_id=bucket_name, resource_type="AWS::S3::Bucket"),
                        remediation="Configure S3 Block Public Access settings",
                    ))

        except Exception as e:
            logger.error(f"Error scanning S3 buckets: {e}")

        self.findings.extend(s3_findings)
        return s3_findings

    def scan_iam_policies(self) -> List[Finding]:
        """Scan IAM users and policies."""
        logger.info("Scanning IAM policies...")
        iam_findings = []

        try:
            response = self.iam_client.list_users()

            for user in response.get('Users', []):
                user_name = user['UserName']
                user_arn = user['Arn']

                # Check attached policies
                try:
                    policies = self.iam_client.list_attached_user_policies(UserName=user_name)
                    admin_policies = ['AdministratorAccess', 'PowerUserAccess', 'IAMFullAccess']

                    for policy in policies.get('AttachedPolicies', []):
                        if policy['PolicyName'] in admin_policies:
                            iam_findings.append(Finding(
                                rule_id="AWS-IAM-001",
                                domain=FindingDomain.AWS,
                                title=f"IAM User Has {policy['PolicyName']} Policy",
                                description=f"User {user_name} has overly permissive {policy['PolicyName']} policy",
                                severity=Severity.HIGH,
                                location=Location(resource_id=user_arn, resource_type="AWS::IAM::User"),
                                remediation="Apply least privilege principle - grant specific permissions",
                                cwe_id="CWE-250",
                                metadata={"user_name": user_name, "policy_name": policy['PolicyName']},
                            ))
                except Exception as e:
                    logger.debug(f"Could not check policies for {user_name}: {e}")

                # Check MFA status
                try:
                    mfa_devices = self.iam_client.list_mfa_devices(UserName=user_name)
                    if not mfa_devices.get('MFADevices', []):
                        iam_findings.append(Finding(
                            rule_id="AWS-IAM-002",
                                domain=FindingDomain.AWS,
                                title="IAM User Without MFA",
                            description=f"User {user_name} does not have MFA enabled",
                            severity=Severity.MEDIUM,
                            location=Location(resource_id=user_arn, resource_type="AWS::IAM::User"),
                            remediation="Enable MFA for the IAM user",
                            cwe_id="CWE-308",
                        ))
                except Exception as e:
                    logger.debug(f"Could not check MFA for {user_name}: {e}")

        except Exception as e:
            logger.error(f"Error scanning IAM policies: {e}")

        self.findings.extend(iam_findings)
        return iam_findings

    def scan_security_groups(self) -> List[Finding]:
        """Scan EC2 security groups."""
        logger.info("Scanning security groups...")
        sg_findings = []

        try:
            response = self.ec2_client.describe_security_groups()

            for sg in response.get('SecurityGroups', []):
                sg_id = sg['GroupId']
                sg_name = sg.get('GroupName', 'Unknown')

                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    protocol = rule.get('IpProtocol', '-1')

                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            if protocol == '-1':
                                sg_findings.append(Finding(
                                    rule_id="AWS-EC2-001",
                                domain=FindingDomain.AWS,
                                title="Security Group Allows All Inbound Traffic",
                                    description=f"Security group {sg_name} ({sg_id}) allows all traffic from any IP",
                                    severity=Severity.CRITICAL,
                                    location=Location(resource_id=sg_id, resource_type="AWS::EC2::SecurityGroup"),
                                    remediation="Restrict inbound rules to specific IPs and ports",
                                    cwe_id="CWE-284",
                                ))

                            for port, (service, severity) in self.SENSITIVE_PORTS.items():
                                if from_port <= port <= to_port:
                                    sg_findings.append(Finding(
                                        rule_id=f"AWS-EC2-{port}",
                                        domain=FindingDomain.AWS,
                                        title=f"Security Group Exposes {service} to Internet",
                                        description=f"Security group {sg_name} allows {service} (port {port}) from any IP",
                                        severity=severity,
                                        location=Location(resource_id=sg_id, resource_type="AWS::EC2::SecurityGroup"),
                                        remediation=f"Restrict {service} access to specific IP ranges",
                                        cwe_id="CWE-284",
                                        metadata={"port": port, "service": service},
                                    ))

        except Exception as e:
            logger.error(f"Error scanning security groups: {e}")

        self.findings.extend(sg_findings)
        return sg_findings

    def list_resources(self, resource_type: str) -> List[Dict[str, Any]]:
        """List cloud resources of a given type.

        Args:
            resource_type: Type of resource to list (s3, iam, ec2)

        Returns:
            List of resource dictionaries
        """
        if resource_type == "s3":
            response = self.s3_client.list_buckets()
            return response.get("Buckets", [])
        elif resource_type == "iam":
            response = self.iam_client.list_users()
            return response.get("Users", [])
        elif resource_type == "ec2":
            response = self.ec2_client.describe_security_groups()
            return response.get("SecurityGroups", [])
        return []
