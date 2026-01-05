"""Tests for AWS scanner."""

import pytest
from unittest.mock import MagicMock, patch

from secureagent.scanners.aws.scanner import AWSScanner
from secureagent.core.models.severity import Severity


class TestAWSScanner:
    """Tests for AWS scanner."""

    def test_scanner_initialization(self):
        """Test scanner initialization."""
        mock_boto3 = MagicMock()
        scanner = AWSScanner(boto3_client=mock_boto3)
        assert scanner is not None
        assert scanner.name == "aws"

    def test_scanner_description(self):
        """Test scanner has description."""
        mock_boto3 = MagicMock()
        scanner = AWSScanner(boto3_client=mock_boto3)
        assert scanner.description is not None
        assert "AWS" in scanner.description

    def test_scan_s3_public_bucket(self):
        """Test S3 bucket scanning detects public access."""
        mock_boto3 = MagicMock()
        mock_s3 = MagicMock()

        mock_s3.list_buckets.return_value = {
            "Buckets": [
                {"Name": "public-bucket"},
            ]
        }
        mock_s3.get_bucket_acl.return_value = {
            "Grants": [
                {
                    "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                    "Permission": "READ",
                }
            ]
        }
        mock_s3.get_public_access_block.side_effect = Exception("No block")
        mock_boto3.client.return_value = mock_s3

        scanner = AWSScanner(boto3_client=mock_boto3)
        findings = scanner.scan_s3_buckets()

        # Should detect public bucket
        public_findings = [f for f in findings if "public" in f.title.lower()]
        assert len(public_findings) > 0
        assert public_findings[0].severity == Severity.CRITICAL

    def test_scan_s3_authenticated_users(self):
        """Test S3 bucket scanning detects AuthenticatedUsers access."""
        mock_boto3 = MagicMock()
        mock_s3 = MagicMock()

        mock_s3.list_buckets.return_value = {
            "Buckets": [{"Name": "auth-users-bucket"}]
        }
        mock_s3.get_bucket_acl.return_value = {
            "Grants": [
                {
                    "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"},
                    "Permission": "READ",
                }
            ]
        }
        mock_s3.get_public_access_block.side_effect = Exception("No block")
        mock_boto3.client.return_value = mock_s3

        scanner = AWSScanner(boto3_client=mock_boto3)
        findings = scanner.scan_s3_buckets()

        # Should detect AuthenticatedUsers access
        auth_findings = [f for f in findings if "AWS-S3-002" in f.rule_id]
        assert len(auth_findings) > 0
        assert auth_findings[0].severity == Severity.HIGH

    def test_scan_s3_no_public_access_block(self):
        """Test S3 bucket scanning detects missing public access block."""
        mock_boto3 = MagicMock()
        mock_s3 = MagicMock()

        mock_s3.list_buckets.return_value = {
            "Buckets": [{"Name": "no-pab-bucket"}]
        }
        mock_s3.get_bucket_acl.return_value = {"Grants": []}
        mock_s3.get_public_access_block.side_effect = Exception("No block configured")
        mock_boto3.client.return_value = mock_s3

        scanner = AWSScanner(boto3_client=mock_boto3)
        findings = scanner.scan_s3_buckets()

        # Should detect missing public access block
        pab_findings = [f for f in findings if "AWS-S3-004" in f.rule_id]
        assert len(pab_findings) > 0

    def test_scan_iam_admin_policy(self):
        """Test IAM scanning detects admin policies."""
        mock_boto3 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_users.return_value = {
            "Users": [
                {
                    "UserName": "admin-user",
                    "Arn": "arn:aws:iam::123456789:user/admin-user",
                }
            ]
        }
        mock_iam.list_attached_user_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
            ]
        }
        mock_iam.list_mfa_devices.return_value = {"MFADevices": [{"SerialNumber": "mfa-device"}]}
        mock_boto3.client.return_value = mock_iam

        scanner = AWSScanner(boto3_client=mock_boto3)
        findings = scanner.scan_iam_policies()

        # Should detect admin policy
        admin_findings = [f for f in findings if "Administrator" in f.title]
        assert len(admin_findings) > 0
        assert admin_findings[0].severity == Severity.HIGH

    def test_scan_iam_no_mfa(self):
        """Test IAM scanning detects users without MFA."""
        mock_boto3 = MagicMock()
        mock_iam = MagicMock()

        mock_iam.list_users.return_value = {
            "Users": [
                {
                    "UserName": "no-mfa-user",
                    "Arn": "arn:aws:iam::123456789:user/no-mfa-user",
                }
            ]
        }
        mock_iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
        mock_iam.list_mfa_devices.return_value = {"MFADevices": []}
        mock_boto3.client.return_value = mock_iam

        scanner = AWSScanner(boto3_client=mock_boto3)
        findings = scanner.scan_iam_policies()

        # Should detect missing MFA
        mfa_findings = [f for f in findings if "MFA" in f.title]
        assert len(mfa_findings) > 0
        assert mfa_findings[0].severity == Severity.MEDIUM

    def test_scan_security_groups_all_traffic(self):
        """Test EC2 security group scanning detects all traffic allowed."""
        mock_boto3 = MagicMock()
        mock_ec2 = MagicMock()

        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-123",
                    "GroupName": "open-sg",
                    "IpPermissions": [
                        {
                            "IpProtocol": "-1",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        }
        mock_boto3.client.return_value = mock_ec2

        scanner = AWSScanner(boto3_client=mock_boto3)
        findings = scanner.scan_security_groups()

        # Should detect open security group
        all_traffic_findings = [f for f in findings if "All" in f.title and "Traffic" in f.title]
        assert len(all_traffic_findings) > 0
        assert all_traffic_findings[0].severity == Severity.CRITICAL

    def test_scan_security_groups_ssh_exposed(self):
        """Test EC2 security group scanning detects SSH exposure."""
        mock_boto3 = MagicMock()
        mock_ec2 = MagicMock()

        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-456",
                    "GroupName": "ssh-open-sg",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        }
        mock_boto3.client.return_value = mock_ec2

        scanner = AWSScanner(boto3_client=mock_boto3)
        findings = scanner.scan_security_groups()

        # Should detect SSH exposure
        ssh_findings = [f for f in findings if "SSH" in f.title]
        assert len(ssh_findings) > 0
        assert ssh_findings[0].severity == Severity.CRITICAL

    def test_scan_security_groups_database_exposed(self):
        """Test EC2 security group scanning detects database exposure."""
        mock_boto3 = MagicMock()
        mock_ec2 = MagicMock()

        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-789",
                    "GroupName": "mysql-open-sg",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 3306,
                            "ToPort": 3306,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        }
        mock_boto3.client.return_value = mock_ec2

        scanner = AWSScanner(boto3_client=mock_boto3)
        findings = scanner.scan_security_groups()

        # Should detect MySQL exposure
        mysql_findings = [f for f in findings if "MySQL" in f.title]
        assert len(mysql_findings) > 0
        assert mysql_findings[0].severity == Severity.HIGH

    def test_full_scan(self):
        """Test full scan runs all checks."""
        mock_boto3 = MagicMock()
        mock_s3 = MagicMock()
        mock_iam = MagicMock()
        mock_ec2 = MagicMock()

        # S3 responses
        mock_s3.list_buckets.return_value = {"Buckets": []}

        # IAM responses
        mock_iam.list_users.return_value = {"Users": []}

        # EC2 responses
        mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}

        def client_factory(service):
            if service == 's3':
                return mock_s3
            elif service == 'iam':
                return mock_iam
            elif service == 'ec2':
                return mock_ec2
            return MagicMock()

        mock_boto3.client.side_effect = client_factory

        scanner = AWSScanner(boto3_client=mock_boto3)
        findings = scanner.scan()

        # Should return list (may be empty with mocked data)
        assert isinstance(findings, list)

    def test_finding_has_location(self):
        """Test that findings include location information."""
        mock_boto3 = MagicMock()
        mock_s3 = MagicMock()

        mock_s3.list_buckets.return_value = {
            "Buckets": [{"Name": "test-bucket"}]
        }
        mock_s3.get_bucket_acl.return_value = {
            "Grants": [
                {
                    "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                    "Permission": "READ",
                }
            ]
        }
        mock_s3.get_public_access_block.side_effect = Exception("No block")
        mock_boto3.client.return_value = mock_s3

        scanner = AWSScanner(boto3_client=mock_boto3)
        findings = scanner.scan_s3_buckets()

        for finding in findings:
            assert finding.location is not None
            assert finding.location.resource_id is not None

    def test_finding_has_remediation(self):
        """Test that findings include remediation guidance."""
        mock_boto3 = MagicMock()
        mock_s3 = MagicMock()

        mock_s3.list_buckets.return_value = {
            "Buckets": [{"Name": "test-bucket"}]
        }
        mock_s3.get_bucket_acl.return_value = {
            "Grants": [
                {
                    "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                    "Permission": "READ",
                }
            ]
        }
        mock_s3.get_public_access_block.side_effect = Exception("No block")
        mock_boto3.client.return_value = mock_s3

        scanner = AWSScanner(boto3_client=mock_boto3)
        findings = scanner.scan_s3_buckets()

        for finding in findings:
            assert finding.remediation is not None
            assert len(finding.remediation) > 0

    def test_sensitive_ports_defined(self):
        """Test that sensitive ports are properly defined."""
        mock_boto3 = MagicMock()
        scanner = AWSScanner(boto3_client=mock_boto3)

        # Should have common sensitive ports defined
        assert 22 in scanner.SENSITIVE_PORTS  # SSH
        assert 3389 in scanner.SENSITIVE_PORTS  # RDP
        assert 3306 in scanner.SENSITIVE_PORTS  # MySQL
        assert 5432 in scanner.SENSITIVE_PORTS  # PostgreSQL
