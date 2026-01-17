"""Tests for Terraform scanner."""

import pytest
from pathlib import Path

from secureagent.scanners.terraform.scanner import TerraformScanner
from secureagent.core.models.severity import Severity


class TestTerraformScanner:
    """Tests for Terraform scanner."""

    def test_scanner_initialization(self, temp_dir):
        """Test scanner initialization."""
        scanner = TerraformScanner(path=temp_dir)
        assert scanner is not None
        assert scanner.name == "terraform"

    def test_scan_public_s3_bucket(self, temp_dir):
        """Test detecting public S3 bucket."""
        tf_config = '''
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
'''
        tf_path = temp_dir / "main.tf"
        tf_path.write_text(tf_config)

        scanner = TerraformScanner(path=tf_path)
        result = scanner.scan()
        findings = result.findings

        # Should find public S3 bucket
        s3_findings = [f for f in findings if "s3" in f.rule_id.lower()]
        assert len(s3_findings) > 0

    def test_scan_open_security_group(self, temp_dir):
        """Test detecting open security group."""
        tf_config = '''
resource "aws_security_group" "open_ssh" {
  name = "open-ssh-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        tf_path = temp_dir / "main.tf"
        tf_path.write_text(tf_config)

        scanner = TerraformScanner(path=tf_path)
        result = scanner.scan()
        findings = result.findings

        # Should find open SSH
        sg_findings = [f for f in findings if "sg" in f.rule_id.lower() or "security" in f.title.lower()]
        assert len(sg_findings) > 0

    def test_scan_all_traffic_security_group(self, temp_dir):
        """Test detecting security group allowing all traffic."""
        tf_config = '''
resource "aws_security_group" "allow_all" {
  name = "allow-all-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        tf_path = temp_dir / "main.tf"
        tf_path.write_text(tf_config)

        scanner = TerraformScanner(path=tf_path)
        result = scanner.scan()
        findings = result.findings

        # Should find critical security group issue
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) > 0

    def test_scan_public_rds(self, temp_dir):
        """Test detecting publicly accessible RDS."""
        tf_config = '''
resource "aws_db_instance" "public_db" {
  identifier            = "my-public-db"
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  publicly_accessible  = true
  storage_encrypted    = false
}
'''
        tf_path = temp_dir / "main.tf"
        tf_path.write_text(tf_config)

        scanner = TerraformScanner(path=tf_path)
        result = scanner.scan()
        findings = result.findings

        # Should find public RDS and unencrypted storage
        rds_findings = [f for f in findings if "rds" in f.rule_id.lower()]
        assert len(rds_findings) >= 2  # public + unencrypted

    def test_scan_secure_config(self, temp_dir):
        """Test scanning a secure Terraform configuration."""
        secure_tf = '''
resource "aws_s3_bucket" "secure" {
  bucket = "secure-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_security_group" "secure" {
  name = "secure-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
'''
        tf_path = temp_dir / "secure.tf"
        tf_path.write_text(secure_tf)

        scanner = TerraformScanner(path=tf_path)
        result = scanner.scan()
        findings = result.findings

        # Should have no critical findings
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_scan_directory(self, temp_dir):
        """Test scanning a directory of Terraform files."""
        main_tf = '''
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
  acl    = "public-read"
}
'''
        vars_tf = '''
variable "region" {
  default = "us-east-1"
}
'''
        (temp_dir / "main.tf").write_text(main_tf)
        (temp_dir / "variables.tf").write_text(vars_tf)

        scanner = TerraformScanner(path=temp_dir)
        result = scanner.scan()
        findings = result.findings

        assert isinstance(findings, list)
        # Should find S3 issue
        assert len(findings) > 0

    def test_scan_ec2_without_imdsv2(self, temp_dir):
        """Test detecting EC2 without IMDSv2 requirement."""
        tf_config = '''
resource "aws_instance" "no_imdsv2" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
}
'''
        tf_path = temp_dir / "main.tf"
        tf_path.write_text(tf_config)

        scanner = TerraformScanner(path=tf_path)
        result = scanner.scan()
        findings = result.findings

        # Should find IMDSv2 not enforced
        ec2_findings = [f for f in findings if "ec2" in f.rule_id.lower() or "imds" in f.title.lower()]
        assert len(ec2_findings) > 0

    def test_scan_unencrypted_ebs(self, temp_dir):
        """Test detecting unencrypted EC2 root volume."""
        tf_config = '''
resource "aws_instance" "unencrypted" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"

  root_block_device {
    volume_size = 20
    encrypted   = false
  }
}
'''
        tf_path = temp_dir / "main.tf"
        tf_path.write_text(tf_config)

        scanner = TerraformScanner(path=tf_path)
        result = scanner.scan()
        findings = result.findings

        # Should find unencrypted volume
        encryption_findings = [
            f for f in findings
            if "encrypt" in f.title.lower() or "volume" in f.title.lower()
        ]
        assert len(encryption_findings) > 0

    def test_discover_targets(self, temp_dir):
        """Test target discovery."""
        (temp_dir / "main.tf").write_text('resource "aws_s3_bucket" "test" {}')
        (temp_dir / "other.txt").write_text("not terraform")

        scanner = TerraformScanner(path=temp_dir)
        targets = list(scanner.discover_targets())

        # Should find .tf files
        assert len(targets) == 1
        assert targets[0].suffix == ".tf"

    def test_finding_has_location(self, temp_dir):
        """Test that findings include location information."""
        tf_config = '''
resource "aws_s3_bucket" "test" {
  bucket = "test"
  acl    = "public-read"
}
'''
        tf_path = temp_dir / "main.tf"
        tf_path.write_text(tf_config)

        scanner = TerraformScanner(path=tf_path)
        result = scanner.scan()
        findings = result.findings

        for finding in findings:
            assert finding.location is not None
            assert finding.location.file_path is not None

    def test_scan_database_ports_exposed(self, temp_dir):
        """Test detecting exposed database ports."""
        tf_config = '''
resource "aws_security_group" "db_exposed" {
  name = "db-sg"

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        tf_path = temp_dir / "main.tf"
        tf_path.write_text(tf_config)

        scanner = TerraformScanner(path=tf_path)
        result = scanner.scan()
        findings = result.findings

        # Should find exposed database port
        db_findings = [f for f in findings if "mysql" in f.title.lower() or "3306" in str(f)]
        assert len(db_findings) > 0
