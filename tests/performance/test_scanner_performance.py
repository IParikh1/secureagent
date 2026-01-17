"""Performance tests for scanners."""

import json
import time
import pytest
from pathlib import Path
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from secureagent.core.scanner.registry import scanner_registry


class TestScannerPerformance:
    """Performance tests for scanning operations."""

    @pytest.fixture
    def large_mcp_config(self, tmp_path) -> Path:
        """Create a large MCP configuration for stress testing."""
        config: Dict[str, Any] = {"mcpServers": {}}

        # Generate 100 servers with detectable credentials
        for i in range(100):
            # Use credential formats that will be detected by the scanner
            # sk-proj- pattern allows hyphens and underscores
            api_key = f"sk-proj-{'a' * 30}{i:04d}"
            config["mcpServers"][f"server-{i:03d}"] = {
                "command": "node",
                "args": [f"server{i}.js", "--port", str(3000 + i)],
                "env": {
                    "OPENAI_API_KEY": api_key,
                    "DEBUG": "true" if i % 2 == 0 else "false",
                    "LOG_LEVEL": "info",
                    "TIMEOUT": str(30000 + i * 100),
                },
            }

        config_path = tmp_path / "large_mcp_config.json"
        config_path.write_text(json.dumps(config, indent=2))
        return config_path

    @pytest.fixture
    def many_small_configs(self, tmp_path) -> List[Path]:
        """Create many small configuration files."""
        configs = []
        config_dir = tmp_path / "configs"
        config_dir.mkdir()

        for i in range(50):
            # Use detectable credential format
            api_key = f"sk-proj-{'b' * 30}{i:04d}"
            config = {
                "mcpServers": {
                    f"server-{i}": {
                        "command": "npx",
                        "args": ["-y", f"@test/mcp-server-{i}"],
                        "env": {"OPENAI_API_KEY": api_key},
                    }
                }
            }
            config_path = config_dir / f"config_{i:03d}.json"
            config_path.write_text(json.dumps(config))
            configs.append(config_path)

        return configs

    @pytest.fixture
    def large_terraform_config(self, tmp_path) -> Path:
        """Create a large Terraform configuration."""
        resources = []

        # Generate 200 resources
        for i in range(50):
            resources.append(f'''
resource "aws_s3_bucket" "bucket_{i:03d}" {{
  bucket = "test-bucket-{i:03d}"

  tags = {{
    Name        = "TestBucket{i}"
    Environment = "test"
    Index       = "{i}"
  }}
}}

resource "aws_security_group" "sg_{i:03d}" {{
  name        = "test-sg-{i:03d}"
  description = "Security group {i}"
  vpc_id      = "vpc-12345678"

  ingress {{
    from_port   = {22 + i}
    to_port     = {22 + i}
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}

resource "aws_iam_role" "role_{i:03d}" {{
  name = "test-role-{i:03d}"

  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {{
        Service = "ec2.amazonaws.com"
      }}
    }}]
  }})
}}

resource "aws_db_instance" "db_{i:03d}" {{
  identifier        = "test-db-{i:03d}"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  password          = "hardcoded-password-{i}"
  publicly_accessible = true
}}
''')

        tf_content = "\n".join(resources)
        tf_path = tmp_path / "main.tf"
        tf_path.write_text(tf_content)
        return tf_path

    def test_mcp_scan_performance(self, large_mcp_config):
        """Test MCP scanner performance on large config."""
        scanner = scanner_registry.get("mcp")
        if not scanner:
            pytest.skip("MCP scanner not available")

        scanner.initialize()
        try:
            start_time = time.perf_counter()
            result = scanner.scan(str(large_mcp_config))
            elapsed = time.perf_counter() - start_time

            # Should complete within 5 seconds for 100 servers
            assert elapsed < 5.0, f"MCP scan took too long: {elapsed:.2f}s"

            # Should find findings (hardcoded credentials)
            assert len(result.findings) > 0

            # Calculate throughput
            servers_per_second = 100 / elapsed
            assert servers_per_second > 20, f"Throughput too low: {servers_per_second:.1f} servers/sec"
        finally:
            scanner.cleanup()

    def test_terraform_scan_performance(self, large_terraform_config):
        """Test Terraform scanner performance on large config."""
        scanner = scanner_registry.get("terraform")
        if not scanner:
            pytest.skip("Terraform scanner not available")

        scanner.initialize()
        try:
            start_time = time.perf_counter()
            result = scanner.scan(str(large_terraform_config))
            elapsed = time.perf_counter() - start_time

            # Should complete within 10 seconds for 200 resources
            assert elapsed < 10.0, f"Terraform scan took too long: {elapsed:.2f}s"

            # Should find findings (public buckets, open security groups)
            assert len(result.findings) > 0
        finally:
            scanner.cleanup()

    def test_sequential_scan_performance(self, many_small_configs):
        """Test scanning many configs sequentially."""
        scanner = scanner_registry.get("mcp")
        if not scanner:
            pytest.skip("MCP scanner not available")

        scanner.initialize()
        try:
            start_time = time.perf_counter()

            total_findings = 0
            for config_path in many_small_configs:
                result = scanner.scan(str(config_path))
                total_findings += len(result.findings)

            elapsed = time.perf_counter() - start_time

            # Should complete within 10 seconds for 50 files
            assert elapsed < 10.0, f"Sequential scan took too long: {elapsed:.2f}s"

            # Should find at least some findings
            assert total_findings > 0

            files_per_second = 50 / elapsed
            assert files_per_second > 5, f"Throughput too low: {files_per_second:.1f} files/sec"
        finally:
            scanner.cleanup()

    def test_concurrent_scan_performance(self, many_small_configs):
        """Test scanning many configs concurrently."""
        scanner = scanner_registry.get("mcp")
        if not scanner:
            pytest.skip("MCP scanner not available")

        scanner.initialize()
        try:
            start_time = time.perf_counter()

            total_findings = 0
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {
                    executor.submit(scanner.scan, str(config_path)): config_path
                    for config_path in many_small_configs
                }

                for future in as_completed(futures):
                    result = future.result()
                    total_findings += len(result.findings)

            elapsed = time.perf_counter() - start_time

            # Should complete within 5 seconds for 50 files with concurrency
            assert elapsed < 5.0, f"Concurrent scan took too long: {elapsed:.2f}s"

            # Should find findings
            assert total_findings > 0
        finally:
            scanner.cleanup()

    def test_scan_memory_efficiency(self, large_mcp_config):
        """Test that scanning doesn't use excessive memory."""
        import tracemalloc

        scanner = scanner_registry.get("mcp")
        if not scanner:
            pytest.skip("MCP scanner not available")

        scanner.initialize()
        try:
            tracemalloc.start()

            # Run scan multiple times to check for memory leaks
            for _ in range(5):
                result = scanner.scan(str(large_mcp_config))

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            # Peak memory should be under 100MB
            peak_mb = peak / (1024 * 1024)
            assert peak_mb < 100, f"Peak memory too high: {peak_mb:.1f}MB"
        finally:
            scanner.cleanup()

    def test_finding_creation_performance(self):
        """Test performance of creating many findings."""
        from secureagent.core.models.finding import Finding, FindingDomain, Location
        from secureagent.core.models.severity import Severity

        start_time = time.perf_counter()

        findings = []
        for i in range(10000):
            finding = Finding(
                rule_id=f"TEST-{i % 100:03d}",
                domain=FindingDomain.MCP,
                title=f"Test Finding {i}",
                description=f"Description for finding {i}",
                severity=Severity.HIGH if i % 2 == 0 else Severity.MEDIUM,
                location=Location(
                    file_path=f"/path/to/file{i}.json",
                    line_number=i + 1,
                ),
                remediation=f"Fix by doing action {i}",
            )
            findings.append(finding)

        elapsed = time.perf_counter() - start_time

        # Should create 10000 findings in under 1 second
        assert elapsed < 1.0, f"Finding creation too slow: {elapsed:.2f}s"
        assert len(findings) == 10000


class TestReportingPerformance:
    """Performance tests for report generation."""

    @pytest.fixture
    def many_findings(self) -> List:
        """Create many findings for testing."""
        from secureagent.core.models.finding import Finding, FindingDomain, Location
        from secureagent.core.models.severity import Severity

        findings = []
        for i in range(1000):
            findings.append(Finding(
                rule_id=f"TEST-{i % 50:03d}",
                domain=FindingDomain.MCP if i % 3 == 0 else FindingDomain.CLOUD,
                title=f"Finding {i}",
                description=f"Detailed description for finding number {i} with some additional context.",
                severity=[Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW][i % 4],
                location=Location(
                    file_path=f"/path/to/config{i % 20}.json",
                    line_number=(i % 100) + 1,
                    snippet=f"some code snippet {i}",
                ),
                remediation=f"Apply fix {i % 10}",
                cwe_id=f"CWE-{(i % 10) + 78}",
            ))
        return findings

    def test_json_report_performance(self, many_findings, tmp_path):
        """Test JSON report generation performance."""
        from secureagent.core.reporters import JSONReporter

        reporter = JSONReporter()
        output_path = tmp_path / "report.json"

        start_time = time.perf_counter()
        reporter.save(many_findings, output_path, scan_target="test")
        elapsed = time.perf_counter() - start_time

        # Should generate 1000-finding report in under 1 second
        assert elapsed < 1.0, f"JSON report too slow: {elapsed:.2f}s"
        assert output_path.exists()

    def test_sarif_report_performance(self, many_findings, tmp_path):
        """Test SARIF report generation performance."""
        from secureagent.core.reporters import SARIFReporter

        reporter = SARIFReporter()
        output_path = tmp_path / "report.sarif"

        start_time = time.perf_counter()
        reporter.save(many_findings, output_path, scan_target="test")
        elapsed = time.perf_counter() - start_time

        # Should generate 1000-finding report in under 2 seconds
        assert elapsed < 2.0, f"SARIF report too slow: {elapsed:.2f}s"
        assert output_path.exists()


class TestRemediationPerformance:
    """Performance tests for remediation operations."""

    @pytest.fixture
    def many_findings_for_fix(self) -> List:
        """Create findings that can be auto-fixed."""
        from secureagent.core.models.finding import Finding, FindingDomain, Location
        from secureagent.core.models.severity import Severity

        findings = []
        rules = ["MCP-001", "MCP-002", "MCP-003", "MCP-004", "MCP-005"]

        for i in range(500):
            findings.append(Finding(
                rule_id=rules[i % len(rules)],
                domain=FindingDomain.MCP,
                title=f"Security Issue {i}",
                description=f"Found issue in configuration {i}",
                severity=Severity.HIGH,
                location=Location(
                    file_path=f"/tmp/config{i % 10}.json",
                    line_number=(i % 50) + 1,
                    snippet=f"sk-proj-{'x' * 40}" if "002" in rules[i % len(rules)] else "suspicious",
                ),
                remediation="Apply appropriate fix",
            ))
        return findings

    def test_fix_generation_performance(self, many_findings_for_fix):
        """Test fix generation performance."""
        from secureagent.remediation import RemediationGenerator

        generator = RemediationGenerator()

        start_time = time.perf_counter()
        fixes = generator.generate_fixes(many_findings_for_fix)
        elapsed = time.perf_counter() - start_time

        # Should generate fixes for 500 findings in under 2 seconds
        assert elapsed < 2.0, f"Fix generation too slow: {elapsed:.2f}s"

        # Should generate some fixes
        assert len(fixes) > 0

    def test_dry_run_performance(self, many_findings_for_fix, tmp_path):
        """Test dry-run fix performance."""
        from secureagent.remediation import RemediationGenerator, Fixer

        # Create actual files to fix
        for i in range(10):
            config = {
                "mcpServers": {
                    "server": {
                        "command": "node",
                        "env": {"API_KEY": f"sk-proj-{'x' * 40}"}
                    }
                }
            }
            config_path = tmp_path / f"config{i}.json"
            config_path.write_text(json.dumps(config, indent=2))

        # Update findings with real paths
        for finding in many_findings_for_fix:
            idx = int(finding.location.file_path.split("config")[1].split(".")[0])
            finding.location.file_path = str(tmp_path / f"config{idx}.json")

        generator = RemediationGenerator()
        fixes = generator.generate_fixes(many_findings_for_fix[:100])  # Limit for test

        fixer = Fixer(backup_dir=tmp_path / "backups")

        start_time = time.perf_counter()
        summary = fixer.apply_fixes(fixes, dry_run=True)
        elapsed = time.perf_counter() - start_time

        # Dry run should be fast
        assert elapsed < 5.0, f"Dry run too slow: {elapsed:.2f}s"
