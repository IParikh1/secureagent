"""Tests for reporters."""

import pytest
import json

from secureagent.core.reporters.console import ConsoleReporter
from secureagent.core.reporters.json_reporter import JSONReporter
from secureagent.core.reporters.sarif import SARIFReporter
from secureagent.core.reporters.html_reporter import HTMLReporter
from secureagent.core.models.finding import Finding, FindingDomain, Location
from secureagent.core.models.severity import Severity


class TestConsoleReporter:
    """Tests for console reporter."""

    def test_reporter_initialization(self):
        """Test reporter initialization."""
        reporter = ConsoleReporter()
        assert reporter is not None

    def test_report_empty_findings(self, capsys):
        """Test reporting with no findings."""
        reporter = ConsoleReporter()
        reporter.report([])

        captured = capsys.readouterr()
        assert "0" in captured.out or "no" in captured.out.lower() or "No" in captured.out

    def test_report_findings(self, sample_finding, capsys):
        """Test reporting findings."""
        reporter = ConsoleReporter()
        reporter.report([sample_finding])

        captured = capsys.readouterr()
        # Should contain finding info
        assert len(captured.out) > 0

    def test_verbose_mode(self, sample_finding, capsys):
        """Test verbose mode output."""
        reporter = ConsoleReporter(verbose=True)
        reporter.report([sample_finding])

        captured = capsys.readouterr()
        assert len(captured.out) > 0


class TestJSONReporter:
    """Tests for JSON reporter."""

    def test_reporter_initialization(self):
        """Test reporter initialization."""
        reporter = JSONReporter()
        assert reporter is not None

    def test_report_returns_json(self, sample_finding):
        """Test report returns valid JSON string."""
        reporter = JSONReporter()
        result = reporter.report([sample_finding])

        # Should be valid JSON
        parsed = json.loads(result)
        assert "findings" in parsed
        assert len(parsed["findings"]) == 1

    def test_report_with_multiple_findings(self, sample_findings):
        """Test report with multiple findings."""
        reporter = JSONReporter()
        result = reporter.report(sample_findings)

        parsed = json.loads(result)
        assert len(parsed["findings"]) == len(sample_findings)

    def test_report_includes_summary(self, sample_finding):
        """Test that report includes summary."""
        reporter = JSONReporter()
        result = reporter.report([sample_finding])

        parsed = json.loads(result)
        assert "summary" in parsed
        assert "total_findings" in parsed["summary"]

    def test_save_to_file(self, sample_finding, temp_dir):
        """Test saving report to file."""
        reporter = JSONReporter()
        output_path = temp_dir / "report.json"

        reporter.save([sample_finding], output_path)

        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert "findings" in data


class TestSARIFReporter:
    """Tests for SARIF reporter."""

    def test_reporter_initialization(self):
        """Test reporter initialization."""
        reporter = SARIFReporter()
        assert reporter is not None

    def test_report_returns_valid_sarif(self, sample_finding):
        """Test report returns valid SARIF JSON."""
        reporter = SARIFReporter()
        result = reporter.report([sample_finding])

        parsed = json.loads(result)
        # Should have required SARIF fields
        assert "$schema" in parsed
        assert "version" in parsed
        assert "runs" in parsed

    def test_sarif_run_structure(self, sample_finding):
        """Test SARIF run structure."""
        reporter = SARIFReporter()
        result = reporter.report([sample_finding])

        parsed = json.loads(result)
        runs = parsed.get("runs", [])
        assert len(runs) > 0

        run = runs[0]
        assert "tool" in run
        assert "results" in run

    def test_sarif_result_mapping(self, sample_finding):
        """Test finding to SARIF result mapping."""
        reporter = SARIFReporter()
        result = reporter.report([sample_finding])

        parsed = json.loads(result)
        runs = parsed.get("runs", [])
        results = runs[0].get("results", [])

        assert len(results) == 1
        sarif_result = results[0]

        # Should have rule ID and message
        assert "ruleId" in sarif_result
        assert "message" in sarif_result

    def test_severity_to_level_mapping(self):
        """Test severity mapping to SARIF levels using class constant."""
        reporter = SARIFReporter()

        # CRITICAL/HIGH -> error
        assert reporter.SEVERITY_TO_LEVEL[Severity.CRITICAL] == "error"
        assert reporter.SEVERITY_TO_LEVEL[Severity.HIGH] == "error"

        # MEDIUM -> warning
        assert reporter.SEVERITY_TO_LEVEL[Severity.MEDIUM] == "warning"

        # LOW/INFO -> note
        assert reporter.SEVERITY_TO_LEVEL[Severity.LOW] == "note"
        assert reporter.SEVERITY_TO_LEVEL[Severity.INFO] == "note"

    def test_save_to_file(self, sample_finding, temp_dir):
        """Test saving SARIF report to file."""
        reporter = SARIFReporter()
        output_path = temp_dir / "report.sarif"

        reporter.save([sample_finding], output_path)

        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert "runs" in data


class TestHTMLReporter:
    """Tests for HTML reporter."""

    def test_reporter_initialization(self):
        """Test reporter initialization."""
        reporter = HTMLReporter()
        assert reporter is not None

    def test_report_returns_html(self, sample_finding):
        """Test report returns valid HTML."""
        reporter = HTMLReporter()
        html = reporter.report([sample_finding])

        assert "<html" in html.lower() or "<!doctype" in html.lower()

    def test_html_contains_finding(self, sample_finding):
        """Test that HTML contains finding info."""
        reporter = HTMLReporter()
        html = reporter.report([sample_finding])

        # Should contain finding title or ID
        assert sample_finding.rule_id in html or sample_finding.title in html

    def test_html_has_styling(self, sample_finding):
        """Test that HTML includes styling."""
        reporter = HTMLReporter()
        html = reporter.report([sample_finding])

        # Should have CSS
        assert "<style" in html

    def test_html_severity_colors(self):
        """Test that different severities have different colors."""
        reporter = HTMLReporter()

        findings = [
            Finding(
                id="f1",
                rule_id="R1",
                domain=FindingDomain.MCP,
                title="Critical Finding",
                description="Test",
                severity=Severity.CRITICAL,
                location=Location(file_path="/test"),
                remediation="Fix it",
            ),
            Finding(
                id="f2",
                rule_id="R2",
                domain=FindingDomain.MCP,
                title="Low Finding",
                description="Test",
                severity=Severity.LOW,
                location=Location(file_path="/test"),
                remediation="Fix it",
            ),
        ]

        html = reporter.report(findings)

        # Should have different styling for different severities
        assert "critical" in html.lower() or "#dc3545" in html

    def test_save_to_file(self, sample_finding, temp_dir):
        """Test saving HTML to file."""
        reporter = HTMLReporter()
        output_path = temp_dir / "report.html"

        reporter.save([sample_finding], output_path)

        assert output_path.exists()
        content = output_path.read_text()
        assert "<html" in content.lower()

    def test_empty_findings_message(self):
        """Test empty findings display message."""
        reporter = HTMLReporter()
        html = reporter.report([])

        assert "no" in html.lower() or "No security issues" in html
