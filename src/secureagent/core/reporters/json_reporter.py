"""JSON reporter for SecureAgent."""

import json
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path

from ..models.finding import Finding
from ..models.severity import Severity


def _get_severity_value(severity) -> str:
    """Get string value from severity, handling both enum and string."""
    if hasattr(severity, 'value'):
        return severity.value
    return str(severity)


class JSONReporter:
    """JSON output for scan results."""

    def __init__(self, pretty: bool = True):
        """Initialize JSON reporter."""
        self.pretty = pretty

    def report(
        self,
        findings: List[Finding],
        scan_target: str = "",
        scan_duration: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate JSON report."""
        report_data = self._build_report(
            findings, scan_target, scan_duration, metadata
        )

        if self.pretty:
            return json.dumps(report_data, indent=2, default=str)
        else:
            return json.dumps(report_data, default=str)

    def _build_report(
        self,
        findings: List[Finding],
        scan_target: str,
        scan_duration: Optional[float],
        metadata: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build report dictionary."""
        severity_counts = self._count_severities(findings)

        return {
            "version": "1.0",
            "tool": {
                "name": "SecureAgent",
                "version": "1.0.0",
            },
            "scan": {
                "target": scan_target,
                "timestamp": datetime.now().isoformat(),
                "duration_seconds": scan_duration,
                "metadata": metadata or {},
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity": {
                    _get_severity_value(severity): count
                    for severity, count in severity_counts.items()
                },
            },
            "findings": [self._finding_to_dict(f) for f in findings],
        }

    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        # Handle domain as either enum or string
        if finding.domain:
            domain_value = finding.domain.value if hasattr(finding.domain, 'value') else str(finding.domain)
        else:
            domain_value = None

        result = {
            "id": finding.id,
            "rule_id": finding.rule_id,
            "domain": domain_value,
            "title": finding.title,
            "description": finding.description,
            "severity": _get_severity_value(finding.severity),
            "remediation": finding.remediation,
        }

        # Location
        if finding.location:
            loc = finding.location
            result["location"] = {
                "file_path": loc.file_path,
                "line_number": loc.line_number,
                "column": loc.column,
                "resource_type": loc.resource_type,
                "resource_id": loc.resource_id,
                "region": loc.region,
            }

        # Optional fields
        if finding.cwe_id:
            result["cwe_id"] = finding.cwe_id
        if finding.owasp_id:
            result["owasp_id"] = finding.owasp_id
        if finding.risk_score is not None:
            result["risk_score"] = finding.risk_score
        if finding.compliance_mappings:
            result["compliance_mappings"] = finding.compliance_mappings
        if finding.metadata:
            result["metadata"] = finding.metadata

        return result

    def _count_severities(self, findings: List[Finding]) -> Dict:
        """Count findings by severity."""
        from ..models.severity import Severity

        counts = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def save(
        self,
        findings: List[Finding],
        output_path: Path,
        scan_target: str = "",
        scan_duration: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Save JSON report to file."""
        report = self.report(findings, scan_target, scan_duration, metadata)
        output_path = Path(output_path)
        output_path.write_text(report)
