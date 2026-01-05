"""HTML reporter for SecureAgent."""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path
from html import escape

from ..models.finding import Finding
from ..models.severity import Severity


def _get_severity_value(severity) -> str:
    """Get string value from severity, handling both enum and string."""
    if hasattr(severity, 'value'):
        return severity.value
    return str(severity)


def _get_severity_enum(severity) -> Severity:
    """Get Severity enum from severity, handling both enum and string."""
    if isinstance(severity, Severity):
        return severity
    return Severity(severity)


class HTMLReporter:
    """HTML output for scan results."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: "#dc3545",
        Severity.HIGH: "#fd7e14",
        Severity.MEDIUM: "#ffc107",
        Severity.LOW: "#17a2b8",
        Severity.INFO: "#6c757d",
    }

    def __init__(self, title: str = "SecureAgent Security Report"):
        """Initialize HTML reporter."""
        self.title = title

    def report(
        self,
        findings: List[Finding],
        scan_target: str = "",
        scan_duration: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Generate HTML report."""
        severity_counts = self._count_severities(findings)
        sorted_findings = sorted(
            findings, key=lambda f: list(Severity).index(_get_severity_enum(f.severity))
        )

        # Build findings HTML
        findings_html = self._build_findings_html(sorted_findings)

        # Build chart data
        chart_data = [severity_counts.get(s, 0) for s in Severity]

        return self._build_html(
            findings=sorted_findings,
            findings_html=findings_html,
            scan_target=scan_target,
            scan_duration=scan_duration,
            severity_counts=severity_counts,
            chart_data=chart_data,
            metadata=metadata,
        )

    def _build_findings_html(self, findings: List[Finding]) -> str:
        """Build HTML for findings list."""
        if not findings:
            return '<div class="no-findings">No security issues found!</div>'

        html_parts = []

        for i, finding in enumerate(findings, 1):
            severity_enum = _get_severity_enum(finding.severity)
            color = self.SEVERITY_COLORS.get(severity_enum, "#6c757d")
            location = self._format_location(finding)

            # CWE/OWASP badges
            badges = ""
            if finding.cwe_id:
                badges += f'<span class="badge cwe">{escape(finding.cwe_id)}</span>'
            if finding.owasp_id:
                badges += f'<span class="badge owasp">{escape(finding.owasp_id)}</span>'

            # Risk score
            risk_html = ""
            if finding.risk_score is not None:
                risk_color = "#dc3545" if finding.risk_score > 0.7 else "#ffc107" if finding.risk_score > 0.4 else "#28a745"
                risk_html = f'<span class="risk-score" style="color: {risk_color}">Risk: {finding.risk_score:.2f}</span>'

            # Remediation
            remediation_html = ""
            if finding.remediation:
                remediation_html = f'''
                <div class="remediation">
                    <strong>Remediation:</strong>
                    <p>{escape(finding.remediation)}</p>
                </div>
                '''

            html_parts.append(f'''
            <div class="finding" id="finding-{i}">
                <div class="finding-header">
                    <span class="finding-number">#{i}</span>
                    <span class="severity-badge" style="background-color: {color}">{_get_severity_value(finding.severity)}</span>
                    <span class="rule-id">{escape(finding.rule_id)}</span>
                    {badges}
                    {risk_html}
                </div>
                <h3 class="finding-title">{escape(finding.title)}</h3>
                <div class="finding-location">{escape(location)}</div>
                <div class="finding-description">{escape(finding.description)}</div>
                {remediation_html}
            </div>
            ''')

        return '\n'.join(html_parts)

    def _build_html(
        self,
        findings: List[Finding],
        findings_html: str,
        scan_target: str,
        scan_duration: Optional[float],
        severity_counts: Dict[Severity, int],
        chart_data: List[int],
        metadata: Optional[Dict[str, Any]],
    ) -> str:
        """Build complete HTML document."""
        total = len(findings)
        critical_high = severity_counts.get(Severity.CRITICAL, 0) + severity_counts.get(Severity.HIGH, 0)

        status_class = "status-pass" if critical_high == 0 else "status-fail"
        status_text = "PASS" if critical_high == 0 else "NEEDS ATTENTION"

        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{escape(self.title)}</title>
    <style>
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background: linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%);
            color: white;
            padding: 30px;
            margin-bottom: 30px;
            border-radius: 12px;
        }}
        h1 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .scan-info {{
            opacity: 0.9;
            font-size: 0.95em;
        }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            text-align: center;
        }}
        .card-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .card-label {{
            color: #666;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }}
        .status-badge {{
            display: inline-block;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .status-pass {{
            background: #d4edda;
            color: #155724;
        }}
        .status-fail {{
            background: #f8d7da;
            color: #721c24;
        }}
        .severity-breakdown {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            justify-content: center;
            margin-top: 15px;
        }}
        .severity-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .severity-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}
        .findings-section {{
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .findings-section h2 {{
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #eee;
        }}
        .finding {{
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            transition: box-shadow 0.2s;
        }}
        .finding:hover {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 10px;
        }}
        .finding-number {{
            color: #999;
            font-weight: bold;
        }}
        .severity-badge {{
            color: white;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .rule-id {{
            font-family: monospace;
            background: #f0f0f0;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.9em;
        }}
        .badge {{
            font-size: 0.8em;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: normal;
        }}
        .badge.cwe {{
            background: #e3f2fd;
            color: #1565c0;
        }}
        .badge.owasp {{
            background: #fce4ec;
            color: #c62828;
        }}
        .risk-score {{
            font-weight: bold;
            font-size: 0.9em;
        }}
        .finding-title {{
            font-size: 1.2em;
            margin-bottom: 8px;
            color: #333;
        }}
        .finding-location {{
            font-family: monospace;
            font-size: 0.9em;
            color: #666;
            background: #f5f5f5;
            padding: 8px 12px;
            border-radius: 4px;
            margin-bottom: 12px;
        }}
        .finding-description {{
            color: #555;
            margin-bottom: 15px;
        }}
        .remediation {{
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 15px;
            border-radius: 0 4px 4px 0;
        }}
        .remediation strong {{
            color: #2e7d32;
        }}
        .remediation p {{
            margin-top: 8px;
        }}
        .no-findings {{
            text-align: center;
            padding: 60px;
            color: #28a745;
            font-size: 1.3em;
        }}
        footer {{
            text-align: center;
            padding: 30px;
            color: #999;
            font-size: 0.9em;
        }}
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            header {{
                padding: 20px;
            }}
            h1 {{
                font-size: 1.5em;
            }}
            .card-value {{
                font-size: 2em;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{escape(self.title)}</h1>
            <div class="scan-info">
                {f'<div>Target: {escape(scan_target)}</div>' if scan_target else ''}
                <div>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                {f'<div>Duration: {scan_duration:.2f}s</div>' if scan_duration else ''}
            </div>
        </header>

        <div class="summary-cards">
            <div class="card">
                <div class="card-value">{total}</div>
                <div class="card-label">Total Findings</div>
            </div>
            <div class="card">
                <div class="card-value" style="color: #dc3545">{severity_counts.get(Severity.CRITICAL, 0)}</div>
                <div class="card-label">Critical</div>
            </div>
            <div class="card">
                <div class="card-value" style="color: #fd7e14">{severity_counts.get(Severity.HIGH, 0)}</div>
                <div class="card-label">High</div>
            </div>
            <div class="card">
                <div class="card-value" style="color: #ffc107">{severity_counts.get(Severity.MEDIUM, 0)}</div>
                <div class="card-label">Medium</div>
            </div>
            <div class="card">
                <div class="status-badge {status_class}">{status_text}</div>
                <div class="card-label" style="margin-top: 10px">Overall Status</div>
            </div>
        </div>

        <div class="findings-section">
            <h2>Security Findings</h2>
            {findings_html}
        </div>

        <footer>
            <p>Generated by SecureAgent - AI & Cloud Security Platform</p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</p>
        </footer>
    </div>
</body>
</html>'''

    def _count_severities(self, findings: List[Finding]) -> Dict[Severity, int]:
        """Count findings by severity."""
        counts: Dict[Severity, int] = {}
        for finding in findings:
            severity_enum = _get_severity_enum(finding.severity)
            counts[severity_enum] = counts.get(severity_enum, 0) + 1
        return counts

    def _format_location(self, finding: Finding) -> str:
        """Format finding location for display."""
        if finding.location:
            loc = finding.location
            if loc.file_path:
                result = loc.file_path
                if loc.line_number:
                    result += f":{loc.line_number}"
                return result
            elif loc.resource_type and loc.resource_id:
                return f"{loc.resource_type}/{loc.resource_id}"
        return "N/A"

    def save(
        self,
        findings: List[Finding],
        output_path: Path,
        scan_target: str = "",
        scan_duration: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Save HTML report to file."""
        report = self.report(findings, scan_target, scan_duration, metadata)
        output_path = Path(output_path)
        output_path.write_text(report)
