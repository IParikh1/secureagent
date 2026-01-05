"""Compliance report generator."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from pathlib import Path
import json

from ..core.models.finding import Finding
from ..core.models.severity import Severity
from .mapper import (
    ComplianceMapper,
    ComplianceFramework,
    ComplianceStatus,
    ComplianceMapping,
)
from .frameworks.owasp_llm import OWASP_LLM_TOP_10, get_all_controls as get_owasp_llm
from .frameworks.owasp_mcp import OWASP_MCP_TOP_10, get_all_controls as get_owasp_mcp
from .frameworks.soc2 import SOC2_CONTROLS, get_all_controls as get_soc2
from .frameworks.pci_dss import PCI_DSS_REQUIREMENTS, get_all_requirements as get_pci
from .frameworks.hipaa import HIPAA_SAFEGUARDS, get_all_safeguards as get_hipaa


@dataclass
class ComplianceReportSection:
    """Section of a compliance report."""

    control_id: str
    control_title: str
    control_description: str
    status: str  # "pass", "fail", "warning", "not_assessed"
    findings: List[Finding] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class ComplianceReport:
    """Complete compliance report."""

    framework: ComplianceFramework
    framework_name: str
    generated_at: datetime
    scan_target: str
    total_controls: int
    controls_passing: int
    controls_failing: int
    controls_warning: int
    controls_not_assessed: int
    compliance_percentage: float
    executive_summary: str
    sections: List[ComplianceReportSection] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ComplianceReportGenerator:
    """Generates compliance reports from scan findings."""

    def __init__(self):
        """Initialize report generator."""
        self.mapper = ComplianceMapper()
        self.framework_names = {
            ComplianceFramework.OWASP_LLM: "OWASP LLM Top 10",
            ComplianceFramework.OWASP_MCP: "OWASP MCP Top 10",
            ComplianceFramework.SOC2: "SOC 2 Type II",
            ComplianceFramework.PCI_DSS: "PCI DSS v4.0",
            ComplianceFramework.HIPAA: "HIPAA Security Rule",
        }

    def generate_report(
        self,
        findings: List[Finding],
        framework: ComplianceFramework,
        scan_target: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ComplianceReport:
        """Generate a compliance report for a specific framework."""
        status = self.mapper.get_compliance_status(findings, framework)
        sections = self._generate_sections(findings, framework, status)

        # Calculate not assessed
        controls_not_assessed = status.total_controls - status.controls_assessed

        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            framework, status, len(findings)
        )

        return ComplianceReport(
            framework=framework,
            framework_name=self.framework_names.get(framework, str(framework)),
            generated_at=datetime.now(),
            scan_target=scan_target,
            total_controls=status.total_controls,
            controls_passing=status.controls_passing,
            controls_failing=status.controls_failing,
            controls_warning=status.controls_warning,
            controls_not_assessed=controls_not_assessed,
            compliance_percentage=status.compliance_percentage,
            executive_summary=executive_summary,
            sections=sections,
            metadata=metadata or {},
        )

    def _generate_sections(
        self,
        findings: List[Finding],
        framework: ComplianceFramework,
        status: ComplianceStatus,
    ) -> List[ComplianceReportSection]:
        """Generate report sections for each control."""
        sections = []

        # Get all controls for the framework
        controls = self._get_framework_controls(framework)

        for control_id, control_info in controls.items():
            control_findings = status.findings_by_control.get(control_id, [])

            # Determine status
            if control_findings:
                has_critical = any(
                    f.severity in (Severity.CRITICAL, Severity.HIGH)
                    for f in control_findings
                )
                has_medium = any(
                    f.severity == Severity.MEDIUM for f in control_findings
                )

                if has_critical:
                    section_status = "fail"
                elif has_medium:
                    section_status = "warning"
                else:
                    section_status = "pass"
            elif control_id in status.findings_by_control:
                section_status = "pass"
            else:
                section_status = "not_assessed"

            # Generate recommendations
            recommendations = self._generate_recommendations(
                control_id, control_findings, framework
            )

            sections.append(
                ComplianceReportSection(
                    control_id=control_id,
                    control_title=control_info.get("title", ""),
                    control_description=control_info.get("description", ""),
                    status=section_status,
                    findings=control_findings,
                    recommendations=recommendations,
                )
            )

        return sections

    def _get_framework_controls(
        self, framework: ComplianceFramework
    ) -> Dict[str, Dict[str, str]]:
        """Get all controls for a framework."""
        controls = {}

        if framework == ComplianceFramework.OWASP_LLM:
            for control in get_owasp_llm():
                controls[control.id] = {
                    "title": control.title,
                    "description": control.description,
                }
        elif framework == ComplianceFramework.OWASP_MCP:
            for control in get_owasp_mcp():
                controls[control.id] = {
                    "title": control.title,
                    "description": control.description,
                }
        elif framework == ComplianceFramework.SOC2:
            for control in get_soc2():
                controls[control.id] = {
                    "title": control.title,
                    "description": control.description,
                }
        elif framework == ComplianceFramework.PCI_DSS:
            for req in get_pci():
                controls[req.id] = {
                    "title": req.title,
                    "description": req.description,
                }
        elif framework == ComplianceFramework.HIPAA:
            for safeguard in get_hipaa():
                controls[safeguard.id] = {
                    "title": safeguard.title,
                    "description": safeguard.description,
                }

        return controls

    def _generate_recommendations(
        self,
        control_id: str,
        findings: List[Finding],
        framework: ComplianceFramework,
    ) -> List[str]:
        """Generate recommendations for a control."""
        recommendations = []

        if not findings:
            return recommendations

        # Collect unique remediations
        seen_remediations = set()
        for finding in findings:
            if finding.remediation and finding.remediation not in seen_remediations:
                recommendations.append(finding.remediation)
                seen_remediations.add(finding.remediation)

        # Add framework-specific recommendations
        framework_recs = self._get_framework_recommendations(control_id, framework)
        for rec in framework_recs:
            if rec not in seen_remediations:
                recommendations.append(rec)

        return recommendations

    def _get_framework_recommendations(
        self, control_id: str, framework: ComplianceFramework
    ) -> List[str]:
        """Get framework-specific recommendations."""
        recommendations = []

        if framework == ComplianceFramework.OWASP_LLM:
            control = OWASP_LLM_TOP_10.get(control_id)
            if control:
                recommendations.extend(control.prevention)
        elif framework == ComplianceFramework.OWASP_MCP:
            control = OWASP_MCP_TOP_10.get(control_id)
            if control:
                recommendations.extend(control.prevention)
        elif framework == ComplianceFramework.SOC2:
            control = SOC2_CONTROLS.get(control_id)
            if control:
                recommendations.extend(control.criteria)
        elif framework == ComplianceFramework.PCI_DSS:
            req = PCI_DSS_REQUIREMENTS.get(control_id)
            if req:
                recommendations.extend(req.sub_requirements)
        elif framework == ComplianceFramework.HIPAA:
            safeguard = HIPAA_SAFEGUARDS.get(control_id)
            if safeguard:
                recommendations.extend(safeguard.implementation_specs)

        return recommendations

    def _generate_executive_summary(
        self,
        framework: ComplianceFramework,
        status: ComplianceStatus,
        total_findings: int,
    ) -> str:
        """Generate executive summary for the report."""
        framework_name = self.framework_names.get(framework, str(framework))

        summary_parts = [
            f"This {framework_name} compliance assessment was conducted on {datetime.now().strftime('%Y-%m-%d')}.",
            "",
        ]

        # Overall status
        if status.compliance_percentage >= 90:
            summary_parts.append(
                f"Overall compliance status: STRONG ({status.compliance_percentage:.1f}%)"
            )
        elif status.compliance_percentage >= 70:
            summary_parts.append(
                f"Overall compliance status: MODERATE ({status.compliance_percentage:.1f}%)"
            )
        else:
            summary_parts.append(
                f"Overall compliance status: NEEDS IMPROVEMENT ({status.compliance_percentage:.1f}%)"
            )

        summary_parts.append("")

        # Key metrics
        summary_parts.append("Key Metrics:")
        summary_parts.append(f"- Total controls assessed: {status.controls_assessed}")
        summary_parts.append(f"- Controls passing: {status.controls_passing}")
        summary_parts.append(f"- Controls failing: {status.controls_failing}")
        summary_parts.append(f"- Controls with warnings: {status.controls_warning}")
        summary_parts.append(f"- Total security findings: {total_findings}")

        if status.controls_failing > 0:
            summary_parts.append("")
            summary_parts.append(
                "IMMEDIATE ACTION REQUIRED: Address failing controls to achieve compliance."
            )

        return "\n".join(summary_parts)

    def to_dict(self, report: ComplianceReport) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "framework": report.framework.value,
            "framework_name": report.framework_name,
            "generated_at": report.generated_at.isoformat(),
            "scan_target": report.scan_target,
            "summary": {
                "total_controls": report.total_controls,
                "controls_passing": report.controls_passing,
                "controls_failing": report.controls_failing,
                "controls_warning": report.controls_warning,
                "controls_not_assessed": report.controls_not_assessed,
                "compliance_percentage": report.compliance_percentage,
            },
            "executive_summary": report.executive_summary,
            "sections": [
                {
                    "control_id": s.control_id,
                    "control_title": s.control_title,
                    "control_description": s.control_description,
                    "status": s.status,
                    "findings": [
                        {
                            "id": f.id,
                            "rule_id": f.rule_id,
                            "title": f.title,
                            "severity": f.severity.value,
                            "description": f.description,
                        }
                        for f in s.findings
                    ],
                    "recommendations": s.recommendations,
                }
                for s in report.sections
            ],
            "metadata": report.metadata,
        }

    def to_json(self, report: ComplianceReport, indent: int = 2) -> str:
        """Convert report to JSON string."""
        return json.dumps(self.to_dict(report), indent=indent)

    def save_report(
        self, report: ComplianceReport, output_path: Path, format: str = "json"
    ) -> None:
        """Save report to file."""
        output_path = Path(output_path)

        if format == "json":
            output_path.write_text(self.to_json(report))
        elif format == "html":
            html_content = self._generate_html_report(report)
            output_path.write_text(html_content)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _generate_html_report(self, report: ComplianceReport) -> str:
        """Generate HTML report."""
        sections_html = []

        for section in report.sections:
            status_color = {
                "pass": "#28a745",
                "fail": "#dc3545",
                "warning": "#ffc107",
                "not_assessed": "#6c757d",
            }.get(section.status, "#6c757d")

            findings_html = ""
            if section.findings:
                findings_items = "".join(
                    f"<li><strong>{f.title}</strong> ({f.severity.value}): {f.description}</li>"
                    for f in section.findings
                )
                findings_html = f"<h4>Findings</h4><ul>{findings_items}</ul>"

            recommendations_html = ""
            if section.recommendations:
                rec_items = "".join(
                    f"<li>{r}</li>" for r in section.recommendations
                )
                recommendations_html = f"<h4>Recommendations</h4><ul>{rec_items}</ul>"

            sections_html.append(
                f"""
                <div class="section">
                    <div class="section-header">
                        <span class="control-id">{section.control_id}</span>
                        <span class="control-title">{section.control_title}</span>
                        <span class="status" style="background-color: {status_color}">{section.status.upper()}</span>
                    </div>
                    <p class="description">{section.control_description}</p>
                    {findings_html}
                    {recommendations_html}
                </div>
                """
            )

        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{report.framework_name} Compliance Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin: 20px 0; }}
        .metric {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: #007bff; }}
        .metric-label {{ color: #666; margin-top: 5px; }}
        .executive-summary {{ background: #e9ecef; padding: 20px; border-radius: 8px; margin: 20px 0; white-space: pre-line; }}
        .section {{ border: 1px solid #dee2e6; border-radius: 8px; margin: 15px 0; padding: 20px; }}
        .section-header {{ display: flex; align-items: center; gap: 15px; margin-bottom: 10px; }}
        .control-id {{ font-weight: bold; color: #007bff; }}
        .control-title {{ flex-grow: 1; font-weight: 500; }}
        .status {{ padding: 4px 12px; border-radius: 4px; color: white; font-size: 0.85em; font-weight: bold; }}
        .description {{ color: #666; margin: 10px 0; }}
        h4 {{ margin: 15px 0 10px; color: #333; }}
        ul {{ margin: 0; padding-left: 20px; }}
        li {{ margin: 5px 0; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{report.framework_name} Compliance Report</h1>
        <p><strong>Generated:</strong> {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
        {f'<p><strong>Target:</strong> {report.scan_target}</p>' if report.scan_target else ''}

        <div class="summary">
            <div class="metric">
                <div class="metric-value">{report.compliance_percentage:.1f}%</div>
                <div class="metric-label">Compliance Score</div>
            </div>
            <div class="metric">
                <div class="metric-value">{report.controls_passing}</div>
                <div class="metric-label">Passing</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: #dc3545">{report.controls_failing}</div>
                <div class="metric-label">Failing</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: #ffc107">{report.controls_warning}</div>
                <div class="metric-label">Warnings</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: #6c757d">{report.controls_not_assessed}</div>
                <div class="metric-label">Not Assessed</div>
            </div>
        </div>

        <h2>Executive Summary</h2>
        <div class="executive-summary">{report.executive_summary}</div>

        <h2>Control Assessment Details</h2>
        {''.join(sections_html)}

        <div class="footer">
            <p>Generated by SecureAgent - AI & Cloud Security Platform</p>
        </div>
    </div>
</body>
</html>
"""

    def generate_gap_analysis(
        self, findings: List[Finding], framework: ComplianceFramework
    ) -> Dict[str, Any]:
        """Generate a compliance gap analysis."""
        status = self.mapper.get_compliance_status(findings, framework)
        controls = self._get_framework_controls(framework)

        gaps = []
        for control_id, control_info in controls.items():
            control_findings = status.findings_by_control.get(control_id, [])

            critical_findings = [
                f
                for f in control_findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH)
            ]

            if critical_findings:
                gaps.append(
                    {
                        "control_id": control_id,
                        "control_title": control_info.get("title", ""),
                        "gap_severity": "high",
                        "finding_count": len(critical_findings),
                        "findings": [
                            {"id": f.id, "title": f.title, "severity": f.severity.value}
                            for f in critical_findings
                        ],
                        "remediation_priority": 1,
                    }
                )

        # Sort by priority
        gaps.sort(key=lambda x: x["remediation_priority"])

        return {
            "framework": framework.value,
            "total_gaps": len(gaps),
            "gaps": gaps,
            "compliance_percentage": status.compliance_percentage,
        }
