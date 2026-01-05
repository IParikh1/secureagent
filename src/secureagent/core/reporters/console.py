"""Rich console reporter for SecureAgent."""

from typing import List, Optional, Dict, Any
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.style import Style
    from rich.box import ROUNDED

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

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


class ConsoleReporter:
    """Rich console output for scan results."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }

    SEVERITY_COLORS_STR = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    SEVERITY_ICONS = {
        Severity.CRITICAL: "[!]",
        Severity.HIGH: "[!]",
        Severity.MEDIUM: "[*]",
        Severity.LOW: "[-]",
        Severity.INFO: "[i]",
    }

    SEVERITY_ICONS_STR = {
        "critical": "[!]",
        "high": "[!]",
        "medium": "[*]",
        "low": "[-]",
        "info": "[i]",
    }

    def __init__(self, verbose: bool = False, no_color: bool = False):
        """Initialize console reporter."""
        self.verbose = verbose
        self.no_color = no_color

        if RICH_AVAILABLE and not no_color:
            self.console = Console()
        else:
            self.console = None

    def report(
        self,
        findings: List[Finding],
        scan_target: str = "",
        scan_duration: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Print scan results to console."""
        if self.console:
            self._report_rich(findings, scan_target, scan_duration, metadata)
        else:
            self._report_plain(findings, scan_target, scan_duration, metadata)

    def _report_rich(
        self,
        findings: List[Finding],
        scan_target: str,
        scan_duration: Optional[float],
        metadata: Optional[Dict[str, Any]],
    ) -> None:
        """Print results using Rich formatting."""
        # Header
        self.console.print()
        header = Panel(
            Text("SecureAgent Security Scan Results", justify="center", style="bold"),
            box=ROUNDED,
            style="blue",
        )
        self.console.print(header)

        # Summary
        self._print_summary_rich(findings, scan_target, scan_duration)

        if not findings:
            self.console.print(
                Panel(
                    "[green]No security issues found![/green]",
                    title="Result",
                    box=ROUNDED,
                )
            )
            return

        # Findings table
        self._print_findings_table_rich(findings)

        # Detailed findings
        if self.verbose:
            self._print_detailed_findings_rich(findings)

        # Footer
        self._print_footer_rich(findings)

    def _print_summary_rich(
        self,
        findings: List[Finding],
        scan_target: str,
        scan_duration: Optional[float],
    ) -> None:
        """Print summary panel with Rich."""
        severity_counts = self._count_severities(findings)

        summary_lines = []
        if scan_target:
            summary_lines.append(f"Target: {scan_target}")
        summary_lines.append(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if scan_duration:
            summary_lines.append(f"Duration: {scan_duration:.2f}s")
        summary_lines.append(f"Total findings: {len(findings)}")
        summary_lines.append("")

        for severity in Severity:
            count = severity_counts.get(severity, 0)
            color = self.SEVERITY_COLORS.get(severity, "white")
            summary_lines.append(f"  [{color}]{_get_severity_value(severity)}: {count}[/{color}]")

        self.console.print(
            Panel("\n".join(summary_lines), title="Scan Summary", box=ROUNDED)
        )

    def _print_findings_table_rich(self, findings: List[Finding]) -> None:
        """Print findings as a Rich table."""
        table = Table(
            title="Security Findings",
            box=ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )

        table.add_column("Severity", style="bold", width=10)
        table.add_column("Rule ID", width=12)
        table.add_column("Title", width=40)
        table.add_column("Location", width=35)

        # Sort by severity
        sorted_findings = sorted(
            findings, key=lambda f: list(Severity).index(_get_severity_enum(f.severity))
        )

        for finding in sorted_findings:
            severity_enum = _get_severity_enum(finding.severity)
            severity_style = self.SEVERITY_COLORS.get(severity_enum, "white")
            location = self._format_location(finding)

            table.add_row(
                Text(_get_severity_value(finding.severity), style=severity_style),
                finding.rule_id,
                finding.title[:40] + "..." if len(finding.title) > 40 else finding.title,
                location[:35] + "..." if len(location) > 35 else location,
            )

        self.console.print(table)

    def _print_detailed_findings_rich(self, findings: List[Finding]) -> None:
        """Print detailed findings with Rich."""
        self.console.print("\n[bold]Detailed Findings[/bold]\n")

        sorted_findings = sorted(
            findings, key=lambda f: list(Severity).index(_get_severity_enum(f.severity))
        )

        for i, finding in enumerate(sorted_findings, 1):
            severity_enum = _get_severity_enum(finding.severity)
            severity_value = _get_severity_value(finding.severity)
            severity_style = self.SEVERITY_COLORS.get(severity_enum, "white")
            icon = self.SEVERITY_ICONS.get(severity_enum, "[ ]")

            # Finding header
            self.console.print(
                f"\n[{severity_style}]{icon} {i}. {finding.title}[/{severity_style}]"
            )
            self.console.print(f"   Rule: {finding.rule_id}")
            self.console.print(f"   Severity: [{severity_style}]{severity_value}[/{severity_style}]")
            self.console.print(f"   Location: {self._format_location(finding)}")

            # Description
            self.console.print(f"\n   [dim]Description:[/dim]")
            self.console.print(f"   {finding.description}")

            # Remediation
            if finding.remediation:
                self.console.print(f"\n   [green]Remediation:[/green]")
                self.console.print(f"   {finding.remediation}")

            # CWE/OWASP
            if finding.cwe_id or finding.owasp_id:
                refs = []
                if finding.cwe_id:
                    refs.append(f"CWE: {finding.cwe_id}")
                if finding.owasp_id:
                    refs.append(f"OWASP: {finding.owasp_id}")
                self.console.print(f"\n   [cyan]References: {', '.join(refs)}[/cyan]")

            # Risk score
            if finding.risk_score is not None:
                score_color = "red" if finding.risk_score > 0.7 else "yellow" if finding.risk_score > 0.4 else "green"
                self.console.print(f"   Risk Score: [{score_color}]{finding.risk_score:.2f}[/{score_color}]")

    def _print_footer_rich(self, findings: List[Finding]) -> None:
        """Print footer with Rich."""
        critical_high = sum(
            1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        )

        if critical_high > 0:
            self.console.print(
                Panel(
                    f"[bold red]Found {critical_high} critical/high severity issues that require immediate attention![/bold red]",
                    box=ROUNDED,
                )
            )
        else:
            self.console.print(
                Panel(
                    "[yellow]Review findings and apply recommended remediations.[/yellow]",
                    box=ROUNDED,
                )
            )

    def _report_plain(
        self,
        findings: List[Finding],
        scan_target: str,
        scan_duration: Optional[float],
        metadata: Optional[Dict[str, Any]],
    ) -> None:
        """Print results using plain text."""
        print("\n" + "=" * 60)
        print("SecureAgent Security Scan Results")
        print("=" * 60)

        # Summary
        print(f"\nScan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if scan_target:
            print(f"Target: {scan_target}")
        if scan_duration:
            print(f"Duration: {scan_duration:.2f}s")
        print(f"Total findings: {len(findings)}")

        severity_counts = self._count_severities(findings)
        print("\nSeverity breakdown:")
        for severity in Severity:
            count = severity_counts.get(severity, 0)
            print(f"  {_get_severity_value(severity)}: {count}")

        if not findings:
            print("\nNo security issues found!")
            return

        # Findings
        print("\n" + "-" * 60)
        print("Findings:")
        print("-" * 60)

        sorted_findings = sorted(
            findings, key=lambda f: list(Severity).index(_get_severity_enum(f.severity))
        )

        for i, finding in enumerate(sorted_findings, 1):
            severity_enum = _get_severity_enum(finding.severity)
            severity_value = _get_severity_value(finding.severity)
            icon = self.SEVERITY_ICONS.get(severity_enum, "[ ]")
            print(f"\n{icon} {i}. [{severity_value}] {finding.title}")
            print(f"    Rule: {finding.rule_id}")
            print(f"    Location: {self._format_location(finding)}")

            if self.verbose:
                print(f"    Description: {finding.description}")
                if finding.remediation:
                    print(f"    Remediation: {finding.remediation}")

        print("\n" + "=" * 60)

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

    def print_progress(self, message: str) -> None:
        """Print progress message."""
        if self.console:
            self.console.print(f"[dim]{message}[/dim]")
        else:
            print(message)

    def print_error(self, message: str) -> None:
        """Print error message."""
        if self.console:
            self.console.print(f"[bold red]Error: {message}[/bold red]")
        else:
            print(f"Error: {message}")

    def print_success(self, message: str) -> None:
        """Print success message."""
        if self.console:
            self.console.print(f"[bold green]{message}[/bold green]")
        else:
            print(message)
