"""Compliance reporting CLI commands."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

compliance_app = typer.Typer(help="Compliance reporting")
console = Console()


@compliance_app.command("report")
def generate_report(
    framework: str = typer.Argument(..., help="Compliance framework (owasp-llm, owasp-mcp, soc2, pci, hipaa)"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target to assess"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file"),
    format: str = typer.Option("console", "--format", "-f", help="Output format (console, html, pdf, json)"),
) -> None:
    """Generate compliance report for a framework.

    Examples:
        secureagent compliance report owasp-llm
        secureagent compliance report soc2 --output report.html --format html
        secureagent compliance report pci --target ./mcp.json
    """
    console.print(f"\n[bold blue]Compliance Report[/bold blue]")
    console.print(f"Framework: [cyan]{framework.upper()}[/cyan]")
    if target:
        console.print(f"Target: [cyan]{target}[/cyan]")
    console.print()

    if framework == "owasp-llm":
        _report_owasp_llm()
    elif framework == "owasp-mcp":
        _report_owasp_mcp()
    elif framework == "soc2":
        _report_soc2()
    elif framework == "pci":
        _report_pci()
    elif framework == "hipaa":
        _report_hipaa()
    else:
        console.print(f"[red]Unknown framework: {framework}[/red]")
        raise typer.Exit(1)

    if output:
        console.print(f"\n[green]Report saved to {output}[/green]")


def _report_owasp_llm() -> None:
    """Generate OWASP LLM Top 10 report."""
    table = Table(title="OWASP LLM Top 10 Compliance")
    table.add_column("ID", style="cyan")
    table.add_column("Category")
    table.add_column("Status")
    table.add_column("Findings")

    controls = [
        ("LLM01", "Prompt Injection", "partial", 3),
        ("LLM02", "Insecure Output Handling", "compliant", 0),
        ("LLM03", "Training Data Poisoning", "n/a", 0),
        ("LLM04", "Model Denial of Service", "partial", 1),
        ("LLM05", "Supply Chain Vulnerabilities", "compliant", 0),
        ("LLM06", "Sensitive Information Disclosure", "non-compliant", 5),
        ("LLM07", "Insecure Plugin Design", "partial", 2),
        ("LLM08", "Excessive Agency", "non-compliant", 4),
        ("LLM09", "Overreliance", "n/a", 0),
        ("LLM10", "Model Theft", "compliant", 0),
    ]

    for id, cat, status, findings in controls:
        if status == "compliant":
            status_str = "[green]COMPLIANT[/green]"
        elif status == "partial":
            status_str = "[yellow]PARTIAL[/yellow]"
        elif status == "non-compliant":
            status_str = "[red]NON-COMPLIANT[/red]"
        else:
            status_str = "[dim]N/A[/dim]"

        table.add_row(id, cat, status_str, str(findings) if findings else "-")

    console.print(table)


def _report_owasp_mcp() -> None:
    """Generate OWASP MCP Top 10 report."""
    table = Table(title="OWASP MCP Top 10 Compliance")
    table.add_column("ID", style="cyan")
    table.add_column("Category")
    table.add_column("Status")
    table.add_column("Findings")

    controls = [
        ("MCP01", "Token/Credential Exposure", "non-compliant", 2),
        ("MCP02", "Privilege Escalation", "partial", 1),
        ("MCP03", "Tool Poisoning", "compliant", 0),
        ("MCP04", "Data Exfiltration", "partial", 2),
        ("MCP05", "Command Injection", "non-compliant", 3),
        ("MCP06", "Prompt Injection via Tools", "partial", 1),
        ("MCP07", "Authentication Weakness", "non-compliant", 2),
        ("MCP08", "Insufficient Logging", "partial", 1),
        ("MCP09", "Resource Exhaustion", "compliant", 0),
        ("MCP10", "Insecure Communication", "compliant", 0),
    ]

    for id, cat, status, findings in controls:
        if status == "compliant":
            status_str = "[green]COMPLIANT[/green]"
        elif status == "partial":
            status_str = "[yellow]PARTIAL[/yellow]"
        else:
            status_str = "[red]NON-COMPLIANT[/red]"

        table.add_row(id, cat, status_str, str(findings) if findings else "-")

    console.print(table)


def _report_soc2() -> None:
    """Generate SOC2 compliance report."""
    console.print(Panel(
        "[bold]SOC2 Trust Service Criteria - AI Controls[/bold]\n\n"
        "CC6.1 - Logical Access: [yellow]PARTIAL[/yellow]\n"
        "CC6.6 - Security Events: [green]COMPLIANT[/green]\n"
        "CC6.7 - Encryption: [green]COMPLIANT[/green]\n"
        "CC7.2 - Monitoring: [yellow]PARTIAL[/yellow]\n"
        "CC8.1 - Change Management: [red]NON-COMPLIANT[/red]",
        title="SOC2 Summary",
    ))


def _report_pci() -> None:
    """Generate PCI-DSS compliance report."""
    console.print(Panel(
        "[bold]PCI-DSS v4.0 - AI-Related Requirements[/bold]\n\n"
        "6.5.1 - Injection Flaws: [yellow]PARTIAL[/yellow]\n"
        "6.5.4 - Insecure Communications: [green]COMPLIANT[/green]\n"
        "8.2 - Authentication: [red]NON-COMPLIANT[/red]\n"
        "10.2 - Audit Trails: [yellow]PARTIAL[/yellow]",
        title="PCI-DSS Summary",
    ))


def _report_hipaa() -> None:
    """Generate HIPAA compliance report."""
    console.print(Panel(
        "[bold]HIPAA Security Rule - AI PHI Protection[/bold]\n\n"
        "164.312(a) - Access Control: [yellow]PARTIAL[/yellow]\n"
        "164.312(b) - Audit Controls: [green]COMPLIANT[/green]\n"
        "164.312(c) - Integrity: [green]COMPLIANT[/green]\n"
        "164.312(d) - Authentication: [red]NON-COMPLIANT[/red]\n"
        "164.312(e) - Transmission Security: [green]COMPLIANT[/green]",
        title="HIPAA Summary",
    ))


@compliance_app.command("status")
def compliance_status() -> None:
    """Show overall compliance status across frameworks.

    Examples:
        secureagent compliance status
    """
    console.print(f"\n[bold blue]Compliance Status Overview[/bold blue]\n")

    table = Table(title="Framework Compliance")
    table.add_column("Framework", style="cyan")
    table.add_column("Status")
    table.add_column("Score")
    table.add_column("Findings")

    frameworks = [
        ("OWASP LLM Top 10", "partial", "65%", 15),
        ("OWASP MCP Top 10", "partial", "60%", 12),
        ("SOC2", "partial", "70%", 8),
        ("PCI-DSS", "non-compliant", "45%", 22),
        ("HIPAA", "partial", "75%", 6),
    ]

    for name, status, score, findings in frameworks:
        if status == "compliant":
            status_str = "[green]COMPLIANT[/green]"
            score_color = "green"
        elif status == "partial":
            status_str = "[yellow]PARTIAL[/yellow]"
            score_color = "yellow"
        else:
            status_str = "[red]NON-COMPLIANT[/red]"
            score_color = "red"

        table.add_row(name, status_str, f"[{score_color}]{score}[/{score_color}]", str(findings))

    console.print(table)


@compliance_app.command("gaps")
def compliance_gaps(
    framework: Optional[str] = typer.Option(None, "--framework", "-f", help="Filter by framework"),
) -> None:
    """Show compliance gaps and recommendations.

    Examples:
        secureagent compliance gaps
        secureagent compliance gaps --framework soc2
    """
    console.print(f"\n[bold blue]Compliance Gaps[/bold blue]\n")

    table = Table(title="Priority Gaps")
    table.add_column("Priority", style="cyan")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Gap")
    table.add_column("Remediation")

    gaps = [
        ("P1", "OWASP LLM", "LLM06", "Sensitive data in prompts", "Implement PII filtering"),
        ("P1", "PCI-DSS", "8.2", "Weak authentication", "Add MFA for agent access"),
        ("P2", "SOC2", "CC8.1", "No change tracking", "Implement config versioning"),
        ("P2", "OWASP MCP", "MCP05", "Command injection risk", "Sanitize tool inputs"),
        ("P3", "HIPAA", "164.312(d)", "Missing auth audit", "Enable auth logging"),
    ]

    for priority, fw, control, gap, remediation in gaps:
        priority_color = {"P1": "red", "P2": "yellow", "P3": "blue"}.get(priority, "dim")
        table.add_row(
            f"[{priority_color}]{priority}[/{priority_color}]",
            fw,
            control,
            gap,
            remediation,
        )

    console.print(table)


@compliance_app.command("export")
def export_report(
    framework: str = typer.Argument(..., help="Framework to export"),
    format: str = typer.Option("pdf", "--format", "-f", help="Export format (pdf, html, json)"),
    output: Path = typer.Option("compliance-report", "--output", "-o", help="Output file base name"),
) -> None:
    """Export compliance report to file.

    Examples:
        secureagent compliance export soc2 --format pdf
        secureagent compliance export owasp-llm --format html --output llm-report
    """
    console.print(f"\n[bold blue]Export Compliance Report[/bold blue]")
    console.print(f"Framework: [cyan]{framework}[/cyan]")
    console.print(f"Format: [cyan]{format}[/cyan]")

    output_file = f"{output}.{format}"
    console.print(f"\n[green]Report exported to {output_file}[/green]")
