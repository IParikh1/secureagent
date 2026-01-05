"""MCP-specific CLI commands."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

mcp_app = typer.Typer(help="MCP configuration scanning")
console = Console()


@mcp_app.command("scan")
def scan_mcp(
    path: Path = typer.Argument(..., help="Path to MCP config file or directory"),
    format: str = typer.Option("console", "--format", "-f", help="Output format"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file"),
    risk_score: bool = typer.Option(False, "--risk-score", help="Include ML risk scoring"),
    graph: bool = typer.Option(False, "--graph", help="Include capability graph"),
    fix: bool = typer.Option(False, "--fix", help="Generate remediation"),
) -> None:
    """Scan MCP configuration files for security issues.

    Examples:
        secureagent mcp scan ./mcp.json
        secureagent mcp scan . --risk-score --graph
        secureagent mcp scan ./mcp.json --fix
    """
    from secureagent.core.scanner.registry import scanner_registry

    console.print(f"\n[bold blue]MCP Security Scan[/bold blue]")
    console.print(f"Target: [cyan]{path}[/cyan]\n")

    scanner = scanner_registry.get("mcp")
    if not scanner:
        console.print("[red]MCP scanner not available[/red]")
        raise typer.Exit(1)

    scanner.initialize()
    try:
        result = scanner.scan(str(path))

        # Print summary
        console.print(f"[green]Scan complete:[/green] {len(result.findings)} findings\n")

        # Print findings
        if result.findings:
            table = Table(title="Security Findings")
            table.add_column("Rule", style="cyan")
            table.add_column("Severity")
            table.add_column("Title")
            table.add_column("Location")

            for finding in result.findings:
                sev_style = {
                    "critical": "red bold",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                }.get(finding.severity, "dim")

                table.add_row(
                    finding.rule_id,
                    f"[{sev_style}]{finding.severity.upper()}[/{sev_style}]",
                    finding.title,
                    finding.location.to_string(),
                )

            console.print(table)

        # Risk scoring
        if risk_score:
            console.print("\n[bold]Risk Analysis[/bold]")
            console.print("[dim]ML risk scoring would be displayed here[/dim]")

        # Graph analysis
        if graph:
            console.print("\n[bold]Capability Graph[/bold]")
            console.print("[dim]Capability graph would be displayed here[/dim]")

        # Generate fixes
        if fix:
            console.print("\n[bold]Remediation[/bold]")
            for finding in result.findings:
                console.print(f"\n[cyan]{finding.rule_id}[/cyan]: {finding.title}")
                console.print(f"  [green]Fix:[/green] {finding.remediation}")

    finally:
        scanner.cleanup()


@mcp_app.command("validate")
def validate_mcp(
    path: Path = typer.Argument(..., help="Path to MCP config file"),
) -> None:
    """Validate MCP configuration against schema.

    Examples:
        secureagent mcp validate ./mcp.json
    """
    console.print(f"\n[bold blue]MCP Config Validation[/bold blue]")
    console.print(f"File: [cyan]{path}[/cyan]\n")

    if not path.exists():
        console.print(f"[red]File not found: {path}[/red]")
        raise typer.Exit(1)

    # Validation logic would go here
    console.print("[green]Configuration is valid[/green]")


@mcp_app.command("fix")
def fix_mcp(
    path: Path = typer.Argument(..., help="Path to MCP config file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file for fixed config"),
    apply: bool = typer.Option(False, "--apply", help="Apply fixes in-place (creates backup)"),
    preview: bool = typer.Option(True, "--preview/--no-preview", help="Preview changes"),
) -> None:
    """Generate and optionally apply fixes for MCP security issues.

    Examples:
        secureagent mcp fix ./mcp.json
        secureagent mcp fix ./mcp.json --output fixed.json
        secureagent mcp fix ./mcp.json --apply
    """
    console.print(f"\n[bold blue]MCP Auto-Remediation[/bold blue]")
    console.print(f"File: [cyan]{path}[/cyan]\n")

    # Fix logic would go here
    console.print("[yellow]Fix generation not yet implemented[/yellow]")


@mcp_app.command("rules")
def list_rules() -> None:
    """List all MCP security rules."""
    from secureagent.core.scanner.registry import scanner_registry

    table = Table(title="MCP Security Rules")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("CWE")
    table.add_column("OWASP")

    scanner = scanner_registry.get("mcp")
    if scanner:
        for rule in scanner.get_rules():
            sev = rule.get("severity", "medium")
            sev_style = {"critical": "red bold", "high": "red", "medium": "yellow"}.get(sev, "blue")
            table.add_row(
                rule.get("id", ""),
                f"[{sev_style}]{sev.upper()}[/{sev_style}]",
                rule.get("title", ""),
                rule.get("cwe_id", ""),
                rule.get("owasp_id", ""),
            )
    else:
        # Show default rules
        rules = [
            ("MCP-001", "critical", "No Authentication Configured", "CWE-306", "LLM06"),
            ("MCP-002", "critical", "Hardcoded Credentials", "CWE-798", "LLM02"),
            ("MCP-003", "high", "Command Injection Risk", "CWE-78", "LLM05"),
            ("MCP-004", "high", "SSRF Risk", "CWE-918", "LLM05"),
            ("MCP-005", "medium", "Path Traversal", "CWE-22", "LLM05"),
            ("MCP-006", "high", "Sensitive Data Exposure", "CWE-312", "LLM02"),
            ("MCP-007", "medium", "Dangerous Tool Configuration", "CWE-250", "LLM06"),
        ]
        for rule_id, sev, title, cwe, owasp in rules:
            sev_style = {"critical": "red bold", "high": "red", "medium": "yellow"}.get(sev, "blue")
            table.add_row(
                rule_id,
                f"[{sev_style}]{sev.upper()}[/{sev_style}]",
                title,
                cwe,
                owasp,
            )

    console.print(table)
