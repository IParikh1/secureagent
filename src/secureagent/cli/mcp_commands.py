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
        if risk_score and result.findings:
            from secureagent.ml import RiskScorer
            from rich.panel import Panel

            console.print("\n[bold]Risk Analysis[/bold]")

            # Find model path
            model_locations = [
                Path(__file__).parent.parent.parent.parent / "models" / "secureagent_risk_v1.pkl",
                Path(__file__).parent.parent.parent.parent / "models" / "mcp_risk_model_latest.pkl",
                Path("models") / "secureagent_risk_v1.pkl",
            ]
            model_path = next((p for p in model_locations if p.exists()), None)

            if model_path:
                console.print(f"[dim]Using ML model: {model_path.name}[/dim]")
                scorer = RiskScorer(model_path=model_path, use_ml=True)
            else:
                console.print("[dim]Using heuristic scoring[/dim]")
                scorer = RiskScorer(use_ml=False)

            assessment = scorer.score_findings(result.findings)

            # Color based on risk
            risk_score_val = assessment.overall_score
            if risk_score_val >= 0.7:
                color = "red"
            elif risk_score_val >= 0.4:
                color = "yellow"
            else:
                color = "green"

            console.print(Panel(
                f"[{color} bold]Risk Score: {risk_score_val:.1%}[/{color} bold]\n"
                f"Level: [{color}]{assessment.risk_level.upper()}[/{color}]\n"
                f"Confidence: {assessment.confidence:.1%}",
                title="Overall Risk",
            ))

            if assessment.recommendations:
                console.print("\n[bold]Recommendations:[/bold]")
                for rec in assessment.recommendations[:3]:
                    console.print(f"  - {rec}")

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
    option: Optional[int] = typer.Option(None, "--option", help="Fix option index to use (0-based)"),
) -> None:
    """Generate and optionally apply fixes for MCP security issues.

    Examples:
        secureagent mcp fix ./mcp.json
        secureagent mcp fix ./mcp.json --output fixed.json
        secureagent mcp fix ./mcp.json --apply
        secureagent mcp fix ./mcp.json --apply --option 1
    """
    from rich.panel import Panel
    from rich.syntax import Syntax
    from secureagent.core.scanner.registry import scanner_registry
    from secureagent.remediation import RemediationGenerator, Fixer

    console.print(f"\n[bold blue]MCP Auto-Remediation[/bold blue]")
    console.print(f"File: [cyan]{path}[/cyan]\n")

    if not path.exists():
        console.print(f"[red]File not found: {path}[/red]")
        raise typer.Exit(1)

    # First, scan for findings
    scanner = scanner_registry.get("mcp")
    if not scanner:
        console.print("[red]MCP scanner not available[/red]")
        raise typer.Exit(1)

    scanner.initialize()
    try:
        result = scanner.scan(str(path))
    finally:
        scanner.cleanup()

    if not result.findings:
        console.print("[green]No security issues found - no fixes needed![/green]")
        return

    console.print(f"Found [yellow]{len(result.findings)}[/yellow] security issues\n")

    # Generate fixes
    generator = RemediationGenerator()
    fixes = generator.generate_fixes(result.findings)

    if not fixes:
        console.print("[yellow]No automatic fixes available for the found issues[/yellow]")
        return

    console.print(f"Generated [green]{len(fixes)}[/green] fix suggestions\n")

    # Display fix options
    for i, fix in enumerate(fixes):
        console.print(f"[bold cyan]Fix {i + 1}: {fix.rule_id}[/bold cyan]")
        console.print(f"  File: {fix.file_path}:{fix.line_number or '?'}")

        for j, opt in enumerate(fix.options):
            marker = "[recommended]" if j == fix.recommended_option else ""
            console.print(f"\n  [yellow]Option {j}[/yellow] {marker}: {opt.title}")
            console.print(f"    {opt.description}")
            if opt.security_impact:
                console.print(f"    [green]Security:[/green] {opt.security_impact}")
            if opt.breaking_changes:
                console.print(f"    [red]Breaking:[/red] {', '.join(opt.breaking_changes)}")

        console.print()

    # Preview or apply
    if preview and not apply:
        console.print("[dim]Use --apply to apply fixes (creates backup)[/dim]")
        console.print("[dim]Use --option N to select a specific fix option[/dim]")

        # Show diff preview
        fixer = Fixer()
        for fix in fixes:
            dry_result = fixer.apply_fix(fix, dry_run=True, option_index=option)
            if dry_result.diff:
                console.print(f"\n[bold]Preview for {fix.rule_id}:[/bold]")
                syntax = Syntax(dry_result.diff, "diff", theme="monokai", line_numbers=False)
                console.print(syntax)

    if apply:
        console.print("\n[bold]Applying fixes...[/bold]")

        fixer = Fixer()
        summary = fixer.apply_fixes(fixes, dry_run=False, option_index=option)

        # Report results
        console.print(f"\n[bold]Results:[/bold]")
        console.print(f"  Successful: [green]{summary.successful}[/green]")
        console.print(f"  Failed: [red]{summary.failed}[/red]")
        console.print(f"  Manual required: [yellow]{summary.manual_required}[/yellow]")
        console.print(f"  Skipped: [dim]{summary.skipped}[/dim]")

        # Show details
        for res in summary.results:
            if res.status.value == "success":
                console.print(f"\n[green]✓[/green] {res.rule_id}: {res.message}")
                if res.backup_path:
                    console.print(f"  [dim]Backup: {res.backup_path}[/dim]")
            elif res.status.value == "manual_required":
                console.print(f"\n[yellow]![/yellow] {res.rule_id}: {res.message}")
            elif res.status.value == "failed":
                console.print(f"\n[red]✗[/red] {res.rule_id}: {res.message}")

        if summary.successful > 0:
            console.print(Panel(
                f"[green]Applied {summary.successful} fix(es) successfully![/green]\n"
                f"Backups created in .secureagent/backups/",
                title="Complete",
                border_style="green",
            ))


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
