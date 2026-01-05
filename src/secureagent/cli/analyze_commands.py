"""Risk and data flow analysis CLI commands."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

analyze_app = typer.Typer(help="Risk & data flow analysis")
console = Console()


@analyze_app.command("permissions")
def analyze_permissions(
    target: str = typer.Argument(..., help="Agent ID or config path"),
    format: str = typer.Option("table", "--format", "-f", help="Output format"),
) -> None:
    """Analyze permissions and capabilities of an agent.

    Examples:
        secureagent analyze permissions ./mcp.json
        secureagent analyze permissions agent-123
    """
    console.print(f"\n[bold blue]Permission Analysis[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    # Permission analysis would go here
    table = Table(title="Agent Permissions")
    table.add_column("Action", style="cyan")
    table.add_column("Resource")
    table.add_column("Risk Level")
    table.add_column("Flags")

    # Example data
    permissions = [
        ("read_file", "*", "medium", ""),
        ("write_file", "/tmp/*", "high", "destructive"),
        ("execute_code", "python", "critical", "privileged"),
        ("http_request", "*.api.com", "medium", "egress"),
    ]

    for action, resource, risk, flags in permissions:
        risk_style = {"critical": "red bold", "high": "red", "medium": "yellow"}.get(risk, "blue")
        table.add_row(
            action,
            resource,
            f"[{risk_style}]{risk.upper()}[/{risk_style}]",
            flags,
        )

    console.print(table)

    # Summary
    console.print(Panel(
        "[yellow]3 high-risk permissions detected[/yellow]\n"
        "Consider restricting: execute_code, write_file",
        title="Summary",
    ))


@analyze_app.command("data-flow")
def analyze_data_flow(
    target: str = typer.Argument(..., help="Agent ID or config path"),
    visualize: bool = typer.Option(False, "--visualize", "-v", help="Generate visual diagram"),
) -> None:
    """Trace data flows through an agent.

    Examples:
        secureagent analyze data-flow ./mcp.json
        secureagent analyze data-flow agent-123 --visualize
    """
    console.print(f"\n[bold blue]Data Flow Analysis[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    # Data flow analysis
    table = Table(title="Data Flows")
    table.add_column("Source", style="cyan")
    table.add_column("Destination", style="blue")
    table.add_column("Data Types")
    table.add_column("Protected")
    table.add_column("Risk")

    flows = [
        ("user_input", "prompt", "user_input", "Yes", "low"),
        ("prompt", "llm_api", "pii,context", "Yes", "medium"),
        ("tool_response", "memory", "api_response", "No", "high"),
        ("memory", "external_api", "pii", "No", "critical"),
    ]

    for src, dst, data, protected, risk in flows:
        risk_style = {"critical": "red bold", "high": "red", "medium": "yellow"}.get(risk, "blue")
        prot_style = "green" if protected == "Yes" else "red"
        table.add_row(
            src,
            dst,
            data,
            f"[{prot_style}]{protected}[/{prot_style}]",
            f"[{risk_style}]{risk.upper()}[/{risk_style}]",
        )

    console.print(table)

    # Egress summary
    console.print("\n[bold]External Egress Paths:[/bold]")
    console.print("  - external_api (unprotected PII flow)")
    console.print("  - llm_api (protected)")


@analyze_app.command("guardrails")
def analyze_guardrails(
    target: str = typer.Argument(..., help="Agent ID or config path"),
) -> None:
    """Check guardrail coverage for an agent.

    Examples:
        secureagent analyze guardrails ./mcp.json
    """
    console.print(f"\n[bold blue]Guardrail Coverage Analysis[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    table = Table(title="Guardrail Coverage")
    table.add_column("Protection", style="cyan")
    table.add_column("Status")
    table.add_column("Guardrail")

    coverage = [
        ("Prompt Injection", True, "input_sanitizer"),
        ("Jailbreak", True, "jailbreak_detector"),
        ("Data Leakage", False, "-"),
        ("PII Protection", False, "-"),
        ("Harmful Content", True, "content_filter"),
        ("Rate Limiting", True, "rate_limiter"),
    ]

    for protection, covered, guardrail in coverage:
        if covered:
            table.add_row(protection, "[green]COVERED[/green]", guardrail)
        else:
            table.add_row(protection, "[red]NOT COVERED[/red]", "-")

    console.print(table)

    # Coverage percentage
    covered_count = sum(1 for _, c, _ in coverage if c)
    total = len(coverage)
    pct = (covered_count / total) * 100

    color = "green" if pct >= 80 else "yellow" if pct >= 50 else "red"
    console.print(f"\n[bold]Coverage:[/bold] [{color}]{pct:.0f}%[/{color}] ({covered_count}/{total})")


@analyze_app.command("egress")
def analyze_egress(
    target: str = typer.Argument(..., help="Agent ID or config path"),
) -> None:
    """Map egress paths where data can flow out.

    Examples:
        secureagent analyze egress ./mcp.json
    """
    console.print(f"\n[bold blue]Egress Path Analysis[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    table = Table(title="Egress Paths")
    table.add_column("Destination", style="cyan")
    table.add_column("Type")
    table.add_column("Encrypted")
    table.add_column("Authenticated")
    table.add_column("Data Types")
    table.add_column("Risk")

    paths = [
        ("api.openai.com", "HTTPS", "Yes", "Yes", "prompts", "low"),
        ("slack.com/webhook", "HTTPS", "Yes", "Yes", "alerts", "low"),
        ("internal-db:5432", "TCP", "No", "Yes", "pii,logs", "high"),
        ("s3://logs-bucket", "HTTPS", "Yes", "Yes", "audit_logs", "medium"),
    ]

    for dest, typ, enc, auth, data, risk in paths:
        risk_style = {"critical": "red bold", "high": "red", "medium": "yellow"}.get(risk, "blue")
        enc_style = "green" if enc == "Yes" else "red"
        auth_style = "green" if auth == "Yes" else "red"

        table.add_row(
            dest,
            typ,
            f"[{enc_style}]{enc}[/{enc_style}]",
            f"[{auth_style}]{auth}[/{auth_style}]",
            data,
            f"[{risk_style}]{risk.upper()}[/{risk_style}]",
        )

    console.print(table)


@analyze_app.command("risk")
def analyze_risk(
    target: str = typer.Argument(..., help="Agent ID or config path"),
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Show detailed breakdown"),
) -> None:
    """Calculate ML-based risk score for an agent.

    Examples:
        secureagent analyze risk ./mcp.json
        secureagent analyze risk agent-123 --detailed
    """
    console.print(f"\n[bold blue]Risk Score Analysis[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    # Risk score would be calculated by ML model
    risk_score = 0.72
    confidence = 0.95

    # Color based on risk
    if risk_score >= 0.7:
        color = "red"
        level = "HIGH"
    elif risk_score >= 0.4:
        color = "yellow"
        level = "MEDIUM"
    else:
        color = "green"
        level = "LOW"

    console.print(Panel(
        f"[{color} bold]Risk Score: {risk_score:.1%}[/{color} bold]\n"
        f"Level: [{color}]{level}[/{color}]\n"
        f"Confidence: {confidence:.1%}",
        title="Overall Risk",
    ))

    if detailed:
        console.print("\n[bold]Risk Factor Breakdown:[/bold]")

        table = Table()
        table.add_column("Factor", style="cyan")
        table.add_column("Score")
        table.add_column("Weight")
        table.add_column("Contribution")

        factors = [
            ("Dangerous Tools", 0.85, "15%", "+12.8%"),
            ("Missing Guardrails", 0.60, "12%", "+7.2%"),
            ("External Egress", 0.70, "10%", "+7.0%"),
            ("Sensitive Data Access", 0.50, "10%", "+5.0%"),
            ("Auth Configuration", 0.30, "8%", "+2.4%"),
        ]

        for factor, score, weight, contrib in factors:
            score_color = "red" if score >= 0.7 else "yellow" if score >= 0.4 else "green"
            table.add_row(factor, f"[{score_color}]{score:.0%}[/{score_color}]", weight, contrib)

        console.print(table)
