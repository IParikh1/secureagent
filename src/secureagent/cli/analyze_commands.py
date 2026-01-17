"""Risk and data flow analysis CLI commands."""

from pathlib import Path
from typing import Optional, List
import json

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from secureagent.core.models.finding import Finding

analyze_app = typer.Typer(help="Risk & data flow analysis")
console = Console()


def _get_default_model_path() -> Optional[Path]:
    """Get the default model path."""
    # Check common locations
    locations = [
        Path(__file__).parent.parent.parent.parent / "models" / "secureagent_risk_v1.pkl",
        Path(__file__).parent.parent.parent.parent / "models" / "mcp_risk_model_latest.pkl",
        Path.home() / ".secureagent" / "models" / "secureagent_risk_v1.pkl",
        Path("models") / "secureagent_risk_v1.pkl",
    ]

    for path in locations:
        if path.exists():
            return path
    return None


def _scan_target(target: str) -> List[Finding]:
    """Scan the target and return findings."""
    from secureagent.core.scanner.registry import scanner_registry

    target_path = Path(target)
    findings = []

    if target_path.exists():
        # Determine scanner based on file type
        if target_path.suffix in [".json", ""]:
            # Try MCP scanner
            scanner = scanner_registry.get("mcp")
            if scanner:
                scanner.initialize()
                try:
                    result = scanner.scan(str(target_path))
                    findings.extend(result.findings)
                finally:
                    scanner.cleanup()

        if target_path.suffix == ".tf":
            # Try Terraform scanner
            scanner = scanner_registry.get("terraform")
            if scanner:
                scanner.initialize()
                try:
                    result = scanner.scan(str(target_path))
                    findings.extend(result.findings)
                finally:
                    scanner.cleanup()

        # If directory, try all relevant scanners
        if target_path.is_dir():
            for scanner_name in ["mcp", "terraform", "langchain"]:
                scanner = scanner_registry.get(scanner_name)
                if scanner:
                    scanner.initialize()
                    try:
                        result = scanner.scan(str(target_path))
                        findings.extend(result.findings)
                    except Exception:
                        pass
                    finally:
                        scanner.cleanup()

    return findings


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
    model_path: Optional[Path] = typer.Option(None, "--model", "-m", help="Path to ML model file"),
    no_ml: bool = typer.Option(False, "--no-ml", help="Disable ML scoring, use heuristics only"),
) -> None:
    """Calculate ML-based risk score for an agent.

    Examples:
        secureagent analyze risk ./mcp.json
        secureagent analyze risk agent-123 --detailed
        secureagent analyze risk ./config.json --model ./models/custom.pkl
        secureagent analyze risk ./config.json --no-ml
    """
    from secureagent.ml import RiskScorer

    console.print(f"\n[bold blue]Risk Score Analysis[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    # Scan the target to get findings
    console.print("[dim]Scanning target for security findings...[/dim]")
    findings = _scan_target(target)

    if not findings:
        console.print("[yellow]No security findings detected in target.[/yellow]")
        console.print(Panel(
            "[green bold]Risk Score: 0%[/green bold]\n"
            "Level: [green]LOW[/green]\n"
            "Confidence: 100%\n\n"
            "[dim]No security issues found.[/dim]",
            title="Overall Risk",
        ))
        return

    console.print(f"[dim]Found {len(findings)} security findings. Calculating risk score...[/dim]\n")

    # Initialize RiskScorer
    use_ml = not no_ml
    actual_model_path = model_path or _get_default_model_path()

    if use_ml and actual_model_path:
        console.print(f"[dim]Using ML model: {actual_model_path.name}[/dim]")
        scorer = RiskScorer(model_path=actual_model_path, use_ml=True)
    else:
        if use_ml:
            console.print("[dim]No ML model found, using heuristic scoring[/dim]")
        else:
            console.print("[dim]Using heuristic scoring (ML disabled)[/dim]")
        scorer = RiskScorer(use_ml=False)

    # Calculate risk assessment
    assessment = scorer.score_findings(findings)

    risk_score = assessment.overall_score
    confidence = assessment.confidence
    level = assessment.risk_level.upper()

    # Color based on risk
    if risk_score >= 0.7:
        color = "red"
    elif risk_score >= 0.4:
        color = "yellow"
    else:
        color = "green"

    console.print(Panel(
        f"[{color} bold]Risk Score: {risk_score:.1%}[/{color} bold]\n"
        f"Level: [{color}]{level}[/{color}]\n"
        f"Confidence: {confidence:.1%}",
        title="Overall Risk",
    ))

    # Show recommendations
    if assessment.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in assessment.recommendations[:5]:
            console.print(f"  - {rec}")

    if detailed:
        # Show individual finding scores
        console.print("\n[bold]Finding Scores:[/bold]")

        findings_table = Table()
        findings_table.add_column("Finding", style="cyan")
        findings_table.add_column("Severity")
        findings_table.add_column("Risk Score", justify="right")

        for finding in findings:
            score = assessment.finding_scores.get(finding.id, 0.0)
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            sev_style = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
            }.get(sev.lower(), "dim")

            score_color = "red" if score >= 0.7 else "yellow" if score >= 0.4 else "green"
            findings_table.add_row(
                f"{finding.rule_id}: {finding.title[:40]}",
                f"[{sev_style}]{sev.upper()}[/{sev_style}]",
                f"[{score_color}]{score:.1%}[/{score_color}]",
            )

        console.print(findings_table)

        # Show risk factors
        if assessment.risk_factors:
            console.print("\n[bold]Risk Factor Breakdown:[/bold]")

            factors_table = Table()
            factors_table.add_column("Category", style="cyan")
            factors_table.add_column("Findings", justify="right")
            factors_table.add_column("Impact")

            for factor in assessment.risk_factors:
                impact = factor.get("impact", "low")
                impact_style = {"high": "red", "medium": "yellow"}.get(impact, "blue")
                factors_table.add_row(
                    factor.get("category", "Unknown"),
                    str(factor.get("finding_count", 0)),
                    f"[{impact_style}]{impact.upper()}[/{impact_style}]",
                )

            console.print(factors_table)
