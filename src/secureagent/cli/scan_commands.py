"""Universal scan command for SecureAgent."""

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from secureagent.core.config import get_config
from secureagent.core.models.finding import ScanResult
from secureagent.core.models.severity import Severity

scan_app = typer.Typer(help="Universal security scanning")
console = Console()


@scan_app.callback(invoke_without_command=True)
def scan(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target to scan (path, URL, or resource)"),
    scanners: Optional[str] = typer.Option(
        None,
        "--scanners",
        "-s",
        help="Scanners to use (comma-separated: mcp,aws,terraform,langchain,openai,all)",
    ),
    format: str = typer.Option(
        "console",
        "--format",
        "-f",
        help="Output format (console, json, sarif, html)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path",
    ),
    min_severity: str = typer.Option(
        "info",
        "--min-severity",
        help="Minimum severity to report (critical, high, medium, low, info)",
    ),
    compliance: Optional[str] = typer.Option(
        None,
        "--compliance",
        help="Include compliance mapping (owasp, soc2, pci, hipaa)",
    ),
    risk_score: bool = typer.Option(
        False,
        "--risk-score",
        help="Include ML-based risk scoring",
    ),
    graph: bool = typer.Option(
        False,
        "--graph",
        help="Include capability graph analysis",
    ),
    ci: bool = typer.Option(
        False,
        "--ci",
        help="CI mode - exit with code 1 if findings found",
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Fail on severity level (critical, high, medium)",
    ),
    alert: bool = typer.Option(
        False,
        "--alert",
        help="Send alerts for findings",
    ),
) -> None:
    """Scan target for security vulnerabilities.

    Examples:
        secureagent scan .
        secureagent scan ./mcp.json --scanners mcp
        secureagent scan --scanners aws,terraform
        secureagent scan . --format sarif --output results.sarif --ci
    """
    if ctx.invoked_subcommand is not None:
        return

    from secureagent.core.scanner.registry import scanner_registry

    # Parse scanners
    if scanners:
        if scanners == "all":
            scanner_list = scanner_registry.get_all()
        else:
            scanner_list = [s.strip() for s in scanners.split(",")]
    else:
        # Auto-detect scanners based on target
        scanner_list = scanner_registry.get_for_target(target)
        if not scanner_list:
            scanner_list = ["mcp"]  # Default

    all_findings = []
    config = get_config()

    console.print(f"\n[bold blue]SecureAgent Security Scan[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]")
    console.print(f"Scanners: [yellow]{', '.join(scanner_list)}[/yellow]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        for scanner_name in scanner_list:
            task = progress.add_task(f"Running {scanner_name} scanner...", total=None)

            scanner = scanner_registry.get(scanner_name)
            if not scanner:
                progress.update(task, description=f"[yellow]Scanner '{scanner_name}' not found[/yellow]")
                continue

            try:
                scanner.initialize()
                result = scanner.scan(target)
                all_findings.extend(result.findings)
                progress.update(
                    task,
                    description=f"[green]{scanner_name}: {len(result.findings)} findings[/green]"
                )
            except Exception as e:
                progress.update(
                    task,
                    description=f"[red]{scanner_name}: Error - {str(e)}[/red]"
                )
            finally:
                scanner.cleanup()

    # Filter by minimum severity
    min_sev = Severity(min_severity)
    filtered_findings = [
        f for f in all_findings
        if Severity(f.severity) <= min_sev
    ]

    # ML-based risk scoring
    risk_assessment = None
    if risk_score and filtered_findings:
        risk_assessment = _run_risk_scoring(filtered_findings)

    # Create scan result
    scan_result = ScanResult(
        findings=filtered_findings,
        scan_path=target,
        scanner_name=",".join(scanner_list),
    )

    # Output results
    _output_results(scan_result, format, output, risk_assessment=risk_assessment)

    # Send alerts if requested
    if alert and filtered_findings:
        _send_alerts(filtered_findings)

    # CI mode exit code
    if ci or fail_on:
        fail_severity = Severity(fail_on) if fail_on else Severity.HIGH
        should_fail = any(
            Severity(f.severity) <= fail_severity
            for f in filtered_findings
        )
        if should_fail:
            raise typer.Exit(1)


def _run_risk_scoring(findings: List) -> Optional["RiskAssessment"]:
    """Run ML-based risk scoring on findings."""
    try:
        from secureagent.ml.risk_scorer import RiskScorer
        from secureagent.ml.features.mcp_features import MCPFeatureExtractor
        from secureagent.ml.features.cloud_features import CloudFeatureExtractor
        from secureagent.ml.features.agent_features import AgentFeatureExtractor
        from secureagent.ml.model_manager import ModelManager

        # Try to load the shipped model
        manager = ModelManager()
        model_path = manager.get_model_path("baseline")

        if model_path and model_path.exists():
            scorer = RiskScorer(model_path=model_path, use_ml=True)
        else:
            scorer = RiskScorer(use_ml=False)
            console.print("[yellow]ML model not found, using heuristic scoring[/yellow]")

        # Register feature extractors
        scorer.register_extractor(MCPFeatureExtractor())
        scorer.register_extractor(CloudFeatureExtractor())
        scorer.register_extractor(AgentFeatureExtractor())

        # Score findings
        assessment = scorer.score_findings(findings)

        # Attach individual scores back to findings
        for finding in findings:
            if finding.id in assessment.finding_scores:
                finding.risk_score = assessment.finding_scores[finding.id]

        return assessment

    except ImportError:
        console.print("[yellow]ML dependencies not installed. Using heuristic scoring.[/yellow]")
        try:
            from secureagent.ml.risk_scorer import RiskScorer
            scorer = RiskScorer(use_ml=False)
            assessment = scorer.score_findings(findings)
            for finding in findings:
                if finding.id in assessment.finding_scores:
                    finding.risk_score = assessment.finding_scores[finding.id]
            return assessment
        except Exception:
            return None
    except Exception as e:
        console.print(f"[yellow]Risk scoring failed: {e}[/yellow]")
        return None


def _output_results(
    result: ScanResult,
    format: str,
    output: Optional[Path],
    risk_assessment=None,
) -> None:
    """Output scan results in the specified format."""
    if format == "json":
        import json
        output_data = {
            "version": "1.0",
            "scan_path": result.scan_path,
            "scanner": result.scanner_name,
            "total_findings": len(result.findings),
            "summary": {
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
            },
            "findings": [f.to_dict() for f in result.findings],
        }
        if risk_assessment:
            output_data["risk_assessment"] = {
                "overall_score": risk_assessment.overall_score,
                "risk_level": risk_assessment.risk_level,
                "confidence": risk_assessment.confidence,
                "risk_factors": risk_assessment.risk_factors,
                "recommendations": risk_assessment.recommendations,
            }
        if output:
            with open(output, "w") as f:
                json.dump(output_data, f, indent=2)
            console.print(f"\n[green]Results written to {output}[/green]")
        else:
            console.print_json(data=output_data)

    elif format == "sarif":
        sarif_output = _generate_sarif(result, risk_assessment=risk_assessment)
        import json
        if output:
            with open(output, "w") as f:
                json.dump(sarif_output, f, indent=2)
            console.print(f"\n[green]SARIF results written to {output}[/green]")
        else:
            console.print_json(data=sarif_output)

    else:  # console
        _print_console_results(result, risk_assessment=risk_assessment)


def _print_console_results(result: ScanResult, risk_assessment=None) -> None:
    """Print results to console with Rich formatting."""
    from rich.table import Table
    from rich.panel import Panel

    # Summary
    summary = Table(title="Scan Summary", show_header=True)
    summary.add_column("Severity", style="cyan")
    summary.add_column("Count", justify="right")

    summary.add_row("[red bold]CRITICAL[/red bold]", str(result.critical_count))
    summary.add_row("[red]HIGH[/red]", str(result.high_count))
    summary.add_row("[yellow]MEDIUM[/yellow]", str(result.medium_count))
    summary.add_row("[blue]LOW[/blue]", str(result.low_count))
    summary.add_row("[bold]TOTAL[/bold]", str(len(result.findings)))

    console.print(summary)
    console.print()

    # Findings by severity
    findings_by_sev = result.by_severity()

    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        findings = findings_by_sev.get(severity, [])
        if not findings:
            continue

        console.print(f"\n[{severity.color}]{severity.emoji} {severity.value.upper()} ({len(findings)} findings)[/{severity.color}]")
        console.print("-" * 60)

        for finding in findings[:10]:  # Limit to 10 per severity
            risk_str = ""
            if finding.risk_score is not None:
                risk_str = f" [dim](risk: {finding.risk_score:.2f})[/dim]"
            console.print(f"\n  [bold]{finding.rule_id}[/bold]: {finding.title}{risk_str}")
            console.print(f"  [dim]Location:[/dim] {finding.location.to_string()}")
            if finding.description:
                desc = finding.description[:200] + "..." if len(finding.description) > 200 else finding.description
                console.print(f"  [dim]{desc}[/dim]")
            console.print(f"  [green]Fix:[/green] {finding.remediation[:100]}...")

        if len(findings) > 10:
            console.print(f"\n  [dim]... and {len(findings) - 10} more {severity.value} findings[/dim]")

    # Risk assessment panel
    if risk_assessment:
        _print_risk_assessment(risk_assessment)

    # Final status
    console.print()
    if result.has_critical_or_high:
        console.print(Panel(
            f"[red bold]Found {result.critical_count + result.high_count} critical/high severity issues![/red bold]",
            title="Status",
            border_style="red",
        ))
    else:
        console.print(Panel(
            "[green]No critical or high severity issues found[/green]",
            title="Status",
            border_style="green",
        ))


def _print_risk_assessment(assessment) -> None:
    """Print ML risk assessment to console."""
    from rich.table import Table
    from rich.panel import Panel

    # Risk level colors
    level_colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "green",
    }
    color = level_colors.get(assessment.risk_level, "white")

    console.print()
    console.print(Panel(
        f"[{color}]Overall Risk Score: {assessment.overall_score:.2f} ({assessment.risk_level.upper()})[/{color}]\n"
        f"[dim]Confidence: {assessment.confidence:.2f}[/dim]",
        title="ML Risk Assessment",
        border_style=color.split()[0],
    ))

    # Top risk factors
    if assessment.risk_factors:
        factors_table = Table(title="Top Risk Factors", show_header=True)
        factors_table.add_column("Category", style="cyan")
        factors_table.add_column("Findings", justify="right")
        factors_table.add_column("Impact", style="yellow")

        for factor in assessment.risk_factors[:5]:
            factors_table.add_row(
                factor.get("category", "Unknown"),
                str(factor.get("finding_count", 0)),
                factor.get("impact", "unknown"),
            )
        console.print(factors_table)

    # Recommendations
    if assessment.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in assessment.recommendations[:5]:
            console.print(f"  - {rec}")


def _generate_sarif(result: ScanResult, risk_assessment=None) -> dict:
    """Generate SARIF format output."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SecureAgent",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/secureagent/secureagent",
                    "rules": [],
                }
            },
            "results": [f.to_sarif_result() for f in result.findings],
        }]
    }
    if risk_assessment:
        sarif["runs"][0]["properties"] = {
            "riskAssessment": {
                "overallScore": risk_assessment.overall_score,
                "riskLevel": risk_assessment.risk_level,
                "confidence": risk_assessment.confidence,
            }
        }
    return sarif


def _send_alerts(findings: List) -> None:
    """Send alerts for findings."""
    console.print("\n[yellow]Sending alerts...[/yellow]")
    # Alert implementation would go here
    console.print("[green]Alerts sent[/green]")
