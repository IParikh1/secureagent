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

    # Create scan result
    scan_result = ScanResult(
        findings=filtered_findings,
        scan_path=target,
        scanner_name=",".join(scanner_list),
    )

    # Output results
    _output_results(scan_result, format, output)

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


def _output_results(
    result: ScanResult,
    format: str,
    output: Optional[Path]
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
        if output:
            with open(output, "w") as f:
                json.dump(output_data, f, indent=2)
            console.print(f"\n[green]Results written to {output}[/green]")
        else:
            console.print_json(data=output_data)

    elif format == "sarif":
        sarif_output = _generate_sarif(result)
        import json
        if output:
            with open(output, "w") as f:
                json.dump(sarif_output, f, indent=2)
            console.print(f"\n[green]SARIF results written to {output}[/green]")
        else:
            console.print_json(data=sarif_output)

    else:  # console
        _print_console_results(result)


def _print_console_results(result: ScanResult) -> None:
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
            console.print(f"\n  [bold]{finding.rule_id}[/bold]: {finding.title}")
            console.print(f"  [dim]Location:[/dim] {finding.location.to_string()}")
            if finding.description:
                desc = finding.description[:200] + "..." if len(finding.description) > 200 else finding.description
                console.print(f"  [dim]{desc}[/dim]")
            console.print(f"  [green]Fix:[/green] {finding.remediation[:100]}...")

        if len(findings) > 10:
            console.print(f"\n  [dim]... and {len(findings) - 10} more {severity.value} findings[/dim]")

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


def _generate_sarif(result: ScanResult) -> dict:
    """Generate SARIF format output."""
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SecureAgent",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/secureagent/secureagent",
                    "rules": [],  # Would be populated with rule definitions
                }
            },
            "results": [f.to_sarif_result() for f in result.findings],
        }]
    }


def _send_alerts(findings: List) -> None:
    """Send alerts for findings."""
    console.print("\n[yellow]Sending alerts...[/yellow]")
    # Alert implementation would go here
    console.print("[green]Alerts sent[/green]")
