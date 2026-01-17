"""Multi-agent security CLI commands for SecureAgent."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel

from secureagent.core.models.severity import Severity

multiagent_app = typer.Typer(help="Multi-agent AI system security scanning")
console = Console()


@multiagent_app.command("scan")
def scan_multiagent(
    target: str = typer.Argument(..., help="Target directory to scan for multi-agent code"),
    check_orchestration: bool = typer.Option(
        True,
        "--orchestration/--no-orchestration",
        help="Check orchestration security",
    ),
    check_communication: bool = typer.Option(
        True,
        "--communication/--no-communication",
        help="Check agent communication security",
    ),
    check_delegation: bool = typer.Option(
        True,
        "--delegation/--no-delegation",
        help="Check delegation security",
    ),
    check_frameworks: bool = typer.Option(
        True,
        "--frameworks/--no-frameworks",
        help="Check framework-specific issues",
    ),
    format: str = typer.Option(
        "console",
        "--format",
        "-f",
        help="Output format (console, json)",
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
    ci: bool = typer.Option(
        False,
        "--ci",
        help="CI mode - exit with code 1 if findings found",
    ),
) -> None:
    """Run comprehensive multi-agent security scan.

    Analyzes agent orchestration, communication, delegation, and framework-specific issues.

    Examples:
        secureagent multiagent scan .
        secureagent multiagent scan ./agents --no-frameworks
        secureagent multiagent scan . --format json --output report.json
    """
    from secureagent.multiagent import MultiAgentSecurityScanner

    console.print("\n[bold blue]Multi-Agent Security Scan[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    scanner = MultiAgentSecurityScanner()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running multi-agent security scan...", total=None)

        try:
            report = scanner.scan_comprehensive(
                target_path=target,
                scan_orchestration=check_orchestration,
                scan_communication=check_communication,
                scan_delegation=check_delegation,
                scan_frameworks=check_frameworks,
            )
            progress.update(task, description="[green]Scan complete[/green]")
        except Exception as e:
            progress.update(task, description=f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

    # Filter by minimum severity
    min_sev = Severity(min_severity)
    filtered_findings = [
        f for f in report.all_findings
        if Severity(f.severity) <= min_sev
    ]

    if format == "json":
        _output_json(report, filtered_findings, output)
    else:
        _print_multiagent_report(report, filtered_findings)

    # CI mode exit code
    if ci and filtered_findings:
        critical_high = [f for f in filtered_findings if f.severity in ["critical", "high"]]
        if critical_high:
            raise typer.Exit(1)


@multiagent_app.command("orchestration")
def scan_orchestration(
    target: str = typer.Argument(..., help="Path to scan for orchestration patterns"),
    format: str = typer.Option(
        "console",
        "--format",
        "-f",
        help="Output format (console, json)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path",
    ),
) -> None:
    """Scan for agent orchestration security issues.

    Checks workflow patterns, cycles, privilege escalation paths, and more.

    Examples:
        secureagent multiagent orchestration .
        secureagent multiagent orchestration ./agents --format json
    """
    from secureagent.multiagent import OrchestrationAnalyzer

    console.print("\n[bold blue]Agent Orchestration Security Scan[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    analyzer = OrchestrationAnalyzer()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing orchestration patterns...", total=None)

        try:
            findings = analyzer.analyze_directory(target)
            progress.update(task, description=f"[green]Found {len(findings)} issues[/green]")
        except Exception as e:
            progress.update(task, description=f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

    if format == "json":
        _output_findings_json(findings, "Orchestration Security", output)
    else:
        _print_findings_table(findings, "Orchestration Security Issues")

    # Show workflows detected
    if analyzer.workflows:
        console.print(f"\n[bold]Workflows Detected:[/bold] {len(analyzer.workflows)}")
        for wf in analyzer.workflows[:5]:
            console.print(f"  - Pattern: {wf.pattern.value}, Nodes: {len(wf.nodes)}, Cycles: {wf.has_cycles}")


@multiagent_app.command("communication")
def scan_communication(
    target: str = typer.Argument(..., help="Path to scan for agent communication"),
    format: str = typer.Option(
        "console",
        "--format",
        "-f",
        help="Output format (console, json)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path",
    ),
) -> None:
    """Scan for agent communication security issues.

    Checks message encryption, authentication, injection, and replay protection.

    Examples:
        secureagent multiagent communication .
        secureagent multiagent communication ./agents --format json
    """
    from secureagent.multiagent import CommunicationAnalyzer

    console.print("\n[bold blue]Agent Communication Security Scan[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    analyzer = CommunicationAnalyzer()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing communication patterns...", total=None)

        try:
            findings = analyzer.analyze_directory(target)
            progress.update(task, description=f"[green]Found {len(findings)} issues[/green]")
        except Exception as e:
            progress.update(task, description=f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

    if format == "json":
        _output_findings_json(findings, "Communication Security", output)
    else:
        _print_findings_table(findings, "Communication Security Issues")


@multiagent_app.command("delegation")
def scan_delegation(
    target: str = typer.Argument(..., help="Path to scan for delegation patterns"),
    format: str = typer.Option(
        "console",
        "--format",
        "-f",
        help="Output format (console, json)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path",
    ),
) -> None:
    """Scan for delegation security issues.

    Checks for circular delegation, privilege escalation, and task injection.

    Examples:
        secureagent multiagent delegation .
        secureagent multiagent delegation ./crew --format json
    """
    from secureagent.multiagent import DelegationAnalyzer

    console.print("\n[bold blue]Agent Delegation Security Scan[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    analyzer = DelegationAnalyzer()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing delegation patterns...", total=None)

        try:
            findings = analyzer.analyze_directory(target)
            progress.update(task, description=f"[green]Found {len(findings)} issues[/green]")
        except Exception as e:
            progress.update(task, description=f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

    if format == "json":
        _output_findings_json(findings, "Delegation Security", output)
    else:
        _print_findings_table(findings, "Delegation Security Issues")

    # Show delegation chains
    if analyzer.chains:
        console.print(f"\n[bold]Delegation Chains Detected:[/bold] {len(analyzer.chains)}")
        for chain in analyzer.chains[:5]:
            chain_str = " -> ".join(chain.agents[:5])
            if len(chain.agents) > 5:
                chain_str += f" -> ... ({len(chain.agents)} total)"
            status = "[red]CYCLE[/red]" if chain.has_cycle else "[green]OK[/green]"
            escalation = "[red]ESCALATION[/red]" if chain.has_privilege_escalation else ""
            console.print(f"  - {chain_str} {status} {escalation}")


@multiagent_app.command("frameworks")
def detect_frameworks(
    target: str = typer.Argument(..., help="Path to scan for multi-agent frameworks"),
    format: str = typer.Option(
        "console",
        "--format",
        "-f",
        help="Output format (console, json)",
    ),
) -> None:
    """Detect multi-agent frameworks and their security configurations.

    Identifies LangGraph, AutoGen, CrewAI, and other multi-agent frameworks.

    Examples:
        secureagent multiagent frameworks .
        secureagent multiagent frameworks ./agents --format json
    """
    from pathlib import Path as FilePath
    from secureagent.multiagent import FrameworkDetector, LangGraphAnalyzer, AutoGenAnalyzer, MultiAgentFramework

    console.print("\n[bold blue]Multi-Agent Framework Detection[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    detector = FrameworkDetector()
    target_path = FilePath(target)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Detecting frameworks...", total=None)

        frameworks_found: dict = {}
        all_findings = []

        try:
            for file_path in target_path.rglob("*.py"):
                try:
                    content = file_path.read_text()
                except Exception:
                    continue

                detected = detector.detect(content)
                for fw in detected:
                    if fw != MultiAgentFramework.UNKNOWN:
                        if fw.value not in frameworks_found:
                            frameworks_found[fw.value] = []
                        frameworks_found[fw.value].append(str(file_path))

                        # Run framework-specific analysis
                        if fw == MultiAgentFramework.LANGGRAPH:
                            analyzer = LangGraphAnalyzer()
                            all_findings.extend(analyzer.analyze(content, str(file_path)))
                        elif fw == MultiAgentFramework.AUTOGEN:
                            analyzer = AutoGenAnalyzer()
                            all_findings.extend(analyzer.analyze(content, str(file_path)))

            progress.update(task, description=f"[green]Found {len(frameworks_found)} frameworks[/green]")
        except Exception as e:
            progress.update(task, description=f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

    if format == "json":
        import json
        output_data = {
            "frameworks": frameworks_found,
            "findings": [f.to_dict() for f in all_findings],
        }
        console.print_json(data=output_data)
    else:
        # Frameworks table
        if frameworks_found:
            table = Table(title="Detected Multi-Agent Frameworks")
            table.add_column("Framework", style="cyan")
            table.add_column("Files", justify="right")
            table.add_column("Sample Files")

            for fw, files in frameworks_found.items():
                sample = ", ".join([FilePath(f).name for f in files[:3]])
                if len(files) > 3:
                    sample += f" (+{len(files)-3} more)"
                table.add_row(fw, str(len(files)), sample)

            console.print(table)
        else:
            console.print("[yellow]No multi-agent frameworks detected[/yellow]")

        # Findings
        if all_findings:
            console.print()
            _print_findings_table(all_findings, "Framework-Specific Security Issues")


@multiagent_app.command("test")
def test_multiagent(
    target: str = typer.Argument(..., help="Multi-agent system endpoint or config to test"),
    max_tests: int = typer.Option(
        10,
        "--max-tests",
        "-n",
        help="Maximum number of test payloads to use",
    ),
    format: str = typer.Option(
        "console",
        "--format",
        "-f",
        help="Output format (console, json)",
    ),
) -> None:
    """Test multi-agent system with security payloads.

    Runs delegation, communication, and orchestration attack tests.

    Examples:
        secureagent multiagent test http://localhost:8000
        secureagent multiagent test ./agent_config.yaml --max-tests 20
    """
    from secureagent.testing.payloads import PayloadGenerator

    console.print("\n[bold blue]Multi-Agent Security Testing[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]")
    console.print(f"Max tests: [yellow]{max_tests}[/yellow]\n")

    generator = PayloadGenerator()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating multi-agent payloads...", total=None)

        payloads = generator.get_multiagent_payloads()[:max_tests]

        progress.update(
            task,
            description=f"[green]Generated {len(payloads)} multi-agent test payloads[/green]"
        )

    # Display payloads
    table = Table(title="Multi-Agent Security Test Payloads")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Category", style="yellow")
    table.add_column("Risk", style="red")
    table.add_column("Payload Preview", style="dim")

    for payload in payloads:
        preview = payload.payload[:40] + "..." if len(payload.payload) > 40 else payload.payload
        preview = preview.replace("\n", "\\n")

        risk_color = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "blue"}.get(payload.risk.value, "white")

        table.add_row(
            payload.id,
            payload.name,
            payload.category.value,
            f"[{risk_color}]{payload.risk.value.upper()}[/{risk_color}]",
            preview,
        )

    console.print(table)
    console.print()

    console.print(Panel(
        "[yellow]Note:[/yellow] Active testing requires a running multi-agent system.\n"
        "Use these payloads to test for delegation attacks, communication spoofing,\n"
        "orchestration hijacking, and other multi-agent vulnerabilities.",
        title="Testing Info",
        border_style="blue",
    ))


def _output_json(report, findings, output: Optional[Path]) -> None:
    """Output multi-agent report as JSON."""
    import json

    output_data = report.to_dict()
    output_data["filtered_findings"] = len(findings)

    if output:
        with open(output, "w") as f:
            json.dump(output_data, f, indent=2)
        console.print(f"\n[green]Results written to {output}[/green]")
    else:
        console.print_json(data=output_data)


def _output_findings_json(findings, title: str, output: Optional[Path]) -> None:
    """Output findings as JSON."""
    import json

    output_data = {
        "title": title,
        "total": len(findings),
        "findings": [f.to_dict() for f in findings],
    }

    if output:
        with open(output, "w") as f:
            json.dump(output_data, f, indent=2)
        console.print(f"\n[green]Results written to {output}[/green]")
    else:
        console.print_json(data=output_data)


def _print_multiagent_report(report, findings) -> None:
    """Print multi-agent security report to console."""
    # Frameworks detected
    if report.frameworks_detected:
        console.print(f"[bold]Frameworks Detected:[/bold] {', '.join(f.value for f in report.frameworks_detected)}")
        console.print(f"[bold]Total Agents Found:[/bold] {report.total_agents_found}")
        console.print()

    # Summary table
    summary = Table(title="Multi-Agent Security Scan Summary")
    summary.add_column("Category", style="cyan")
    summary.add_column("Issues Found", justify="right")

    summary.add_row("Orchestration Issues", str(len(report.orchestration_findings)))
    summary.add_row("Communication Issues", str(len(report.communication_findings)))
    summary.add_row("Delegation Issues", str(len(report.delegation_findings)))
    summary.add_row("Framework Issues", str(len(report.framework_findings)))
    summary.add_row("[bold]Total Findings[/bold]", f"[bold]{len(findings)}[/bold]")

    console.print(summary)
    console.print()

    # Severity breakdown
    sev_table = Table(title="Severity Breakdown")
    sev_table.add_column("Severity", style="cyan")
    sev_table.add_column("Count", justify="right")

    critical = len([f for f in findings if f.severity == "critical"])
    high = len([f for f in findings if f.severity == "high"])
    medium = len([f for f in findings if f.severity == "medium"])
    low = len([f for f in findings if f.severity == "low"])

    sev_table.add_row("[red bold]CRITICAL[/red bold]", str(critical))
    sev_table.add_row("[red]HIGH[/red]", str(high))
    sev_table.add_row("[yellow]MEDIUM[/yellow]", str(medium))
    sev_table.add_row("[blue]LOW[/blue]", str(low))

    console.print(sev_table)
    console.print()

    # Show top findings
    if findings:
        console.print("[bold]Top Findings:[/bold]")
        for finding in findings[:10]:
            sev = Severity(finding.severity)
            console.print(f"\n  [{sev.color}]{finding.rule_id}[/{sev.color}]: {finding.title}")
            console.print(f"  [dim]Location:[/dim] {finding.location.to_string()}")
            if finding.remediation:
                console.print(f"  [green]Fix:[/green] {finding.remediation[:100]}...")

        if len(findings) > 10:
            console.print(f"\n  [dim]... and {len(findings) - 10} more findings[/dim]")

    # Status panel
    console.print()
    if critical or high:
        console.print(Panel(
            f"[red bold]Found {critical + high} critical/high severity multi-agent security issues![/red bold]",
            title="Status",
            border_style="red",
        ))
    elif findings:
        console.print(Panel(
            f"[yellow]Found {len(findings)} multi-agent security issues to review[/yellow]",
            title="Status",
            border_style="yellow",
        ))
    else:
        console.print(Panel(
            "[green]No multi-agent security issues found[/green]",
            title="Status",
            border_style="green",
        ))


def _print_findings_table(findings, title: str) -> None:
    """Print findings as a Rich table."""
    if not findings:
        console.print(f"\n[green]No {title.lower()} found[/green]")
        return

    table = Table(title=title)
    table.add_column("Rule ID", style="cyan")
    table.add_column("Severity", style="yellow")
    table.add_column("Title")
    table.add_column("Location", style="dim")

    for finding in findings:
        sev = Severity(finding.severity)
        table.add_row(
            finding.rule_id,
            f"[{sev.color}]{finding.severity.upper()}[/{sev.color}]",
            finding.title,
            finding.location.to_string()[:50],
        )

    console.print(table)
