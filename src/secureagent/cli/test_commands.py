"""Active security testing CLI commands."""

import asyncio
import json
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

test_app = typer.Typer(help="Active security testing (prompt injection, etc.)")
console = Console()


@test_app.command("injection")
def test_injection(
    target: str = typer.Argument(..., help="Target URL, MCP config path, or 'simulate:<level>'"),
    quick: bool = typer.Option(False, "--quick", "-q", help="Quick test (critical/high risk only)"),
    full: bool = typer.Option(False, "--full", "-f", help="Full comprehensive test"),
    categories: Optional[str] = typer.Option(None, "--categories", "-c", help="Comma-separated categories"),
    risk: Optional[str] = typer.Option(None, "--risk", "-r", help="Minimum risk level (low,medium,high,critical)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output report file (JSON)"),
    timeout: float = typer.Option(30.0, "--timeout", "-t", help="Timeout per test in seconds"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
) -> None:
    """Test an AI agent for prompt injection vulnerabilities.

    Target can be:
      - URL: http://localhost:8000/api/chat (HTTP-based agent)
      - MCP config: ./mcp.json (MCP server)
      - Simulated: simulate:high (simulated agent with vulnerability level)

    Examples:
        secureagent test injection http://localhost:8000/chat
        secureagent test injection ./mcp.json --quick
        secureagent test injection simulate:medium --full
        secureagent test injection http://api.example.com/agent --categories direct_override,jailbreak
    """
    from secureagent.testing import (
        InjectionTester,
        PayloadCategory,
        PayloadRisk,
    )
    from secureagent.testing.injection_tester import (
        SimulatedAgent,
        HTTPAgentInterface,
        MCPAgentInterface,
    )

    console.print("\n[bold blue]Prompt Injection Testing[/bold blue]\n")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    # Create agent interface based on target
    if target.startswith("simulate:"):
        level = target.split(":")[1] if ":" in target else "medium"
        console.print(f"[dim]Using simulated agent (vulnerability: {level})[/dim]\n")
        agent = SimulatedAgent(vulnerability_level=level)

    elif target.startswith("http://") or target.startswith("https://"):
        console.print(f"[dim]Using HTTP agent interface[/dim]\n")
        agent = HTTPAgentInterface(url=target, timeout=timeout)

    elif Path(target).exists():
        config_path = Path(target)
        console.print(f"[dim]Loading MCP config from {config_path}[/dim]\n")

        # Parse MCP config
        try:
            config = json.loads(config_path.read_text())
            servers = config.get("mcpServers", {})

            if not servers:
                console.print("[red]No MCP servers found in config[/red]")
                raise typer.Exit(1)

            # Use first server
            server_name = list(servers.keys())[0]
            server_config = servers[server_name]

            command = [server_config.get("command", "node")]
            command.extend(server_config.get("args", []))
            env = server_config.get("env", {})

            console.print(f"[dim]Testing MCP server: {server_name}[/dim]\n")
            agent = MCPAgentInterface(
                server_command=command,
                env=env,
                timeout=timeout,
            )

        except json.JSONDecodeError:
            console.print("[red]Invalid JSON in config file[/red]")
            raise typer.Exit(1)
        except Exception as e:
            console.print(f"[red]Failed to parse config: {e}[/red]")
            raise typer.Exit(1)

    else:
        console.print(f"[red]Invalid target: {target}[/red]")
        console.print("[dim]Use URL, MCP config path, or 'simulate:<level>'[/dim]")
        raise typer.Exit(1)

    # Create tester
    tester = InjectionTester(timeout=timeout)

    # Parse filters
    category_filter = None
    if categories:
        try:
            category_filter = [PayloadCategory(c.strip()) for c in categories.split(",")]
        except ValueError as e:
            console.print(f"[red]Invalid category: {e}[/red]")
            console.print(f"[dim]Valid categories: {', '.join(c.value for c in PayloadCategory)}[/dim]")
            raise typer.Exit(1)

    risk_filter = None
    if risk:
        try:
            min_risk = PayloadRisk(risk.lower())
            risk_order = [PayloadRisk.LOW, PayloadRisk.MEDIUM, PayloadRisk.HIGH, PayloadRisk.CRITICAL]
            min_idx = risk_order.index(min_risk)
            risk_filter = risk_order[min_idx:]
        except ValueError:
            console.print(f"[red]Invalid risk level: {risk}[/red]")
            raise typer.Exit(1)

    # Run tests
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task_id = progress.add_task("Running injection tests...", total=None)

        if quick:
            report = tester.quick_test(agent)
        elif full:
            report = tester.full_test(agent)
        else:
            report = tester.test_agent_sync(
                agent,
                categories=category_filter,
                risk_levels=risk_filter,
            )

        progress.update(task_id, completed=report.total_tests, total=report.total_tests)

    # Display results
    console.print("\n[bold]Test Results[/bold]\n")

    # Summary panel
    vuln_color = "red" if report.vulnerability_rate > 0.3 else "yellow" if report.vulnerability_rate > 0 else "green"
    summary_text = f"""[bold]Tests Run:[/bold] {report.total_tests}
[bold]Vulnerable:[/bold] [{vuln_color}]{report.vulnerable_count}[/{vuln_color}]
[bold]Protected:[/bold] [green]{report.protected_count}[/green]
[bold]Partial:[/bold] [yellow]{report.partial_count}[/yellow]
[bold]Errors:[/bold] [dim]{report.error_count}[/dim]

[bold]Vulnerability Rate:[/bold] [{vuln_color}]{report.vulnerability_rate:.1%}[/{vuln_color}]
[bold]Critical Vulnerabilities:[/bold] [red bold]{len(report.critical_vulnerabilities)}[/red bold]
[bold]High Vulnerabilities:[/bold] [red]{len(report.high_vulnerabilities)}[/red]"""

    console.print(Panel(summary_text, title="Summary", border_style=vuln_color))

    # Vulnerabilities table
    vulnerable_results = [r for r in report.results if r.status.value == "vulnerable"]
    if vulnerable_results:
        console.print("\n[bold red]Vulnerabilities Found[/bold red]\n")

        vuln_table = Table()
        vuln_table.add_column("ID", style="cyan")
        vuln_table.add_column("Name")
        vuln_table.add_column("Category")
        vuln_table.add_column("Risk")
        vuln_table.add_column("Confidence", justify="right")

        for result in vulnerable_results:
            risk_style = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
            }.get(result.risk.value, "dim")

            vuln_table.add_row(
                result.payload_id,
                result.payload_name,
                result.category.value,
                f"[{risk_style}]{result.risk.value.upper()}[/{risk_style}]",
                f"{result.confidence:.0%}",
            )

        console.print(vuln_table)

        # Show responses for critical/high vulnerabilities
        if verbose:
            console.print("\n[bold]Vulnerability Details[/bold]\n")
            for result in vulnerable_results:
                if result.risk in [PayloadRisk.CRITICAL, PayloadRisk.HIGH]:
                    console.print(f"[cyan]{result.payload_id}[/cyan]: {result.payload_name}")
                    console.print(f"  [dim]Indicators found: {', '.join(result.success_indicators_found)}[/dim]")
                    console.print(f"  [dim]Response (truncated): {result.response[:200]}...[/dim]\n")

    # Protected tests
    if verbose:
        protected_results = [r for r in report.results if r.status.value == "protected"]
        if protected_results:
            console.print("\n[bold green]Protected Against[/bold green]\n")

            prot_table = Table()
            prot_table.add_column("ID", style="cyan")
            prot_table.add_column("Name")
            prot_table.add_column("Category")
            prot_table.add_column("Blocked By")

            for result in protected_results[:10]:  # Show first 10
                prot_table.add_row(
                    result.payload_id,
                    result.payload_name,
                    result.category.value,
                    ", ".join(result.failure_indicators_found[:2]) or "General refusal",
                )

            console.print(prot_table)

            if len(protected_results) > 10:
                console.print(f"[dim]  ... and {len(protected_results) - 10} more[/dim]")

    # Recommendations
    if report.vulnerable_count > 0:
        console.print("\n[bold]Recommendations[/bold]\n")

        if report.critical_vulnerabilities:
            console.print("[red]CRITICAL: Implement prompt injection defenses immediately![/red]")
            console.print("  - Add input validation and sanitization")
            console.print("  - Implement guardrails (e.g., Guardrails AI, NeMo Guardrails)")
            console.print("  - Use structured outputs to limit response format")

        categories_vulnerable = set(r.category for r in vulnerable_results)

        if PayloadCategory.EXTRACTION_SYSTEM_PROMPT in categories_vulnerable:
            console.print("\n[yellow]System Prompt Extraction vulnerable:[/yellow]")
            console.print("  - Never include sensitive info in system prompts")
            console.print("  - Use prompt injection detection before processing")

        if any(c.value.startswith("tool") for c in categories_vulnerable):
            console.print("\n[yellow]Tool manipulation vulnerable:[/yellow]")
            console.print("  - Validate and sanitize all tool parameters")
            console.print("  - Implement allowlists for tool operations")

        if any(c.value.startswith("indirect") for c in categories_vulnerable):
            console.print("\n[yellow]Indirect injection vulnerable:[/yellow]")
            console.print("  - Scan external content for injection attempts")
            console.print("  - Isolate user content from instructions")

    # Save report
    if output:
        output.write_text(json.dumps(report.to_dict(), indent=2))
        console.print(f"\n[green]Report saved to: {output}[/green]")

    # Exit code based on results
    if report.critical_vulnerabilities:
        raise typer.Exit(2)
    elif report.vulnerable_count > 0:
        raise typer.Exit(1)


@test_app.command("payloads")
def list_payloads(
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by category"),
    risk: Optional[str] = typer.Option(None, "--risk", "-r", help="Filter by risk level"),
    search: Optional[str] = typer.Option(None, "--search", "-s", help="Search by name/description"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show payload content"),
) -> None:
    """List available injection test payloads.

    Examples:
        secureagent test payloads
        secureagent test payloads --category jailbreak_dan
        secureagent test payloads --risk critical
        secureagent test payloads --search "system prompt"
    """
    from secureagent.testing import PayloadLibrary, PayloadCategory, PayloadRisk

    console.print("\n[bold blue]Injection Payloads[/bold blue]\n")

    library = PayloadLibrary()

    # Filter payloads
    if search:
        payloads = library.search(search)
    elif category:
        try:
            cat = PayloadCategory(category)
            payloads = library.list_by_category(cat)
        except ValueError:
            console.print(f"[red]Invalid category: {category}[/red]")
            console.print(f"[dim]Valid: {', '.join(c.value for c in PayloadCategory)}[/dim]")
            raise typer.Exit(1)
    elif risk:
        try:
            r = PayloadRisk(risk.lower())
            payloads = library.list_by_risk(r)
        except ValueError:
            console.print(f"[red]Invalid risk level: {risk}[/red]")
            raise typer.Exit(1)
    else:
        payloads = library.list_all()

    if not payloads:
        console.print("[yellow]No payloads found matching criteria[/yellow]")
        return

    table = Table(title=f"Payloads ({len(payloads)})")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Risk")
    table.add_column("Tags")

    for payload in payloads:
        risk_style = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
        }.get(payload.risk.value, "dim")

        table.add_row(
            payload.id,
            payload.name[:30],
            payload.category.value[:20],
            f"[{risk_style}]{payload.risk.value.upper()}[/{risk_style}]",
            ", ".join(payload.tags[:3]),
        )

    console.print(table)

    if verbose and len(payloads) <= 10:
        console.print("\n[bold]Payload Details[/bold]\n")
        for payload in payloads:
            console.print(f"[cyan]{payload.id}[/cyan]: {payload.name}")
            console.print(f"  [dim]{payload.description}[/dim]")
            console.print(f"  [dim]Payload: {payload.payload[:100]}...[/dim]\n")


@test_app.command("categories")
def list_categories() -> None:
    """List all payload categories.

    Examples:
        secureagent test categories
    """
    from secureagent.testing import PayloadCategory, PayloadLibrary

    console.print("\n[bold blue]Payload Categories[/bold blue]\n")

    library = PayloadLibrary()

    table = Table()
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Description")

    category_descriptions = {
        PayloadCategory.DIRECT_OVERRIDE: "Direct instruction override attempts",
        PayloadCategory.DIRECT_IGNORE: "Attempts to ignore previous context",
        PayloadCategory.DIRECT_ROLEPLAY: "Roleplay-based bypasses",
        PayloadCategory.INDIRECT_DOCUMENT: "Injection via document content",
        PayloadCategory.INDIRECT_TOOL_RESULT: "Injection via tool results",
        PayloadCategory.INDIRECT_RAG: "Injection via RAG content",
        PayloadCategory.JAILBREAK_DAN: "DAN-style jailbreaks",
        PayloadCategory.JAILBREAK_ROLEPLAY: "Roleplay jailbreaks",
        PayloadCategory.JAILBREAK_HYPOTHETICAL: "Hypothetical scenario jailbreaks",
        PayloadCategory.EXTRACTION_SYSTEM_PROMPT: "System prompt extraction",
        PayloadCategory.EXTRACTION_CONTEXT: "Context extraction attempts",
        PayloadCategory.EXTRACTION_MEMORY: "Memory/history extraction",
        PayloadCategory.TOOL_INJECTION: "Tool execution injection",
        PayloadCategory.TOOL_PARAMETER_INJECTION: "Tool parameter manipulation",
        PayloadCategory.ENCODING_BASE64: "Base64 encoded payloads",
        PayloadCategory.ENCODING_ROT13: "ROT13 encoded payloads",
        PayloadCategory.ENCODING_UNICODE: "Unicode obfuscation",
        PayloadCategory.MULTI_TURN_CONTEXT: "Multi-turn context attacks",
        PayloadCategory.MULTI_TURN_GRADUAL: "Gradual trust building attacks",
    }

    for cat in PayloadCategory:
        count = len(library.list_by_category(cat))
        desc = category_descriptions.get(cat, "")
        table.add_row(cat.value, str(count), desc)

    console.print(table)


@test_app.command("simulate")
def simulate_test(
    level: str = typer.Argument("medium", help="Vulnerability level (none, low, medium, high, full)"),
    payloads: int = typer.Option(5, "--payloads", "-n", help="Number of payloads to test"),
) -> None:
    """Run a simulated test to see how the tester works.

    Examples:
        secureagent test simulate
        secureagent test simulate high --payloads 10
        secureagent test simulate none
    """
    from secureagent.testing import InjectionTester
    from secureagent.testing.injection_tester import SimulatedAgent

    console.print("\n[bold blue]Simulated Injection Test[/bold blue]\n")
    console.print(f"Simulating agent with [cyan]{level}[/cyan] vulnerability level\n")

    valid_levels = ["none", "low", "medium", "high", "full"]
    if level not in valid_levels:
        console.print(f"[red]Invalid level. Choose from: {', '.join(valid_levels)}[/red]")
        raise typer.Exit(1)

    agent = SimulatedAgent(vulnerability_level=level)
    tester = InjectionTester()

    # Get first N payloads
    all_payloads = tester.payload_library.list_all()[:payloads]
    payload_ids = [p.id for p in all_payloads]

    report = tester.test_agent_sync(
        agent,
        payload_ids=payload_ids,
    )

    # Display results
    table = Table(title="Simulation Results")
    table.add_column("Payload", style="cyan")
    table.add_column("Status")
    table.add_column("Latency", justify="right")

    for result in report.results:
        status_style = {
            "vulnerable": "red bold",
            "protected": "green",
            "partial": "yellow",
            "error": "dim",
        }.get(result.status.value, "dim")

        table.add_row(
            result.payload_name[:30],
            f"[{status_style}]{result.status.value.upper()}[/{status_style}]",
            f"{result.latency_ms:.0f}ms",
        )

    console.print(table)

    console.print(f"\n[bold]Summary:[/bold] {report.vulnerable_count}/{report.total_tests} vulnerable")

    if level == "none":
        console.print("[green]This is what a well-protected agent looks like![/green]")
    elif level == "full":
        console.print("[red]This is what a completely vulnerable agent looks like![/red]")
