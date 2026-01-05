"""Main CLI application for SecureAgent."""

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from secureagent import __version__
from secureagent.core.config import get_config, load_config
from secureagent.core.models.severity import Severity

# Create main app
app = typer.Typer(
    name="secureagent",
    help="SecureAgent - Comprehensive AI & Cloud Security Platform",
    add_completion=True,
    no_args_is_help=True,
)

console = Console()

# Import and add subcommand groups
from secureagent.cli.scan_commands import scan_app
from secureagent.cli.mcp_commands import mcp_app
from secureagent.cli.cloud_commands import cloud_app
from secureagent.cli.inventory_commands import inventory_app
from secureagent.cli.analyze_commands import analyze_app
from secureagent.cli.compliance_commands import compliance_app
from secureagent.cli.compat import compat_app

app.add_typer(scan_app, name="scan", help="Universal security scanning")
app.add_typer(mcp_app, name="mcp", help="MCP configuration scanning")
app.add_typer(cloud_app, name="cloud", help="Cloud infrastructure scanning")
app.add_typer(inventory_app, name="inventory", help="AI agent inventory & discovery")
app.add_typer(analyze_app, name="analyze", help="Risk & data flow analysis")
app.add_typer(compliance_app, name="compliance", help="Compliance reporting")


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print(f"[bold blue]SecureAgent[/bold blue] version [green]{__version__}[/green]")
        raise typer.Exit()


def show_banner() -> None:
    """Display the SecureAgent banner."""
    banner = f"""
[bold blue]╔═══════════════════════════════════════════════════════════════╗[/bold blue]
[bold blue]║[/bold blue]  [bold white]SecureAgent[/bold white] v{__version__}                                        [bold blue]║[/bold blue]
[bold blue]║[/bold blue]  [dim]Comprehensive AI & Cloud Security Platform[/dim]                 [bold blue]║[/bold blue]
[bold blue]╚═══════════════════════════════════════════════════════════════╝[/bold blue]
"""
    console.print(banner)


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Enable verbose output",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress non-essential output",
    ),
) -> None:
    """SecureAgent - Comprehensive AI & Cloud Security Platform.

    Scan AI agents (MCP, LangChain, OpenAI, AutoGPT) and cloud infrastructure
    (AWS, Azure, Terraform) for security vulnerabilities.
    """
    # Load configuration
    if config_file:
        load_config(str(config_file))

    # Set verbosity
    config = get_config()
    if verbose:
        config.debug = True
        config.log_level = "DEBUG"
    elif quiet:
        config.log_level = "WARNING"


@app.command()
def version() -> None:
    """Show version information."""
    show_banner()

    table = Table(title="Version Information", show_header=False)
    table.add_column("Component", style="cyan")
    table.add_column("Version", style="green")

    table.add_row("SecureAgent", __version__)
    table.add_row("Python", "3.9+")

    console.print(table)


@app.command()
def info() -> None:
    """Show information about available scanners and capabilities."""
    show_banner()

    # Scanners table
    scanner_table = Table(title="Available Scanners")
    scanner_table.add_column("Scanner", style="cyan")
    scanner_table.add_column("Domain", style="blue")
    scanner_table.add_column("Description")

    scanners = [
        ("mcp", "AI Agents", "MCP server configuration scanning"),
        ("langchain", "AI Agents", "LangChain agent security"),
        ("openai", "AI Agents", "OpenAI Assistants scanning"),
        ("autogpt", "AI Agents", "AutoGPT/CrewAI scanning"),
        ("aws", "Cloud", "AWS infrastructure scanning"),
        ("azure", "Cloud", "Azure infrastructure scanning"),
        ("terraform", "IaC", "Terraform configuration scanning"),
    ]

    for name, domain, desc in scanners:
        scanner_table.add_row(name, domain, desc)

    console.print(scanner_table)
    console.print()

    # Capabilities table
    cap_table = Table(title="Capabilities")
    cap_table.add_column("Feature", style="cyan")
    cap_table.add_column("Status", style="green")

    capabilities = [
        ("AI Agent Inventory", "Available"),
        ("Permission Analysis", "Available"),
        ("Data Flow Analysis", "Available"),
        ("Guardrail Coverage", "Available"),
        ("ML Risk Scoring", "Available"),
        ("OWASP LLM Top 10", "Available"),
        ("SOC2 Compliance", "Available"),
        ("GitHub Integration", "Available"),
        ("Slack Bot", "Available"),
    ]

    for feature, status in capabilities:
        cap_table.add_row(feature, f"[green]{status}[/green]")

    console.print(cap_table)


@app.command()
def config(
    show: bool = typer.Option(False, "--show", "-s", help="Show current configuration"),
    init: bool = typer.Option(False, "--init", help="Initialize configuration file"),
    validate: bool = typer.Option(False, "--validate", help="Validate configuration"),
) -> None:
    """Manage SecureAgent configuration."""
    cfg = get_config()

    if init:
        # Create default config file
        config_path = Path(".secureagent.yaml")
        if config_path.exists():
            console.print("[yellow]Configuration file already exists[/yellow]")
            raise typer.Exit(1)

        import yaml
        with open(config_path, "w") as f:
            yaml.dump(cfg.to_dict(), f, default_flow_style=False)

        console.print(f"[green]Created configuration file:[/green] {config_path}")
        return

    if validate:
        warnings = cfg.validate()
        if warnings:
            console.print("[yellow]Configuration warnings:[/yellow]")
            for warning in warnings:
                console.print(f"  - {warning}")
        else:
            console.print("[green]Configuration is valid[/green]")
        return

    if show:
        console.print(Panel.fit(
            str(cfg.to_dict()),
            title="Current Configuration",
        ))
        return

    # Default: show help
    console.print("Use --show to display configuration, --init to create, or --validate to check")


@app.command()
def rules(
    scanner: Optional[str] = typer.Option(None, "--scanner", "-s", help="Filter by scanner"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter by severity"),
) -> None:
    """List all security rules."""
    from secureagent.core.scanner.registry import scanner_registry

    table = Table(title="Security Rules")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Scanner", style="blue")
    table.add_column("Severity", style="yellow")
    table.add_column("Title")
    table.add_column("CWE")

    # Get rules from registered scanners
    for scanner_name in scanner_registry.get_all():
        if scanner and scanner_name != scanner:
            continue

        scanner_instance = scanner_registry.get(scanner_name)
        if scanner_instance:
            for rule in scanner_instance.get_rules():
                rule_severity = rule.get("severity", "medium")
                if severity and rule_severity != severity:
                    continue

                sev = Severity(rule_severity)
                table.add_row(
                    rule.get("id", ""),
                    scanner_name,
                    f"[{sev.color}]{rule_severity.upper()}[/{sev.color}]",
                    rule.get("title", ""),
                    rule.get("cwe_id", ""),
                )

    console.print(table)


def main_entry() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main_entry()
