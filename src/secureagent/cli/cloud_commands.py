"""Cloud infrastructure scanning CLI commands."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

cloud_app = typer.Typer(help="Cloud infrastructure scanning")
console = Console()


@cloud_app.command("scan")
def scan_cloud(
    provider: str = typer.Option(
        "all",
        "--provider",
        "-p",
        help="Cloud provider (aws, azure, gcp, all)",
    ),
    region: Optional[str] = typer.Option(None, "--region", "-r", help="Cloud region"),
    profile: Optional[str] = typer.Option(None, "--profile", help="Credential profile"),
    format: str = typer.Option("console", "--format", "-f", help="Output format"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file"),
    alert: bool = typer.Option(False, "--alert", help="Send alerts for findings"),
) -> None:
    """Scan cloud infrastructure for security issues.

    Examples:
        secureagent cloud scan
        secureagent cloud scan --provider aws --region us-east-1
        secureagent cloud scan --provider azure --format json
    """
    from secureagent.core.scanner.registry import scanner_registry

    console.print(f"\n[bold blue]Cloud Security Scan[/bold blue]")
    console.print(f"Provider: [cyan]{provider}[/cyan]")
    if region:
        console.print(f"Region: [cyan]{region}[/cyan]")
    console.print()

    providers = ["aws", "azure"] if provider == "all" else [provider]
    all_findings = []

    for p in providers:
        console.print(f"[yellow]Scanning {p.upper()}...[/yellow]")
        scanner = scanner_registry.get(p)

        if not scanner:
            console.print(f"  [dim]{p} scanner not available[/dim]")
            continue

        try:
            scanner.initialize()
            result = scanner.scan(p, region=region, profile=profile)
            all_findings.extend(result.findings)
            console.print(f"  [green]{len(result.findings)} findings[/green]")
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")
        finally:
            scanner.cleanup()

    # Print summary
    console.print(f"\n[bold]Total findings: {len(all_findings)}[/bold]")

    if all_findings:
        table = Table(title="Cloud Security Findings")
        table.add_column("Provider", style="cyan")
        table.add_column("Resource")
        table.add_column("Severity")
        table.add_column("Finding")

        for finding in all_findings[:20]:  # Limit display
            sev_style = {
                "critical": "red bold",
                "high": "red",
                "medium": "yellow",
            }.get(finding.severity, "blue")

            table.add_row(
                finding.domain.upper() if hasattr(finding.domain, 'upper') else str(finding.domain),
                finding.location.resource_id or finding.location.to_string(),
                f"[{sev_style}]{finding.severity.upper() if hasattr(finding.severity, 'upper') else finding.severity}[/{sev_style}]",
                finding.title,
            )

        console.print(table)


@cloud_app.command("aws")
def scan_aws(
    service: Optional[str] = typer.Argument(None, help="AWS service (s3, iam, ec2, lambda, all)"),
    region: Optional[str] = typer.Option(None, "--region", "-r", help="AWS region"),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile"),
) -> None:
    """Scan AWS infrastructure.

    Examples:
        secureagent cloud aws
        secureagent cloud aws s3
        secureagent cloud aws iam --region us-west-2
    """
    console.print(f"\n[bold blue]AWS Security Scan[/bold blue]")
    if service:
        console.print(f"Service: [cyan]{service}[/cyan]")

    # AWS scanning logic would go here
    console.print("\n[yellow]AWS scanning in progress...[/yellow]")
    console.print("[dim]This will scan S3, IAM, EC2, and other AWS services[/dim]")


@cloud_app.command("azure")
def scan_azure(
    service: Optional[str] = typer.Argument(None, help="Azure service (storage, keyvault, all)"),
    subscription: Optional[str] = typer.Option(None, "--subscription", "-s", help="Subscription ID"),
) -> None:
    """Scan Azure infrastructure.

    Examples:
        secureagent cloud azure
        secureagent cloud azure storage
    """
    console.print(f"\n[bold blue]Azure Security Scan[/bold blue]")
    if service:
        console.print(f"Service: [cyan]{service}[/cyan]")

    # Azure scanning logic would go here
    console.print("\n[yellow]Azure scanning in progress...[/yellow]")


@cloud_app.command("terraform")
def scan_terraform(
    path: Path = typer.Argument(".", help="Path to Terraform files"),
    format: str = typer.Option("console", "--format", "-f", help="Output format"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file"),
) -> None:
    """Scan Terraform configuration for security issues.

    Examples:
        secureagent cloud terraform ./infrastructure
        secureagent cloud terraform . --format sarif
    """
    from secureagent.core.scanner.registry import scanner_registry

    console.print(f"\n[bold blue]Terraform Security Scan[/bold blue]")
    console.print(f"Path: [cyan]{path}[/cyan]\n")

    scanner = scanner_registry.get("terraform")
    if not scanner:
        console.print("[red]Terraform scanner not available[/red]")
        raise typer.Exit(1)

    try:
        scanner.initialize()
        result = scanner.scan(str(path))
        console.print(f"[green]Scan complete:[/green] {len(result.findings)} findings")

        if result.findings:
            table = Table(title="Terraform Findings")
            table.add_column("Rule", style="cyan")
            table.add_column("Severity")
            table.add_column("Resource")
            table.add_column("Finding")

            for finding in result.findings:
                sev_style = {"critical": "red bold", "high": "red", "medium": "yellow"}.get(
                    finding.severity if isinstance(finding.severity, str) else finding.severity.value,
                    "blue"
                )
                table.add_row(
                    finding.rule_id,
                    f"[{sev_style}]{finding.severity.upper() if hasattr(finding.severity, 'upper') else finding.severity}[/{sev_style}]",
                    finding.location.file_path or "",
                    finding.title,
                )
            console.print(table)

    finally:
        scanner.cleanup()
