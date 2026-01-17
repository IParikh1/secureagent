"""RAG security CLI commands for SecureAgent."""

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel

from secureagent.core.models.severity import Severity

rag_app = typer.Typer(help="RAG (Retrieval-Augmented Generation) security scanning")
console = Console()


@rag_app.command("scan")
def scan_rag(
    target: str = typer.Argument(..., help="Target directory or vector store config to scan"),
    vector_store: Optional[str] = typer.Option(
        None,
        "--vector-store",
        "-v",
        help="Vector store type (pinecone, chroma, weaviate, qdrant, milvus, pgvector, redis, faiss)",
    ),
    check_documents: bool = typer.Option(
        True,
        "--documents/--no-documents",
        help="Scan documents in directory for security threats",
    ),
    check_poisoning: bool = typer.Option(
        True,
        "--poisoning/--no-poisoning",
        help="Check for RAG poisoning indicators",
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
    """Run comprehensive RAG security scan.

    Analyzes vector store configurations, documents, and checks for poisoning.

    Examples:
        secureagent rag scan .
        secureagent rag scan ./config --vector-store pinecone
        secureagent rag scan . --format json --output rag-report.json
    """
    from secureagent.rag import RAGSecurityScanner, RAGSecurityReport

    console.print("\n[bold blue]RAG Security Scan[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    scanner = RAGSecurityScanner()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running comprehensive RAG security scan...", total=None)

        try:
            report = scanner.scan_comprehensive(
                target_path=target,
                vector_store_type=vector_store,
                scan_documents=check_documents,
                detect_poisoning=check_poisoning,
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
        _print_rag_report(report, filtered_findings)

    # CI mode exit code
    if ci and filtered_findings:
        critical_high = [f for f in filtered_findings if f.severity in ["critical", "high"]]
        if critical_high:
            raise typer.Exit(1)


@rag_app.command("vector-stores")
def scan_vector_stores(
    target: str = typer.Argument(..., help="Path to scan for vector store configurations"),
    store_type: Optional[str] = typer.Option(
        None,
        "--type",
        "-t",
        help="Specific vector store type to scan for",
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
) -> None:
    """Scan for vector store security issues.

    Checks configurations for Pinecone, Chroma, Weaviate, Qdrant, Milvus, and more.

    Examples:
        secureagent rag vector-stores .
        secureagent rag vector-stores ./config --type pinecone
    """
    from secureagent.rag import VectorStoreSecurityAnalyzer, VectorStoreType

    console.print("\n[bold blue]Vector Store Security Scan[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    analyzer = VectorStoreSecurityAnalyzer()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning for vector store configurations...", total=None)

        try:
            if store_type:
                vs_type = VectorStoreType(store_type)
                findings = analyzer.scan_directory(target, [vs_type])
            else:
                findings = analyzer.scan_directory(target)
            progress.update(task, description=f"[green]Found {len(findings)} issues[/green]")
        except Exception as e:
            progress.update(task, description=f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

    if format == "json":
        _output_findings_json(findings, "Vector Store Security", output)
    else:
        _print_findings_table(findings, "Vector Store Security Issues")


@rag_app.command("documents")
def scan_documents(
    target: str = typer.Argument(..., help="Path to documents or directory to scan"),
    recursive: bool = typer.Option(
        True,
        "--recursive/--no-recursive",
        "-r",
        help="Scan subdirectories recursively",
    ),
    file_types: Optional[str] = typer.Option(
        None,
        "--types",
        help="File extensions to scan (comma-separated, e.g., .txt,.pdf,.md)",
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
) -> None:
    """Scan documents for security threats before RAG ingestion.

    Detects injection payloads, hidden instructions, invisible text, PII, and more.

    Examples:
        secureagent rag documents ./docs
        secureagent rag documents ./data --types .txt,.md,.pdf
    """
    from secureagent.rag import DocumentSecurityScanner

    console.print("\n[bold blue]Document Security Scan[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]\n")

    scanner = DocumentSecurityScanner()
    target_path = Path(target)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning documents...", total=None)

        try:
            # Parse file types if provided
            extensions = None
            if file_types:
                extensions = [ext.strip() for ext in file_types.split(",")]

            # Collect files to scan
            if target_path.is_file():
                files = [target_path]
            else:
                if recursive:
                    files = list(target_path.rglob("*"))
                else:
                    files = list(target_path.glob("*"))
                files = [f for f in files if f.is_file()]
                if extensions:
                    files = [f for f in files if f.suffix in extensions]

            # Scan each file
            all_results = []
            for file_path in files:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    result = scanner.scan_document(content, str(file_path))
                    if result.threats:
                        all_results.append(result)
                except Exception:
                    continue

            progress.update(
                task,
                description=f"[green]Scanned {len(files)} files, {len(all_results)} with threats[/green]"
            )
        except Exception as e:
            progress.update(task, description=f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

    if format == "json":
        _output_document_results_json(all_results, output)
    else:
        _print_document_results(all_results)


@rag_app.command("poisoning")
def detect_poisoning(
    target: str = typer.Argument(..., help="Path to knowledge base or documents to analyze"),
    threshold: float = typer.Option(
        0.7,
        "--threshold",
        "-t",
        help="Confidence threshold for poisoning detection (0.0-1.0)",
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
) -> None:
    """Detect RAG poisoning indicators in knowledge base.

    Identifies instruction injection, authority spoofing, fact pollution, and more.

    Examples:
        secureagent rag poisoning ./knowledge-base
        secureagent rag poisoning ./docs --threshold 0.8
    """
    from secureagent.rag import RAGPoisoningDetector

    console.print("\n[bold blue]RAG Poisoning Detection[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]")
    console.print(f"Confidence threshold: [yellow]{threshold}[/yellow]\n")

    detector = RAGPoisoningDetector()
    target_path = Path(target)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing for poisoning indicators...", total=None)

        try:
            # Collect content to analyze
            documents = []
            if target_path.is_file():
                with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                    documents.append(f.read())
            else:
                for file_path in target_path.rglob("*"):
                    if file_path.is_file():
                        try:
                            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                                documents.append(f.read())
                        except Exception:
                            continue

            # Analyze for poisoning
            all_indicators = []
            for doc in documents:
                result = detector.analyze(doc)
                indicators = [i for i in result.indicators if i.confidence >= threshold]
                all_indicators.extend(indicators)

            progress.update(
                task,
                description=f"[green]Analyzed {len(documents)} documents, found {len(all_indicators)} indicators[/green]"
            )
        except Exception as e:
            progress.update(task, description=f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

    if format == "json":
        _output_poisoning_json(all_indicators, output)
    else:
        _print_poisoning_results(all_indicators)


@rag_app.command("test")
def test_rag(
    target: str = typer.Argument(..., help="RAG endpoint or system to test"),
    payloads: Optional[str] = typer.Option(
        None,
        "--payloads",
        "-p",
        help="Path to custom payloads file (JSON)",
    ),
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
    """Test RAG system with security payloads.

    Runs injection tests against a RAG system to identify vulnerabilities.

    Examples:
        secureagent rag test http://localhost:8000/query
        secureagent rag test ./rag_config.json --max-tests 20
    """
    from secureagent.testing.payloads import PayloadGenerator

    console.print("\n[bold blue]RAG Security Testing[/bold blue]")
    console.print(f"Target: [cyan]{target}[/cyan]")
    console.print(f"Max tests: [yellow]{max_tests}[/yellow]\n")

    generator = PayloadGenerator()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating RAG-specific payloads...", total=None)

        # Get RAG-specific payloads
        rag_payloads = generator.get_rag_payloads()[:max_tests]

        progress.update(
            task,
            description=f"[green]Generated {len(rag_payloads)} RAG test payloads[/green]"
        )

    # Display payloads
    table = Table(title="RAG Security Test Payloads")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Category", style="yellow")
    table.add_column("Payload Preview", style="dim")

    for payload in rag_payloads:
        preview = payload.payload[:50] + "..." if len(payload.payload) > 50 else payload.payload
        preview = preview.replace("\n", "\\n")
        table.add_row(
            payload.id,
            payload.name,
            payload.category,
            preview,
        )

    console.print(table)
    console.print()

    console.print(Panel(
        "[yellow]Note:[/yellow] Active testing requires a running RAG endpoint.\n"
        "Use these payloads to test your RAG system for injection vulnerabilities.",
        title="Testing Info",
        border_style="blue",
    ))


def _output_json(report, findings, output: Optional[Path]) -> None:
    """Output RAG report as JSON."""
    import json

    output_data = {
        "summary": {
            "total_findings": len(findings),
            "critical": len([f for f in findings if f.severity == "critical"]),
            "high": len([f for f in findings if f.severity == "high"]),
            "medium": len([f for f in findings if f.severity == "medium"]),
            "low": len([f for f in findings if f.severity == "low"]),
        },
        "vector_store_findings": len(report.vector_store_findings),
        "document_threats": len(report.document_threats),
        "poisoning_indicators": len(report.poisoning_indicators),
        "findings": [f.to_dict() for f in findings],
    }

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


def _output_document_results_json(results, output: Optional[Path]) -> None:
    """Output document scan results as JSON."""
    import json

    output_data = {
        "documents_with_threats": len(results),
        "results": [
            {
                "document": r.document_id,
                "risk_level": r.risk_level.value,
                "threats": [
                    {
                        "category": t.category.value,
                        "description": t.description,
                        "severity": t.severity.value,
                        "location": t.location,
                    }
                    for t in r.threats
                ],
            }
            for r in results
        ],
    }

    if output:
        with open(output, "w") as f:
            json.dump(output_data, f, indent=2)
        console.print(f"\n[green]Results written to {output}[/green]")
    else:
        console.print_json(data=output_data)


def _output_poisoning_json(indicators, output: Optional[Path]) -> None:
    """Output poisoning indicators as JSON."""
    import json

    output_data = {
        "total_indicators": len(indicators),
        "indicators": [
            {
                "type": i.poisoning_type.value,
                "severity": i.severity.value,
                "confidence": i.confidence,
                "description": i.description,
                "evidence": i.evidence,
            }
            for i in indicators
        ],
    }

    if output:
        with open(output, "w") as f:
            json.dump(output_data, f, indent=2)
        console.print(f"\n[green]Results written to {output}[/green]")
    else:
        console.print_json(data=output_data)


def _print_rag_report(report, findings) -> None:
    """Print RAG security report to console."""
    # Summary table
    summary = Table(title="RAG Security Scan Summary")
    summary.add_column("Category", style="cyan")
    summary.add_column("Issues Found", justify="right")

    summary.add_row("Vector Store Issues", str(len(report.vector_store_findings)))
    summary.add_row("Document Threats", str(len(report.document_threats)))
    summary.add_row("Poisoning Indicators", str(len(report.poisoning_indicators)))
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
            f"[red bold]Found {critical + high} critical/high severity RAG security issues![/red bold]",
            title="Status",
            border_style="red",
        ))
    elif findings:
        console.print(Panel(
            f"[yellow]Found {len(findings)} RAG security issues to review[/yellow]",
            title="Status",
            border_style="yellow",
        ))
    else:
        console.print(Panel(
            "[green]No RAG security issues found[/green]",
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


def _print_document_results(results) -> None:
    """Print document scan results."""
    if not results:
        console.print("\n[green]No document security threats found[/green]")
        return

    console.print(f"\n[bold]Documents with Security Threats ({len(results)}):[/bold]")

    for result in results[:10]:
        risk_color = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "clean": "green",
        }.get(result.risk_level.value, "white")

        console.print(f"\n  [{risk_color}]{result.risk_level.value.upper()}[/{risk_color}]: {result.document_id}")

        for threat in result.threats[:5]:
            console.print(f"    - [{threat.category.value}] {threat.description}")

        if len(result.threats) > 5:
            console.print(f"    [dim]... and {len(result.threats) - 5} more threats[/dim]")

    if len(results) > 10:
        console.print(f"\n[dim]... and {len(results) - 10} more documents with threats[/dim]")


def _print_poisoning_results(indicators) -> None:
    """Print poisoning detection results."""
    if not indicators:
        console.print("\n[green]No RAG poisoning indicators found[/green]")
        return

    table = Table(title="RAG Poisoning Indicators")
    table.add_column("Type", style="cyan")
    table.add_column("Severity", style="yellow")
    table.add_column("Confidence", justify="right")
    table.add_column("Description")

    for indicator in indicators:
        sev_color = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
        }.get(indicator.severity.value, "white")

        table.add_row(
            indicator.poisoning_type.value,
            f"[{sev_color}]{indicator.severity.value.upper()}[/{sev_color}]",
            f"{indicator.confidence:.0%}",
            indicator.description[:60] + "..." if len(indicator.description) > 60 else indicator.description,
        )

    console.print(table)
