"""Model management CLI commands."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

model_app = typer.Typer(help="ML model management")
console = Console()


@model_app.command("list")
def list_models() -> None:
    """List all registered models.

    Examples:
        secureagent model list
    """
    from secureagent.ml.model_manager import ModelManager

    console.print("\n[bold blue]Registered Models[/bold blue]\n")

    manager = ModelManager()
    models = manager.list_models()

    if not models:
        console.print("[yellow]No models registered[/yellow]")
        return

    table = Table()
    table.add_column("Model ID", style="cyan")
    table.add_column("Type")
    table.add_column("Use Case")
    table.add_column("Accuracy", justify="right")
    table.add_column("Version")

    for model in models:
        type_style = {
            "baseline": "green",
            "custom": "blue",
            "fine_tuned": "yellow",
            "industry": "magenta",
        }.get(model.model_type.value, "dim")

        accuracy = model.metrics.get("accuracy", 0)
        acc_str = f"{accuracy:.1%}" if accuracy else "-"

        table.add_row(
            model.model_id,
            f"[{type_style}]{model.model_type.value}[/{type_style}]",
            model.use_case or "-",
            acc_str,
            model.version,
        )

    console.print(table)


@model_app.command("info")
def model_info(
    model_id: str = typer.Argument("baseline", help="Model ID to inspect"),
) -> None:
    """Show detailed information about a model.

    Examples:
        secureagent model info
        secureagent model info baseline
        secureagent model info my-custom-model
    """
    from secureagent.ml.model_manager import ModelManager

    console.print(f"\n[bold blue]Model Information[/bold blue]\n")

    manager = ModelManager()
    metadata = manager.get_model_metadata(model_id)

    if not metadata:
        console.print(f"[red]Model not found: {model_id}[/red]")
        raise typer.Exit(1)

    model_path = manager.get_model_path(model_id)

    # Basic info
    console.print(f"[bold]Model ID:[/bold] {metadata.model_id}")
    console.print(f"[bold]Type:[/bold] {metadata.model_type.value}")
    console.print(f"[bold]Version:[/bold] {metadata.version}")
    console.print(f"[bold]Created:[/bold] {metadata.created_at}")
    console.print(f"[bold]Description:[/bold] {metadata.description}")

    if model_path:
        size_mb = model_path.stat().st_size / (1024 * 1024)
        console.print(f"[bold]Path:[/bold] {model_path}")
        console.print(f"[bold]Size:[/bold] {size_mb:.2f} MB")

    if metadata.use_case:
        console.print(f"[bold]Use Case:[/bold] {metadata.use_case}")
    if metadata.industry:
        console.print(f"[bold]Industry:[/bold] {metadata.industry}")
    if metadata.organization:
        console.print(f"[bold]Organization:[/bold] {metadata.organization}")
    if metadata.parent_model:
        console.print(f"[bold]Parent Model:[/bold] {metadata.parent_model}")

    # Metrics
    if metadata.metrics:
        console.print("\n[bold]Metrics:[/bold]")
        metrics_table = Table(show_header=False)
        metrics_table.add_column("Metric", style="cyan")
        metrics_table.add_column("Value", justify="right")

        for name, value in metadata.metrics.items():
            if isinstance(value, float):
                metrics_table.add_row(name, f"{value:.4f}")
            else:
                metrics_table.add_row(name, str(value))

        console.print(metrics_table)

    # Tags
    if metadata.tags:
        console.print(f"\n[bold]Tags:[/bold] {', '.join(metadata.tags)}")

    # Verify integrity
    console.print("\n[bold]Integrity Check:[/bold]", end=" ")
    if manager.verify_model(model_id):
        console.print("[green]PASSED[/green]")
    else:
        console.print("[red]FAILED[/red]")


@model_app.command("import")
def import_model(
    model_path: Path = typer.Argument(..., help="Path to model file (.pkl)"),
    model_id: Optional[str] = typer.Option(None, "--id", help="Model ID (default: filename)"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Model description"),
    use_case: Optional[str] = typer.Option(None, "--use-case", help="Use case"),
    industry: Optional[str] = typer.Option(None, "--industry", help="Industry vertical"),
) -> None:
    """Import a custom model.

    Examples:
        secureagent model import ./my_model.pkl
        secureagent model import ./healthcare_model.pkl --id healthcare-v1 --industry healthcare
    """
    from secureagent.ml.model_manager import ModelManager, ModelType

    console.print(f"\n[bold blue]Import Model[/bold blue]\n")

    if not model_path.exists():
        console.print(f"[red]File not found: {model_path}[/red]")
        raise typer.Exit(1)

    manager = ModelManager()

    # Check for metadata file
    meta_path = model_path.with_suffix(".meta.json")
    if meta_path.exists():
        console.print(f"[dim]Found metadata file: {meta_path.name}[/dim]")
        metadata = manager.import_model(model_path, model_id)
    else:
        # Manual registration
        final_id = model_id or model_path.stem
        metadata = manager.register_model(
            model_path=model_path,
            model_id=final_id,
            model_type=ModelType.CUSTOM,
            description=description or f"Custom model imported from {model_path.name}",
            use_case=use_case,
            industry=industry,
        )

    console.print(f"[green]Model imported successfully![/green]")
    console.print(f"  Model ID: [cyan]{metadata.model_id}[/cyan]")
    console.print(f"  Checksum: {metadata.checksum[:16]}...")


@model_app.command("export")
def export_model(
    model_id: str = typer.Argument(..., help="Model ID to export"),
    output: Path = typer.Option(..., "--output", "-o", help="Output path"),
) -> None:
    """Export a model to a file.

    Examples:
        secureagent model export baseline -o ./baseline_model.pkl
        secureagent model export my-custom-model -o ./export/model.pkl
    """
    from secureagent.ml.model_manager import ModelManager

    console.print(f"\n[bold blue]Export Model[/bold blue]\n")

    manager = ModelManager()

    if manager.export_model(model_id, output):
        console.print(f"[green]Model exported successfully![/green]")
        console.print(f"  Model: {output}")
        console.print(f"  Metadata: {output.with_suffix('.meta.json')}")
    else:
        console.print(f"[red]Model not found: {model_id}[/red]")
        raise typer.Exit(1)


@model_app.command("delete")
def delete_model(
    model_id: str = typer.Argument(..., help="Model ID to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
) -> None:
    """Delete a registered model.

    Examples:
        secureagent model delete my-old-model
        secureagent model delete my-old-model --force
    """
    from secureagent.ml.model_manager import ModelManager

    console.print(f"\n[bold blue]Delete Model[/bold blue]\n")

    manager = ModelManager()

    if model_id == "baseline":
        console.print("[red]Cannot delete the baseline model[/red]")
        raise typer.Exit(1)

    metadata = manager.get_model_metadata(model_id)
    if not metadata:
        console.print(f"[red]Model not found: {model_id}[/red]")
        raise typer.Exit(1)

    if not force:
        console.print(f"Model: [cyan]{model_id}[/cyan]")
        console.print(f"Type: {metadata.model_type.value}")
        console.print(f"Description: {metadata.description}")
        confirm = typer.confirm("\nAre you sure you want to delete this model?")
        if not confirm:
            console.print("[yellow]Cancelled[/yellow]")
            raise typer.Exit(0)

    if manager.delete_model(model_id):
        console.print(f"[green]Model deleted: {model_id}[/green]")
    else:
        console.print(f"[red]Failed to delete model[/red]")
        raise typer.Exit(1)


@model_app.command("presets")
def list_presets() -> None:
    """List available retraining presets.

    Examples:
        secureagent model presets
    """
    from secureagent.ml.model_manager import ModelManager, RetrainingStrategy

    console.print("\n[bold blue]Retraining Presets[/bold blue]\n")
    console.print("[dim]Use these presets when training custom models for specific use cases.[/dim]\n")

    manager = ModelManager()
    presets = manager.list_retraining_presets()

    # Group by category
    categories = {
        "Industry-Specific": ["healthcare", "finance", "government"],
        "Risk Tolerance": ["high_security", "balanced", "low_friction"],
        "Tech Stack": ["aws_heavy", "azure_heavy", "multi_cloud"],
        "Training Workflow": ["feedback_driven", "active_learning", "custom_agents"],
    }

    for category, preset_names in categories.items():
        console.print(f"\n[bold]{category}[/bold]")

        table = Table(show_header=True)
        table.add_column("Preset", style="cyan")
        table.add_column("Strategy")
        table.add_column("Min Samples", justify="right")
        table.add_column("Description")

        for name in preset_names:
            if name in presets:
                preset = presets[name]
                strategy_style = {
                    RetrainingStrategy.TRANSFER_LEARNING: "green",
                    RetrainingStrategy.FEEDBACK_LOOP: "blue",
                    RetrainingStrategy.FULL_RETRAIN: "yellow",
                    RetrainingStrategy.ACTIVE_LEARNING: "magenta",
                    RetrainingStrategy.ENSEMBLE_BLEND: "cyan",
                }.get(preset.strategy, "dim")

                table.add_row(
                    name,
                    f"[{strategy_style}]{preset.strategy.value}[/{strategy_style}]",
                    str(preset.min_samples),
                    preset.description[:50] + "..." if len(preset.description) > 50 else preset.description,
                )

        console.print(table)


@model_app.command("recommend")
def recommend_preset(
    industry: Optional[str] = typer.Option(None, "--industry", "-i", help="Industry vertical"),
    samples: int = typer.Option(0, "--samples", "-n", help="Number of training samples available"),
) -> None:
    """Get a recommended retraining preset.

    Examples:
        secureagent model recommend --industry healthcare
        secureagent model recommend --samples 300
        secureagent model recommend --industry finance --samples 1000
    """
    from secureagent.ml.model_manager import ModelManager

    console.print("\n[bold blue]Preset Recommendation[/bold blue]\n")

    manager = ModelManager()
    preset_name = manager.get_recommended_preset(
        industry=industry,
        sample_count=samples,
    )

    preset = manager.get_retraining_preset(preset_name)
    if not preset:
        console.print("[red]Could not determine recommendation[/red]")
        raise typer.Exit(1)

    console.print(Panel(
        f"[bold]Recommended Preset:[/bold] [cyan]{preset_name}[/cyan]\n\n"
        f"[bold]Strategy:[/bold] {preset.strategy.value}\n"
        f"[bold]Description:[/bold] {preset.description}\n"
        f"[bold]Minimum Samples:[/bold] {preset.min_samples}\n"
        f"[bold]Include Baseline Data:[/bold] {'Yes' if preset.include_baseline_data else 'No'}",
        title="Recommendation",
    ))

    console.print("\n[dim]To train with this preset:[/dim]")
    console.print(f"  secureagent ml train --preset {preset_name} --data your_data.json")


@model_app.command("verify")
def verify_model(
    model_id: str = typer.Argument("baseline", help="Model ID to verify"),
) -> None:
    """Verify model integrity.

    Examples:
        secureagent model verify
        secureagent model verify my-custom-model
    """
    from secureagent.ml.model_manager import ModelManager

    console.print(f"\n[bold blue]Verify Model Integrity[/bold blue]\n")

    manager = ModelManager()
    metadata = manager.get_model_metadata(model_id)

    if not metadata:
        console.print(f"[red]Model not found: {model_id}[/red]")
        raise typer.Exit(1)

    console.print(f"Model: [cyan]{model_id}[/cyan]")
    console.print(f"Expected checksum: {metadata.checksum[:32]}...")

    model_path = manager.get_model_path(model_id)
    if not model_path:
        console.print("[red]Model file not found[/red]")
        raise typer.Exit(1)

    import hashlib
    sha256 = hashlib.sha256()
    with open(model_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    actual_checksum = sha256.hexdigest()

    console.print(f"Actual checksum:   {actual_checksum[:32]}...")

    if actual_checksum == metadata.checksum:
        console.print("\n[green bold]INTEGRITY CHECK PASSED[/green bold]")
    else:
        console.print("\n[red bold]INTEGRITY CHECK FAILED[/red bold]")
        console.print("[yellow]The model file may have been modified or corrupted.[/yellow]")
        raise typer.Exit(1)
