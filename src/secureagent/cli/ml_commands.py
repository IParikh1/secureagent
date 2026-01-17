"""ML model training and management CLI commands."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

ml_app = typer.Typer(help="ML model training and management")
console = Console()


@ml_app.command("train")
def train_model(
    data_path: Optional[Path] = typer.Option(
        None, "--data", "-d", help="Path to training data JSON file"
    ),
    synthetic: bool = typer.Option(
        False, "--synthetic", "-s", help="Train using synthetic data"
    ),
    samples: int = typer.Option(
        1000, "--samples", "-n", help="Number of synthetic samples to generate"
    ),
    output_dir: Path = typer.Option(
        Path("models"), "--output", "-o", help="Output directory for trained model"
    ),
    model_name: str = typer.Option(
        "secureagent_risk_v1", "--name", help="Model name"
    ),
    validation_split: float = typer.Option(
        0.2, "--val-split", help="Validation split ratio"
    ),
    preset: Optional[str] = typer.Option(
        None, "--preset", "-p", help="Retraining preset (e.g., healthcare, finance, high_security)"
    ),
    register: bool = typer.Option(
        False, "--register", "-r", help="Register model in model registry after training"
    ),
    use_case: Optional[str] = typer.Option(
        None, "--use-case", help="Use case description for registration"
    ),
    industry: Optional[str] = typer.Option(
        None, "--industry", help="Industry vertical for registration"
    ),
) -> None:
    """Train a risk prediction model.

    Examples:
        secureagent ml train --synthetic
        secureagent ml train --synthetic --samples 2000
        secureagent ml train --data training_data.json
        secureagent ml train --data client_data.json --preset healthcare --register
        secureagent ml train --data my_data.json --preset finance --name finance-model-v1
        secureagent ml train --synthetic --output ./custom_models
    """
    from secureagent.ml.trainer import ModelTrainer
    from secureagent.ml.model_manager import ModelManager, ModelType, RETRAINING_PRESETS

    console.print("\n[bold blue]ML Model Training[/bold blue]\n")

    # Handle preset configuration
    preset_config = None
    if preset:
        if preset not in RETRAINING_PRESETS:
            console.print(f"[red]Unknown preset: {preset}[/red]")
            console.print(f"[dim]Available presets: {', '.join(RETRAINING_PRESETS.keys())}[/dim]")
            raise typer.Exit(1)

        preset_config = RETRAINING_PRESETS[preset]
        console.print(f"[dim]Using preset: {preset}[/dim]")
        console.print(f"[dim]Strategy: {preset_config.strategy.value}[/dim]")
        console.print(f"[dim]Description: {preset_config.description}[/dim]\n")

        # Override samples if preset specifies minimum
        if samples < preset_config.min_samples:
            console.print(f"[yellow]Warning: Preset requires minimum {preset_config.min_samples} samples[/yellow]")

    trainer = ModelTrainer(output_dir=output_dir, model_name=model_name)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            if synthetic:
                task = progress.add_task(
                    f"Generating {samples} synthetic samples and training...",
                    total=None,
                )
                result = trainer.train_from_synthetic(
                    sample_count=samples,
                    validation_split=validation_split,
                )
            elif data_path:
                if not data_path.exists():
                    console.print(f"[red]Data file not found: {data_path}[/red]")
                    raise typer.Exit(1)

                task = progress.add_task("Loading data and training...", total=None)
                X, y, feature_names = trainer.load_training_data(data_path)

                # Create findings from loaded data (simplified)
                from secureagent.core.models.finding import Finding, FindingDomain, Location
                from secureagent.core.models.severity import Severity

                findings = []
                for i, label in enumerate(y):
                    findings.append(
                        Finding(
                            rule_id=f"TRAIN-{i:04d}",
                            domain=FindingDomain.MCP,
                            title=f"Training sample {i}",
                            description="Training data sample",
                            severity=Severity.HIGH if label == 1 else Severity.LOW,
                            location=Location(),
                            remediation="N/A",
                            risk_score=float(label),
                        )
                    )

                result = trainer.train(findings, validation_split=validation_split)
            else:
                console.print("[yellow]No data source specified.[/yellow]")
                console.print("Use --synthetic for synthetic data or --data for a data file.")
                raise typer.Exit(1)

            progress.update(task, description="[green]Training complete![/green]")

        # Display results
        console.print("\n[bold]Training Results[/bold]\n")

        metrics_table = Table(title="Model Metrics")
        metrics_table.add_column("Metric", style="cyan")
        metrics_table.add_column("Value", justify="right")

        metrics_table.add_row("Accuracy", f"{result.metrics.accuracy:.4f}")
        metrics_table.add_row("Precision", f"{result.metrics.precision:.4f}")
        metrics_table.add_row("Recall", f"{result.metrics.recall:.4f}")
        metrics_table.add_row("F1 Score", f"{result.metrics.f1_score:.4f}")
        metrics_table.add_row("AUC-ROC", f"{result.metrics.auc_roc:.4f}")

        console.print(metrics_table)

        # Feature importance
        if result.feature_importance:
            console.print("\n[bold]Top Feature Importance[/bold]")
            importance_sorted = sorted(
                result.feature_importance.items(),
                key=lambda x: x[1],
                reverse=True,
            )[:10]

            for feature, importance in importance_sorted:
                bar = "█" * int(importance * 30)
                console.print(f"  {feature:30s} {bar} {importance:.4f}")

        console.print(Panel(
            f"[green]Model saved to: {result.model_path}[/green]",
            title="Complete",
            border_style="green",
        ))

        # Register model if requested
        if register:
            console.print("\n[dim]Registering model...[/dim]")

            manager = ModelManager()

            # Determine model type
            if preset_config:
                model_type = ModelType.FINE_TUNED
            elif synthetic:
                model_type = ModelType.BASELINE
            else:
                model_type = ModelType.CUSTOM

            # Build description
            description = use_case or preset_config.description if preset_config else f"Custom model: {model_name}"

            metadata = manager.register_model(
                model_path=result.model_path,
                model_id=model_name,
                model_type=model_type,
                description=description,
                metrics={
                    "accuracy": result.metrics.accuracy,
                    "precision": result.metrics.precision,
                    "recall": result.metrics.recall,
                    "f1_score": result.metrics.f1_score,
                    "auc_roc": result.metrics.auc_roc,
                },
                training_config={
                    "preset": preset,
                    "samples": samples,
                    "validation_split": validation_split,
                    "synthetic": synthetic,
                },
                use_case=preset_config.use_case if preset_config else use_case,
                industry=industry,
                parent_model="baseline" if preset_config else None,
            )

            console.print(f"[green]Model registered as: {metadata.model_id}[/green]")
            console.print(f"[dim]Checksum: {metadata.checksum[:16]}...[/dim]")

    except ImportError as e:
        console.print(f"[red]Missing ML dependencies: {e}[/red]")
        console.print("Install with: pip install secureagent[ml]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Training failed: {e}[/red]")
        raise typer.Exit(1)


@ml_app.command("evaluate")
def evaluate_model(
    data_path: Path = typer.Argument(..., help="Path to test data JSON file"),
    model_path: Optional[Path] = typer.Option(
        None, "--model", "-m", help="Path to model file"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file for evaluation report"
    ),
) -> None:
    """Evaluate a trained model on test data.

    Examples:
        secureagent ml evaluate test_data.json
        secureagent ml evaluate test_data.json --model models/custom.pkl
        secureagent ml evaluate test_data.json --output report.json
    """
    from secureagent.ml.trainer import ModelTrainer

    console.print("\n[bold blue]Model Evaluation[/bold blue]\n")

    if not data_path.exists():
        console.print(f"[red]Data file not found: {data_path}[/red]")
        raise typer.Exit(1)

    trainer = ModelTrainer()

    try:
        # Load test data
        X, y, feature_names = trainer.load_training_data(data_path)

        # Create findings from loaded data
        from secureagent.core.models.finding import Finding, FindingDomain, Location
        from secureagent.core.models.severity import Severity

        findings = []
        for i, label in enumerate(y):
            findings.append(
                Finding(
                    rule_id=f"TEST-{i:04d}",
                    domain=FindingDomain.MCP,
                    title=f"Test sample {i}",
                    description="Test data sample",
                    severity=Severity.HIGH if label == 1 else Severity.LOW,
                    location=Location(),
                    remediation="N/A",
                    risk_score=float(label),
                )
            )

        # Evaluate
        report = trainer.evaluate(findings, model_path=model_path)

        # Display results
        console.print("[bold]Evaluation Results[/bold]\n")

        metrics_table = Table(title="Metrics")
        metrics_table.add_column("Metric", style="cyan")
        metrics_table.add_column("Value", justify="right")

        metrics_table.add_row("Accuracy", f"{report.accuracy:.4f}")
        metrics_table.add_row("Precision", f"{report.precision:.4f}")
        metrics_table.add_row("Recall", f"{report.recall:.4f}")
        metrics_table.add_row("F1 Score", f"{report.f1_score:.4f}")
        metrics_table.add_row("AUC-ROC", f"{report.auc_roc:.4f}")

        console.print(metrics_table)

        # Confusion matrix
        console.print("\n[bold]Confusion Matrix[/bold]")
        cm = report.confusion_matrix
        if cm:
            console.print(f"  TN: {cm[0][0]:5d}  FP: {cm[0][1]:5d}")
            console.print(f"  FN: {cm[1][0]:5d}  TP: {cm[1][1]:5d}")

        # Classification report
        console.print("\n[bold]Classification Report[/bold]")
        console.print(report.classification_report)

        # Save report if requested
        if output:
            import json
            output.write_text(json.dumps(report.to_dict(), indent=2))
            console.print(f"\n[green]Report saved to: {output}[/green]")

    except Exception as e:
        console.print(f"[red]Evaluation failed: {e}[/red]")
        raise typer.Exit(1)


@ml_app.command("cross-validate")
def cross_validate_model(
    synthetic: bool = typer.Option(
        True, "--synthetic/--no-synthetic", help="Use synthetic data"
    ),
    samples: int = typer.Option(
        1000, "--samples", "-n", help="Number of samples"
    ),
    folds: int = typer.Option(
        5, "--folds", "-k", help="Number of cross-validation folds"
    ),
) -> None:
    """Perform cross-validation on the model.

    Examples:
        secureagent ml cross-validate
        secureagent ml cross-validate --samples 2000 --folds 10
    """
    from secureagent.ml.trainer import ModelTrainer, SyntheticDataGenerator

    console.print("\n[bold blue]Cross-Validation[/bold blue]\n")

    trainer = ModelTrainer()

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running cross-validation...", total=None)

            if synthetic:
                generator = SyntheticDataGenerator()
                findings, labels = generator.generate(count=samples)

                # Set risk scores
                for finding, label in zip(findings, labels):
                    finding.risk_score = float(label)
            else:
                console.print("[yellow]Non-synthetic cross-validation requires data file[/yellow]")
                raise typer.Exit(1)

            results = trainer.cross_validate(findings, folds=folds)
            progress.update(task, description="[green]Complete![/green]")

        # Display results
        console.print("\n[bold]Cross-Validation Results[/bold]\n")

        results_table = Table(title=f"{folds}-Fold Cross-Validation")
        results_table.add_column("Metric", style="cyan")
        results_table.add_column("Mean", justify="right")
        results_table.add_column("Std", justify="right")

        results_table.add_row(
            "Accuracy",
            f"{results['accuracy_mean']:.4f}",
            f"±{results['accuracy_std']:.4f}",
        )
        results_table.add_row(
            "F1 Score",
            f"{results['f1_mean']:.4f}",
            f"±{results['f1_std']:.4f}",
        )
        results_table.add_row(
            "AUC-ROC",
            f"{results['roc_auc_mean']:.4f}",
            f"±{results['roc_auc_std']:.4f}",
        )

        console.print(results_table)

    except Exception as e:
        console.print(f"[red]Cross-validation failed: {e}[/red]")
        raise typer.Exit(1)


@ml_app.command("generate-data")
def generate_training_data(
    output: Path = typer.Argument(..., help="Output file path"),
    samples: int = typer.Option(
        1000, "--samples", "-n", help="Number of samples to generate"
    ),
    high_risk_ratio: float = typer.Option(
        0.4, "--high-risk-ratio", "-r", help="Ratio of high-risk samples"
    ),
) -> None:
    """Generate synthetic training data file.

    Examples:
        secureagent ml generate-data training_data.json
        secureagent ml generate-data training_data.json --samples 5000
        secureagent ml generate-data training_data.json --high-risk-ratio 0.5
    """
    from secureagent.ml.trainer import ModelTrainer, SyntheticDataGenerator

    console.print("\n[bold blue]Generate Training Data[/bold blue]\n")

    try:
        generator = SyntheticDataGenerator()
        findings, labels = generator.generate(
            count=samples,
            high_risk_ratio=high_risk_ratio,
        )

        # Set risk scores
        for finding, label in zip(findings, labels):
            finding.risk_score = float(label)

        trainer = ModelTrainer()
        trainer.generate_training_data(findings, output)

        # Stats
        high_count = sum(labels)
        low_count = len(labels) - high_count

        console.print(f"[green]Generated {len(findings)} samples[/green]")
        console.print(f"  High risk: {high_count} ({high_count/len(labels)*100:.1f}%)")
        console.print(f"  Low risk: {low_count} ({low_count/len(labels)*100:.1f}%)")
        console.print(f"\n[green]Saved to: {output}[/green]")

    except Exception as e:
        console.print(f"[red]Generation failed: {e}[/red]")
        raise typer.Exit(1)


@ml_app.command("info")
def model_info(
    model_path: Optional[Path] = typer.Option(
        None, "--model", "-m", help="Path to model file"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file for model info"
    ),
) -> None:
    """Display information about a trained model.

    Examples:
        secureagent ml info
        secureagent ml info --model models/custom.pkl
        secureagent ml info --output model_info.json
    """
    from secureagent.ml.trainer import ModelTrainer

    console.print("\n[bold blue]Model Information[/bold blue]\n")

    trainer = ModelTrainer()

    try:
        info = trainer.export_model_info(output_path=output)

        # Display info
        console.print(f"[bold]Model Name:[/bold] {info['model_name']}")
        console.print(f"[bold]Model Path:[/bold] {info['model_path']}")
        console.print(f"[bold]Model Exists:[/bold] {'Yes' if info['model_exists'] else 'No'}")

        if info.get("feature_extractors"):
            console.print(f"\n[bold]Feature Extractors:[/bold]")
            for extractor in info["feature_extractors"]:
                console.print(f"  - {extractor}")

        if info.get("feature_names"):
            console.print(f"\n[bold]Features ({len(info['feature_names'])}):[/bold]")
            for name in info["feature_names"][:15]:
                console.print(f"  - {name}")
            if len(info["feature_names"]) > 15:
                console.print(f"  ... and {len(info['feature_names']) - 15} more")

        if info.get("feature_importance"):
            console.print(f"\n[bold]Top Feature Importance:[/bold]")
            importance_sorted = sorted(
                info["feature_importance"].items(),
                key=lambda x: x[1],
                reverse=True,
            )[:10]
            for feature, importance in importance_sorted:
                bar = "█" * int(importance * 30)
                console.print(f"  {feature:30s} {bar} {importance:.4f}")

        if output:
            console.print(f"\n[green]Info saved to: {output}[/green]")

    except Exception as e:
        console.print(f"[red]Failed to get model info: {e}[/red]")
        raise typer.Exit(1)


@ml_app.command("tune")
def tune_hyperparameters(
    samples: int = typer.Option(
        1000, "--samples", "-n", help="Number of synthetic samples"
    ),
    folds: int = typer.Option(
        5, "--folds", "-k", help="Number of cross-validation folds"
    ),
) -> None:
    """Tune model hyperparameters using grid search.

    Examples:
        secureagent ml tune
        secureagent ml tune --samples 2000 --folds 10
    """
    from secureagent.ml.trainer import ModelTrainer, SyntheticDataGenerator

    console.print("\n[bold blue]Hyperparameter Tuning[/bold blue]\n")
    console.print("[dim]This may take a while...[/dim]\n")

    try:
        generator = SyntheticDataGenerator()
        findings, labels = generator.generate(count=samples)

        for finding, label in zip(findings, labels):
            finding.risk_score = float(label)

        trainer = ModelTrainer()
        results = trainer.tune_hyperparameters(findings, cv_folds=folds)

        # Display results
        console.print("\n[bold]Best Parameters:[/bold]")
        for param, value in results["best_params"].items():
            console.print(f"  {param}: {value}")

        console.print(f"\n[bold]Best Score:[/bold] {results['best_score']:.4f}")

    except Exception as e:
        console.print(f"[red]Tuning failed: {e}[/red]")
        raise typer.Exit(1)
