"""Backward compatibility wrappers for mcpscan and cybermonitor."""

import sys
from typing import List

from rich.console import Console

console = Console()

# Typer app for compat commands
import typer

compat_app = typer.Typer(hidden=True)


def mcpscan_main() -> None:
    """Entry point for mcpscan command (backward compatibility).

    This provides backward compatibility for users migrating from
    the standalone mcpscan tool.
    """
    console.print(
        "\n[yellow]Note:[/yellow] [bold]mcpscan[/bold] has been merged into [bold]secureagent[/bold].\n"
        "This command is provided for backward compatibility.\n"
    )
    console.print("Consider migrating to:")
    console.print("  [cyan]secureagent mcp scan <path>[/cyan]")
    console.print("  [cyan]secureagent mcp validate <path>[/cyan]")
    console.print("  [cyan]secureagent mcp fix <path>[/cyan]")
    console.print("  [cyan]secureagent mcp rules[/cyan]")
    console.print()

    # Map old arguments to new commands
    args = sys.argv[1:]

    if not args:
        # No args - show help
        console.print("Usage: mcpscan <command> [options]")
        console.print("\nCommands:")
        console.print("  scan      Scan MCP configurations")
        console.print("  validate  Validate MCP config schema")
        console.print("  fix       Generate fixes for issues")
        console.print("  rules     List security rules")
        return

    command = args[0]
    remaining_args = args[1:]

    # Import and run the appropriate command
    from secureagent.cli.app import app

    if command == "scan":
        # mcpscan scan <path> -> secureagent mcp scan <path>
        new_args = ["mcp", "scan"] + remaining_args
    elif command == "validate":
        new_args = ["mcp", "validate"] + remaining_args
    elif command == "fix":
        new_args = ["mcp", "fix"] + remaining_args
    elif command == "rules":
        new_args = ["mcp", "rules"] + remaining_args
    elif command == "risk":
        # mcpscan risk <path> -> secureagent analyze risk <path>
        new_args = ["analyze", "risk"] + remaining_args
    elif command == "graph":
        # mcpscan graph <path> -> secureagent analyze data-flow <path> --visualize
        new_args = ["analyze", "data-flow"] + remaining_args + ["--visualize"]
    else:
        console.print(f"[red]Unknown command: {command}[/red]")
        console.print("Run 'mcpscan' without arguments for help")
        return

    # Execute the new command
    sys.argv = ["secureagent"] + new_args

    try:
        app()
    except SystemExit:
        pass


def cybermonitor_main() -> None:
    """Entry point for cybermonitor command (backward compatibility).

    This provides backward compatibility for users migrating from
    the standalone cybermonitor tool.
    """
    console.print(
        "\n[yellow]Note:[/yellow] [bold]cybermonitor[/bold] has been merged into [bold]secureagent[/bold].\n"
        "This command is provided for backward compatibility.\n"
    )
    console.print("Consider migrating to:")
    console.print("  [cyan]secureagent cloud scan --provider aws[/cyan]")
    console.print("  [cyan]secureagent cloud scan --provider azure[/cyan]")
    console.print("  [cyan]secureagent cloud terraform <path>[/cyan]")
    console.print()

    # Map old arguments to new commands
    args = sys.argv[1:]

    if not args:
        console.print("Usage: cybermonitor scan <provider> [options]")
        console.print("\nProviders: aws, azure, terraform, all")
        return

    command = args[0]
    remaining_args = args[1:]

    from secureagent.cli.app import app

    if command == "scan":
        if remaining_args:
            provider = remaining_args[0]
            provider_args = remaining_args[1:]

            if provider == "terraform":
                # cybermonitor scan terraform --path <path> -> secureagent cloud terraform <path>
                new_args = ["cloud", "terraform"] + _extract_path_arg(provider_args)
            elif provider in ["aws", "azure", "all"]:
                # cybermonitor scan aws -> secureagent cloud scan --provider aws
                new_args = ["cloud", "scan", "--provider", provider] + provider_args
            else:
                console.print(f"[red]Unknown provider: {provider}[/red]")
                return
        else:
            new_args = ["cloud", "scan"]
    else:
        console.print(f"[red]Unknown command: {command}[/red]")
        return

    sys.argv = ["secureagent"] + new_args

    try:
        app()
    except SystemExit:
        pass


def _extract_path_arg(args: List[str]) -> List[str]:
    """Extract --path argument from args list."""
    result = []
    i = 0
    while i < len(args):
        if args[i] == "--path" and i + 1 < len(args):
            result.append(args[i + 1])
            i += 2
        else:
            result.append(args[i])
            i += 1
    return result if result else ["."]


# Legacy function aliases for programmatic usage
def scan_mcp_config(config_path: str, **kwargs):
    """Legacy function to scan MCP configuration.

    Deprecated: Use secureagent.scanners.mcp.MCPScanner instead.
    """
    import warnings

    warnings.warn(
        "scan_mcp_config is deprecated. Use secureagent.scanners.mcp.MCPScanner instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    from ..scanners.mcp import MCPScanner

    scanner = MCPScanner()
    return scanner.scan_file(config_path)


def scan_aws(**kwargs):
    """Legacy function to scan AWS resources.

    Deprecated: Use secureagent.scanners.aws.AWSScanner instead.
    """
    import warnings

    warnings.warn(
        "scan_aws is deprecated. Use secureagent.scanners.aws.AWSScanner instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    from ..scanners.aws import AWSScanner

    scanner = AWSScanner()
    return scanner.scan()


def scan_terraform(path: str, **kwargs):
    """Legacy function to scan Terraform files.

    Deprecated: Use secureagent.scanners.terraform.TerraformScanner instead.
    """
    import warnings

    warnings.warn(
        "scan_terraform is deprecated. Use secureagent.scanners.terraform.TerraformScanner instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    from ..scanners.terraform import TerraformScanner

    scanner = TerraformScanner()
    return scanner.scan_directory(path)


# Version compatibility
__mcpscan_version__ = "2.0.0"  # Last mcpscan version
__cybermonitor_version__ = "1.5.0"  # Last cybermonitor version


def get_legacy_version(tool: str) -> str:
    """Get version string for legacy tools."""
    if tool == "mcpscan":
        return __mcpscan_version__
    elif tool == "cybermonitor":
        return __cybermonitor_version__
    else:
        raise ValueError(f"Unknown tool: {tool}")
