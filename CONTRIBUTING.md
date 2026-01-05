# Contributing to SecureAgent

Thank you for your interest in contributing to SecureAgent! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)

## Code of Conduct

By participating in this project, you agree to maintain a welcoming, inclusive, and harassment-free environment for everyone.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Set up the development environment
4. Create a branch for your changes
5. Make your changes
6. Submit a pull request

## Development Setup

### Prerequisites

- Python 3.9 or higher
- Git
- pip

### Installation

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/secureagent.git
cd secureagent

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pip install pre-commit
pre-commit install
```

### Verify Setup

```bash
# Run tests
pytest tests/ -v

# Run linting
ruff check src/

# Run the CLI
secureagent --version
```

## Making Changes

### Branch Naming

Use descriptive branch names:
- `feature/add-new-scanner` - New features
- `fix/mcp-credential-detection` - Bug fixes
- `docs/update-readme` - Documentation
- `refactor/scanner-registry` - Refactoring

### Commit Messages

Follow conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

Examples:
```
feat(scanner): add CrewAI scanner support

fix(mcp): handle empty config files gracefully

docs(readme): update installation instructions
```

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=src/secureagent --cov-report=html

# Run specific test file
pytest tests/scanners/test_mcp_scanner.py -v

# Run specific test
pytest tests/scanners/test_mcp_scanner.py::TestMCPScanner::test_scan_config -v
```

### Writing Tests

- Place tests in the `tests/` directory mirroring `src/` structure
- Use pytest fixtures for common test data
- Aim for high coverage of new code
- Include both positive and negative test cases

Example test:

```python
import pytest
from secureagent.scanners.mcp.scanner import MCPScanner

class TestMCPScanner:
    def test_scan_detects_hardcoded_credential(self, tmp_path):
        # Arrange
        config_file = tmp_path / "config.json"
        config_file.write_text('{"mcpServers": {"test": {"env": {"API_KEY": "sk-secret"}}}}')

        # Act
        scanner = MCPScanner()
        findings = scanner.scan(str(config_file))

        # Assert
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP-001"
```

## Submitting Changes

### Pull Request Process

1. Ensure all tests pass locally
2. Update documentation if needed
3. Add tests for new functionality
4. Create a pull request with a clear description
5. Link any related issues
6. Wait for CI checks to pass
7. Address review feedback

### PR Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Code follows style guidelines
- [ ] All CI checks pass
- [ ] PR description explains changes

## Code Style

### Python Style

We use:
- **Black** for formatting
- **isort** for import sorting
- **Ruff** for linting
- **MyPy** for type checking

```bash
# Format code
black src/ tests/

# Sort imports
isort src/ tests/

# Lint
ruff check src/ tests/

# Type check
mypy src/secureagent
```

### Style Guidelines

- Use type hints for function signatures
- Write docstrings for public functions/classes
- Keep functions focused and small
- Use meaningful variable names
- Follow PEP 8 guidelines

### Example Code Style

```python
from typing import List, Optional

from secureagent.core.models.finding import Finding


def scan_file(
    file_path: str,
    rules: Optional[List[str]] = None,
    verbose: bool = False,
) -> List[Finding]:
    """Scan a file for security issues.

    Args:
        file_path: Path to the file to scan.
        rules: Optional list of rule IDs to check.
        verbose: Enable verbose output.

    Returns:
        List of security findings.

    Raises:
        FileNotFoundError: If file doesn't exist.
    """
    findings: List[Finding] = []
    # Implementation...
    return findings
```

## Adding a New Scanner

1. Create a new directory under `src/secureagent/scanners/`
2. Implement the scanner class extending `BaseScanner`
3. Add security rules
4. Write comprehensive tests
5. Update documentation

```python
# src/secureagent/scanners/myframework/scanner.py
from secureagent.core.scanner.base import BaseScanner

class MyFrameworkScanner(BaseScanner):
    name = "myframework"
    description = "Scans MyFramework configurations"

    def scan(self, target: str) -> List[Finding]:
        # Implementation
        pass

    def discover_targets(self, path: str) -> List[str]:
        # Implementation
        pass
```

## Questions?

- Open a [GitHub Discussion](https://github.com/IParikh1/secureagent/discussions)
- Check existing [Issues](https://github.com/IParikh1/secureagent/issues)

Thank you for contributing!
