.PHONY: help install install-dev test lint format type-check clean build docker pre-commit

# Default target
help:
	@echo "SecureAgent Development Commands"
	@echo "================================"
	@echo ""
	@echo "Setup:"
	@echo "  install       Install package"
	@echo "  install-dev   Install with dev dependencies"
	@echo "  pre-commit    Install pre-commit hooks"
	@echo ""
	@echo "Development:"
	@echo "  test          Run tests"
	@echo "  test-cov      Run tests with coverage"
	@echo "  lint          Run linters"
	@echo "  format        Format code"
	@echo "  type-check    Run type checking"
	@echo ""
	@echo "Build:"
	@echo "  build         Build package"
	@echo "  docker        Build Docker image"
	@echo "  clean         Clean build artifacts"
	@echo ""
	@echo "CI:"
	@echo "  ci            Run all CI checks"

# Installation
install:
	pip install -e .

install-dev:
	pip install -e ".[dev,full]"
	pre-commit install

# Testing
test:
	PYTHONPATH=src pytest tests/ -v

test-cov:
	PYTHONPATH=src pytest tests/ -v --cov=src/secureagent --cov-report=html --cov-report=term-missing

test-fast:
	PYTHONPATH=src pytest tests/ -v -x --tb=short

# Linting & Formatting
lint:
	ruff check src/ tests/
	black --check src/ tests/
	isort --check-only src/ tests/

format:
	black src/ tests/
	isort src/ tests/
	ruff check --fix src/ tests/

type-check:
	mypy src/secureagent --ignore-missing-imports

# Building
build: clean
	python -m build
	twine check dist/*

docker:
	docker build -t secureagent:latest -f docker/Dockerfile .

docker-full:
	docker build -t secureagent:full -f docker/Dockerfile.full .

# Cleaning
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf src/*.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Pre-commit
pre-commit:
	pre-commit install
	pre-commit run --all-files

# CI - Run all checks
ci: lint type-check test

# Self-scan
scan:
	secureagent scan . --scanners mcp,langchain

# Documentation
docs-serve:
	@echo "Documentation is in docs/ directory"
	@echo "View on GitHub: https://github.com/IParikh1/secureagent/tree/main/docs"
