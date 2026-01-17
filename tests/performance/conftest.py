"""Pytest configuration for performance tests."""

import pytest


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers",
        "performance: mark test as a performance test (may be slow)",
    )
    config.addinivalue_line(
        "markers",
        "slow: mark test as slow running",
    )


@pytest.fixture(scope="session")
def benchmark_results():
    """Collect benchmark results across tests."""
    results = {}
    yield results

    # Print summary at end of session
    if results:
        print("\n" + "=" * 60)
        print("PERFORMANCE BENCHMARK SUMMARY")
        print("=" * 60)
        for name, data in sorted(results.items()):
            print(f"{name}:")
            for key, value in data.items():
                if isinstance(value, float):
                    print(f"  {key}: {value:.4f}")
                else:
                    print(f"  {key}: {value}")
        print("=" * 60)


@pytest.fixture
def record_benchmark(benchmark_results):
    """Record a benchmark result."""
    def _record(name: str, **metrics):
        benchmark_results[name] = metrics
    return _record


@pytest.fixture
def performance_threshold():
    """Configurable performance thresholds."""
    return {
        "scan_per_file_ms": 100,  # Max ms per file scanned
        "findings_per_second": 500,  # Min findings created per second
        "feature_extraction_ms": 1,  # Max ms per feature extraction
        "model_inference_ms": 2,  # Max ms per model inference
        "cli_startup_ms": 2000,  # Max CLI startup time
        "report_generation_ms": 1000,  # Max report generation time
    }
