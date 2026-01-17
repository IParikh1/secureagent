"""Remediation module for SecureAgent.

This module provides rule-based fix generation and application
for security findings discovered by scanners.

Usage:
    from secureagent.remediation import RemediationGenerator, Fixer

    # Generate fixes for findings
    generator = RemediationGenerator()
    fixes = generator.generate_fixes(findings)

    # Apply fixes
    fixer = Fixer()
    results = fixer.apply_fixes(fixes, dry_run=True)
"""

from secureagent.remediation.generator import (
    RemediationGenerator,
    RemediationOption,
    GeneratedFix,
)
from secureagent.remediation.fixer import (
    Fixer,
    FixResult,
    FixStatus,
)

__all__ = [
    "RemediationGenerator",
    "RemediationOption",
    "GeneratedFix",
    "Fixer",
    "FixResult",
    "FixStatus",
]
