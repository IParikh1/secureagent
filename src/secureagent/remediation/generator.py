"""Rule-based remediation generator for SecureAgent.

Generates context-aware fixes for security findings based on rule definitions
and configuration patterns.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
from uuid import uuid4

from secureagent.core.models.finding import Finding, FindingDomain
from secureagent.core.models.severity import Severity


class FixComplexity(str, Enum):
    """Complexity level of a fix."""

    TRIVIAL = "trivial"      # Simple replacement
    SIMPLE = "simple"        # Single change with validation
    MODERATE = "moderate"    # Multiple related changes
    COMPLEX = "complex"      # Requires manual review


class FixType(str, Enum):
    """Type of fix being applied."""

    REPLACE = "replace"           # Replace text
    INSERT = "insert"             # Insert new content
    DELETE = "delete"             # Remove content
    RESTRUCTURE = "restructure"   # Reorganize structure
    MANUAL = "manual"             # Requires manual intervention


@dataclass
class RemediationOption:
    """A single remediation option for a finding."""

    id: str = field(default_factory=lambda: str(uuid4())[:8])
    title: str = ""
    description: str = ""
    fix_type: FixType = FixType.REPLACE
    complexity: FixComplexity = FixComplexity.SIMPLE

    # The actual fix content
    original: str = ""           # What to replace
    replacement: str = ""        # What to replace with

    # For structured fixes (JSON/YAML)
    json_path: Optional[str] = None      # JSONPath to the value
    new_value: Optional[Any] = None      # New value to set

    # Impact assessment
    security_impact: str = ""    # How this improves security
    usability_impact: str = ""   # Any usability tradeoffs
    breaking_changes: List[str] = field(default_factory=list)

    # Validation
    validation_regex: Optional[str] = None  # Regex to validate the fix

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "fix_type": self.fix_type.value,
            "complexity": self.complexity.value,
            "original": self.original,
            "replacement": self.replacement,
            "security_impact": self.security_impact,
            "usability_impact": self.usability_impact,
            "breaking_changes": self.breaking_changes,
        }


@dataclass
class GeneratedFix:
    """A complete fix package for a finding."""

    id: str = field(default_factory=lambda: str(uuid4()))
    finding_id: str = ""
    rule_id: str = ""
    file_path: str = ""
    line_number: Optional[int] = None

    # Fix options (usually 1-3)
    options: List[RemediationOption] = field(default_factory=list)
    recommended_option: int = 0  # Index of recommended option

    # Metadata
    generated_at: str = ""
    confidence: float = 1.0      # How confident we are in the fix
    requires_review: bool = False

    @property
    def primary_fix(self) -> Optional[RemediationOption]:
        """Get the recommended fix option."""
        if self.options and 0 <= self.recommended_option < len(self.options):
            return self.options[self.recommended_option]
        return self.options[0] if self.options else None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "options": [opt.to_dict() for opt in self.options],
            "recommended_option": self.recommended_option,
            "confidence": self.confidence,
            "requires_review": self.requires_review,
        }


class RemediationGenerator:
    """Generates remediation fixes for security findings.

    This generator provides rule-based fix generation for common
    security issues found by SecureAgent scanners.
    """

    def __init__(self):
        """Initialize the remediation generator."""
        self._fix_handlers: Dict[str, Callable] = {
            # MCP rules
            "MCP-001": self._fix_no_auth,
            "MCP-002": self._fix_hardcoded_credentials,
            "MCP-003": self._fix_command_injection,
            "MCP-004": self._fix_ssrf,
            "MCP-005": self._fix_path_traversal,
            "MCP-006": self._fix_sensitive_env,
            "MCP-007": self._fix_dangerous_tools,

            # AWS rules
            "AWS-S3-001": self._fix_s3_public_access,
            "AWS-S3-002": self._fix_s3_encryption,
            "AWS-IAM-001": self._fix_iam_wildcard,

            # Terraform rules
            "TF-001": self._fix_tf_encryption,
            "TF-002": self._fix_tf_public_access,

            # LangChain rules
            "LC-001": self._fix_langchain_arbitrary_code,
            "LC-002": self._fix_langchain_prompt_injection,
        }

    def generate_fixes(
        self,
        findings: List[Finding],
        include_manual: bool = True,
    ) -> List[GeneratedFix]:
        """Generate fixes for a list of findings.

        Args:
            findings: List of security findings
            include_manual: Whether to include manual fix suggestions

        Returns:
            List of generated fixes
        """
        fixes = []

        for finding in findings:
            fix = self.generate_fix(finding, include_manual)
            if fix:
                fixes.append(fix)

        return fixes

    def generate_fix(
        self,
        finding: Finding,
        include_manual: bool = True,
    ) -> Optional[GeneratedFix]:
        """Generate a fix for a single finding.

        Args:
            finding: Security finding to fix
            include_manual: Whether to include manual fix if no auto-fix available

        Returns:
            Generated fix or None if no fix available
        """
        from datetime import datetime

        handler = self._fix_handlers.get(finding.rule_id)

        if handler:
            fix = handler(finding)
            if fix:
                fix.generated_at = datetime.utcnow().isoformat()
                return fix

        # Generate manual fix suggestion if no handler
        if include_manual:
            return self._generate_manual_fix(finding)

        return None

    def _generate_manual_fix(self, finding: Finding) -> GeneratedFix:
        """Generate a manual fix suggestion."""
        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=finding.location.file_path or "",
            line_number=finding.location.line_number,
            options=[
                RemediationOption(
                    title="Manual Review Required",
                    description=finding.remediation,
                    fix_type=FixType.MANUAL,
                    complexity=FixComplexity.COMPLEX,
                    security_impact="Addresses the identified security issue",
                    usability_impact="May require configuration changes",
                )
            ],
            confidence=0.5,
            requires_review=True,
        )

    # =========================================================================
    # MCP Fix Handlers
    # =========================================================================

    def _fix_no_auth(self, finding: Finding) -> Optional[GeneratedFix]:
        """Fix MCP-001: No Authentication Configured."""
        file_path = finding.location.file_path
        if not file_path:
            return None

        # Extract server name from description
        server_match = re.search(r"server '([^']+)'", finding.description)
        server_name = server_match.group(1) if server_match else "server"

        options = [
            RemediationOption(
                title="Add API Key Authentication",
                description=f"Add an API key environment variable for authentication",
                fix_type=FixType.INSERT,
                complexity=FixComplexity.SIMPLE,
                original="",
                replacement=f'"env": {{\n        "API_KEY": "${{API_KEY}}"\n      }}',
                security_impact="Adds authentication to prevent unauthorized access",
                usability_impact="Requires setting API_KEY environment variable",
                breaking_changes=["Server will require API_KEY to be set"],
            ),
            RemediationOption(
                title="Add Bearer Token Authentication",
                description="Add bearer token authentication via environment variable",
                fix_type=FixType.INSERT,
                complexity=FixComplexity.SIMPLE,
                original="",
                replacement=f'"env": {{\n        "AUTHORIZATION": "Bearer ${{AUTH_TOKEN}}"\n      }}',
                security_impact="Adds bearer token authentication",
                usability_impact="Requires setting AUTH_TOKEN environment variable",
                breaking_changes=["Server will require AUTH_TOKEN to be set"],
            ),
        ]

        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=file_path,
            line_number=finding.location.line_number,
            options=options,
            recommended_option=0,
            confidence=0.8,
            requires_review=True,
        )

    def _fix_hardcoded_credentials(self, finding: Finding) -> Optional[GeneratedFix]:
        """Fix MCP-002: Hardcoded Credentials."""
        file_path = finding.location.file_path
        snippet = finding.location.snippet or ""

        if not file_path:
            return None

        # Try to identify the credential type and suggest env var name
        env_var_name = "SECRET_KEY"

        if "openai" in snippet.lower() or "sk-" in snippet:
            env_var_name = "OPENAI_API_KEY"
        elif "anthropic" in snippet.lower() or "sk-ant-" in snippet:
            env_var_name = "ANTHROPIC_API_KEY"
        elif "github" in snippet.lower() or "ghp_" in snippet or "gho_" in snippet:
            env_var_name = "GITHUB_TOKEN"
        elif "slack" in snippet.lower() or "xox" in snippet:
            env_var_name = "SLACK_TOKEN"
        elif "aws" in snippet.lower() or "AKIA" in snippet:
            env_var_name = "AWS_ACCESS_KEY_ID"
        elif "password" in snippet.lower():
            env_var_name = "PASSWORD"
        elif "token" in snippet.lower():
            env_var_name = "AUTH_TOKEN"
        elif "api" in snippet.lower() and "key" in snippet.lower():
            env_var_name = "API_KEY"

        # Extract the actual credential value for replacement pattern
        cred_patterns = [
            r'sk-[a-zA-Z0-9\-_]{20,}',
            r'sk-proj-[a-zA-Z0-9\-_]{20,}',
            r'sk-ant-[a-zA-Z0-9\-_]{20,}',
            r'ghp_[a-zA-Z0-9]{36}',
            r'gho_[a-zA-Z0-9]{36}',
            r'xox[baprs]-[0-9\-a-zA-Z]+',
            r'AKIA[0-9A-Z]{16}',
            r'"[^"]{20,}"',  # Generic long string in quotes
        ]

        original = ""
        for pattern in cred_patterns:
            match = re.search(pattern, snippet)
            if match:
                original = match.group(0)
                break

        options = [
            RemediationOption(
                title="Use Environment Variable",
                description=f"Replace hardcoded credential with ${{{env_var_name}}} reference",
                fix_type=FixType.REPLACE,
                complexity=FixComplexity.TRIVIAL,
                original=original,
                replacement=f'"${{{env_var_name}}}"',
                security_impact="Removes hardcoded credential from configuration",
                usability_impact=f"Requires setting {env_var_name} environment variable",
                breaking_changes=[f"Must set {env_var_name} before running"],
            ),
            RemediationOption(
                title="Use Secrets Manager Reference",
                description="Reference credential from a secrets manager",
                fix_type=FixType.REPLACE,
                complexity=FixComplexity.MODERATE,
                original=original,
                replacement=f'"${{secrets:{env_var_name.lower()}}}"',
                security_impact="Centralizes credential management",
                usability_impact="Requires secrets manager integration",
                breaking_changes=["Requires secrets manager setup"],
            ),
        ]

        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=file_path,
            line_number=finding.location.line_number,
            options=options,
            recommended_option=0,
            confidence=0.9,
            requires_review=False,
        )

    def _fix_command_injection(self, finding: Finding) -> Optional[GeneratedFix]:
        """Fix MCP-003: Command Injection Risk."""
        file_path = finding.location.file_path
        snippet = finding.location.snippet or ""

        if not file_path:
            return None

        # Identify dangerous patterns
        dangerous_chars = ['|', ';', '&&', '||', '`', '$(']
        found_char = None
        for char in dangerous_chars:
            if char in snippet:
                found_char = char
                break

        options = [
            RemediationOption(
                title="Remove Shell Metacharacters",
                description="Remove potentially dangerous shell metacharacters from command",
                fix_type=FixType.MANUAL,
                complexity=FixComplexity.MODERATE,
                security_impact="Prevents command injection attacks",
                usability_impact="May require restructuring command execution",
                breaking_changes=["Command behavior may change"],
            ),
            RemediationOption(
                title="Use Parameterized Arguments",
                description="Split command into separate args array elements",
                fix_type=FixType.RESTRUCTURE,
                complexity=FixComplexity.MODERATE,
                original=snippet,
                replacement="Use 'args' array with individual parameters instead of shell string",
                security_impact="Prevents shell interpretation of special characters",
                usability_impact="Requires command restructuring",
            ),
        ]

        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=file_path,
            line_number=finding.location.line_number,
            options=options,
            recommended_option=0,
            confidence=0.7,
            requires_review=True,
        )

    def _fix_ssrf(self, finding: Finding) -> Optional[GeneratedFix]:
        """Fix MCP-004: SSRF Risk."""
        file_path = finding.location.file_path
        snippet = finding.location.snippet or ""

        if not file_path:
            return None

        options = [
            RemediationOption(
                title="Use External URL",
                description="Replace internal URL with external/public endpoint",
                fix_type=FixType.REPLACE,
                complexity=FixComplexity.MODERATE,
                original=snippet[:100] if len(snippet) > 100 else snippet,
                replacement="https://api.example.com/endpoint",
                security_impact="Prevents access to internal network resources",
                usability_impact="Must configure external endpoint",
                breaking_changes=["Internal endpoints will no longer be accessible"],
            ),
            RemediationOption(
                title="Add URL Allowlist",
                description="Implement URL validation against an allowlist",
                fix_type=FixType.MANUAL,
                complexity=FixComplexity.COMPLEX,
                security_impact="Restricts accessible URLs to approved list",
                usability_impact="Requires maintaining allowlist",
            ),
        ]

        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=file_path,
            line_number=finding.location.line_number,
            options=options,
            recommended_option=0,
            confidence=0.6,
            requires_review=True,
        )

    def _fix_path_traversal(self, finding: Finding) -> Optional[GeneratedFix]:
        """Fix MCP-005: Path Traversal."""
        file_path = finding.location.file_path
        snippet = finding.location.snippet or ""

        if not file_path:
            return None

        # Detect the type of path issue
        if "../" in snippet or "..\\" in snippet:
            issue_type = "relative path traversal"
            fix_suggestion = "Use absolute paths within allowed directories"
        else:
            issue_type = "absolute path reference"
            fix_suggestion = "Use relative paths from a safe base directory"

        options = [
            RemediationOption(
                title="Use Safe Base Directory",
                description=f"Fix {issue_type} by using paths relative to a safe base",
                fix_type=FixType.REPLACE,
                complexity=FixComplexity.SIMPLE,
                original=snippet[:100] if len(snippet) > 100 else snippet,
                replacement="./data/",
                security_impact="Prevents access to files outside intended directory",
                usability_impact="Files must be within the allowed directory",
                breaking_changes=["May need to relocate files"],
            ),
            RemediationOption(
                title="Use Environment Variable for Path",
                description="Reference path from environment variable",
                fix_type=FixType.REPLACE,
                complexity=FixComplexity.SIMPLE,
                original=snippet[:100] if len(snippet) > 100 else snippet,
                replacement="${DATA_DIR}",
                security_impact="Allows controlled path configuration",
                usability_impact="Requires setting DATA_DIR environment variable",
            ),
        ]

        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=file_path,
            line_number=finding.location.line_number,
            options=options,
            recommended_option=0,
            confidence=0.8,
            requires_review=True,
        )

    def _fix_sensitive_env(self, finding: Finding) -> Optional[GeneratedFix]:
        """Fix MCP-006: Sensitive Data Exposure."""
        file_path = finding.location.file_path

        if not file_path:
            return None

        # Extract env var name from description
        env_match = re.search(r"variable '([^']+)'", finding.description)
        env_name = env_match.group(1) if env_match else "SENSITIVE_VAR"

        options = [
            RemediationOption(
                title="Use Environment Variable Reference",
                description=f"Replace hardcoded value with ${{{env_name}}} reference",
                fix_type=FixType.REPLACE,
                complexity=FixComplexity.TRIVIAL,
                json_path=f"$.mcpServers.*.env.{env_name}",
                new_value=f"${{{env_name}}}",
                security_impact="Removes sensitive data from configuration file",
                usability_impact=f"Requires setting {env_name} in environment",
                breaking_changes=[f"Must set {env_name} before running"],
            ),
        ]

        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=file_path,
            line_number=finding.location.line_number,
            options=options,
            recommended_option=0,
            confidence=0.95,
            requires_review=False,
        )

    def _fix_dangerous_tools(self, finding: Finding) -> Optional[GeneratedFix]:
        """Fix MCP-007: Dangerous Tool Configuration."""
        file_path = finding.location.file_path

        if not file_path:
            return None

        options = [
            RemediationOption(
                title="Add Input Validation",
                description="Implement input validation for dangerous tool",
                fix_type=FixType.MANUAL,
                complexity=FixComplexity.COMPLEX,
                security_impact="Validates inputs before execution",
                usability_impact="May reject some valid inputs",
            ),
            RemediationOption(
                title="Restrict Tool Permissions",
                description="Add permission restrictions to limit tool capabilities",
                fix_type=FixType.INSERT,
                complexity=FixComplexity.MODERATE,
                replacement='"permissions": {\n        "allowedOperations": ["read"],\n        "sandbox": true\n      }',
                security_impact="Limits what the tool can do",
                usability_impact="Some operations may be blocked",
                breaking_changes=["Tool capabilities will be restricted"],
            ),
            RemediationOption(
                title="Remove Dangerous Tool",
                description="Remove the tool with dangerous capabilities",
                fix_type=FixType.DELETE,
                complexity=FixComplexity.SIMPLE,
                security_impact="Eliminates the security risk entirely",
                usability_impact="Functionality will be unavailable",
                breaking_changes=["Tool will no longer be available"],
            ),
        ]

        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=file_path,
            line_number=finding.location.line_number,
            options=options,
            recommended_option=0,
            confidence=0.6,
            requires_review=True,
        )

    # =========================================================================
    # AWS Fix Handlers
    # =========================================================================

    def _fix_s3_public_access(self, finding: Finding) -> Optional[GeneratedFix]:
        """Fix AWS-S3-001: Public S3 Bucket."""
        options = [
            RemediationOption(
                title="Block Public Access",
                description="Enable S3 Block Public Access settings",
                fix_type=FixType.MANUAL,
                complexity=FixComplexity.SIMPLE,
                security_impact="Prevents public access to bucket",
                usability_impact="Public access will be blocked",
                breaking_changes=["Any public URLs will stop working"],
            ),
        ]

        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=finding.location.resource_id or "",
            options=options,
            confidence=0.9,
            requires_review=True,
        )

    def _fix_s3_encryption(self, finding: Finding) -> Optional[GeneratedFix]:
        """Fix AWS-S3-002: S3 Bucket Without Encryption."""
        options = [
            RemediationOption(
                title="Enable SSE-S3 Encryption",
                description="Enable server-side encryption with S3-managed keys",
                fix_type=FixType.MANUAL,
                complexity=FixComplexity.SIMPLE,
                security_impact="Encrypts data at rest",
                usability_impact="Minimal - automatic encryption",
            ),
            RemediationOption(
                title="Enable SSE-KMS Encryption",
                description="Enable server-side encryption with KMS-managed keys",
                fix_type=FixType.MANUAL,
                complexity=FixComplexity.MODERATE,
                security_impact="Encrypts data with customer-managed keys",
                usability_impact="Requires KMS key management",
            ),
        ]

        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=finding.location.resource_id or "",
            options=options,
            confidence=0.9,
            requires_review=True,
        )

    def _fix_iam_wildcard(self, finding: Finding) -> Optional[GeneratedFix]:
        """Fix AWS-IAM-001: IAM Wildcard Permissions."""
        options = [
            RemediationOption(
                title="Use Specific Resources",
                description="Replace * with specific resource ARNs",
                fix_type=FixType.REPLACE,
                complexity=FixComplexity.MODERATE,
                original='"Resource": "*"',
                replacement='"Resource": "arn:aws:s3:::specific-bucket/*"',
                security_impact="Limits access to specific resources",
                usability_impact="Must specify all required resources",
                breaking_changes=["Access to unlisted resources will be denied"],
            ),
            RemediationOption(
                title="Use Specific Actions",
                description="Replace Action: * with specific actions needed",
                fix_type=FixType.REPLACE,
                complexity=FixComplexity.MODERATE,
                original='"Action": "*"',
                replacement='"Action": ["s3:GetObject", "s3:PutObject"]',
                security_impact="Limits allowed actions",
                usability_impact="Must specify all required actions",
            ),
        ]

        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=finding.location.file_path or finding.location.resource_id or "",
            options=options,
            confidence=0.7,
            requires_review=True,
        )

    # =========================================================================
    # Terraform Fix Handlers
    # =========================================================================

    def _fix_tf_encryption(self, finding: Finding) -> Optional[GeneratedFix]:
        """Fix TF-001: Missing Encryption."""
        options = [
            RemediationOption(
                title="Enable Encryption",
                description="Add encryption configuration to resource",
                fix_type=FixType.INSERT,
                complexity=FixComplexity.SIMPLE,
                replacement='  encryption_configuration {\n    rule {\n      apply_server_side_encryption_by_default {\n        sse_algorithm = "AES256"\n      }\n    }\n  }',
                security_impact="Enables encryption at rest",
                usability_impact="None - transparent encryption",
            ),
        ]

        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=finding.location.file_path or "",
            line_number=finding.location.line_number,
            options=options,
            confidence=0.9,
            requires_review=False,
        )

    def _fix_tf_public_access(self, finding: Finding) -> Optional[GeneratedFix]:
        """Fix TF-002: Public Access Enabled."""
        options = [
            RemediationOption(
                title="Disable Public Access",
                description="Set public access to false",
                fix_type=FixType.REPLACE,
                complexity=FixComplexity.TRIVIAL,
                original='public = true',
                replacement='public = false',
                security_impact="Disables public access",
                usability_impact="Resource will only be privately accessible",
                breaking_changes=["Public access will be removed"],
            ),
        ]

        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=finding.location.file_path or "",
            line_number=finding.location.line_number,
            options=options,
            confidence=0.95,
            requires_review=False,
        )

    # =========================================================================
    # LangChain Fix Handlers
    # =========================================================================

    def _fix_langchain_arbitrary_code(self, finding: Finding) -> Optional[GeneratedFix]:
        """Fix LC-001: Arbitrary Code Execution."""
        options = [
            RemediationOption(
                title="Use Sandboxed Execution",
                description="Execute code in a sandboxed environment",
                fix_type=FixType.MANUAL,
                complexity=FixComplexity.COMPLEX,
                security_impact="Isolates code execution",
                usability_impact="Some operations may be restricted",
            ),
            RemediationOption(
                title="Disable Code Execution",
                description="Remove or disable code execution capabilities",
                fix_type=FixType.DELETE,
                complexity=FixComplexity.SIMPLE,
                security_impact="Eliminates code execution risk",
                usability_impact="Code execution will not be available",
                breaking_changes=["Agent cannot execute code"],
            ),
        ]

        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=finding.location.file_path or "",
            line_number=finding.location.line_number,
            options=options,
            confidence=0.6,
            requires_review=True,
        )

    def _fix_langchain_prompt_injection(self, finding: Finding) -> Optional[GeneratedFix]:
        """Fix LC-002: Prompt Injection Vulnerability."""
        options = [
            RemediationOption(
                title="Add Input Sanitization",
                description="Sanitize user inputs before including in prompts",
                fix_type=FixType.MANUAL,
                complexity=FixComplexity.MODERATE,
                security_impact="Prevents prompt injection attacks",
                usability_impact="Some special characters may be escaped",
            ),
            RemediationOption(
                title="Use Structured Prompts",
                description="Use structured prompt templates with clear boundaries",
                fix_type=FixType.MANUAL,
                complexity=FixComplexity.MODERATE,
                security_impact="Makes injection more difficult",
                usability_impact="Requires prompt restructuring",
            ),
        ]

        return GeneratedFix(
            finding_id=finding.id,
            rule_id=finding.rule_id,
            file_path=finding.location.file_path or "",
            line_number=finding.location.line_number,
            options=options,
            confidence=0.5,
            requires_review=True,
        )

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def get_supported_rules(self) -> List[str]:
        """Get list of rule IDs with automatic fix support."""
        return list(self._fix_handlers.keys())

    def has_automatic_fix(self, rule_id: str) -> bool:
        """Check if a rule has automatic fix support."""
        return rule_id in self._fix_handlers
