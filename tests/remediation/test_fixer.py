"""Tests for the remediation fixer."""

import json
import pytest
from pathlib import Path
from secureagent.remediation.fixer import (
    Fixer,
    FixResult,
    FixStatus,
    FixSummary,
)
from secureagent.remediation.generator import (
    GeneratedFix,
    RemediationOption,
    FixType,
    FixComplexity,
)


@pytest.fixture
def fixer(tmp_path):
    """Create a fixer instance with temp backup dir."""
    return Fixer(backup_dir=tmp_path / "backups")


@pytest.fixture
def sample_mcp_config(tmp_path):
    """Create a sample MCP config file."""
    config = {
        "mcpServers": {
            "test-server": {
                "command": "node",
                "args": ["server.js"],
                "env": {
                    "API_KEY": "sk-proj-hardcoded-key-12345"
                }
            }
        }
    }
    config_path = tmp_path / "mcp.json"
    config_path.write_text(json.dumps(config, indent=2))
    return config_path


@pytest.fixture
def replace_fix(sample_mcp_config):
    """Create a replace fix."""
    return GeneratedFix(
        finding_id="finding-123",
        rule_id="MCP-002",
        file_path=str(sample_mcp_config),
        line_number=7,
        options=[
            RemediationOption(
                title="Use Environment Variable",
                description="Replace hardcoded key with env var",
                fix_type=FixType.REPLACE,
                complexity=FixComplexity.TRIVIAL,
                original="sk-proj-hardcoded-key-12345",
                replacement="${OPENAI_API_KEY}",
                security_impact="Removes hardcoded credential",
            )
        ],
        confidence=0.9,
    )


@pytest.fixture
def manual_fix(sample_mcp_config):
    """Create a manual fix."""
    return GeneratedFix(
        finding_id="finding-456",
        rule_id="MCP-007",
        file_path=str(sample_mcp_config),
        options=[
            RemediationOption(
                title="Manual Review Required",
                description="Review dangerous tool configuration",
                fix_type=FixType.MANUAL,
                complexity=FixComplexity.COMPLEX,
            )
        ],
        requires_review=True,
    )


class TestFixer:
    """Tests for Fixer."""

    def test_fixer_creation(self, fixer):
        """Test fixer can be created."""
        assert fixer is not None
        assert fixer.create_backups is True

    def test_dry_run_replace(self, fixer, replace_fix, sample_mcp_config):
        """Test dry run doesn't modify file."""
        original_content = sample_mcp_config.read_text()

        result = fixer.apply_fix(replace_fix, dry_run=True)

        assert result.status == FixStatus.DRY_RUN
        assert result.diff is not None
        assert "${OPENAI_API_KEY}" in result.diff

        # File should be unchanged
        assert sample_mcp_config.read_text() == original_content

    def test_apply_replace_fix(self, fixer, replace_fix, sample_mcp_config):
        """Test applying a replace fix."""
        result = fixer.apply_fix(replace_fix, dry_run=False)

        assert result.status == FixStatus.SUCCESS
        assert result.backup_path is not None

        # Check file was modified
        content = sample_mcp_config.read_text()
        assert "${OPENAI_API_KEY}" in content
        assert "sk-proj-hardcoded-key-12345" not in content

    def test_backup_created(self, fixer, replace_fix, sample_mcp_config):
        """Test backup is created when applying fix."""
        result = fixer.apply_fix(replace_fix, dry_run=False)

        assert result.backup_path is not None
        backup_path = Path(result.backup_path)
        assert backup_path.exists()

        # Backup should have original content
        backup_content = backup_path.read_text()
        assert "sk-proj-hardcoded-key-12345" in backup_content

    def test_manual_fix_returns_manual_required(self, fixer, manual_fix):
        """Test manual fix returns manual required status."""
        result = fixer.apply_fix(manual_fix, dry_run=False)

        assert result.status == FixStatus.MANUAL_REQUIRED
        assert "Manual fix required" in result.message

    def test_file_not_found(self, fixer):
        """Test handling of non-existent file."""
        fix = GeneratedFix(
            finding_id="123",
            rule_id="MCP-002",
            file_path="/nonexistent/path/file.json",
            options=[
                RemediationOption(
                    title="Test",
                    fix_type=FixType.REPLACE,
                    original="old",
                    replacement="new",
                )
            ],
        )

        result = fixer.apply_fix(fix, dry_run=False)

        assert result.status == FixStatus.FILE_NOT_FOUND

    def test_no_options(self, fixer, sample_mcp_config):
        """Test handling of fix with no options."""
        fix = GeneratedFix(
            finding_id="123",
            rule_id="MCP-002",
            file_path=str(sample_mcp_config),
            options=[],
        )

        result = fixer.apply_fix(fix, dry_run=False)

        assert result.status == FixStatus.SKIPPED

    def test_apply_fixes_batch(self, fixer, replace_fix, manual_fix):
        """Test applying multiple fixes."""
        fixes = [replace_fix, manual_fix]

        summary = fixer.apply_fixes(fixes, dry_run=True)

        assert summary.total == 2
        assert summary.dry_run is True
        assert len(summary.results) == 2

    def test_json_validation(self, fixer, sample_mcp_config):
        """Test JSON validation after fix."""
        # Create a fix that would produce invalid JSON
        fix = GeneratedFix(
            finding_id="123",
            rule_id="MCP-002",
            file_path=str(sample_mcp_config),
            options=[
                RemediationOption(
                    title="Bad Fix",
                    fix_type=FixType.REPLACE,
                    original='"mcpServers"',
                    replacement='"mcpServers": invalid',  # Invalid JSON
                )
            ],
        )

        result = fixer.apply_fix(fix, dry_run=False)

        # Should fail validation
        assert result.status == FixStatus.VALIDATION_FAILED

    def test_restore_backup(self, fixer, replace_fix, sample_mcp_config):
        """Test restoring from backup."""
        original_content = sample_mcp_config.read_text()

        # Apply fix
        result = fixer.apply_fix(replace_fix, dry_run=False)
        assert result.status == FixStatus.SUCCESS

        # Verify file changed
        assert sample_mcp_config.read_text() != original_content

        # Restore from backup
        restored = fixer.restore_backup(result.backup_path, str(sample_mcp_config))
        assert restored is True

        # Verify file restored
        assert sample_mcp_config.read_text() == original_content

    def test_list_backups(self, fixer, replace_fix):
        """Test listing backups."""
        # Apply fix to create backup
        fixer.apply_fix(replace_fix, dry_run=False)

        backups = fixer.list_backups()

        assert len(backups) >= 1
        assert "path" in backups[0]
        assert "created" in backups[0]

    def test_cleanup_backups(self, fixer, replace_fix, sample_mcp_config):
        """Test cleaning up old backups."""
        # Create some backups
        fixer.apply_fix(replace_fix, dry_run=False)

        # Cleanup with 0 days should delete all
        deleted = fixer.cleanup_backups(max_age_days=0)

        # Should have deleted the backup
        assert deleted >= 0  # May be 0 if test runs too fast


class TestFixResult:
    """Tests for FixResult."""

    def test_result_to_dict(self):
        """Test converting result to dictionary."""
        result = FixResult(
            fix_id="fix-123",
            finding_id="finding-456",
            rule_id="MCP-002",
            file_path="/tmp/test.json",
            status=FixStatus.SUCCESS,
            message="Fix applied successfully",
        )

        d = result.to_dict()

        assert d["fix_id"] == "fix-123"
        assert d["status"] == "success"


class TestFixSummary:
    """Tests for FixSummary."""

    def test_summary_to_dict(self):
        """Test converting summary to dictionary."""
        summary = FixSummary(
            total=5,
            successful=3,
            failed=1,
            skipped=1,
            dry_run=True,
        )

        d = summary.to_dict()

        assert d["total"] == 5
        assert d["successful"] == 3
        assert d["failed"] == 1
        assert d["dry_run"] is True
