"""Fix applicator for SecureAgent remediation.

Applies generated fixes to files with support for dry-run mode,
backup creation, and validation.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from secureagent.remediation.generator import (
    GeneratedFix,
    RemediationOption,
    FixType,
    FixComplexity,
)


class FixStatus(str, Enum):
    """Status of a fix application."""

    SUCCESS = "success"           # Fix applied successfully
    FAILED = "failed"             # Fix application failed
    SKIPPED = "skipped"           # Fix was skipped
    DRY_RUN = "dry_run"           # Dry run - not actually applied
    VALIDATION_FAILED = "validation_failed"  # Fix validation failed
    MANUAL_REQUIRED = "manual_required"      # Requires manual intervention
    BACKUP_FAILED = "backup_failed"          # Could not create backup
    FILE_NOT_FOUND = "file_not_found"        # Target file not found


@dataclass
class FixResult:
    """Result of applying a fix."""

    fix_id: str
    finding_id: str
    rule_id: str
    file_path: str
    status: FixStatus
    option_used: int = 0         # Index of the option that was applied
    message: str = ""
    backup_path: Optional[str] = None
    diff: Optional[str] = None   # Unified diff of changes
    applied_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "fix_id": self.fix_id,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "status": self.status.value,
            "option_used": self.option_used,
            "message": self.message,
            "backup_path": self.backup_path,
            "diff": self.diff,
            "applied_at": self.applied_at,
        }


@dataclass
class FixSummary:
    """Summary of fix application results."""

    total: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    manual_required: int = 0
    dry_run: bool = False
    results: List[FixResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total": self.total,
            "successful": self.successful,
            "failed": self.failed,
            "skipped": self.skipped,
            "manual_required": self.manual_required,
            "dry_run": self.dry_run,
            "results": [r.to_dict() for r in self.results],
        }


class Fixer:
    """Applies remediation fixes to files.

    Supports dry-run mode, backup creation, and validation
    of applied fixes.
    """

    def __init__(
        self,
        backup_dir: Optional[Path] = None,
        create_backups: bool = True,
    ):
        """Initialize the fixer.

        Args:
            backup_dir: Directory for backup files (default: .secureagent/backups)
            create_backups: Whether to create backups before applying fixes
        """
        self.backup_dir = backup_dir or Path(".secureagent/backups")
        self.create_backups = create_backups

    def apply_fixes(
        self,
        fixes: List[GeneratedFix],
        dry_run: bool = True,
        option_index: Optional[int] = None,
        interactive: bool = False,
    ) -> FixSummary:
        """Apply a list of fixes.

        Args:
            fixes: List of generated fixes to apply
            dry_run: If True, don't actually modify files
            option_index: Specific option index to apply (None = use recommended)
            interactive: If True, prompt for confirmation

        Returns:
            Summary of fix application results
        """
        summary = FixSummary(total=len(fixes), dry_run=dry_run)

        for fix in fixes:
            result = self.apply_fix(
                fix,
                dry_run=dry_run,
                option_index=option_index,
                interactive=interactive,
            )
            summary.results.append(result)

            if result.status == FixStatus.SUCCESS or result.status == FixStatus.DRY_RUN:
                summary.successful += 1
            elif result.status == FixStatus.FAILED:
                summary.failed += 1
            elif result.status == FixStatus.MANUAL_REQUIRED:
                summary.manual_required += 1
            else:
                summary.skipped += 1

        return summary

    def apply_fix(
        self,
        fix: GeneratedFix,
        dry_run: bool = True,
        option_index: Optional[int] = None,
        interactive: bool = False,
    ) -> FixResult:
        """Apply a single fix.

        Args:
            fix: Generated fix to apply
            dry_run: If True, don't actually modify the file
            option_index: Specific option index to apply (None = use recommended)
            interactive: If True, prompt for confirmation

        Returns:
            Result of the fix application
        """
        timestamp = datetime.utcnow().isoformat()

        # Determine which option to use
        idx = option_index if option_index is not None else fix.recommended_option
        if idx < 0 or idx >= len(fix.options):
            idx = 0

        if not fix.options:
            return FixResult(
                fix_id=fix.id,
                finding_id=fix.finding_id,
                rule_id=fix.rule_id,
                file_path=fix.file_path,
                status=FixStatus.SKIPPED,
                message="No fix options available",
                applied_at=timestamp,
            )

        option = fix.options[idx]

        # Handle manual fixes
        if option.fix_type == FixType.MANUAL:
            return FixResult(
                fix_id=fix.id,
                finding_id=fix.finding_id,
                rule_id=fix.rule_id,
                file_path=fix.file_path,
                status=FixStatus.MANUAL_REQUIRED,
                option_used=idx,
                message=f"Manual fix required: {option.description}",
                applied_at=timestamp,
            )

        # Check if file exists
        file_path = Path(fix.file_path)
        if not file_path.exists():
            return FixResult(
                fix_id=fix.id,
                finding_id=fix.finding_id,
                rule_id=fix.rule_id,
                file_path=fix.file_path,
                status=FixStatus.FILE_NOT_FOUND,
                option_used=idx,
                message=f"File not found: {fix.file_path}",
                applied_at=timestamp,
            )

        # Read original content
        try:
            original_content = file_path.read_text()
        except Exception as e:
            return FixResult(
                fix_id=fix.id,
                finding_id=fix.finding_id,
                rule_id=fix.rule_id,
                file_path=fix.file_path,
                status=FixStatus.FAILED,
                option_used=idx,
                message=f"Failed to read file: {e}",
                applied_at=timestamp,
            )

        # Generate fixed content
        try:
            fixed_content, diff = self._apply_option(
                original_content,
                option,
                fix.line_number,
                file_path,
            )
        except Exception as e:
            return FixResult(
                fix_id=fix.id,
                finding_id=fix.finding_id,
                rule_id=fix.rule_id,
                file_path=fix.file_path,
                status=FixStatus.FAILED,
                option_used=idx,
                message=f"Failed to generate fix: {e}",
                applied_at=timestamp,
            )

        # Validate the fix if there's a validation regex
        if option.validation_regex:
            if not re.search(option.validation_regex, fixed_content):
                return FixResult(
                    fix_id=fix.id,
                    finding_id=fix.finding_id,
                    rule_id=fix.rule_id,
                    file_path=fix.file_path,
                    status=FixStatus.VALIDATION_FAILED,
                    option_used=idx,
                    message="Fix validation failed",
                    diff=diff,
                    applied_at=timestamp,
                )

        # Validate JSON if it's a JSON file
        if file_path.suffix == ".json":
            try:
                json.loads(fixed_content)
            except json.JSONDecodeError as e:
                return FixResult(
                    fix_id=fix.id,
                    finding_id=fix.finding_id,
                    rule_id=fix.rule_id,
                    file_path=fix.file_path,
                    status=FixStatus.VALIDATION_FAILED,
                    option_used=idx,
                    message=f"Invalid JSON after fix: {e}",
                    diff=diff,
                    applied_at=timestamp,
                )

        # Dry run - don't actually apply
        if dry_run:
            return FixResult(
                fix_id=fix.id,
                finding_id=fix.finding_id,
                rule_id=fix.rule_id,
                file_path=fix.file_path,
                status=FixStatus.DRY_RUN,
                option_used=idx,
                message="Dry run - fix not applied",
                diff=diff,
                applied_at=timestamp,
            )

        # Create backup
        backup_path = None
        if self.create_backups:
            try:
                backup_path = self._create_backup(file_path, original_content)
            except Exception as e:
                return FixResult(
                    fix_id=fix.id,
                    finding_id=fix.finding_id,
                    rule_id=fix.rule_id,
                    file_path=fix.file_path,
                    status=FixStatus.BACKUP_FAILED,
                    option_used=idx,
                    message=f"Failed to create backup: {e}",
                    applied_at=timestamp,
                )

        # Apply the fix
        try:
            file_path.write_text(fixed_content)
        except Exception as e:
            # Attempt to restore from backup
            if backup_path:
                try:
                    shutil.copy(backup_path, file_path)
                except Exception:
                    pass
            return FixResult(
                fix_id=fix.id,
                finding_id=fix.finding_id,
                rule_id=fix.rule_id,
                file_path=fix.file_path,
                status=FixStatus.FAILED,
                option_used=idx,
                message=f"Failed to write fix: {e}",
                backup_path=str(backup_path) if backup_path else None,
                applied_at=timestamp,
            )

        return FixResult(
            fix_id=fix.id,
            finding_id=fix.finding_id,
            rule_id=fix.rule_id,
            file_path=fix.file_path,
            status=FixStatus.SUCCESS,
            option_used=idx,
            message=f"Fix applied: {option.title}",
            backup_path=str(backup_path) if backup_path else None,
            diff=diff,
            applied_at=timestamp,
        )

    def _apply_option(
        self,
        content: str,
        option: RemediationOption,
        line_number: Optional[int],
        file_path: Path,
    ) -> Tuple[str, str]:
        """Apply a fix option to content.

        Args:
            content: Original file content
            option: Fix option to apply
            line_number: Line number of the finding
            file_path: Path to the file

        Returns:
            Tuple of (fixed_content, unified_diff)
        """
        fixed_content = content

        if option.fix_type == FixType.REPLACE:
            fixed_content = self._apply_replace(content, option, line_number)

        elif option.fix_type == FixType.INSERT:
            fixed_content = self._apply_insert(content, option, line_number, file_path)

        elif option.fix_type == FixType.DELETE:
            fixed_content = self._apply_delete(content, option, line_number)

        elif option.fix_type == FixType.RESTRUCTURE:
            fixed_content = self._apply_restructure(content, option, file_path)

        # Generate diff
        diff = self._generate_diff(content, fixed_content, str(file_path))

        return fixed_content, diff

    def _apply_replace(
        self,
        content: str,
        option: RemediationOption,
        line_number: Optional[int],
    ) -> str:
        """Apply a replace fix."""
        if not option.original:
            return content

        # If we have a specific line number, try to replace only on that line
        if line_number:
            lines = content.split('\n')
            if 0 < line_number <= len(lines):
                line_idx = line_number - 1
                if option.original in lines[line_idx]:
                    lines[line_idx] = lines[line_idx].replace(
                        option.original,
                        option.replacement,
                        1,  # Replace only first occurrence
                    )
                    return '\n'.join(lines)

        # Fall back to global replace (first occurrence only)
        return content.replace(option.original, option.replacement, 1)

    def _apply_insert(
        self,
        content: str,
        option: RemediationOption,
        line_number: Optional[int],
        file_path: Path,
    ) -> str:
        """Apply an insert fix."""
        if not option.replacement:
            return content

        # For JSON files, try to insert at the appropriate location
        if file_path.suffix == ".json":
            return self._insert_into_json(content, option)

        # For other files, insert after the specified line
        if line_number:
            lines = content.split('\n')
            if 0 < line_number <= len(lines):
                # Detect indentation from the target line
                target_line = lines[line_number - 1]
                indent = len(target_line) - len(target_line.lstrip())
                indent_str = target_line[:indent] if indent > 0 else ""

                # Add proper indentation to replacement
                replacement_lines = option.replacement.split('\n')
                indented_replacement = '\n'.join(
                    indent_str + line if line.strip() else line
                    for line in replacement_lines
                )

                lines.insert(line_number, indented_replacement)
                return '\n'.join(lines)

        # Fall back to appending
        return content + '\n' + option.replacement

    def _apply_delete(
        self,
        content: str,
        option: RemediationOption,
        line_number: Optional[int],
    ) -> str:
        """Apply a delete fix."""
        if option.original:
            return content.replace(option.original, '', 1)

        # If no specific content to delete but we have a line number,
        # comment out the line (safer than deletion)
        if line_number:
            lines = content.split('\n')
            if 0 < line_number <= len(lines):
                line_idx = line_number - 1
                # Add a comment marker (this is a simple approach)
                lines[line_idx] = "// REMOVED: " + lines[line_idx]
                return '\n'.join(lines)

        return content

    def _apply_restructure(
        self,
        content: str,
        option: RemediationOption,
        file_path: Path,
    ) -> str:
        """Apply a restructure fix."""
        # Restructure fixes are complex and typically require manual review
        # For now, just return the content unchanged with a note
        return content

    def _insert_into_json(self, content: str, option: RemediationOption) -> str:
        """Insert content into a JSON file intelligently."""
        try:
            data = json.loads(content)

            # If we have a JSON path, use it
            if option.json_path and option.new_value is not None:
                # Simple JSON path implementation (supports basic paths)
                self._set_json_path(data, option.json_path, option.new_value)
            else:
                # Try to parse the replacement as JSON and merge
                try:
                    replacement_data = json.loads('{' + option.replacement + '}')
                    # Find the right place to insert (e.g., into mcpServers.*.env)
                    if "mcpServers" in data:
                        for server_name, server_config in data["mcpServers"].items():
                            if isinstance(server_config, dict):
                                server_config.update(replacement_data)
                                break
                except json.JSONDecodeError:
                    # If replacement isn't valid JSON, return original
                    return content

            # Re-serialize with nice formatting
            return json.dumps(data, indent=2) + '\n'

        except json.JSONDecodeError:
            return content

    def _set_json_path(self, data: dict, path: str, value: Any) -> None:
        """Set a value at a JSON path (simple implementation)."""
        # Remove leading $. if present
        path = path.lstrip('$.')

        parts = path.split('.')
        current = data

        for i, part in enumerate(parts[:-1]):
            if part == '*':
                # Wildcard - apply to all items
                if isinstance(current, dict):
                    for key in current:
                        if isinstance(current[key], dict):
                            remaining_path = '.'.join(parts[i + 1:])
                            self._set_json_path(current[key], remaining_path, value)
                return
            elif part in current:
                current = current[part]
            else:
                return

        # Set the final value
        final_key = parts[-1]
        if final_key in current or isinstance(current, dict):
            current[final_key] = value

    def _create_backup(self, file_path: Path, content: str) -> Path:
        """Create a backup of a file.

        Args:
            file_path: Original file path
            content: Original file content

        Returns:
            Path to the backup file
        """
        # Create backup directory
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # Generate backup filename with timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{file_path.stem}_{timestamp}{file_path.suffix}.bak"
        backup_path = self.backup_dir / backup_name

        # Write backup
        backup_path.write_text(content)

        return backup_path

    def _generate_diff(
        self,
        original: str,
        modified: str,
        filename: str,
    ) -> str:
        """Generate a unified diff between original and modified content."""
        import difflib

        original_lines = original.splitlines(keepends=True)
        modified_lines = modified.splitlines(keepends=True)

        diff = difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )

        return ''.join(diff)

    def restore_backup(self, backup_path: str, target_path: str) -> bool:
        """Restore a file from backup.

        Args:
            backup_path: Path to the backup file
            target_path: Path to restore to

        Returns:
            True if successful, False otherwise
        """
        try:
            shutil.copy(backup_path, target_path)
            return True
        except Exception:
            return False

    def list_backups(self) -> List[Dict[str, Any]]:
        """List all available backups.

        Returns:
            List of backup information dictionaries
        """
        backups = []

        if not self.backup_dir.exists():
            return backups

        for backup_file in self.backup_dir.glob("*.bak"):
            stat = backup_file.stat()
            backups.append({
                "path": str(backup_file),
                "name": backup_file.name,
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            })

        return sorted(backups, key=lambda x: x["created"], reverse=True)

    def cleanup_backups(self, max_age_days: int = 7) -> int:
        """Clean up old backup files.

        Args:
            max_age_days: Maximum age of backups to keep

        Returns:
            Number of backups deleted
        """
        import time

        if not self.backup_dir.exists():
            return 0

        deleted = 0
        cutoff = time.time() - (max_age_days * 86400)

        for backup_file in self.backup_dir.glob("*.bak"):
            if backup_file.stat().st_ctime < cutoff:
                try:
                    backup_file.unlink()
                    deleted += 1
                except Exception:
                    pass

        return deleted
