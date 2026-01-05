"""GitLab integration for SecureAgent."""

import os
import tempfile
import subprocess
from typing import List, Optional, Dict, Any
from pathlib import Path
from dataclasses import dataclass

from ...core.models.finding import Finding
from ...core.models.severity import Severity


@dataclass
class GitLabProject:
    """GitLab project information."""

    id: int
    name: str
    path_with_namespace: str
    default_branch: str
    http_url: str
    visibility: str


class GitLabIntegration:
    """GitLab integration for SecureAgent."""

    def __init__(
        self,
        token: Optional[str] = None,
        base_url: str = "https://gitlab.com",
    ):
        """Initialize GitLab integration."""
        self.token = token or os.environ.get("GITLAB_TOKEN")
        self.base_url = base_url.rstrip("/")
        self._gitlab = None

    @property
    def gitlab(self):
        """Lazy-load python-gitlab."""
        if self._gitlab is None:
            try:
                import gitlab

                self._gitlab = gitlab.Gitlab(
                    self.base_url, private_token=self.token
                )
                self._gitlab.auth()
            except ImportError:
                raise ImportError(
                    "python-gitlab is required for GitLab integration. "
                    "Install with: pip install python-gitlab"
                )
        return self._gitlab

    def get_project(self, project_path: str) -> GitLabProject:
        """Get project information."""
        project = self.gitlab.projects.get(project_path)
        return GitLabProject(
            id=project.id,
            name=project.name,
            path_with_namespace=project.path_with_namespace,
            default_branch=project.default_branch,
            http_url=project.http_url_to_repo,
            visibility=project.visibility,
        )

    def scan_project(
        self,
        project_path: str,
        scanners: Optional[List[str]] = None,
        branch: Optional[str] = None,
    ) -> List[Finding]:
        """Scan a GitLab project."""
        from ...scanners import scan_directory

        project_info = self.get_project(project_path)
        target_branch = branch or project_info.default_branch

        with tempfile.TemporaryDirectory() as temp_dir:
            clone_path = Path(temp_dir) / project_info.name

            clone_url = self._get_authenticated_url(project_info)
            self._clone_project(clone_url, clone_path, target_branch)

            findings = scan_directory(
                str(clone_path),
                scanner_types=scanners,
            )

            for finding in findings:
                if finding.location and finding.location.file_path:
                    relative_path = Path(finding.location.file_path).relative_to(
                        clone_path
                    )
                    finding.location.file_path = str(relative_path)
                    finding.metadata = finding.metadata or {}
                    finding.metadata["project"] = project_path
                    finding.metadata["branch"] = target_branch

            return findings

    def _get_authenticated_url(self, project_info: GitLabProject) -> str:
        """Get clone URL with authentication."""
        if self.token and project_info.visibility != "public":
            return project_info.http_url.replace(
                "https://", f"https://oauth2:{self.token}@"
            )
        return project_info.http_url

    def _clone_project(self, url: str, path: Path, branch: str) -> None:
        """Clone a project."""
        cmd = [
            "git",
            "clone",
            "--depth",
            "1",
            "--branch",
            branch,
            url,
            str(path),
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to clone project: {result.stderr}")

    def post_mr_comment(
        self,
        project_path: str,
        mr_iid: int,
        findings: List[Finding],
    ) -> None:
        """Post findings as merge request comment."""
        project = self.gitlab.projects.get(project_path)
        mr = project.mergerequests.get(mr_iid)

        comment = self._format_mr_comment(findings)
        mr.notes.create({"body": comment})

    def create_mr_discussion(
        self,
        project_path: str,
        mr_iid: int,
        finding: Finding,
    ) -> None:
        """Create a discussion on a specific line in MR."""
        project = self.gitlab.projects.get(project_path)
        mr = project.mergerequests.get(mr_iid)

        if not finding.location or not finding.location.file_path:
            return

        # Get diff refs
        diff = mr.diffs.list()[0]

        discussion_data = {
            "body": self._format_finding_comment(finding),
            "position": {
                "base_sha": mr.diff_refs["base_sha"],
                "start_sha": mr.diff_refs["start_sha"],
                "head_sha": mr.diff_refs["head_sha"],
                "position_type": "text",
                "new_path": finding.location.file_path,
                "new_line": finding.location.line_number or 1,
            },
        }

        mr.discussions.create(discussion_data)

    def create_issue(
        self,
        project_path: str,
        finding: Finding,
        labels: Optional[List[str]] = None,
    ) -> int:
        """Create an issue for a finding."""
        project = self.gitlab.projects.get(project_path)

        title = f"[Security] {finding.severity.value}: {finding.title}"
        description = self._format_issue_description(finding)

        issue_labels = ["security", f"severity::{finding.severity.value.lower()}"]
        if labels:
            issue_labels.extend(labels)

        issue = project.issues.create(
            {
                "title": title,
                "description": description,
                "labels": issue_labels,
            }
        )

        return issue.iid

    def update_pipeline_status(
        self,
        project_path: str,
        commit_sha: str,
        findings: List[Finding],
        pipeline_id: Optional[int] = None,
    ) -> None:
        """Update pipeline with security scan results."""
        project = self.gitlab.projects.get(project_path)

        # Determine status
        has_critical_high = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings
        )

        state = "failed" if has_critical_high else "success"
        description = f"Found {len(findings)} security issues"

        project.commits.get(commit_sha).statuses.create(
            {
                "state": state,
                "name": "SecureAgent Security Scan",
                "description": description,
                "target_url": None,
            }
        )

    def upload_sarif(
        self,
        project_path: str,
        sarif_content: str,
        commit_sha: str,
    ) -> None:
        """Upload SARIF report to GitLab security dashboard."""
        project = self.gitlab.projects.get(project_path)

        # Upload as security report artifact
        project.upload(
            "security-report.sarif",
            sarif_content.encode(),
            "security",
        )

    def _format_mr_comment(self, findings: List[Finding]) -> str:
        """Format findings as MR comment."""
        if not findings:
            return (
                "## :white_check_mark: SecureAgent Security Scan\n\n"
                "No security issues found!"
            )

        severity_counts: Dict[Severity, int] = {}
        for finding in findings:
            severity_counts[finding.severity] = (
                severity_counts.get(finding.severity, 0) + 1
            )

        comment = "## :shield: SecureAgent Security Scan Results\n\n"

        comment += "| Severity | Count |\n"
        comment += "|----------|-------|\n"
        for severity in Severity:
            count = severity_counts.get(severity, 0)
            if count > 0:
                comment += f"| {severity.value} | {count} |\n"

        comment += f"\n**Total:** {len(findings)} findings\n\n"

        # List critical/high findings
        critical_high = [
            f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        if critical_high:
            comment += "### Critical/High Severity Findings\n\n"
            for finding in critical_high[:10]:
                location = ""
                if finding.location and finding.location.file_path:
                    location = f" (`{finding.location.file_path}`)"
                comment += f"- **{finding.title}**{location}\n"

        return comment

    def _format_finding_comment(self, finding: Finding) -> str:
        """Format single finding as comment."""
        comment = f"**:warning: {finding.severity.value}: {finding.title}**\n\n"
        comment += f"{finding.description}\n\n"
        if finding.remediation:
            comment += f"**Remediation:** {finding.remediation}"
        return comment

    def _format_issue_description(self, finding: Finding) -> str:
        """Format finding as issue description."""
        desc = f"## Security Finding: {finding.title}\n\n"
        desc += f"**Severity:** {finding.severity.value}\n"
        desc += f"**Rule ID:** {finding.rule_id}\n"

        if finding.location and finding.location.file_path:
            desc += f"**Location:** `{finding.location.file_path}"
            if finding.location.line_number:
                desc += f":{finding.location.line_number}"
            desc += "`\n"

        desc += f"\n### Description\n\n{finding.description}\n"

        if finding.remediation:
            desc += f"\n### Remediation\n\n{finding.remediation}\n"

        if finding.cwe_id or finding.owasp_id:
            desc += "\n### References\n\n"
            if finding.cwe_id:
                desc += f"- {finding.cwe_id}\n"
            if finding.owasp_id:
                desc += f"- {finding.owasp_id}\n"

        return desc
