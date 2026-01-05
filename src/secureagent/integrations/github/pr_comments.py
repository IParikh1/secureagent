"""GitHub PR comment posting for SecureAgent."""

import os
from typing import List, Optional
from dataclasses import dataclass

from ...core.models.finding import Finding
from ...core.models.severity import Severity


@dataclass
class PRComment:
    """Pull request comment."""

    body: str
    path: Optional[str] = None
    line: Optional[int] = None
    side: str = "RIGHT"


class PRCommentPoster:
    """Post security findings as PR comments."""

    SEVERITY_EMOJIS = {
        Severity.CRITICAL: ":rotating_light:",
        Severity.HIGH: ":warning:",
        Severity.MEDIUM: ":yellow_circle:",
        Severity.LOW: ":information_source:",
        Severity.INFO: ":bulb:",
    }

    def __init__(self, token: Optional[str] = None):
        """Initialize PR comment poster."""
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self._github = None

    @property
    def github(self):
        """Lazy-load PyGithub."""
        if self._github is None:
            try:
                from github import Github

                self._github = Github(self.token)
            except ImportError:
                raise ImportError(
                    "PyGithub is required for GitHub integration. "
                    "Install with: pip install secureagent[github]"
                )
        return self._github

    def post_review(
        self,
        repo_full_name: str,
        pr_number: int,
        findings: List[Finding],
        commit_sha: Optional[str] = None,
    ) -> None:
        """Post a review with inline comments for findings."""
        repo = self.github.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)

        if not commit_sha:
            commit_sha = pr.head.sha

        # Group findings by file
        findings_by_file = self._group_by_file(findings)

        # Build review comments
        comments = []
        for file_path, file_findings in findings_by_file.items():
            for finding in file_findings:
                if finding.location and finding.location.line_number:
                    comments.append(
                        {
                            "path": file_path,
                            "line": finding.location.line_number,
                            "body": self._format_inline_comment(finding),
                        }
                    )

        # Determine review event based on severity
        has_critical_high = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings
        )

        event = "REQUEST_CHANGES" if has_critical_high else "COMMENT"

        # Create review
        if comments:
            pr.create_review(
                commit=repo.get_commit(commit_sha),
                body=self._format_summary(findings),
                event=event,
                comments=comments,
            )
        else:
            # Post summary comment if no inline comments
            self.post_summary_comment(repo_full_name, pr_number, findings)

    def post_summary_comment(
        self,
        repo_full_name: str,
        pr_number: int,
        findings: List[Finding],
    ) -> None:
        """Post a summary comment on the PR."""
        repo = self.github.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)

        comment_body = self._format_summary(findings)
        pr.create_issue_comment(comment_body)

    def _group_by_file(self, findings: List[Finding]) -> dict:
        """Group findings by file path."""
        grouped = {}
        for finding in findings:
            if finding.location and finding.location.file_path:
                path = finding.location.file_path
                if path not in grouped:
                    grouped[path] = []
                grouped[path].append(finding)
        return grouped

    def _format_inline_comment(self, finding: Finding) -> str:
        """Format a finding as an inline comment."""
        emoji = self.SEVERITY_EMOJIS.get(finding.severity, ":question:")

        comment = f"{emoji} **{finding.severity.value}: {finding.title}**\n\n"
        comment += f"{finding.description}\n\n"

        if finding.remediation:
            comment += f"**Remediation:** {finding.remediation}\n\n"

        refs = []
        if finding.cwe_id:
            refs.append(f"[{finding.cwe_id}](https://cwe.mitre.org/data/definitions/{finding.cwe_id.replace('CWE-', '')}.html)")
        if finding.owasp_id:
            refs.append(finding.owasp_id)

        if refs:
            comment += f"**References:** {', '.join(refs)}\n"

        return comment

    def _format_summary(self, findings: List[Finding]) -> str:
        """Format a summary of all findings."""
        if not findings:
            return (
                "## :white_check_mark: SecureAgent Security Scan\n\n"
                "No security issues found!"
            )

        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity] = (
                severity_counts.get(finding.severity, 0) + 1
            )

        summary = "## :shield: SecureAgent Security Scan Results\n\n"

        # Summary table
        summary += "| Severity | Count |\n"
        summary += "|----------|-------|\n"
        for severity in Severity:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = self.SEVERITY_EMOJIS.get(severity, "")
                summary += f"| {emoji} {severity.value} | {count} |\n"

        summary += f"\n**Total:** {len(findings)} findings\n\n"

        # Critical/High findings details
        critical_high = [
            f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        if critical_high:
            summary += "### :rotating_light: Critical/High Severity Findings\n\n"
            for finding in critical_high[:10]:  # Limit to 10
                location = ""
                if finding.location and finding.location.file_path:
                    location = f" (`{finding.location.file_path}"
                    if finding.location.line_number:
                        location += f":{finding.location.line_number}"
                    location += "`)"
                summary += f"- **{finding.title}**{location}\n"

            if len(critical_high) > 10:
                summary += f"\n*...and {len(critical_high) - 10} more*\n"

        summary += "\n---\n*Generated by SecureAgent*"
        return summary

    def update_check_status(
        self,
        repo_full_name: str,
        commit_sha: str,
        findings: List[Finding],
        check_name: str = "SecureAgent Security Scan",
    ) -> None:
        """Update GitHub check status for a commit."""
        repo = self.github.get_repo(repo_full_name)

        # Determine conclusion
        has_critical = any(f.severity == Severity.CRITICAL for f in findings)
        has_high = any(f.severity == Severity.HIGH for f in findings)

        if has_critical:
            conclusion = "failure"
        elif has_high:
            conclusion = "failure"
        elif findings:
            conclusion = "neutral"
        else:
            conclusion = "success"

        # Create check run
        repo.create_check_run(
            name=check_name,
            head_sha=commit_sha,
            status="completed",
            conclusion=conclusion,
            output={
                "title": f"Found {len(findings)} security issues",
                "summary": self._format_check_summary(findings),
                "annotations": self._findings_to_annotations(findings)[:50],  # Limit
            },
        )

    def _format_check_summary(self, findings: List[Finding]) -> str:
        """Format summary for check run."""
        if not findings:
            return "No security issues found."

        severity_counts = {}
        for finding in findings:
            severity_counts[finding.severity] = (
                severity_counts.get(finding.severity, 0) + 1
            )

        summary = f"Found {len(findings)} security issues:\n\n"
        for severity in Severity:
            count = severity_counts.get(severity, 0)
            if count > 0:
                summary += f"- {severity.value}: {count}\n"

        return summary

    def _findings_to_annotations(
        self, findings: List[Finding]
    ) -> List[dict]:
        """Convert findings to GitHub annotations."""
        annotations = []

        for finding in findings:
            if not finding.location or not finding.location.file_path:
                continue

            annotation_level = {
                Severity.CRITICAL: "failure",
                Severity.HIGH: "failure",
                Severity.MEDIUM: "warning",
                Severity.LOW: "notice",
                Severity.INFO: "notice",
            }.get(finding.severity, "notice")

            annotations.append(
                {
                    "path": finding.location.file_path,
                    "start_line": finding.location.line_number or 1,
                    "end_line": finding.location.line_number or 1,
                    "annotation_level": annotation_level,
                    "title": finding.title,
                    "message": finding.description,
                }
            )

        return annotations
