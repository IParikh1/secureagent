"""GitHub issue creation for SecureAgent."""

import os
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from ...core.models.finding import Finding
from ...core.models.severity import Severity


@dataclass
class SecurityIssue:
    """Created security issue."""

    number: int
    title: str
    url: str
    finding_id: str


class IssueCreator:
    """Create GitHub issues for security findings."""

    SEVERITY_LABELS = {
        Severity.CRITICAL: "security-critical",
        Severity.HIGH: "security-high",
        Severity.MEDIUM: "security-medium",
        Severity.LOW: "security-low",
        Severity.INFO: "security-info",
    }

    def __init__(self, token: Optional[str] = None):
        """Initialize issue creator."""
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

    def create_issue(
        self,
        repo_full_name: str,
        finding: Finding,
        labels: Optional[List[str]] = None,
        assignees: Optional[List[str]] = None,
        milestone: Optional[str] = None,
    ) -> SecurityIssue:
        """Create a GitHub issue for a finding."""
        repo = self.github.get_repo(repo_full_name)

        # Build issue title
        title = f"[Security] {finding.severity.value}: {finding.title}"

        # Build issue body
        body = self._format_issue_body(finding)

        # Collect labels
        issue_labels = ["security"]
        if finding.severity in self.SEVERITY_LABELS:
            issue_labels.append(self.SEVERITY_LABELS[finding.severity])
        if labels:
            issue_labels.extend(labels)

        # Ensure labels exist
        self._ensure_labels_exist(repo, issue_labels)

        # Create issue
        issue = repo.create_issue(
            title=title,
            body=body,
            labels=issue_labels,
            assignees=assignees or [],
        )

        return SecurityIssue(
            number=issue.number,
            title=issue.title,
            url=issue.html_url,
            finding_id=finding.id,
        )

    def create_issues_for_findings(
        self,
        repo_full_name: str,
        findings: List[Finding],
        min_severity: Severity = Severity.HIGH,
        max_issues: int = 10,
        labels: Optional[List[str]] = None,
    ) -> List[SecurityIssue]:
        """Create issues for multiple findings."""
        issues = []

        # Filter by severity
        filtered_findings = [
            f
            for f in findings
            if list(Severity).index(f.severity) <= list(Severity).index(min_severity)
        ]

        # Sort by severity
        sorted_findings = sorted(
            filtered_findings, key=lambda f: list(Severity).index(f.severity)
        )

        # Create issues up to max
        for finding in sorted_findings[:max_issues]:
            issue = self.create_issue(repo_full_name, finding, labels=labels)
            issues.append(issue)

        return issues

    def create_tracking_issue(
        self,
        repo_full_name: str,
        findings: List[Finding],
        title: str = "Security Scan Results",
    ) -> SecurityIssue:
        """Create a tracking issue that lists all findings."""
        repo = self.github.get_repo(repo_full_name)

        body = self._format_tracking_issue_body(findings)

        issue = repo.create_issue(
            title=f"[Security] {title}",
            body=body,
            labels=["security", "tracking"],
        )

        return SecurityIssue(
            number=issue.number,
            title=issue.title,
            url=issue.html_url,
            finding_id="tracking",
        )

    def _format_issue_body(self, finding: Finding) -> str:
        """Format finding as issue body."""
        body = f"## Security Finding: {finding.title}\n\n"

        body += f"**Severity:** {finding.severity.value}\n"
        body += f"**Rule ID:** {finding.rule_id}\n"

        if finding.location:
            loc = finding.location
            if loc.file_path:
                body += f"**Location:** `{loc.file_path}"
                if loc.line_number:
                    body += f":{loc.line_number}"
                body += "`\n"

        body += "\n### Description\n\n"
        body += f"{finding.description}\n"

        if finding.remediation:
            body += "\n### Remediation\n\n"
            body += f"{finding.remediation}\n"

        body += "\n### References\n\n"
        if finding.cwe_id:
            cwe_num = finding.cwe_id.replace("CWE-", "")
            body += f"- [{finding.cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)\n"
        if finding.owasp_id:
            body += f"- OWASP: {finding.owasp_id}\n"

        if finding.risk_score is not None:
            body += f"\n**Risk Score:** {finding.risk_score:.2f}\n"

        body += "\n---\n*Created by SecureAgent Security Scanner*"
        return body

    def _format_tracking_issue_body(self, findings: List[Finding]) -> str:
        """Format tracking issue body."""
        body = "## Security Scan Summary\n\n"

        # Severity breakdown
        severity_counts: Dict[Severity, int] = {}
        for finding in findings:
            severity_counts[finding.severity] = (
                severity_counts.get(finding.severity, 0) + 1
            )

        body += "### Findings by Severity\n\n"
        body += "| Severity | Count |\n"
        body += "|----------|-------|\n"
        for severity in Severity:
            count = severity_counts.get(severity, 0)
            body += f"| {severity.value} | {count} |\n"

        body += f"\n**Total:** {len(findings)} findings\n\n"

        # List findings as checklist
        body += "### Findings Checklist\n\n"

        sorted_findings = sorted(
            findings, key=lambda f: list(Severity).index(f.severity)
        )

        for finding in sorted_findings:
            location = ""
            if finding.location and finding.location.file_path:
                location = f" - `{finding.location.file_path}`"
            body += f"- [ ] **[{finding.severity.value}]** {finding.title}{location}\n"

        body += "\n---\n*Created by SecureAgent Security Scanner*"
        return body

    def _ensure_labels_exist(self, repo, labels: List[str]) -> None:
        """Ensure required labels exist in the repository."""
        existing_labels = {label.name for label in repo.get_labels()}

        label_colors = {
            "security": "d73a4a",
            "security-critical": "b60205",
            "security-high": "d93f0b",
            "security-medium": "fbca04",
            "security-low": "0e8a16",
            "security-info": "1d76db",
            "tracking": "5319e7",
        }

        for label in labels:
            if label not in existing_labels:
                color = label_colors.get(label, "ededed")
                try:
                    repo.create_label(name=label, color=color)
                except Exception:
                    pass  # Label might already exist (race condition)

    def find_existing_issue(
        self,
        repo_full_name: str,
        finding: Finding,
    ) -> Optional[int]:
        """Find an existing issue for a finding."""
        repo = self.github.get_repo(repo_full_name)

        # Search by title
        search_title = f"[Security] {finding.severity.value}: {finding.title}"

        issues = repo.get_issues(state="open", labels=["security"])
        for issue in issues:
            if issue.title == search_title:
                return issue.number

        return None

    def close_resolved_issues(
        self,
        repo_full_name: str,
        current_findings: List[Finding],
        comment: str = "This issue has been resolved.",
    ) -> List[int]:
        """Close issues for findings that no longer exist."""
        repo = self.github.get_repo(repo_full_name)
        closed_issues = []

        # Get current finding titles
        current_titles = {
            f"[Security] {f.severity.value}: {f.title}" for f in current_findings
        }

        # Check open security issues
        issues = repo.get_issues(state="open", labels=["security"])
        for issue in issues:
            if issue.title.startswith("[Security]") and issue.title not in current_titles:
                issue.create_comment(comment)
                issue.edit(state="closed")
                closed_issues.append(issue.number)

        return closed_issues
