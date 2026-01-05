"""GitHub repository scanner for SecureAgent."""

import os
import tempfile
import subprocess
from typing import List, Optional, Dict, Any
from pathlib import Path
from dataclasses import dataclass

from ...core.models.finding import Finding


@dataclass
class GitHubRepo:
    """GitHub repository information."""

    owner: str
    name: str
    full_name: str
    default_branch: str
    clone_url: str
    is_private: bool


class GitHubScanner:
    """Scan GitHub repositories for security issues."""

    def __init__(
        self,
        token: Optional[str] = None,
        base_url: str = "https://api.github.com",
    ):
        """Initialize GitHub scanner."""
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.base_url = base_url
        self._github = None

    @property
    def github(self):
        """Lazy-load PyGithub."""
        if self._github is None:
            try:
                from github import Github

                self._github = Github(self.token, base_url=self.base_url)
            except ImportError:
                raise ImportError(
                    "PyGithub is required for GitHub integration. "
                    "Install with: pip install secureagent[github]"
                )
        return self._github

    def get_repo(self, repo_full_name: str) -> GitHubRepo:
        """Get repository information."""
        repo = self.github.get_repo(repo_full_name)
        return GitHubRepo(
            owner=repo.owner.login,
            name=repo.name,
            full_name=repo.full_name,
            default_branch=repo.default_branch,
            clone_url=repo.clone_url,
            is_private=repo.private,
        )

    def scan_repository(
        self,
        repo_full_name: str,
        scanners: Optional[List[str]] = None,
        branch: Optional[str] = None,
    ) -> List[Finding]:
        """Scan a GitHub repository.

        Args:
            repo_full_name: Repository in format "owner/repo"
            scanners: List of scanner types to use (mcp, langchain, etc.)
            branch: Branch to scan (default: default branch)

        Returns:
            List of security findings
        """
        from ...scanners import scan_directory

        repo_info = self.get_repo(repo_full_name)
        target_branch = branch or repo_info.default_branch

        # Clone repository to temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            clone_path = Path(temp_dir) / repo_info.name

            # Clone with token for private repos
            clone_url = self._get_authenticated_url(repo_info)
            self._clone_repo(clone_url, clone_path, target_branch)

            # Run scanners
            findings = scan_directory(
                str(clone_path),
                scanner_types=scanners,
            )

            # Update finding locations to use repo reference
            for finding in findings:
                if finding.location and finding.location.file_path:
                    # Convert local path to repo path
                    relative_path = Path(finding.location.file_path).relative_to(
                        clone_path
                    )
                    finding.location.file_path = str(relative_path)
                    finding.metadata = finding.metadata or {}
                    finding.metadata["repository"] = repo_full_name
                    finding.metadata["branch"] = target_branch

            return findings

    def _get_authenticated_url(self, repo_info: GitHubRepo) -> str:
        """Get clone URL with authentication."""
        if self.token and repo_info.is_private:
            # Insert token into URL
            return repo_info.clone_url.replace(
                "https://", f"https://{self.token}@"
            )
        return repo_info.clone_url

    def _clone_repo(self, url: str, path: Path, branch: str) -> None:
        """Clone a repository."""
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

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise RuntimeError(f"Failed to clone repository: {result.stderr}")

    def list_repos(
        self,
        org: Optional[str] = None,
        user: Optional[str] = None,
        limit: int = 100,
    ) -> List[GitHubRepo]:
        """List repositories for organization or user."""
        repos = []

        if org:
            org_obj = self.github.get_organization(org)
            github_repos = org_obj.get_repos()[:limit]
        elif user:
            user_obj = self.github.get_user(user)
            github_repos = user_obj.get_repos()[:limit]
        else:
            github_repos = self.github.get_user().get_repos()[:limit]

        for repo in github_repos:
            repos.append(
                GitHubRepo(
                    owner=repo.owner.login,
                    name=repo.name,
                    full_name=repo.full_name,
                    default_branch=repo.default_branch,
                    clone_url=repo.clone_url,
                    is_private=repo.private,
                )
            )

        return repos

    def get_changed_files(
        self,
        repo_full_name: str,
        base_ref: str,
        head_ref: str,
    ) -> List[str]:
        """Get list of changed files between two refs."""
        repo = self.github.get_repo(repo_full_name)
        comparison = repo.compare(base_ref, head_ref)
        return [f.filename for f in comparison.files]

    def scan_pull_request(
        self,
        repo_full_name: str,
        pr_number: int,
        scanners: Optional[List[str]] = None,
    ) -> List[Finding]:
        """Scan files changed in a pull request."""
        from ...scanners import scan_directory

        repo = self.github.get_repo(repo_full_name)
        pr = repo.get_pull(pr_number)

        # Get changed files
        changed_files = [f.filename for f in pr.get_files()]

        # Clone and scan only changed files
        with tempfile.TemporaryDirectory() as temp_dir:
            clone_path = Path(temp_dir) / repo.name

            clone_url = self._get_authenticated_url(
                GitHubRepo(
                    owner=repo.owner.login,
                    name=repo.name,
                    full_name=repo.full_name,
                    default_branch=repo.default_branch,
                    clone_url=repo.clone_url,
                    is_private=repo.private,
                )
            )

            # Clone PR head
            self._clone_pr_head(clone_url, clone_path, pr.head.ref)

            # Scan directory but filter findings to changed files
            all_findings = scan_directory(
                str(clone_path),
                scanner_types=scanners,
            )

            # Filter to only findings in changed files
            findings = []
            for finding in all_findings:
                if finding.location and finding.location.file_path:
                    relative_path = Path(finding.location.file_path).relative_to(
                        clone_path
                    )
                    if str(relative_path) in changed_files:
                        finding.location.file_path = str(relative_path)
                        finding.metadata = finding.metadata or {}
                        finding.metadata["repository"] = repo_full_name
                        finding.metadata["pull_request"] = pr_number
                        findings.append(finding)

            return findings

    def _clone_pr_head(self, url: str, path: Path, branch: str) -> None:
        """Clone PR head branch."""
        self._clone_repo(url, path, branch)
