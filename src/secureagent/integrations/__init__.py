"""External integrations for SecureAgent."""

from .github.scanner import GitHubScanner
from .github.pr_comments import PRCommentPoster
from .github.issues import IssueCreator
from .gitlab.integration import GitLabIntegration
from .slack.bot import SlackBot
from .webhooks.dispatcher import WebhookDispatcher

__all__ = [
    "GitHubScanner",
    "PRCommentPoster",
    "IssueCreator",
    "GitLabIntegration",
    "SlackBot",
    "WebhookDispatcher",
]
