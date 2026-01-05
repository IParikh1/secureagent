"""Tests for webhook dispatcher."""

import pytest

from secureagent.integrations.webhooks.dispatcher import (
    WebhookDispatcher,
    WebhookConfig,
    WebhookEvent,
)


class TestWebhookDispatcher:
    """Tests for webhook dispatcher."""

    def test_dispatcher_initialization(self):
        """Test dispatcher initialization."""
        dispatcher = WebhookDispatcher()
        assert dispatcher is not None
        assert len(dispatcher.webhooks) == 0

    def test_add_webhook(self):
        """Test adding webhook configuration."""
        dispatcher = WebhookDispatcher()

        config = WebhookConfig(
            url="https://example.com/webhook",
            events=[WebhookEvent.SCAN_COMPLETED],
        )
        dispatcher.add_webhook(config)

        assert len(dispatcher.webhooks) == 1

    def test_remove_webhook(self):
        """Test removing webhook configuration."""
        dispatcher = WebhookDispatcher()

        config = WebhookConfig(
            url="https://example.com/webhook",
            events=[WebhookEvent.SCAN_COMPLETED],
        )
        dispatcher.add_webhook(config)
        dispatcher.remove_webhook("https://example.com/webhook")

        assert len(dispatcher.webhooks) == 0

    def test_signature_generation(self):
        """Test webhook signature generation."""
        payload = {"event": "test", "data": {"key": "value"}}
        secret = "test-secret"

        signature = WebhookDispatcher._generate_signature(None, payload, secret)

        assert signature.startswith("sha256=")
        assert len(signature) > 10

    def test_signature_verification(self):
        """Test webhook signature verification."""
        import json

        payload = {"event": "test", "data": {"key": "value"}}
        secret = "test-secret"
        payload_bytes = json.dumps(payload, sort_keys=True).encode()

        # Generate signature
        import hashlib
        import hmac

        signature = "sha256=" + hmac.new(
            secret.encode(), payload_bytes, hashlib.sha256
        ).hexdigest()

        # Verify
        is_valid = WebhookDispatcher.verify_signature(
            payload_bytes, signature, secret
        )
        assert is_valid

    def test_invalid_signature_rejected(self):
        """Test that invalid signatures are rejected."""
        payload_bytes = b'{"event": "test"}'
        invalid_signature = "sha256=invalid"
        secret = "test-secret"

        is_valid = WebhookDispatcher.verify_signature(
            payload_bytes, invalid_signature, secret
        )
        assert not is_valid
