"""Webhook signing and verification using HMAC."""
import hashlib
import hmac
import json
import time
from typing import Any


class WebhookSigner:
    """Sign outgoing webhooks and verify incoming ones."""

    def __init__(self, secret: str):
        """Initialize with webhook secret."""
        self.secret = secret.encode() if isinstance(secret, str) else secret

    def sign_payload(self, payload: dict[str, Any]) -> tuple[str, str]:
        """Sign a webhook payload.

        Returns:
            (timestamp, signature) tuple for inclusion in headers
        """
        timestamp = str(int(time.time()))
        payload_json = json.dumps(payload, sort_keys=True)

        message = f"{timestamp}.{payload_json}".encode()
        signature = hmac.new(self.secret, message, hashlib.sha256).hexdigest()

        return timestamp, signature

    def verify_signature(
        self, payload_json: str, signature: str, timestamp: str, tolerance_seconds: int = 300
    ) -> bool:
        """Verify a webhook signature.

        Args:
            payload_json: JSON string of payload
            signature: Signature from X-Webhook-Signature header
            timestamp: Timestamp from X-Webhook-Timestamp header
            tolerance_seconds: Allow this many seconds of clock skew

        Returns:
            True if signature is valid and timestamp is fresh, False otherwise
        """
        # Check timestamp freshness
        try:
            ts = int(timestamp)
            if abs(int(time.time()) - ts) > tolerance_seconds:
                return False
        except (ValueError, TypeError):
            return False

        # Verify signature
        message = f"{timestamp}.{payload_json}".encode()
        expected = hmac.new(self.secret, message, hashlib.sha256).hexdigest()

        return hmac.compare_digest(signature, expected)


def create_webhook_headers(payload: dict[str, Any], secret: str) -> dict[str, str]:
    """Create headers for webhook request."""
    signer = WebhookSigner(secret)
    timestamp, signature = signer.sign_payload(payload)

    return {
        "X-Webhook-Signature": signature,
        "X-Webhook-Timestamp": timestamp,
        "Content-Type": "application/json",
    }
