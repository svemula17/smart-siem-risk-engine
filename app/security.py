"""Security utilities: rate limiting, CSRF tokens, session management."""
import secrets
import time
from collections import defaultdict
from datetime import datetime, timedelta


class RateLimiter:
    """Simple in-memory rate limiter."""
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        """Check if key is within rate limit."""
        now = time.time()
        cutoff = now - self.window_seconds

        self.requests[key] = [ts for ts in self.requests[key] if ts > cutoff]

        if len(self.requests[key]) < self.max_requests:
            self.requests[key].append(now)
            return True
        return False


class CSRFTokenManager:
    """Generate and validate CSRF tokens."""
    def __init__(self, token_ttl_seconds: int = 3600):
        self.tokens = {}
        self.token_ttl_seconds = token_ttl_seconds

    def generate_token(self) -> str:
        """Generate a new CSRF token."""
        token = secrets.token_urlsafe(32)
        self.tokens[token] = datetime.utcnow() + timedelta(seconds=self.token_ttl_seconds)
        return token

    def validate_token(self, token: str) -> bool:
        """Validate CSRF token and remove it (single-use)."""
        if token not in self.tokens:
            return False
        if datetime.utcnow() > self.tokens[token]:
            del self.tokens[token]
            return False
        del self.tokens[token]
        return True

    def cleanup_expired(self):
        """Remove expired tokens."""
        now = datetime.utcnow()
        self.tokens = {k: v for k, v in self.tokens.items() if v > now}


class APIKeyManager:
    """Generate and validate API keys."""
    def __init__(self):
        self.keys = {}  # In production, store in DB

    def generate_key(self, user_id: int, name: str) -> tuple[str, str]:
        """Generate API key and secret. Secret shown only once."""
        key = f"sk_{secrets.token_urlsafe(16)}"
        secret = secrets.token_urlsafe(32)
        secret_hash = _hash_secret(secret)
        self.keys[key] = {"user_id": user_id, "name": name, "secret_hash": secret_hash, "created_at": datetime.utcnow()}
        return key, secret

    def validate_key(self, key: str, secret: str) -> int | None:
        """Validate API key and return user_id."""
        if key not in self.keys:
            return None
        key_data = self.keys[key]
        if _hash_secret(secret) != key_data["secret_hash"]:
            return None
        return key_data["user_id"]


def _hash_secret(secret: str) -> str:
    """Hash API secret."""
    import hashlib
    return hashlib.sha256(secret.encode()).hexdigest()


# Singletons
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
csrf_manager = CSRFTokenManager()
api_key_manager = APIKeyManager()
