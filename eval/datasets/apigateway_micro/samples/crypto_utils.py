"""Cryptographic verification and token generation routines.

Clean control module providing secure HMAC checks and random token generation.
"""

import hashlib
import hmac
import secrets


def generate_hmac_signature(secret_key: str, message: str) -> str:
    """Generate HMAC-SHA256 signature for message payload."""
    return hmac.new(
        secret_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def verify_hmac_signature(secret_key: str, message: str, signature: str) -> bool:
    """Verify HMAC signature using constant-time digest comparison."""
    if not signature:
        return False
    expected = generate_hmac_signature(secret_key, message)
    return hmac.compare_digest(expected, signature)


def generate_secure_token(nbytes: int = 16) -> str:
    """Generate cryptographically secure hexadecimal token."""
    return secrets.token_hex(nbytes)
