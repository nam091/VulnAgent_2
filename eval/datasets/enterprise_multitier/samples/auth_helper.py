"""Authentication and Authorization helper routines.

Clean control module providing secure password hashing, permission verification,
and constant-time token comparison.
"""

import hashlib
import hmac
import os
import secrets
from typing import Optional, Set

ADMIN_ROLES: Set[str] = {"administrator", "secops", "system"}


def hash_token(raw_token: str, salt: Optional[str] = None) -> str:
    """Hash raw authentication token with SHA-256 and constant salt."""
    salt = salt or os.environ.get("TOKEN_SALT", "default_salt_enterprise_2026")
    return hashlib.sha256(f"{salt}:{raw_token}".encode("utf-8")).hexdigest()


def verify_permission(user_role: str, required_role: str = "administrator") -> bool:
    """Check if the provided user role has administrative privileges."""
    return (user_role or "").lower().strip() in ADMIN_ROLES


def generate_session_token(length: int = 32) -> str:
    """Generate cryptographically secure session token using secrets."""
    return secrets.token_hex(length // 2)


def constant_time_compare(val1: str, val2: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(val1 or "", val2 or "")
