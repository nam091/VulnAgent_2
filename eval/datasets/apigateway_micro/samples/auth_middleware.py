"""Authentication & Authorization Middleware Module.

Clean control module verifying authorization headers, extracting bearer tokens,
and checking authentication before routing requests to microservices.
"""

import os
from typing import Any, Dict, Optional
import crypto_utils

DEFAULT_API_KEY = "valid-gateway-secret-token"
AUTH_HEADER = "Authorization"


def extract_bearer_token(headers: Dict[str, Any]) -> Optional[str]:
    """Extract Bearer token string from HTTP Authorization header."""
    if not headers or not isinstance(headers, dict):
        return None
    auth_val = headers.get(AUTH_HEADER) or headers.get(AUTH_HEADER.lower())
    if not auth_val or not isinstance(auth_val, str):
        return None
    parts = auth_val.strip().split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def verify_auth_token(token: Optional[str], expected_token: str = DEFAULT_API_KEY) -> bool:
    """Validate Bearer token using constant-time comparison against expected key."""
    if not token or not isinstance(token, str):
        return False
    return crypto_utils.hmac.compare_digest(token.strip(), expected_token.strip())


def authenticate_gateway_request(headers: Dict[str, Any]) -> bool:
    """Verify that incoming request has valid bearer authentication."""
    token = extract_bearer_token(headers)
    return verify_auth_token(token)
