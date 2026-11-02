"""Reverse Proxy and Upstream Forwarding Handler.

Microservice component forwarding incoming client requests to upstream backends.
Contains Cross-File Server-Side Request Forgery sink (CWE-918).
"""

from typing import Any, Dict, Optional
import requests
import validators


def forward_request(upstream_url: str, params: Optional[Dict[str, Any]] = None, timeout: int = 5) -> Dict[str, Any]:
    """Forward client request to upstream target URL.

    VULNERABILITY: Cross-File SSRF (CWE-918).
    The upstream_url parameter is supplied by client requests in gateway_router.py,
    forwarded without domain allowlist validation, and directly fetched via
    requests.get(upstream_url).
    """
    # Line 22: Untrusted upstream URL request dispatch (Sink)
    # Forward request directly to target
    resp = requests.get(upstream_url, params=params, timeout=timeout)
    return {
        "status_code": resp.status_code,
        "body": resp.text,
    }


def forward_request_safe(upstream_url: str, params: Optional[Dict[str, Any]] = None, timeout: int = 5) -> Dict[str, Any]:
    """Safe counterpart validating destination domain before dispatch."""
    if not validators.validate_upstream_url(upstream_url):
        raise ValueError("Upstream URL rejected: Destination domain not permitted")
    resp = requests.get(upstream_url, params=params, timeout=timeout, allow_redirects=False)
    return {"status_code": resp.status_code, "body": resp.text}
