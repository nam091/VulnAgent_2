"""Network integration client for enterprise webhooks and external APIs.

Contains Cross-File Server-Side Request Forgery sink (CWE-918).
"""

from typing import Any, Dict, Optional
import requests
import config


def fetch_remote_webhook(target_url: str) -> Dict[str, Any]:
    """Fetch remote payload or trigger outbound webhook notification.

    VULNERABILITY: Cross-File SSRF (CWE-918).
    The target_url parameter is supplied by client requests in controllers.py,
    passed via notification dispatcher, and directly consumed by requests.get()
    without domain allowlisting or internal IP check.
    """
    # Line 20: Untrusted URL dispatch allows SSRF against internal services (Sink)
    resp = requests.get(target_url, timeout=10)
    return {
        "status_code": resp.status_code,
        "content": resp.text[:500],
    }


def dispatch_webhook_safe(target_url: str) -> Dict[str, Any]:
    """Safe counterpart verifying destination domain against approved allowlist."""
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    if parsed.netloc not in config.ALLOWED_WEBHOOK_DOMAINS:
        raise ValueError(f"Prohibited webhook domain: {parsed.netloc}")
    resp = requests.get(target_url, timeout=10, allow_redirects=False)
    return {"status_code": resp.status_code, "content": resp.text[:500]}
