"""URL and markup validation routines.

Clean control module providing domain allowlisting, scheme validation,
and HTML markup escaping.
"""

from urllib.parse import urlparse
import html
from typing import Set

ALLOWED_DOMAINS: Set[str] = {"api.internal.corp", "sub.partner.api.com", "services.internal.net"}
ALLOWED_SCHEMES: Set[str] = {"https", "http"}


def is_valid_url_scheme(url: str) -> bool:
    """Validate that URL uses http or https scheme."""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url.strip())
        return parsed.scheme in ALLOWED_SCHEMES
    except Exception:
        return False


def is_whitelisted_domain(url: str) -> bool:
    """Verify that URL host belongs to the authorized domain whitelist."""
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url.strip())
        return parsed.netloc in ALLOWED_DOMAINS
    except Exception:
        return False


def validate_upstream_url(url: str) -> bool:
    """Validate both scheme and domain allowlist for upstream requests."""
    return is_valid_url_scheme(url) and is_whitelisted_domain(url)


def sanitize_html(text: str) -> str:
    """Escape HTML metacharacters to prevent markup injection."""
    if not text:
        return ""
    return html.escape(text)
