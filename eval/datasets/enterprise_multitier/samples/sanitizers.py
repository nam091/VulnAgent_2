"""Defensive sanitization and validation helper module.

Contains robust input sanitizers, integer boundary checks, and strict
allowlist validators protecting downstream services against injection defects.
"""

import os
import re
from pathlib import Path
from typing import Optional, Set


def safe_int_cast(val: Optional[str], default: int = 0) -> int:
    """Safely cast user input to an integer to prevent SQL injection in numeric fields."""
    if not val:
        return default
    try:
        return int(val.strip())
    except (ValueError, TypeError):
        return default


def validate_whitelist_path(user_filename: str, base_directory: Path) -> Path:
    """Normalize and verify that user_filename resides strictly inside base_directory."""
    clean_name = os.path.basename(user_filename.strip())
    resolved_target = (base_directory / clean_name).resolve()
    resolved_base = base_directory.resolve()
    if not resolved_target.is_relative_to(resolved_base):
        raise PermissionError(f"Directory traversal detected: {user_filename}")
    return resolved_target


def escape_markup(text: str) -> str:
    """Escape HTML metacharacters to neutralize Cross-Site Scripting (XSS)."""
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def sanitize_alphanumeric(input_val: str) -> str:
    """Strip all non-alphanumeric characters for safe command/query interpolation."""
    return re.sub(r"[^a-zA-Z0-9_-]", "", input_val or "")
