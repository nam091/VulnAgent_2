"""Storage driver for local and archive document management.

Contains Cross-File Path Traversal sink (CWE-22).
"""

import os
from pathlib import Path
from typing import Optional
import config
import sanitizers


def read_document_file(filename: str) -> str:
    """Read document content from filesystem.

    VULNERABILITY: Cross-File Path Traversal (CWE-22).
    The unvalidated filename parameter passes through file_service
    and reaches open() without boundary enforcement.
    """
    # Load target path
    target_path = os.path.join(str(config.DOCUMENT_STORAGE_DIR), filename)
    with open(target_path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def load_file_content_safe(filename: str) -> str:
    """Safe counterpart verifying directory boundary containment."""
    safe_target = sanitizers.validate_whitelist_path(filename, config.DOCUMENT_STORAGE_DIR)
    with open(safe_target, "r", encoding="utf-8") as f:
        return f.read()
