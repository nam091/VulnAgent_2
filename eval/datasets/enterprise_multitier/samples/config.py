"""Global enterprise application configuration module.

Declares immutable application constants, database connection settings,
directory paths, and network allowlists for downstream layers.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATIC_ROOT = BASE_DIR / "static"
DOCUMENT_STORAGE_DIR = BASE_DIR / "documents"
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///enterprise.db")
BACKUP_ARCHIVE_DIR = BASE_DIR / "backups"

# Strict network allowlists for safe webhooks
ALLOWED_WEBHOOK_DOMAINS = [
    "api.partner.corp",
    "webhooks.internal.corp",
    "notifications.enterprise.com",
]

# Max upload limits
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024
DEFAULT_QUERY_TIMEOUT_SECONDS = 30
