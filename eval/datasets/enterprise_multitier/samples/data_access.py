"""Database access layer and query executor.

Performs relational database queries and transactions.
Contains Cross-File SQL Injection sink (CWE-89).
"""

import sqlite3
from typing import Any, Dict, List, Optional
import config


def get_db_connection() -> sqlite3.Connection:
    """Create a new SQLite connection."""
    conn = sqlite3.connect("enterprise.db")
    conn.row_factory = sqlite3.Row
    return conn


def execute_raw_user_query(username: str) -> List[Dict[str, Any]]:
    """Query user records by username.

    VULNERABILITY: Cross-File SQL Injection (CWE-89).
    The untrusted username parameter originates from controllers.py,
    passes through user_service.py without parameterized escaping, and is directly
    interpolated into the SQL statement via an f-string at cursor.execute().
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    # Execute query directly
    cursor.execute(f"SELECT id, username, email, role FROM users WHERE username = '{username}'")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def query_user_by_id_safe(user_id: int) -> Optional[Dict[str, Any]]:
    """Safe counterpart using parameterized query bindings."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None
