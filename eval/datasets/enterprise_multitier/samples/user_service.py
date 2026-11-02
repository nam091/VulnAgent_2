"""User management business service layer.

Acts as intermediate propagation layer receiving taint from controllers
and forwarding to data_access or task_executor.
"""

from typing import Any, Dict, List
import data_access
import task_executor


def find_users_by_name(raw_username: str) -> List[Dict[str, Any]]:
    """Query users by username, propagating untrusted input to data_access."""
    # Line 14: Taint propagation to data_access
    return data_access.execute_raw_user_query(raw_username)


def trigger_user_backup(requested_path: str) -> Dict[str, Any]:
    """Trigger archive backup job for user data directory, propagating taint."""
    # Line 34: Taint propagation to task_executor
    return task_executor.execute_maintenance_backup(requested_path)
