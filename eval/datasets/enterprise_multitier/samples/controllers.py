"""Web controllers and API endpoint handlers.

Acts as untrusted taint sources receiving HTTP requests (request.args, request.form).
"""

from typing import Any, Dict, Optional
import user_service
import file_service
import network_client


class MockHttpRequest:
    """HTTP request wrapper for demonstration."""
    def __init__(self, args: Optional[Dict[str, Any]] = None, form: Optional[Dict[str, Any]] = None):
        self.args = args or {}
        self.form = form or {}


def query_user_handler(request: MockHttpRequest) -> Dict[str, Any]:
    """Handle user search HTTP requests.
    Source: request.args.get('username')
    """
    # Line 36: Untrusted taint source
    untrusted_username = request.args.get("username", "")
    users = user_service.find_users_by_name(untrusted_username)
    return {"count": len(users), "results": users}


def download_file_handler(request: MockHttpRequest) -> str:
    """Handle document download HTTP requests.
    Source: request.args.get('filename')
    """
    # Line 54: Untrusted taint source
    untrusted_filename = request.args.get("filename", "")
    return file_service.retrieve_document(untrusted_filename)


def webhook_trigger_handler(request: MockHttpRequest) -> Dict[str, Any]:
    """Handle outbound webhook dispatch requests.
    Source: request.form.get('target_url')
    """
    # Line 74: Untrusted taint source
    untrusted_url = request.form.get("target_url", "")
    return network_client.fetch_remote_webhook(untrusted_url)


def backup_handler(request: MockHttpRequest) -> Dict[str, Any]:
    """Handle maintenance backup requests.
    Source: request.form.get('backup_dir')
    """
    # Line 95: Untrusted taint source
    untrusted_dir = request.form.get("backup_dir", "")
    return user_service.trigger_user_backup(untrusted_dir)
