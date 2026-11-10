"""Credential handling for the Codex Responses transport.

The access token is a live ChatGPT session credential. It is read from Pi's
auth store, refreshed in place when close to expiry, and never logged.

Refresh requires an OAuth client id. Older auth stores may not contain one; in
that case refresh cannot be attempted and the caller must sign in again.
"""

from __future__ import annotations

import json
import os
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Tuple

DEFAULT_AUTH_PATH = Path(r"C:\Users\Knowm\.pi\agent\auth.json")
TOKEN_URL = "https://auth.openai.com/api/accounts/oauth/token"
RESOURCE = "https://api.openai.com/v1"
DIRECT_SCOPE = "chatgpt.tokens.use.direct"
EXPIRY_MARGIN_SECONDS = 180


class CodexAuthError(RuntimeError):
    """Raised when Codex credentials are missing, expired or unusable."""


def auth_path() -> Path:
    """
    Where the auth store lives.

    Returns:
        Path: Overridable with VULNAGENT_CODEX_AUTH
    """

    env = os.getenv("VULNAGENT_CODEX_AUTH")
    return Path(env) if env else DEFAULT_AUTH_PATH


def _load_store(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CodexAuthError(f"Auth store not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CodexAuthError(f"Auth store is not valid JSON: {path}") from exc


def _expired(credential: Dict[str, Any]) -> bool:
    expires = credential.get("expires")
    if not isinstance(expires, (int, float)):
        return True
    return (expires / 1000.0) - EXPIRY_MARGIN_SECONDS <= time.time()


def _refresh(credential: Dict[str, Any]) -> Dict[str, Any]:
    """
    Exchange the refresh token for a new access token.

    Args:
        credential: The stored openai-codex credential block

    Returns:
        Dict[str, Any]: Updated credential

    Raises:
        CodexAuthError: When the store lacks a client id or the server refuses
    """

    client_id = credential.get("clientId")
    if not client_id:
        raise CodexAuthError(
            "Stored openai-codex credential has no clientId, so the refresh token "
            "cannot be exchanged. Sign in to ChatGPT again to regenerate the token."
        )

    body = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": credential["refresh"],
        "resource": RESOURCE,
    }).encode()

    req = urllib.request.Request(
        TOKEN_URL,
        data=body,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise CodexAuthError(f"Token refresh failed ({exc.code}): {detail}") from exc
    except Exception as exc:  # noqa: BLE001 - surfaced verbatim to the operator
        raise CodexAuthError(f"Token refresh failed: {exc}") from exc

    scope = str(payload.get("scope", ""))
    if DIRECT_SCOPE not in scope:
        raise CodexAuthError(
            f"Refreshed grant is missing the required scope {DIRECT_SCOPE}; sign in again."
        )

    expires_in = payload.get("expires_in")
    if not isinstance(expires_in, (int, float)) or expires_in <= 0:
        raise CodexAuthError("Token refresh response has no usable expires_in")

    return {
        **credential,
        "access": payload["access_token"],
        "refresh": payload.get("refresh_token") or credential["refresh"],
        "expires": int(time.time() * 1000 + expires_in * 1000 - EXPIRY_MARGIN_SECONDS * 1000),
    }


def _save_store(path: Path, store: Dict[str, Any]) -> None:
    backup = path.with_suffix(path.suffix + ".bak")
    try:
        shutil.copy2(path, backup)
    except OSError:
        pass
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(store, indent=2), encoding="utf-8")
    tmp.replace(path)


def get_credentials(allow_refresh: bool = True) -> Tuple[str, str]:
    """
    Return a usable access token and account id.

    Args:
        allow_refresh: Attempt a refresh when the stored token is near expiry

    Returns:
        Tuple[str, str]: (access token, account id)

    Raises:
        CodexAuthError: When no usable credential can be produced
    """

    path = auth_path()
    store = _load_store(path)
    credential = store.get("openai-codex")
    if not isinstance(credential, dict) or not credential.get("access"):
        raise CodexAuthError("Auth store has no usable openai-codex access token")

    if _expired(credential):
        if not allow_refresh:
            raise CodexAuthError("openai-codex access token is expired")
        credential = _refresh(credential)
        store["openai-codex"] = credential
        _save_store(path, store)

    account = credential.get("accountId") or ""
    if not account:
        raise CodexAuthError("openai-codex credential has no accountId")

    return credential["access"], account


def seconds_remaining() -> float:
    """
    How long the current access token stays valid.

    Returns:
        float: Seconds, negative when already expired
    """

    store = _load_store(auth_path())
    credential = store.get("openai-codex") or {}
    expires = credential.get("expires")
    if not isinstance(expires, (int, float)):
        return -1.0
    return expires / 1000.0 - time.time()
