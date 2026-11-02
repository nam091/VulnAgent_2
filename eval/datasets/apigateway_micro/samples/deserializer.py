"""Binary and State Deserialization Service.

Microservice handler responsible for restoring session state and cached objects.
Contains Cross-File Insecure Deserialization sink (CWE-502).
"""

import base64
import json
import pickle
from typing import Any, Dict, Optional


def deserialize_session_payload(payload: bytes) -> Any:
    """Deserialize binary session state or cached payload using Python pickle.

    VULNERABILITY: Cross-File Insecure Deserialization (CWE-502).
    The untrusted binary payload is provided by HTTP clients via gateway_router.py
    and passed directly to pickle.loads(), allowing arbitrary object instantiation
    and remote code execution via __reduce__ exploitation.
    """
    return pickle.loads(payload)


def deserialize_from_base64(base64_string: str) -> Any:
    """Decode base64 string and deserialize payload."""
    raw_bytes = base64.b64decode(base64_string)
    # Line 27: Calling deserialize_session_payload
    return deserialize_session_payload(raw_bytes)


def deserialize_session_safe(payload_str: str) -> Dict[str, Any]:
    """Safe counterpart deserializing session data from standard JSON format."""
    if not payload_str or not isinstance(payload_str, str):
        return {}
    return json.loads(payload_str)
