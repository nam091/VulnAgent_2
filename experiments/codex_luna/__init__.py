"""Experimental Codex transport for gpt-6-luna.

Isolated on purpose: nothing in `src/` imports this package. It exists to run
thesis experiments against the Codex Responses backend, which exposes reasoning
summaries that the 9Router `cx/` alias strips.

Only `gpt-6-luna` is permitted here. Any other model id is rejected.
"""

from .auth import CodexAuthError, get_credentials
from .client import CodexClient, CodexResponse, normalize_model
from .openai_shim import ShimClient

__all__ = [
    "CodexAuthError",
    "get_credentials",
    "CodexClient",
    "CodexResponse",
    "ShimClient",
    "normalize_model",
]
