"""Streaming client for the ChatGPT Codex Responses endpoint.

The endpoint differs from chat/completions in three ways that matter here:

* reasoning is requested with ``reasoning: {effort, summary}`` rather than
  ``reasoning_effort``; the server may upgrade ``summary`` to ``detailed``;
* the readable chain-of-thought arrives only as ``reasoning_summary_text.delta``
  events, because ``reasoning.encrypted_content`` is opaque;
* tools are declared flat (``{type, name, parameters}``) and results travel back
  as ``function_call_output`` items instead of ``role: tool`` messages.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from .auth import CodexAuthError, get_credentials

ENDPOINT = "https://chatgpt.com/backend-api/codex/responses"

#: The only model this experiment is allowed to call.
ALLOWED_MODEL = "gpt-6-luna"


def normalize_model(model: str) -> str:
    """
    Map router aliases onto the bare Codex model id.

    Args:
        model: e.g. "cx/gpt-6-luna" or "gpt-6-luna"

    Returns:
        str: "gpt-6-luna"

    Raises:
        ValueError: For any other model id
    """

    bare = re.split(r"[/:]", (model or "").strip())[-1]
    bare = bare.replace("[1m]", "")
    if bare != ALLOWED_MODEL:
        raise ValueError(
            f"Codex transport only permits {ALLOWED_MODEL!r}; got {model!r}"
        )
    return bare


@dataclass
class CodexResponse:
    """One completed turn."""

    text: str = ""
    reasoning_summary: str = ""
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    usage: Dict[str, Any] = field(default_factory=dict)
    reasoning_meta: Dict[str, Any] = field(default_factory=dict)
    output_items: List[Dict[str, Any]] = field(default_factory=list)
    encrypted_reasoning: str = ""


class CodexClient:
    """Minimal streaming client. One instance per process is enough."""

    def __init__(self, timeout: int = 300) -> None:
        self.timeout = timeout
        self._access = ""
        self._account = ""

    def _headers(self) -> Dict[str, str]:
        if not self._access:
            self._access, self._account = get_credentials()
        return {
            "Authorization": f"Bearer {self._access}",
            "chatgpt-account-id": self._account,
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "OpenAI-Beta": "responses=experimental",
            "originator": "pi",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "Chrome/131.0 Safari/537.36"
            ),
        }

    def create(
        self,
        model: str,
        input_items: Iterable[Dict[str, Any]],
        instructions: str = "",
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: str = "auto",
        reasoning_effort: str = "high",
        verbosity: str = "low",
    ) -> CodexResponse:
        """
        Send one turn and collect the stream.

        Args:
            model: Only gpt-6-luna is accepted
            input_items: Responses API input items
            instructions: System-level instructions
            tools: Flat Responses tool declarations
            tool_choice: "auto" or "none"
            reasoning_effort: low | medium | high
            verbosity: text verbosity hint

        Returns:
            CodexResponse: Text, reasoning summary, tool calls and usage

        Raises:
            CodexAuthError: Credential problems
            RuntimeError: Transport failure with the server message attached
        """

        bare = normalize_model(model)
        payload: Dict[str, Any] = {
            "model": bare,
            "store": False,
            "stream": True,
            "instructions": instructions or "You are a helpful assistant.",
            "input": list(input_items),
            "reasoning": {"effort": reasoning_effort, "summary": "auto"},
            "include": ["reasoning.encrypted_content"],
            "text": {"verbosity": verbosity},
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            ENDPOINT, data=body, headers=self._headers(), method="POST"
        )

        result = CodexResponse()
        summary_parts: List[str] = []
        text_parts: List[str] = []
        pending_calls: Dict[str, Dict[str, Any]] = {}

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                for raw in resp:
                    line = raw.decode("utf-8", "replace").strip()
                    if not line.startswith("data:"):
                        continue
                    blob = line[5:].strip()
                    if blob == "[DONE]":
                        break
                    try:
                        event = json.loads(blob)
                    except json.JSONDecodeError:
                        continue
                    self._consume(event, result, summary_parts, text_parts, pending_calls)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            if exc.code in (401, 403):
                self._access = ""
                raise CodexAuthError(f"Codex rejected the session ({exc.code}): {detail}") from exc
            raise RuntimeError(f"Codex HTTP {exc.code}: {detail}") from exc

        result.text = "".join(text_parts)
        result.reasoning_summary = "".join(summary_parts).strip()
        result.tool_calls = [
            {"id": call_id, **call} for call_id, call in pending_calls.items()
        ]
        return result

    @staticmethod
    def _consume(
        event: Dict[str, Any],
        result: CodexResponse,
        summary_parts: List[str],
        text_parts: List[str],
        pending_calls: Dict[str, Dict[str, Any]],
    ) -> None:
        etype = event.get("type", "")

        if etype == "response.reasoning_summary_text.delta":
            summary_parts.append(event.get("delta", ""))
        elif etype == "response.output_text.delta":
            text_parts.append(event.get("delta", ""))
        elif etype == "response.output_item.added":
            item = event.get("item") or {}
            if item.get("type") == "reasoning" and item.get("encrypted_content"):
                result.encrypted_reasoning = item["encrypted_content"]
            if item.get("type") == "function_call":
                pending_calls[item.get("call_id", item.get("id", ""))] = {
                    "name": item.get("name", ""),
                    "arguments": item.get("arguments", "") or "",
                }
        elif etype == "response.function_call_arguments.delta":
            call_id = event.get("item_id") or event.get("call_id") or ""
            if call_id in pending_calls:
                pending_calls[call_id]["arguments"] += event.get("delta", "")
        elif etype == "response.output_item.done":
            item = event.get("item") or {}
            if item.get("type") == "function_call":
                call_id = item.get("call_id", item.get("id", ""))
                pending_calls[call_id] = {
                    "name": item.get("name", ""),
                    "arguments": item.get("arguments", "") or "",
                }
            result.output_items.append(item)
        elif etype == "response.completed":
            response = event.get("response") or {}
            usage = response.get("usage") or {}
            result.usage = usage
            result.reasoning_meta = response.get("reasoning") or {}
