"""OpenAI-SDK-compatible shim over the Codex Responses client.

The core pipeline (Tier 2 scan and Tier 3 verifier) only ever calls
``client.chat.completions.create(...)``. This shim implements exactly that
surface so the experiment can drive the real pipeline without editing `src/`.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from .client import CodexClient, normalize_model


def _flatten_tools(tools: Optional[List[Dict[str, Any]]]) -> Optional[List[Dict[str, Any]]]:
    """
    Convert OpenAI nested tool schemas into the flat Responses shape.

    Args:
        tools: [{"type":"function","function":{name,description,parameters}}]

    Returns:
        Optional[List[Dict[str, Any]]]: Flat declarations, or None
    """

    if not tools:
        return None
    flat = []
    for tool in tools:
        fn = tool.get("function") if isinstance(tool, dict) else None
        if not fn:
            continue
        flat.append({
            "type": "function",
            "name": fn.get("name", ""),
            "description": fn.get("description", ""),
            "parameters": fn.get("parameters") or {"type": "object", "properties": {}},
        })
    return flat or None


def _to_input_items(messages: List[Dict[str, Any]]) -> (List[Dict[str, Any]], str):
    """
    Convert an OpenAI message list into Responses input items.

    Args:
        messages: Conversation as the agent loop builds it

    Returns:
        tuple: (input items, instructions)
    """

    instructions: List[str] = []
    items: List[Dict[str, Any]] = []

    for message in messages:
        role = message.get("role")
        content = message.get("content")

        if role == "system":
            instructions.append(content or "")
            continue

        if role == "user":
            items.append({
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": content or ""}],
            })
            continue

        if role == "assistant":
            if content:
                items.append({
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": content}],
                })
            for call in message.get("tool_calls") or []:
                fn = (call.get("function") or {}) if isinstance(call, dict) else {}
                items.append({
                    "type": "function_call",
                    "call_id": call.get("id", ""),
                    "name": fn.get("name", ""),
                    "arguments": fn.get("arguments", "") or "{}",
                })
            continue

        if role == "tool":
            items.append({
                "type": "function_call_output",
                "call_id": message.get("tool_call_id", ""),
                "output": content if isinstance(content, str) else json.dumps(content, ensure_ascii=False),
            })

    return items, "\n\n".join(part for part in instructions if part)


class _Usage(SimpleNamespace):
    """Usage object shaped like the OpenAI SDK one."""


class _ChatCompletions:
    def __init__(self, outer: "ShimClient") -> None:
        self._outer = outer

    def create(self, **kwargs: Any) -> Any:
        model = normalize_model(kwargs.get("model", ""))
        messages = kwargs.get("messages") or []
        items, instructions = _to_input_items(messages)

        response = self._outer.codex.create(
            model=model,
            input_items=items,
            instructions=instructions,
            tools=_flatten_tools(kwargs.get("tools")),
            tool_choice=kwargs.get("tool_choice") or "auto",
            reasoning_effort=self._outer.reasoning_effort,
            verbosity=self._outer.verbosity,
        )

        tool_calls = [
            SimpleNamespace(
                id=call["id"],
                type="function",
                function=SimpleNamespace(
                    name=call["name"],
                    arguments=call["arguments"] or "{}",
                ),
            )
            for call in response.tool_calls
        ]

        usage = response.usage or {}
        details = usage.get("output_tokens_details") or {}
        message = SimpleNamespace(
            role="assistant",
            content=response.text or None,
            tool_calls=tool_calls or None,
            reasoning_content=response.reasoning_summary or None,
        )
        choice = SimpleNamespace(
            index=0,
            message=message,
            finish_reason="tool_calls" if tool_calls else "stop",
        )
        usage_obj = _Usage(
            prompt_tokens=usage.get("input_tokens", 0),
            completion_tokens=usage.get("output_tokens", 0),
            total_tokens=usage.get("total_tokens", 0),
            completion_tokens_details=_Usage(
                reasoning_tokens=details.get("reasoning_tokens", 0)
            ),
        )
        return SimpleNamespace(choices=[choice], usage=usage_obj, model=model)


class ShimClient:
    """
    Drop-in replacement for ``openai.Client`` limited to chat.completions.

    Only gpt-6-luna is permitted; other ids raise ValueError so an experiment
    cannot silently drift onto a different model.
    """

    def __init__(self, reasoning_effort: str = "high", verbosity: str = "low", timeout: int = 300):
        self.codex = CodexClient(timeout=timeout)
        self.reasoning_effort = reasoning_effort
        self.verbosity = verbosity
        self.chat = SimpleNamespace(completions=_ChatCompletions(self))
