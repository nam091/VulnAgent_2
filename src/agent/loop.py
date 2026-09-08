"""A bounded tool-calling loop over an OpenAI-compatible chat API.

This is the piece that makes the LLM tier an agent rather than a single
prompt: the model can ask to read code, receive it, and decide what to look
at next before committing to an answer.

The loop is deliberately bounded. An analysis agent that can call tools
indefinitely will, and each turn costs a request; `max_turns` caps the
investigation and the loop reports when it hit the cap rather than
presenting a truncated investigation as a finished one.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

MAX_TOOL_RESULT_CHARS = 6_000


@dataclass
class AgentRun:
    """
    The outcome of one agent conversation.
    """

    text: str = ""
    turns: int = 0
    tool_calls: int = 0
    hit_turn_cap: bool = False
    tools_unsupported: bool = False
    transcript: List[Dict[str, Any]] = field(default_factory=list)
    successful_reads: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def investigated(self) -> bool:
        """
        Whether the agent actually gathered evidence rather than answering blind.
        Requires at least one tool read/inspection to succeed without error.

        Returns:
            bool: True when at least one read succeeded without error
        """

        return len(self.successful_reads) > 0


class ToolCallingAgent:
    """
    Drives a chat model through a bounded read-investigate-answer loop.
    """

    def __init__(
        self,
        client: Any,
        model: str,
        dispatch: Callable[[str, Dict[str, Any]], Dict[str, Any]],
        tool_schemas: List[Dict[str, Any]],
        max_turns: int = 6,
        temperature: Optional[float] = 0
    ) -> None:
        """
        Args:
            client: An OpenAI-compatible client
            model: Model identifier
            dispatch: Callable that executes a tool by name
            tool_schemas: Tool definitions in OpenAI function-calling format
            max_turns: Maximum model turns before the loop gives up
            temperature: Sampling temperature, or None to omit the parameter
        """

        self.client = client
        self.model = model
        self.dispatch = dispatch
        self.tool_schemas = tool_schemas
        self.max_turns = max(1, max_turns)
        self.temperature = temperature

    async def run(
        self,
        system_prompt: str,
        user_prompt: str
    ) -> AgentRun:
        """
        Run the loop until the model answers without requesting a tool.

        Args:
            system_prompt: System message
            user_prompt: Initial user message

        Returns:
            AgentRun: Final text plus what the agent did to reach it
        """

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        run = AgentRun()

        for turn in range(self.max_turns):
            run.turns = turn + 1
            try:
                message = await self._complete(messages, with_tools=not run.tools_unsupported)
            except _ToolsUnsupported:
                # Some OpenAI-compatible providers reject the tools parameter.
                # Degrade to a single-shot answer rather than failing outright,
                # and record it so results are never silently non-agentic.
                logging.warning(
                    "Provider rejected tool calling; falling back to single-shot analysis"
                )
                run.tools_unsupported = True
                message = await self._complete(messages, with_tools=False)

            tool_calls = getattr(message, "tool_calls", None)
            if not tool_calls:
                run.text = message.content or ""
                return run

            messages.append(self._assistant_message(message, tool_calls))

            call_signatures: Set[str] = set()
            for call in tool_calls:
                name, arguments = self._parse_call(call)
                arg_key = f"{name}:{json.dumps(arguments, sort_keys=True)}"

                if arg_key in call_signatures:
                    result = {
                        "error": "Duplicate tool call with identical arguments in the same turn. Proceed with analysis."
                    }
                else:
                    call_signatures.add(arg_key)
                    try:
                        result = self.dispatch(name, arguments)
                    except Exception as e:
                        logging.debug(f"Tool {name} dispatch raised: {e}")
                        result = {"error": f"Tool '{name}' failed: {e}"}

                run.tool_calls += 1
                run.transcript.append({"tool": name, "args": arguments})

                # Record successful reads when tool executes without error (P1 requirement)
                if isinstance(result, dict) and "error" not in result:
                    res_path = result.get("path") or arguments.get("path") or arguments.get("file") or ""
                    read_entry = {
                        "tool": name,
                        "path": str(res_path),
                        "start_line": int(result.get("start_line", result.get("line", arguments.get("start_line", 1)))),
                        "end_line": int(result.get("end_line", result.get("line", arguments.get("end_line", result.get("start_line", 1))))),
                    }
                    run.successful_reads.append(read_entry)

                # Ensure result is safely truncated without breaking JSON structure
                if isinstance(result, dict) and "content" in result and isinstance(result["content"], str):
                    if len(result["content"]) > MAX_TOOL_RESULT_CHARS:
                        result["content"] = result["content"][:MAX_TOOL_RESULT_CHARS] + "\n... [truncated]"
                        result["truncated"] = True

                payload = json.dumps(result, ensure_ascii=False, default=str)
                if len(payload) > MAX_TOOL_RESULT_CHARS + 500:
                    payload = json.dumps({
                        "note": "Tool output too large; truncated",
                        "summary": str(result)[:MAX_TOOL_RESULT_CHARS] + "..."
                    })

                messages.append({
                    "role": "tool",
                    "tool_call_id": getattr(call, "id", None) or name,
                    "content": payload,
                })

        # Out of turns. Ask once more, without tools, so the agent has to
        # commit to a conclusion from what it already gathered.
        run.hit_turn_cap = True
        messages.append({
            "role": "user",
            "content": (
                "You have used your investigation budget. Give your final answer now "
                "using only what you have already read. Do not request more tools."
            ),
        })
        try:
            message = await self._complete(messages, with_tools=False)
            run.text = message.content or ""
        except Exception as e:
            logging.error(f"Agent failed on final turn: {e}")
            run.text = ""
        return run

    async def _complete(self, messages: List[Dict[str, Any]], with_tools: bool) -> Any:
        """
        Make one chat completion request.

        Args:
            messages: Conversation so far
            with_tools: Whether to advertise the tool schemas

        Returns:
            Any: The assistant message

        Raises:
            _ToolsUnsupported: When the provider rejects tool calling
        """

        kwargs: Dict[str, Any] = {"model": self.model, "messages": messages}
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if with_tools and self.tool_schemas:
            kwargs["tools"] = self.tool_schemas
            kwargs["tool_choice"] = "auto"

        # Synchronous client: run it off-thread or every agent turn stalls
        # the event loop and the "concurrent" verification runs serially.
        try:
            response = await asyncio.to_thread(
                lambda: self.client.chat.completions.create(**kwargs)
            )
        except Exception as e:
            text = str(e).lower()
            if with_tools and ("tool" in text or "function" in text):
                raise _ToolsUnsupported(str(e))
            if "temperature" in text and self.temperature is not None:
                kwargs.pop("temperature", None)
                response = await asyncio.to_thread(
                    lambda: self.client.chat.completions.create(**kwargs)
                )
                return response.choices[0].message
            raise

        return response.choices[0].message

    @staticmethod
    def _assistant_message(message: Any, tool_calls: Any) -> Dict[str, Any]:
        """
        Re-encode an assistant tool-call message for the next request.

        Args:
            message: The assistant message object
            tool_calls: Its tool calls

        Returns:
            Dict[str, Any]: A plain dictionary the API will accept back
        """

        return {
            "role": "assistant",
            "content": message.content or "",
            "tool_calls": [
                {
                    "id": getattr(call, "id", None) or f"call_{index}",
                    "type": "function",
                    "function": {
                        "name": call.function.name,
                        "arguments": call.function.arguments or "{}",
                    },
                }
                for index, call in enumerate(tool_calls)
            ],
        }

    @staticmethod
    def _parse_call(call: Any) -> Tuple[str, Dict[str, Any]]:
        """
        Extract a tool name and arguments from a model tool call.

        Args:
            call: The tool call object

        Returns:
            Tuple[str, Dict[str, Any]]: Name and parsed arguments
        """

        name = call.function.name
        raw = call.function.arguments or "{}"
        try:
            arguments = json.loads(raw)
        except json.JSONDecodeError:
            logging.debug(f"Model sent unparseable arguments for {name}: {raw[:200]}")
            arguments = {}
        if not isinstance(arguments, dict):
            arguments = {}
        return name, arguments


class _ToolsUnsupported(RuntimeError):
    """Raised when the provider does not accept the tools parameter."""
