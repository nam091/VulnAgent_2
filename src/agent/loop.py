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
import re
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
        temperature: Optional[float] = 0,
        evidence_store: Optional[Any] = None,
        snapshot_id: Optional[str] = None,
    ) -> None:
        """
        Args:
            client: An OpenAI-compatible client
            model: Model identifier
            dispatch: Callable that executes a tool by name
            tool_schemas: Tool definitions in OpenAI function-calling format
            max_turns: Maximum model turns before the loop gives up
            temperature: Sampling temperature, or None to omit the parameter
            evidence_store: Optional EvidenceStore for recording read evidence
            snapshot_id: Optional snapshot identifier
        """

        self.client = client
        self.model = model
        self.dispatch = dispatch
        self.tool_schemas = tool_schemas
        self.max_turns = max(1, max_turns)
        self.temperature = temperature
        self.evidence_store = evidence_store
        self.snapshot_id = snapshot_id

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

                reads = self._process_tool_result_and_reads(name, arguments, result)

                # Remove internal raw_lines helper before serializing to model payload
                if isinstance(result, dict):
                    result.pop("raw_lines", None)
                    if "definitions" in result and isinstance(result["definitions"], list):
                        for d in result["definitions"]:
                            if isinstance(d, dict):
                                d.pop("raw_lines", None)

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
                    reads = []

                run.successful_reads.extend(reads)

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

    def _process_tool_result_and_reads(
        self,
        name: str,
        arguments: Dict[str, Any],
        result: Any
    ) -> List[Dict[str, Any]]:
        """
        Extract and record actual code evidence delivered to the model,
        ensuring line ranges strictly reflect visible content after truncation.
        """
        if not isinstance(result, dict) or "error" in result:
            return []

        reads: List[Dict[str, Any]] = []

        if name == "read_lines":
            content = result.get("content")
            if not isinstance(content, str) or not content.strip():
                return []

            raw_lines = result.get("raw_lines") or []
            # Truncate line-by-line so recorded range strictly reflects what model sees (P1 bug 3)
            if len(content) > MAX_TOOL_RESULT_CHARS:
                body_lines = content.split("\n")
                kept_body = []
                kept_raw = []
                curr_len = 0
                has_raw_match = len(raw_lines) == len(body_lines)
                for idx, bline in enumerate(body_lines):
                    rline = raw_lines[idx] if has_raw_match else ""
                    if curr_len + len(bline) + 1 > MAX_TOOL_RESULT_CHARS:
                        break
                    kept_body.append(bline)
                    kept_raw.append(rline)
                    curr_len += len(bline) + 1

                if not kept_body and body_lines:
                    kept_body.append(body_lines[0][:MAX_TOOL_RESULT_CHARS])
                    if raw_lines:
                        kept_raw.append(raw_lines[0][:MAX_TOOL_RESULT_CHARS])

                result["content"] = "\n".join(kept_body) + "\n... [truncated]"
                result["truncated"] = True
                content = result["content"]
                raw_lines = kept_raw

            # Extract line numbers strictly present in the delivered output
            visible_line_nums = [
                int(m.group(1))
                for m in re.finditer(r"^\s*(\d+)\s*\|", content, re.MULTILINE)
            ]
            if visible_line_nums:
                actual_start = min(visible_line_nums)
                actual_end = max(visible_line_nums)
                result["start_line"] = actual_start
                result["end_line"] = actual_end

                target_path = result.get("path") or arguments.get("path") or ""
                evidence_id = ""
                if self.evidence_store and self.snapshot_id and target_path:
                    rec = self.evidence_store.record_evidence(
                        snapshot_id=self.snapshot_id,
                        path=target_path,
                        start_line=actual_start,
                        end_line=actual_end,
                        content="\n".join(raw_lines) if raw_lines else None,
                        origin="read_lines",
                    )
                    evidence_id = rec.evidence_id if rec.read_succeeded else ""

                reads.append({
                    "tool": name,
                    "path": target_path,
                    "start_line": actual_start,
                    "end_line": actual_end,
                    "evidence_id": evidence_id,
                })

        elif name == "find_definition":
            if result.get("found") is True and result.get("definitions"):
                for d in result["definitions"]:
                    dfile = d.get("file")
                    dstart = d.get("start_line")
                    dend = d.get("end_line")
                    dsource = d.get("source", "")
                    draw = d.get("raw_lines", [])
                    if dfile and dstart is not None and dend is not None:
                        vis_lines = [
                            int(m.group(1))
                            for m in re.finditer(r"^\s*(\d+)\s*\|", dsource, re.MULTILINE)
                        ]
                        start_line = min(vis_lines) if vis_lines else dstart
                        end_line = max(vis_lines) if vis_lines else dend

                        evidence_id = ""
                        if self.evidence_store and self.snapshot_id:
                            rec = self.evidence_store.record_evidence(
                                snapshot_id=self.snapshot_id,
                                path=dfile,
                                start_line=start_line,
                                end_line=end_line,
                                content="\n".join(draw) if draw else None,
                                origin="find_definition",
                            )
                            evidence_id = rec.evidence_id if rec.read_succeeded else ""

                        reads.append({
                            "tool": name,
                            "path": dfile,
                            "start_line": start_line,
                            "end_line": end_line,
                            "evidence_id": evidence_id,
                        })

        elif name == "search":
            matches = result.get("matches")
            if isinstance(matches, list) and matches:
                for m in matches:
                    mfile = m.get("file")
                    mline = m.get("line")
                    mtext = m.get("text", "")
                    if mfile and mline:
                        evidence_id = ""
                        if self.evidence_store and self.snapshot_id:
                            rec = self.evidence_store.record_evidence(
                                snapshot_id=self.snapshot_id,
                                path=mfile,
                                start_line=mline,
                                end_line=mline,
                                content=mtext,
                                origin="search",
                            )
                            evidence_id = rec.evidence_id if rec.read_succeeded else ""

                        reads.append({
                            "tool": name,
                            "path": mfile,
                            "start_line": mline,
                            "end_line": mline,
                            "evidence_id": evidence_id,
                        })

        return reads

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
