"""Decide whether a candidate attack chain is one an attacker could walk.

The heuristic that proposes chains works from a small hand-written table of
escalation patterns plus locality. That table covers five source types out of
sixty, so most real chains are outside it, and locality lets unrelated
findings that happen to sit near each other look connected.

Neither problem is fixable by adding rows to the table: whether a defect can
be used to reach another is a question about what an attacker can do with
the code, not about which categories the two findings belong to. So the
heuristic is left to propose candidates cheaply, and this asks a model to
throw out the ones that make no sense - which works for any pair of types,
including combinations nobody wrote a rule for.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from agent.loop import ToolCallingAgent
from agent.tools import TOOL_SCHEMAS, CodeTools
from models.vulnerability import Vulnerability, VulnerabilityChain

SYSTEM_PROMPT = """You judge whether a proposed attack chain is real.

A chain is real when an attacker can use one weakness to reach or worsen
another: the first gives them access, data, or control that the second needs.
Two weaknesses sitting in the same file, or sharing a topic, are NOT a chain.

Examples of a real chain:
  - SQL injection leaks a password hash, which enables authentication bypass
  - Path traversal reads a config file, which exposes the key used to sign
    session tokens
  - Deserialization gives code execution, which reaches a command sink

Examples of things that are NOT a chain:
  - Two injections in unrelated handlers, exploitable independently
  - A weak hash and a missing log statement in the same function
  - Anything where step two is exploitable on its own without step one

Use the tools to read the code before deciding. Judge what an attacker can
actually do, not whether the categories sound related.

Answer with ONLY a JSON object, no prose and no code fence:

{
  "is_real_chain": true | false,
  "reason": "one or two sentences on why it does or does not chain",
  "attack_narrative": "if real: the concrete steps an attacker takes, in order",
  "ordered_steps": [0, 1],
  "confidence": 0.0
}

ordered_steps lists the finding indexes in the order an attacker would use
them, which is not necessarily the order given. Leave it [] when not real.
confidence is 0.0-1.0. Default to is_real_chain=false when unsure: reporting
a chain that does not exist wastes the reader's attention on a fiction."""


@dataclass
class ChainVerdict:
    """
    The outcome of judging one candidate chain.
    """

    is_real: bool = False
    reason: str = ""
    narrative: str = ""
    ordered_steps: List[int] = field(default_factory=list)
    confidence: float = 0.0
    tool_calls: int = 0
    error: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "is_real": self.is_real,
            "reason": self.reason,
            "attack_narrative": self.narrative,
            "confidence": round(self.confidence, 2),
            "tool_calls": self.tool_calls,
        }


class ChainJudge:
    """
    Asks a model whether proposed chains describe a reachable attack path.
    """

    def __init__(
        self,
        client: Any,
        model: str,
        root: Path,
        max_turns: int = 5,
        temperature: Optional[float] = 0
    ) -> None:
        """
        Args:
            client: An OpenAI-compatible client
            model: Model identifier
            root: Scan root the tools are confined to
            max_turns: Investigation budget per chain
            temperature: Sampling temperature, or None to omit
        """

        self.client = client
        self.model = model
        self.root = Path(root)
        self.max_turns = max_turns
        self.temperature = temperature

    async def judge(self, chain: VulnerabilityChain) -> ChainVerdict:
        """
        Judge one candidate chain.

        Args:
            chain: The proposed chain

        Returns:
            ChainVerdict: Whether it holds up, and the attack path if so
        """

        if len(chain.vulnerabilities) < 2:
            return ChainVerdict(is_real=False, reason="a chain needs at least two steps")

        tools = CodeTools(self.root)
        agent = ToolCallingAgent(
            client=self.client,
            model=self.model,
            dispatch=tools.dispatch,
            tool_schemas=TOOL_SCHEMAS,
            max_turns=self.max_turns,
            temperature=self.temperature,
        )

        try:
            run = await agent.run(SYSTEM_PROMPT, self._prompt(chain.vulnerabilities))
        except Exception as e:
            logging.error(f"Chain judging failed: {e}")
            return ChainVerdict(error=str(e))

        verdict = self._parse(run.text)
        verdict.tool_calls = run.tool_calls
        return verdict

    @staticmethod
    def _prompt(vulns: Sequence[Vulnerability]) -> str:
        """
        Describe the candidate chain for the model.

        Args:
            vulns: Findings in the proposed chain

        Returns:
            str: The user prompt
        """

        blocks = []
        for index, vuln in enumerate(vulns):
            taint = ""
            if vuln.taint_path:
                steps = " -> ".join(
                    f"{s.get('kind', 'step')}@{s.get('file', '')}:{s.get('line', '')}"
                    for s in vuln.taint_path
                )
                taint = f"\n  Traced dataflow: {steps}"
            blocks.append(
                f"[{index}] {vuln.type.value} ({vuln.severity.value})\n"
                f"  Location: {vuln.location.file_path}:{vuln.location.start_line}\n"
                f"  What it is: {(vuln.description or '')[:400]}\n"
                f"  Impact: {(vuln.impact or '')[:250]}"
                f"{taint}\n"
                f"  Code: {(vuln.location.context or '(not captured)')[:300]}"
            )

        return (
            "A heuristic proposed that these findings form an attack chain. "
            "It works from a small table of escalation patterns plus how close "
            "the findings sit in the file, so it proposes plenty of chains that "
            "are not real. Decide whether this one is.\n\n"
            + "\n\n".join(blocks)
            + "\n\nInvestigate and return your verdict as JSON."
        )

    @staticmethod
    def _parse(text: str) -> ChainVerdict:
        """
        Parse the model's JSON verdict.

        Args:
            text: Raw model output

        Returns:
            ChainVerdict: Parsed verdict, not-real when unparseable
        """

        if not text or not text.strip():
            return ChainVerdict(error="empty response")

        body = text.strip()
        fence = re.match(r"^```(?:json)?\s*([\s\S]*?)\s*```$", body)
        if fence:
            body = fence.group(1).strip()

        start, end = body.find("{"), body.rfind("}")
        if start != -1 and end > start:
            body = body[start:end + 1]

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as e:
            logging.debug(f"Unparseable chain verdict: {text[:200]}")
            return ChainVerdict(error=f"unparseable verdict: {e}")

        steps = payload.get("ordered_steps") or []
        return ChainVerdict(
            is_real=bool(payload.get("is_real_chain")),
            reason=str(payload.get("reason", ""))[:500],
            narrative=str(payload.get("attack_narrative", ""))[:1200],
            ordered_steps=[s for s in steps if isinstance(s, int)],
            confidence=float(payload.get("confidence") or 0.0),
        )
