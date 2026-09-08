"""Adversarial verification of candidate findings.

The measured weakness of the LLM tier is precision, not recall: it reaches
every labelled vulnerability but also reports defects that are not there,
and six of its seven false positives land on a file where every dangerous
pattern is used correctly. A second single-shot prompt asking "is this
right?" mostly agrees with the first, because the model is being asked to
confirm its own reasoning from the same evidence.

So this stage does two things differently. It gives the model tools to go
and read the code the claim depends on, and it assigns it the opposite goal:
find the reason the finding is wrong. A claim that survives an agent that
was told to break it is worth more than one that survives agreement.

The verdict also carries a taint path when confirmed, which is where the
dataflow evidence for vulnerability chaining comes from.
"""

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.loop import ToolCallingAgent
from agent.tools import TOOL_SCHEMAS, CodeTools
from models.vulnerability import FindingSource, Vulnerability, VulnerabilityType

SYSTEM_PROMPT = """You are a security engineer reviewing a vulnerability report written
by someone else. Your job is to find the reason the report is WRONG.

Reports get filed for code that turns out to be safe. Common reasons a report
is wrong:
  - A validating or sanitising call upstream that the reporter did not read
  - The value is a literal or a constant, not attacker-controlled
  - The dangerous-looking API is called with a fixed argument list
  - Reading a secret from the environment or a vault, which is correct practice
  - Using a cryptographically secure API the reporter mistook for a weak one
  - The code path is unreachable, or is test or example code

Use the tools to READ THE ACTUAL CODE before deciding. Do not reason from the
snippet alone - it is what misled the reporter. Follow the value back to where
it enters the program, and check what happens to it on the way.

Rules for your verdict:
  - "refuted" requires positive evidence: name the control that makes it safe
    and where you read it. Never refute merely because you are unsure.
  - "confirmed" requires that you traced attacker-controlled data to the
    dangerous operation with no adequate control in between.
  - "uncertain" when you could not establish either, for example when the
    entry point is outside the code you can read.

Answer with ONLY a JSON object, no prose and no code fence:

{
  "verdict": "confirmed" | "refuted" | "uncertain",
  "reason": "one or two sentences citing what you read",
  "evidence_file": "path you based this on, or empty",
  "evidence_line": 0,
  "taint_path": [
    {"step": "what happens here", "file": "path", "line": 0, "kind": "source|propagator|sanitizer|sink"}
  ],
  "mitigating_control": "the control that makes it safe, when refuted, else empty"
}

taint_path must be present and non-empty when the verdict is "confirmed": list
the source where attacker data enters, any propagation, and the sink. Leave it
as [] otherwise."""

USER_TEMPLATE = """Reported vulnerability

  Type:      {vuln_type}
  Severity:  {severity}
  CWE:       {cwe}
  Location:  {file}:{start_line}-{end_line}
  Reported by: {source}

  Claim:  {description}
  Impact: {impact}

Code at the reported location:

{context}

Investigate and return your verdict as JSON."""


@dataclass
class Verdict:
    """
    The outcome of verifying one finding.
    """

    verdict: str = "uncertain"
    reason: str = ""
    evidence_file: str = ""
    evidence_line: int = 0
    taint_path: List[Dict[str, Any]] = field(default_factory=list)
    mitigating_control: str = ""
    tool_calls: int = 0
    investigated: bool = False
    hit_turn_cap: bool = False
    tools_unsupported: bool = False
    duration_seconds: float = 0.0
    error: str = ""

    @property
    def refuted(self) -> bool:
        return self.verdict == "refuted"

    @property
    def confirmed(self) -> bool:
        return self.verdict == "confirmed"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "evidence_file": self.evidence_file,
            "evidence_line": self.evidence_line,
            "taint_path": self.taint_path,
            "mitigating_control": self.mitigating_control,
            "tool_calls": self.tool_calls,
            "investigated": self.investigated,
            "hit_turn_cap": self.hit_turn_cap,
            "tools_unsupported": self.tools_unsupported,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }


class VerificationAgent:
    """
    Runs adversarial verification over candidate findings.
    """

    def __init__(
        self,
        client: Any,
        model: str,
        root: Path,
        max_turns: int = 6,
        temperature: Optional[float] = 0
    ) -> None:
        """
        Args:
            client: An OpenAI-compatible client
            model: Model identifier
            root: Scan root the tools are confined to
            max_turns: Investigation budget per finding
            temperature: Sampling temperature, or None to omit
        """

        self.client = client
        self.model = model
        self.root = Path(root)
        self.max_turns = max_turns
        self.temperature = temperature

    async def verify(self, vuln: Vulnerability) -> Verdict:
        """
        Verify one finding.

        Args:
            vuln: The candidate finding

        Returns:
            Verdict: The outcome, with an error field set on failure
        """

        tools = CodeTools(self.root)
        agent = ToolCallingAgent(
            client=self.client,
            model=self.model,
            dispatch=tools.dispatch,
            tool_schemas=TOOL_SCHEMAS,
            max_turns=self.max_turns,
            temperature=self.temperature,
        )

        prompt = USER_TEMPLATE.format(
            vuln_type=vuln.type.value,
            severity=vuln.severity.value,
            cwe=vuln.cwe_id or "unknown",
            file=vuln.location.file_path,
            start_line=vuln.location.start_line,
            end_line=vuln.location.end_line,
            source=vuln.source.value,
            description=(vuln.description or "")[:800],
            impact=(vuln.impact or "")[:400],
            context=(vuln.location.context or "(not captured)")[:1500],
        )

        start_time = time.perf_counter()
        try:
            run = await agent.run(SYSTEM_PROMPT, prompt)
        except Exception as e:
            logging.error(f"Verification failed for {vuln.type.value}: {e}")
            return Verdict(
                verdict="uncertain",
                error=str(e),
                duration_seconds=round(time.perf_counter() - start_time, 2)
            )

        verdict = self._parse(run.text)
        verdict.tool_calls = run.tool_calls
        verdict.investigated = run.investigated
        verdict.duration_seconds = round(time.perf_counter() - start_time, 2)
        if hasattr(run, "hit_turn_cap"):
            verdict.hit_turn_cap = getattr(run, "hit_turn_cap", False)

        # Refutation decision policy (B02 / G2)
        if verdict.refuted:
            if not verdict.mitigating_control.strip():
                logging.info(
                    f"Refutation without a named control for {vuln.type.value} "
                    f"at {vuln.location.file_path}:{vuln.location.start_line}; "
                    "downgraded to uncertain"
                )
                verdict.verdict = "uncertain"
                verdict.reason = "Bác bỏ không có tên hoặc mô tả biện pháp kiểm soát cụ thể."
            elif not verdict.investigated or verdict.tool_calls == 0:
                logging.info(
                    f"Refutation without successful tool investigation for {vuln.type.value} "
                    f"at {vuln.location.file_path}:{vuln.location.start_line}; "
                    "downgraded to uncertain"
                )
                verdict.verdict = "uncertain"
                verdict.reason = "Agent không thực hiện đọc mã nguồn thành công để kiểm chứng."
            elif not verdict.evidence_file or not verdict.evidence_file.strip():
                logging.info(
                    f"Refutation without evidence file for {vuln.type.value} "
                    f"at {vuln.location.file_path}:{vuln.location.start_line}; "
                    "downgraded to uncertain"
                )
                verdict.verdict = "uncertain"
                verdict.reason = "Bác bỏ thiếu đường dẫn file bằng chứng chứng minh kiểm soát an toàn."
            else:
                try:
                    resolved = (self.root / verdict.evidence_file.lstrip("/\\")).resolve()
                    if (resolved != self.root and self.root not in resolved.parents) or not resolved.is_file():
                        logging.info(
                            f"Refutation cites invalid/escaping file {verdict.evidence_file}; "
                            "downgraded to uncertain"
                        )
                        verdict.verdict = "uncertain"
                        verdict.reason = f"File bằng chứng '{verdict.evidence_file}' không tồn tại trong phạm vi quét."
                    elif verdict.evidence_line is not None:
                        total_lines = len(resolved.read_text(encoding="utf-8", errors="replace").splitlines())
                        if verdict.evidence_line < 1 or verdict.evidence_line > total_lines:
                            verdict.verdict = "uncertain"
                            verdict.reason = f"Dòng bằng chứng {verdict.evidence_line} ngoài phạm vi file '{verdict.evidence_file}' ({total_lines} dòng)."
                except Exception as e:
                    verdict.verdict = "uncertain"
                    verdict.reason = f"Lỗi xác thực file bằng chứng: {e}"

        # Confirmation decision policy
        if verdict.confirmed:
            if vuln.type in (
                VulnerabilityType.SQL_INJECTION,
                VulnerabilityType.OS_COMMAND_INJECTION,
                VulnerabilityType.PATH_TRAVERSAL
            ):
                if not verdict.taint_path and not verdict.reason:
                    verdict.verdict = "uncertain"
                    verdict.reason = "Xác nhận thiếu chuỗi dữ liệu (taint path) hoặc lý do cụ thể."

        return verdict

    @staticmethod
    def _parse(text: str) -> Verdict:
        """
        Parse the agent's JSON verdict.

        Args:
            text: Raw model output

        Returns:
            Verdict: Parsed verdict, "uncertain" when unparseable
        """

        if not text or not text.strip():
            return Verdict(error="empty response")

        body = text.strip()
        fence = re.match(r"^```(?:json)?\s*([\s\S]*?)\s*```$", body)
        if fence:
            body = fence.group(1).strip()

        start = body.find("{")
        end = body.rfind("}")
        if start != -1 and end > start:
            body = body[start:end + 1]

        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, Exception) as e:
            logging.debug(f"Unparseable verdict: {text[:200]}")
            return Verdict(error=f"unparseable verdict: {e}")

        if not isinstance(payload, dict):
            return Verdict(error="verdict payload must be a JSON object")

        verdict = str(payload.get("verdict", "uncertain")).lower().strip()
        if verdict not in ("confirmed", "refuted", "uncertain"):
            verdict = "uncertain"

        path = payload.get("taint_path") or []
        if not isinstance(path, list):
            path = []

        line_val = payload.get("evidence_line")
        try:
            if isinstance(line_val, str):
                digits = re.findall(r"\d+", line_val)
                evidence_line = int(digits[0]) if digits else 0
            else:
                evidence_line = int(line_val or 0)
        except (ValueError, TypeError):
            evidence_line = 0

        return Verdict(
            verdict=verdict,
            reason=str(payload.get("reason", "") or "")[:600],
            evidence_file=str(payload.get("evidence_file", "") or "")[:300],
            evidence_line=evidence_line,
            taint_path=[p for p in path if isinstance(p, dict)][:12],
            mitigating_control=str(payload.get("mitigating_control", "") or "")[:400],
        )
