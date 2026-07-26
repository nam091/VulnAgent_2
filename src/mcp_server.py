"""MCP server exposing VulnAgent to AI coding agents.

The point of this surface is to move the security check *inside* the code
generation loop. An agent writing code can scan what it just produced,
receive the findings, repair them, and rescan - all before the code ever
reaches the person who asked for it. That audience never reads a security
report, but the agent working on their behalf can act on one.

Run with:  python src/mcp_server.py
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# Allow execution as a plain script from any working directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from analyzer.scanner import ScanOptions, Scanner
from analyzer.semgrep_runner import SemgrepRunner
from models.vulnerability import FindingSource, Vulnerability

load_dotenv()

INSTRUCTIONS = """VulnAgent finds security vulnerabilities in source code by combining
rule-based static analysis (Semgrep) with LLM semantic analysis.

Use `scan_code` on any code you generate that touches user input, databases,
the filesystem, subprocesses, authentication, or network requests - before
presenting it to the user. Default to mode="fast" inside a generation loop;
it takes roughly ten seconds, nearly all of it fixed rule-engine startup, so
snippet size barely affects it. Use mode="deep" for a final review or when
the code handles authentication, secrets or payments - that adds an LLM call
per file and takes appreciably longer.

Findings carry a `source` field:
  - confirmed : both engines agree. Fix these.
  - rule-only : the rule engine matched. Almost always real.
  - llm-only  : semantic judgement, unverified. Assess before acting.

Know what fast mode misses. The rule engine's taint rules need a recognised
source - `request.args`, a route handler, a framework entry point. A plain
helper function has none, so `os.system("echo " + cmd)` inside `def run(cmd)`
returns clean in fast mode and CRITICAL in deep mode. A clean fast-mode result
on standalone utility code means very little; use deep mode there.
"""

mcp = FastMCP("vulnagent", instructions=INSTRUCTIONS)


def _severity_marker(severity: str) -> str:
    """
    Short marker used in the compact text rendering.

    Args:
        severity: Severity name

    Returns:
        str: A fixed-width label
    """

    return {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH    ",
        "MEDIUM": "MEDIUM  ",
        "LOW": "LOW     ",
        "INFO": "INFO    ",
    }.get(severity, severity)


def _to_dict(vuln: Vulnerability) -> Dict[str, Any]:
    """
    Render a finding as a compact dictionary for an agent to consume.

    Verbose report fields are deliberately trimmed: an agent needs to know
    where the defect is, why it matters and what to write instead.

    Args:
        vuln: The finding

    Returns:
        Dict[str, Any]: Compact representation
    """

    label = {
        FindingSource.CONFIRMED: "confirmed",
        FindingSource.SEMGREP: "rule-only",
        FindingSource.LLM: "llm-only",
    }.get(vuln.source, vuln.source.value)

    payload = {
        "id": vuln.id,
        "type": vuln.type.value,
        "severity": vuln.severity.value,
        "source": label,
        "confidence": round(vuln.confidence, 2),
        "file": vuln.location.file_path,
        "start_line": vuln.location.start_line,
        "end_line": vuln.location.end_line,
        "cwe": vuln.cwe_id,
        "description": vuln.description,
        "impact": vuln.impact,
        "remediation": vuln.remediation,
    }
    if vuln.secure_code_example:
        payload["secure_code_example"] = vuln.secure_code_example
    if vuln.location.context:
        payload["snippet"] = vuln.location.context
    return payload


def _summarise(vulns: List[Vulnerability], elapsed: Optional[float] = None) -> str:
    """
    Build a one-glance summary line.

    Args:
        vulns: Findings
        elapsed: Optional scan duration in seconds

    Returns:
        str: Human-readable summary
    """

    if not vulns:
        return "No vulnerabilities found."

    counts: Dict[str, int] = {}
    for vuln in vulns:
        counts[vuln.severity.value] = counts.get(vuln.severity.value, 0) + 1

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    parts = [f"{counts[s]} {s.lower()}" for s in order if s in counts]
    tail = f" in {elapsed:.1f}s" if elapsed is not None else ""
    return f"{len(vulns)} finding(s): " + ", ".join(parts) + tail


async def _scan_target(
    target: str,
    mode: str,
    concurrency: int = 5
) -> Dict[str, Any]:
    """
    Run a scan and package the result for MCP consumers.

    Args:
        target: File or directory path
        mode: "fast" for the rule tier only, "deep" for both tiers
        concurrency: Concurrent LLM calls in deep mode

    Returns:
        Dict[str, Any]: Summary, findings and scan statistics
    """

    options = ScanOptions(
        target=target,
        use_llm=(mode == "deep"),
        use_semgrep=True,
        concurrency=concurrency,
    )
    result = await Scanner(options).scan()
    vulns = result.vulnerabilities

    return {
        "summary": _summarise(vulns, result.stats.get("total_seconds")),
        "clean": not vulns,
        "mode": mode,
        "findings": [_to_dict(v) for v in vulns],
        "attack_chains": [
            {
                "severity": chain.combined_severity.value,
                "likelihood": chain.likelihood,
                "steps": [v.type.value for v in chain.vulnerabilities],
                "prerequisites": chain.prerequisites,
            }
            for report in result.reports
            for chain in report.chained_vulnerabilities
        ],
        "stats": result.stats,
        "degraded": result.degraded,
    }


@mcp.tool(
    description=(
        "Scan a snippet of source code for security vulnerabilities. Use this on "
        "code you just generated, before showing it to the user. mode='fast' uses "
        "the rule engine only and takes about ten seconds; mode='deep' adds LLM "
        "semantic analysis and takes appreciably longer."
    )
)
async def scan_code(
    code: str,
    filename: str = "snippet.py",
    mode: str = "fast"
) -> Dict[str, Any]:
    """
    Scan code held in memory.

    Args:
        code: The source to analyse
        filename: Name used for language detection and in reported locations
        mode: "fast" (rules only) or "deep" (rules + LLM)

    Returns:
        Dict[str, Any]: Findings and summary
    """

    if not code or not code.strip():
        return {"summary": "No code supplied.", "clean": True, "findings": []}

    if mode not in ("fast", "deep"):
        mode = "fast"

    suffix = Path(filename).suffix or ".py"
    tmp_dir = tempfile.mkdtemp(prefix="vulnagent_mcp_")
    # The caller's filename is used only for its extension; writing to a
    # path built from untrusted input would be its own traversal bug.
    tmp_path = Path(tmp_dir) / f"snippet{suffix}"

    try:
        tmp_path.write_text(code, encoding="utf-8")
        result = await _scan_target(str(tmp_path), mode)
        for finding in result["findings"]:
            finding["file"] = filename
        return result
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
            Path(tmp_dir).rmdir()
        except OSError:
            pass


@mcp.tool(
    description=(
        "Scan a file on disk for security vulnerabilities. mode='fast' uses the "
        "rule engine only; mode='deep' adds LLM semantic analysis."
    )
)
async def scan_file(path: str, mode: str = "deep") -> Dict[str, Any]:
    """
    Scan a single file.

    Args:
        path: Path to the file
        mode: "fast" or "deep"

    Returns:
        Dict[str, Any]: Findings and summary
    """

    target = Path(path)
    if not target.is_file():
        return {"error": f"not a file: {path}", "findings": []}

    return await _scan_target(str(target), mode if mode in ("fast", "deep") else "deep")


@mcp.tool(
    description=(
        "Scan a whole directory tree. Vendored directories (venv, node_modules, "
        "build artefacts) are skipped automatically. In deep mode only files whose "
        "risk signals warrant it are sent to the LLM, so cost stays bounded."
    )
)
async def scan_directory(
    path: str,
    mode: str = "deep",
    concurrency: int = 5
) -> Dict[str, Any]:
    """
    Scan a directory tree.

    Args:
        path: Directory to scan
        mode: "fast" or "deep"
        concurrency: Concurrent LLM calls in deep mode

    Returns:
        Dict[str, Any]: Findings and summary
    """

    target = Path(path)
    if not target.is_dir():
        return {"error": f"not a directory: {path}", "findings": []}

    return await _scan_target(
        str(target),
        mode if mode in ("fast", "deep") else "deep",
        concurrency=concurrency
    )


@mcp.tool(
    description=(
        "List the vulnerability classes the rule engine can detect, to check "
        "whether a given concern is covered before relying on a clean scan."
    )
)
async def capabilities() -> Dict[str, Any]:
    """
    Report what the installed engines can do.

    Returns:
        Dict[str, Any]: Engine availability and configuration
    """

    runner = SemgrepRunner()
    return {
        "rule_engine": {
            "name": "semgrep",
            "available": runner.available,
            "rule_packs": list(runner.configs),
        },
        "llm_engine": {
            "model": os.getenv("OPENAI_MODEL", "o1-mini-2024-09-12"),
            "configured": bool(os.getenv("OPENAI_API_KEY")),
        },
        "languages": ["python"],
        "note": (
            "Cross-file taint analysis is not available; findings are "
            "established within a single file."
        ),
    }


def main() -> None:
    """
    Start the MCP server on stdio.
    """

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
