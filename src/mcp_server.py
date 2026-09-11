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

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    class FastMCP:  # type: ignore
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def tool(self, *args: Any, **kwargs: Any) -> Any:
            def decorator(f: Any) -> Any:
                return f
            return decorator

        def run(self) -> None:
            print("mcp package is not installed. Install with: pip install mcp", file=sys.stderr)

from analyzer.fixer import classify_patch, unified_diff
from analyzer.scanner import ScanOptions, Scanner
from analyzer.semgrep_runner import SemgrepRunner
from context.ast_context import ASTContextExtractor
from context.diff_scope import DiffScopeAnalyzer
from evidence.safe_reader import SafeReader
from evidence.store import EvidenceStore
from models.assessment import (
    AssessmentStatus,
    AssessmentStore,
    FindingAssessment,
    check_assessment_stale,
    evaluate_assessment_policy,
)
from models.evidence import EvidenceStatus
from models.vulnerability import FindingSource, Vulnerability
import ast
import time
import uuid

load_dotenv()

# Mode selection: 'editor' (zero outbound LLM calls) or 'standalone' (allows backend LLM calls)
EDITOR_MODE = os.getenv("VULNAGENT_MODE", "editor").lower() in ("editor", "local", "rule_only")

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
    Render a finding as a versioned dictionary for an agent to consume.
    Provides structured provenance and assessment contracts alongside backward-compatible fields.
    """
    label = {
        FindingSource.CONFIRMED: "confirmed",
        FindingSource.SEMGREP: "rule-only",
        FindingSource.LLM: "llm-only",
    }.get(vuln.source, vuln.source.value if hasattr(vuln.source, "value") else str(vuln.source))

    engine_sources = getattr(vuln, "engine_sources", [label])
    corroborated = getattr(vuln, "corroborated", False)
    assessment_status = getattr(vuln, "assessment_status", "unreviewed")
    file_hash = getattr(vuln, "file_hash", None)

    payload = {
        "id": vuln.id,
        "type": vuln.type.value if hasattr(vuln.type, "value") else str(vuln.type),
        "severity": vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity),
        "file": vuln.location.file_path,
        "start_line": vuln.location.start_line,
        "end_line": vuln.location.end_line,
        "cwe": vuln.cwe_id,
        "description": vuln.description,
        "impact": vuln.impact,
        "remediation": vuln.remediation,
        # Structured provenance (B10, R10)
        "provenance": {
            "source": label,
            "engine_sources": engine_sources,
            "corroborated": corroborated,
            "confidence": round(vuln.confidence, 2),
            "file_hash": file_hash,
        },
        # Structured assessment & evidence semantics
        "assessment": {
            "status": assessment_status,
            "details": getattr(vuln, "assessment", None),
            "evidence_ids": getattr(vuln, "evidence_ids", []),
            "taint_path": getattr(vuln, "taint_path", []),
        },
        # Backward-compatible fields
        "source": label,
        "confidence": round(vuln.confidence, 2),
        "corroborated": corroborated,
        "assessment_status": assessment_status,
    }
    if vuln.location.context:
        payload["snippet"] = vuln.location.context

    fix = _fix_for(vuln)
    if fix:
        payload["fix"] = fix
    return payload


def _fix_for(vuln: Vulnerability) -> Optional[Dict[str, Any]]:
    """
    Package a finding's suggested rewrite with a safety verdict.

    An agent will act on whatever it is handed, so a rewrite is never
    returned bare. `risk` states whether it is a clean substitution, and
    `risk_reasons` names what an agent has to check before applying it -
    an invented placeholder path, a duplicated return, new control flow.

    Args:
        vuln: The finding

    Returns:
        Optional[Dict[str, Any]]: Fix details, or None when no rewrite exists
    """

    replacement = (vuln.secure_code_example or "").strip()
    if not replacement:
        return None

    original = (vuln.location.context or "").strip()
    reasons = classify_patch(original, replacement) if original else [
        "no original snippet captured, so the patch could not be checked"
    ]
    return {
        "replacement": replacement,
        "risk": "safe" if not reasons else "review",
        "risk_reasons": reasons,
        "diff": unified_diff(original, replacement, vuln.location.file_path)
                if original else "",
    }


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

    use_llm = (mode == "deep") and not EDITOR_MODE
    options = ScanOptions(
        target=target,
        use_llm=use_llm,
        use_semgrep=True,
        concurrency=concurrency,
    )
    result = await Scanner(options).scan()
    vulns = result.vulnerabilities

    # A degraded scan must never be reported as clean. An agent reading
    # "No vulnerabilities found" will ship the code.
    summary = _summarise(vulns, result.stats.get("total_seconds"))
    if result.degraded:
        summary = ("INCOMPLETE SCAN - an analysis engine did not finish, so "
                   "this result cannot be trusted. " + summary)

    return {
        "summary": summary,
        "clean": (not vulns) and not result.degraded,
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
        "Scan code and return only the findings that come with an applicable "
        "fix, each with a diff and a safety verdict. Use this after scan_code "
        "reports something, to repair the code before showing it to the user. "
        "Apply patches marked risk='safe' directly; for risk='review', read "
        "risk_reasons and adapt the fix rather than pasting it."
    )
)
async def suggest_fix(
    code: str,
    filename: str = "snippet.py",
    mode: str = "deep"
) -> Dict[str, Any]:
    """
    Return validated fixes for the vulnerabilities in a snippet.

    Args:
        code: The source to analyse
        filename: Name used for language detection and reported locations
        mode: "fast" (rules only, rarely yields fixes) or "deep"

    Returns:
        Dict[str, Any]: Findings that carry a fix, plus a summary
    """

    result = await scan_code(code=code, filename=filename, mode=mode)
    findings = result.get("findings", [])
    fixable = [f for f in findings if f.get("fix")]
    safe = [f for f in fixable if f["fix"]["risk"] == "safe"]

    # Field names are spelled out rather than abbreviated: this payload is
    # read by another model, and "suggested_code" needs no interpretation
    # where "replacement" invites guessing what it replaces.
    suggestions = [
        {
            "line": f["start_line"],
            "end_line": f["end_line"],
            "severity": f["severity"],
            "vulnerability": f["type"],
            "cwe": f.get("cwe", ""),
            "what_is_wrong": f.get("description", ""),
            "impact": f.get("impact", ""),
            "how_to_fix": f.get("remediation", ""),
            "current_code": f.get("snippet", ""),
            "suggested_code": f["fix"]["replacement"],
            "diff": f["fix"]["diff"],
            "risk": f["fix"]["risk"],
            "risk_reasons": f["fix"]["risk_reasons"],
            "evidence": f.get("source", ""),
        }
        for f in fixable
    ]

    unfixable = [
        {
            "line": f["start_line"],
            "vulnerability": f["type"],
            "severity": f["severity"],
            "what_is_wrong": f.get("description", ""),
            "how_to_fix": f.get("remediation", ""),
            "note": "no code suggestion available; fix by hand",
        }
        for f in findings if not f.get("fix")
    ]

    return {
        "summary": (
            f"{len(findings)} finding(s), {len(suggestions)} with a code "
            f"suggestion ({len(safe)} clean substitutions)"
        ),
        "suggestions": suggestions,
        "no_suggestion": unfixable,
        "how_to_use": (
            "These are suggestions only - nothing is written to disk. Apply them "
            "yourself with your own editing tools. risk='safe' means the "
            "suggestion replaces the same lines cleanly. risk='review' means read "
            "risk_reasons first and adapt it: the model may have invented a "
            "placeholder path, added a return that duplicates one below, or "
            "expanded one line into a block that will not splice in. After "
            "editing, call scan_code again to confirm the finding is gone."
        ),
        "note": (
            "The rule engine does not write code, so mode='fast' rarely yields "
            "suggestions. Use mode='deep' when you want fixes."
        ),
    }


_scan_sessions: Dict[str, Dict[str, Any]] = {}


@mcp.tool(
    description=(
        "Scan changed files in the working tree for security candidates. "
        "Editor mode: uses rule static analysis and local AST context with ZERO outbound LLM calls. "
        "Returns scan_id, snapshot_id, changed files, and candidates for host investigation."
    )
)
async def scan_changes(
    target: str = ".",
    base_ref: Optional[str] = None,
    include_untracked: bool = True
) -> Dict[str, Any]:
    target_path = Path(target).resolve()
    root = target_path if target_path.is_dir() else target_path.parent
    evidence_store = EvidenceStore(root)
    snapshot = evidence_store.create_snapshot(root)
    diff_analyzer = DiffScopeAnalyzer(root)
    changed_files = diff_analyzer.get_changed_files(base_ref=base_ref, include_untracked=include_untracked)

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    _scan_sessions[scan_id] = {
        "root": root,
        "snapshot": snapshot,
        "evidence_store": evidence_store,
        "scanner": None,
        "findings": {},
        "assessments": {},
        "changed_files": [],
        "expanded_files": [],
        "created_at": time.time(),
    }

    if not changed_files:
        return {
            "scan_id": scan_id,
            "snapshot_id": snapshot.snapshot_id,
            "changed_files": [],
            "candidates": [],
            "coverage": {"files_scanned": 0, "status": "completed"},
            "summary": "No changed Python files found.",
        }

    expanded_files = diff_analyzer.expand_scope(changed_files, max_extra_files=3)

    options = ScanOptions(
        target=str(root),
        use_llm=False,
        use_semgrep=True,
        files=expanded_files,
    )
    scanner = Scanner(options)
    result = await scanner.scan()

    target_scope = {Path(f).as_posix().lstrip("./") for f in expanded_files}
    candidates = [
        v for v in result.vulnerabilities
        if Path(v.location.file_path).as_posix().lstrip("./") in target_scope
    ]

    audit_dir = root / ".vulnagent-audit"
    assessment_store = AssessmentStore(storage_dir=audit_dir)
    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    _scan_sessions[scan_id] = {
        "root": root,
        "snapshot": snapshot,
        "evidence_store": evidence_store,
        "assessment_store": assessment_store,
        "scanner": scanner,
        "findings": {v.id: v for v in candidates},
        "assessments": {},
        "changed_files": changed_files,
        "expanded_files": expanded_files,
        "created_at": time.time(),
    }

    scanned_count = len([r for r in result.reports if r.status in ("completed", "partial")])
    coverage_info = {
        "files_requested": list(expanded_files),
        "files_scanned": [r.file_name for r in result.reports if r.file_name],
        "scanned_count": scanned_count,
        "total_files": len(result.reports),
        "status": result.status,
        "degraded": result.degraded,
        "file_statuses": {
            r.file_name: {"status": r.status, "engine_status": r.engine_status}
            for r in result.reports if r.file_name
        },
    }

    return {
        "scan_id": scan_id,
        "snapshot_id": snapshot.snapshot_id,
        "changed_files": changed_files,
        "expanded_files": expanded_files,
        "candidates": [_to_dict(v) for v in candidates],
        "coverage": coverage_info,
        "summary": f"Scanned {scanned_count} of {len(expanded_files)} file(s); found {len(candidates)} security candidate(s).",
    }


@mcp.tool(
    description=(
        "Retrieve AST enclosing scope, context, and issue initial evidence IDs for a candidate finding."
    )
)
async def get_finding_context(
    scan_id: str,
    finding_id: str
) -> Dict[str, Any]:
    session = _scan_sessions.get(scan_id)
    if not session:
        return {"error": f"Unknown scan_id: {scan_id}. Run scan_changes first."}

    vuln = session["findings"].get(finding_id)
    if not vuln:
        return {"error": f"Unknown finding_id: {finding_id} in scan {scan_id}."}

    root = session["root"]
    evidence_store: EvidenceStore = session["evidence_store"]
    snapshot = session["snapshot"]
    ast_extractor = ASTContextExtractor(root)

    file_rel = vuln.location.file_path
    scope_info = ast_extractor.find_enclosing_scope(file_rel, vuln.location.start_line)

    start_line = max(1, vuln.location.start_line - 5)
    end_line = vuln.location.end_line + 5
    safe_reader = SafeReader(root)
    read_data = safe_reader.read_lines(file_rel, start_line, end_line)

    raw_content = "\n".join(read_data.get("raw_lines", []))
    ev_rec = evidence_store.record_evidence(
        snapshot_id=snapshot.snapshot_id,
        path=read_data.get("path", file_rel),
        start_line=read_data["start_line"],
        end_line=read_data["end_line"],
        content=raw_content,
    )

    return {
        "finding_id": finding_id,
        "file": file_rel,
        "line": vuln.location.start_line,
        "cwe": vuln.cwe_id,
        "type": vuln.type.value,
        "enclosing_scope": scope_info,
        "snippet": vuln.location.context or "",
        "initial_evidence_id": ev_rec.evidence_id,
        "evidence_status": ev_rec.status.value,
        "start_line": read_data["start_line"],
        "end_line": read_data["end_line"],
        "context_slice": read_data["content"],
        "instructions": (
            "Review whether mitigating controls sanitize the inputs. "
            "If safe, call submit_assessment with verdict='refuted' citing mitigating_control and evidence_id. "
            "If vulnerable, call submit_assessment with verdict='supported'."
        ),
    }


@mcp.tool(
    description=(
        "Safely read a slice of a source file within scan scope and issue an authenticated evidence ID."
    )
)
async def read_evidence(
    scan_id: str,
    path: str,
    start_line: int = 1,
    end_line: int = 0
) -> Dict[str, Any]:
    session = _scan_sessions.get(scan_id)
    if not session:
        return {"error": f"Unknown scan_id: {scan_id}."}

    root = session["root"]
    evidence_store: EvidenceStore = session["evidence_store"]
    snapshot = session["snapshot"]
    safe_reader = SafeReader(root)

    try:
        data = safe_reader.read_lines(path, start_line, end_line)
        raw_content = "\n".join(data.get("raw_lines", []))
        rec = evidence_store.record_evidence(
            snapshot_id=snapshot.snapshot_id,
            path=data["path"],
            start_line=data["start_line"],
            end_line=data["end_line"],
            content=raw_content,
        )
        return {
            "evidence_id": rec.evidence_id,
            "path": rec.path,
            "start_line": rec.start_line,
            "end_line": rec.end_line,
            "content": data["content"],
            "raw_content": raw_content,
            "status": rec.status.value,
            "read_succeeded": rec.read_succeeded,
        }
    except Exception as e:
        return {"error": f"Failed to read evidence: {e}", "read_succeeded": False}


@mcp.tool(
    description=(
        "Submit a security assessment for a finding with cited evidence IDs. "
        "Verdicts: 'supported', 'refuted', or 'uncertain'. "
        "'refuted' requires valid evidence_id from the scan and non-empty mitigating_control. "
        "'supported' requires valid evidence_id and taint_path binding for injection flaws."
    )
)
async def submit_assessment(
    scan_id: str,
    finding_id: str,
    verdict: str,
    evidence_ids: List[str] = [],
    reason: str = "",
    mitigating_control: Optional[str] = None,
    control_evidence_id: Optional[str] = None,
    taint_path: List[Dict[str, Any]] = [],
    missing_context: List[str] = [],
    limitations: List[str] = [],
) -> Dict[str, Any]:
    session = _scan_sessions.get(scan_id)
    if not session:
        return {"error": f"Unknown scan_id: {scan_id}."}

    vuln = session["findings"].get(finding_id)
    if not vuln:
        return {"error": f"Unknown finding_id: {finding_id}."}

    snapshot = session["snapshot"]
    evidence_store: EvidenceStore = session["evidence_store"]
    assessment_store: AssessmentStore = session.get("assessment_store")
    if assessment_store is None:
        assessment_store = AssessmentStore()
        session["assessment_store"] = assessment_store

    vuln_type = vuln.type.value if hasattr(vuln.type, "value") else str(vuln.type)

    assessment = evaluate_assessment_policy(
        vuln_id=finding_id,
        vuln_type=vuln_type,
        snapshot_id=snapshot.snapshot_id,
        evidence_store=evidence_store,
        verdict=verdict,
        evidence_ids=evidence_ids,
        reason=reason,
        mitigating_control=mitigating_control,
        control_evidence_id=control_evidence_id or (evidence_ids[0] if evidence_ids else None),
        taint_path=taint_path,
        missing_context=missing_context,
        limitations=limitations,
        assessor="host_editor",
    )

    assessment_store.save(assessment)
    session.setdefault("assessments", {})[finding_id] = assessment
    vuln.assessment_status = assessment.status.value
    vuln.assessment = assessment.model_dump()

    return {
        "finding_id": finding_id,
        "submitted_verdict": verdict,
        "accepted_status": assessment.status.value,
        "reason": assessment.reason,
        "policy_verified": assessment.status.value == verdict.strip().lower(),
        "created_at": assessment.created_at,
    }


@mcp.tool(
    description="Check for stale assessments in a scan session whose underlying source files have changed."
)
async def check_stale_assessments(scan_id: str) -> Dict[str, Any]:
    session = _scan_sessions.get(scan_id)
    if not session:
        return {"error": f"Unknown scan_id: {scan_id}."}

    evidence_store: EvidenceStore = session["evidence_store"]
    assessment_store: AssessmentStore = session.get("assessment_store")
    if not assessment_store:
        return {"stale_finding_ids": [], "summary": "No assessments recorded yet."}

    stale_ids = assessment_store.check_all_stale(evidence_store)
    for fid in stale_ids:
        if fid in session["findings"]:
            session["findings"][fid].assessment_status = AssessmentStatus.STALE.value
            ass = assessment_store.get(fid)
            if ass:
                session["findings"][fid].assessment = ass.model_dump()

    return {
        "stale_count": len(stale_ids),
        "stale_finding_ids": stale_ids,
        "summary": f"Identified {len(stale_ids)} stale assessment(s) due to disk modifications.",
    }


@mcp.tool(
    description="Retrieve assessment history and audit trail for a finding or all findings in a scan."
)
async def get_assessment_history(scan_id: str, finding_id: Optional[str] = None) -> Dict[str, Any]:
    session = _scan_sessions.get(scan_id)
    if not session:
        return {"error": f"Unknown scan_id: {scan_id}."}

    assessment_store: AssessmentStore = session.get("assessment_store")
    if not assessment_store:
        return {"history": []}

    if finding_id:
        entries = assessment_store.get_history(finding_id)
        events = [e for e in assessment_store.get_events() if e.get("finding_id") == finding_id]
        return {
            "finding_id": finding_id,
            "history": [e.model_dump() for e in entries],
            "events": events,
        }
    else:
        all_hist = {
            fid: [e.model_dump() for e in assessment_store.get_history(fid)]
            for fid in session["findings"]
        }
        return {"history": all_hist, "events": assessment_store.get_events()}


@mcp.tool(
    description=(
        "Check whether target findings have been resolved after editing. "
        "Rescans the current working tree, validates syntax, and reports if findings are resolved or if regressions were introduced."
    )
)
async def check_fix(
    scan_id: str,
    finding_ids: List[str] = []
) -> Dict[str, Any]:
    session = _scan_sessions.get(scan_id)
    if not session:
        return {"error": f"Unknown scan_id: {scan_id}."}

    root = session["root"]
    changed_files = session.get("changed_files", [])

    syntax_errors = {}
    for f in changed_files:
        try:
            p = (root / f).resolve()
            if p.is_file():
                ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError as se:
            syntax_errors[f] = f"Syntax error at line {se.lineno}: {se.msg}"

    if syntax_errors:
        return {
            "syntax_valid": False,
            "errors": syntax_errors,
            "resolved": [],
            "persistent": finding_ids,
            "new_findings": [],
            "summary": "Fix broke syntax. Check errors and repair.",
        }

    options = ScanOptions(
        target=str(root),
        use_llm=False,
        use_semgrep=True,
        files=session.get("expanded_files") or changed_files,
    )
    new_result = await Scanner(options).scan()

    target_ids = list(finding_ids) if finding_ids else list(session["findings"].keys())

    # Gate: Failed or degraded scan cannot confirm fixes (B01/B16)
    scan_status = getattr(new_result, "status", "completed")
    if new_result.degraded or scan_status != "completed":
        return {
            "syntax_valid": True,
            "clean": False,
            "status": "incomplete",
            "degraded": True,
            "scan_status": scan_status,
            "resolved_findings": [],
            "persistent_findings": target_ids,
            "new_regressions": [],
            "summary": (
                f"Verification scan failed or was degraded (status={scan_status}, degraded={new_result.degraded}). "
                "Findings cannot be marked as resolved."
            ),
        }

    failed_files = {r.file_name for r in new_result.reports if r.status == "failed" or r.degraded}
    current_vuln_ids = {v.id for v in new_result.vulnerabilities}
    resolved = []
    persistent = []
    for fid in target_ids:
        orig_vuln = session["findings"].get(fid)
        file_path = orig_vuln.location.file_path if orig_vuln and orig_vuln.location else ""
        rel_vf = Path(file_path).as_posix().lstrip("./") if file_path else ""
        if fid in current_vuln_ids or (rel_vf and rel_vf in failed_files):
            persistent.append(fid)
        else:
            resolved.append(fid)

    old_ids = set(session["findings"].keys())
    scan_scope = list(session.get("expanded_files") or changed_files)
    scope_lookup = {Path(f).as_posix().lstrip("./") for f in scan_scope}

    def is_in_scope(file_path: str) -> bool:
        if not scan_scope:
            return True
        norm = Path(file_path).as_posix().lstrip("./")
        return norm in scope_lookup

    new_regressions = [
        _to_dict(v) for v in new_result.vulnerabilities
        if v.id not in old_ids and is_in_scope(v.location.file_path)
    ]

    return {
        "syntax_valid": True,
        "clean": len(persistent) == 0 and len(new_regressions) == 0,
        "status": "completed",
        "degraded": False,
        "resolved_findings": resolved,
        "persistent_findings": persistent,
        "new_regressions": new_regressions,
        "summary": (
            f"Fix verification: {len(resolved)} resolved, {len(persistent)} persistent, "
            f"{len(new_regressions)} regression(s)."
        ),
    }


@mcp.tool(
    description=(
        "Report system capabilities, schema version, engine availability, and supported CWEs."
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
        "schema_version": "2.0.0",
        "editor_mode": EDITOR_MODE,
        "backend_llm_calls": not EDITOR_MODE,
        "mode": "editor" if EDITOR_MODE else "standalone",
        "tools": {
            "scan_changes": {"mode": "editor", "backend_llm_calls": False},
            "get_finding_context": {"mode": "editor", "backend_llm_calls": False},
            "read_evidence": {"mode": "editor", "backend_llm_calls": False},
            "submit_assessment": {"mode": "editor", "backend_llm_calls": False},
            "check_stale_assessments": {"mode": "editor", "backend_llm_calls": False},
            "get_assessment_history": {"mode": "editor", "backend_llm_calls": False},
            "check_fix": {"mode": "editor", "backend_llm_calls": False},
            "scan_code": {"mode": "standalone" if not EDITOR_MODE else "editor", "backend_llm_calls": not EDITOR_MODE},
            "scan_file": {"mode": "standalone" if not EDITOR_MODE else "editor", "backend_llm_calls": not EDITOR_MODE},
            "scan_directory": {"mode": "standalone" if not EDITOR_MODE else "editor", "backend_llm_calls": not EDITOR_MODE},
            "suggest_fix": {"mode": "standalone" if not EDITOR_MODE else "editor", "backend_llm_calls": not EDITOR_MODE},
        },
        "rule_engine": {
            "name": "semgrep",
            "available": runner.available,
            "rule_packs": list(runner.configs),
        },
        "supported_cwes": [
            {"cwe": "CWE-89", "name": "SQL Injection"},
            {"cwe": "CWE-22", "name": "Path Traversal"},
            {"cwe": "CWE-78", "name": "OS Command Injection"},
            {"cwe": "CWE-79", "name": "Cross-Site Scripting"},
            {"cwe": "CWE-798", "name": "Hardcoded Credentials"},
        ],
        "limits": {
            "max_file_bytes": 512_000,
            "max_read_lines": 200,
        },
        "languages": ["python"],
        "note": (
            "Editor mode runs local rule analysis with zero outbound model requests. "
            "Host editor drives investigations and submits evidence-backed assessments."
            if EDITOR_MODE else
            "Standalone mode allows both fast rule analysis and deep LLM semantic analysis."
        ),
    }


def main() -> None:
    """
    Start the MCP server on stdio.
    """

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
