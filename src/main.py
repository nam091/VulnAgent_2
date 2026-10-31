"""HTTP API and web dashboard.

Wraps the same Scanner the CLI and MCP server use. Nothing analytical lives
here - this layer handles transport, input validation, job lifecycle and
progress streaming.

Scans run as background jobs rather than inside a request, so the browser
can be refreshed, closed or reopened without losing one.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import uvicorn
from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
# The form parser produces Starlette's UploadFile, and fastapi.UploadFile is
# a subclass of it, so an isinstance check against the FastAPI class silently
# matches nothing.
from starlette.datastructures import UploadFile as StarletteUploadFile
from pydantic import BaseModel, Field

from analyzer.fixer import classify_patch, unified_diff
from analyzer.scanner import ScanOptions, Scanner
from evidence.safe_reader import enrich_taint_path, read_code_snippet
from jobs import Job, JobStore, run_job
from models.vulnerability import (
    FindingSource,
    StandardFindingOutput,
    StandardScanOutput,
    Vulnerability,
    normalize_posix_path,
)

STATIC_DIR = Path(__file__).resolve().parent / "web"
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Cloning arbitrary URLs on request is a server-side request forgery
# primitive, so only well-known code hosts over https are accepted.
ALLOWED_GIT_HOSTS = {
    "github.com", "www.github.com",
    "gitlab.com", "www.gitlab.com",
    "bitbucket.org", "www.bitbucket.org",
}
def _limit(name: str, default: int) -> int:
    """
    Read a size limit from the environment.

    Args:
        name: Environment variable name
        default: Value to use when unset or unparseable

    Returns:
        int: The limit, where 0 means no limit
    """

    try:
        return max(0, int(os.getenv(name, default)))
    except (TypeError, ValueError):
        return default


# Generous by default and overridable, because the corpora people actually
# want to scan are large: the OWASP Benchmark for Python alone is 1,230
# files. Set either to 0 to remove the limit entirely. Note that Chrome caps
# its own directory picker at 1,000 files regardless of what the server
# accepts, so a bigger tree has to come through the CLI.
MAX_UPLOAD_FILES = _limit("VULNAGENT_MAX_UPLOAD_FILES", 50_000)
MAX_TOTAL_UPLOAD_BYTES = _limit("VULNAGENT_MAX_UPLOAD_BYTES", 1024 * 1024 * 1024)
MAX_SINGLE_FILE_BYTES = _limit("VULNAGENT_MAX_FILE_BYTES", 8 * 1024 * 1024)
MAX_CODE_CHARS = _limit("VULNAGENT_MAX_CODE_CHARS", 2_000_000)
SCANNABLE_SUFFIXES = {".py", ".pyi", ".txt", ".cfg", ".ini", ".toml", ".env", ".yml", ".yaml"}

app = FastAPI(
    title="VulnAgent",
    description="Hybrid vulnerability detection: rule-based static analysis + LLM agent",
    version="1.0.0"
)

store = JobStore()

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class SnippetRequest(BaseModel):
    code: str = Field(..., description="Source code to analyse")
    filename: str = Field("snippet.py", description="Name used for language detection")
    mode: str = Field("deep-verify", description="'deep-verify', 'llm', or 'semgrep'")
    verify: bool = Field(True, description="Run the adversarial verification agent")
    concurrency: int = Field(16, ge=1, le=50, description="Parallel analysis workers")


class RepositoryRequest(BaseModel):
    repository_url: str
    branch: str = "main"
    mode: str = "deep-verify"
    verify: bool = True
    concurrency: int = Field(16, ge=1, le=50, description="Parallel analysis workers")
    max_files: int = Field(40, ge=1, le=200)


class SettingsRequest(BaseModel):
    openai_base_url: Optional[str] = Field(None, description="OpenAI-compatible Base URL")
    openai_model: Optional[str] = Field(None, description="Model identifier")
    openai_api_key: Optional[str] = Field(None, description="API Key")


class RenameJobRequest(BaseModel):
    label: str = Field(..., min_length=1, max_length=200, description="New job label")


def _resolve_file_on_disk(file_str: str, workspace: Optional[Path] = None) -> Optional[Path]:
    """Find a source file on disk across workspace, repository, and standard benchmark datasets."""
    if not file_str:
        return None
    p = Path(file_str)
    if workspace:
        w_cand = Path(workspace) / file_str
        if w_cand.is_file():
            return w_cand
        w_name = Path(workspace) / p.name
        if w_name.is_file():
            return w_name

    if p.is_file():
        return p
    if (PROJECT_ROOT / file_str).is_file():
        return PROJECT_ROOT / file_str

    datasets_dir = PROJECT_ROOT / "eval" / "datasets"
    if datasets_dir.is_dir():
        for d in datasets_dir.iterdir():
            cand = d / "samples" / p.name
            if cand.is_file():
                return cand

    source_test_dir = PROJECT_ROOT / "source_test"
    if source_test_dir.is_dir():
        cand = source_test_dir / file_str
        if cand.is_file():
            return cand

    return None


def _read_code_snippet(file_str: str, line: int, workspace: Optional[Path] = None, context_lines: int = 2) -> Optional[str]:
    """Extract code lines around target line with line numbering and current line marker."""
    snippet = read_code_snippet(file_str, line, root_dir=workspace, context_lines=context_lines)
    if snippet:
        return snippet
    p = _resolve_file_on_disk(file_str, workspace=workspace)
    if not p:
        return None
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        if not lines:
            return None
        start = max(1, line - context_lines)
        end = min(len(lines), line + context_lines)
        snippet_lines = []
        for i in range(start, end + 1):
            marker = ">" if i == line else " "
            snippet_lines.append(f"{marker} {i:>4} | {lines[i-1]}")
        return "\n".join(snippet_lines)
    except Exception:
        return None


def _enrich_taint_path(taint_path: List[Dict[str, Any]], fallback_file: str, workspace: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Proactively populate step['code'] for each taint path step and ensure unified schema compliance."""
    return enrich_taint_path(taint_path, default_file=fallback_file, root_dir=workspace)


def _serialise(vuln: Vulnerability, workspace: Optional[Path] = None) -> Dict[str, Any]:
    """
    Render a finding conforming to StandardFindingOutput schema.

    Args:
        vuln: The finding
        workspace: Optional scan root path for file context resolution

    Returns:
        Dict[str, Any]: JSON-safe representation
    """
    std = StandardFindingOutput.from_vulnerability(vuln, workspace=workspace)
    data = std.model_dump()
    data["taint_path"] = _enrich_taint_path(data.get("taint_path") or [], data.get("file") or "", workspace=workspace)
    data["fix"] = _fix_payload(vuln)
    return data


def _fix_payload(vuln: Vulnerability) -> Optional[Dict[str, Any]]:
    """
    Package a finding's suggested rewrite with a diff and a safety verdict.

    The uploaded workspace is deleted once a scan finishes, so the browser
    cannot be offered an "apply" that writes back to the user's files - they
    uploaded copies. What it can be offered is everything needed to apply the
    fix themselves: the diff, whether the patch is a clean substitution, and
    the reasons if it is not.

    Args:
        vuln: The finding

    Returns:
        Optional[Dict[str, Any]]: Fix details, or None when no rewrite exists
    """

    replacement = (vuln.secure_code_example or "").strip()
    original = (vuln.location.context or "").strip()
    if not replacement:
        return None

    reasons = classify_patch(original, replacement) if original else [
        "no original snippet captured, so the patch could not be checked"
    ]
    return {
        "original": original,
        "replacement": replacement,
        "diff": unified_diff(original, replacement, Path(vuln.location.file_path).name)
                if original else "",
        "risk": "safe" if not reasons else "review",
        "risk_reasons": reasons,
    }


def _package(result: Any) -> Dict[str, Any]:
    """
    Build the response body shared by every scan adhering to StandardScanOutput.

    Args:
        result: A ScanResult or _PartialResult

    Returns:
        Dict[str, Any]: The response payload
    """

    vulns = getattr(result, "vulnerabilities", [])
    ws = getattr(result, "root", None)
    findings = [_serialise(v, workspace=ws) for v in vulns]
    refuted = [_serialise(v, workspace=ws) for v in getattr(result, "refuted_vulnerabilities", [])]

    counts: Dict[str, int] = {}
    sources: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "")
        counts[sev] = counts.get(sev, 0) + 1
        src = f.get("source", "")
        sources[src] = sources.get(src, 0) + 1

    reports = getattr(result, "reports", [])
    chains = [
        {
            "severity": chain.combined_severity.value if hasattr(chain.combined_severity, "value") else str(chain.combined_severity),
            "likelihood": chain.likelihood,
            "mitigation_priority": chain.mitigation_priority,
            "prerequisites": chain.prerequisites,
            "steps": [
                {
                    "type": v.type.value if hasattr(v.type, "value") else str(v.type),
                    "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                    "file": normalize_posix_path(v.location.file_path, root=ws) if v.location and v.location.file_path else "",
                    "line": v.location.start_line if v.location else 0,
                }
                for v in chain.vulnerabilities
            ],
        }
        for report in reports
        for chain in getattr(report, "chained_vulnerabilities", [])
    ]

    files = [
        {
            "file": normalize_posix_path(report.file_name, root=ws) if getattr(report, "file_name", None) else "",
            "findings": len(getattr(report, "vulnerabilities", [])),
            "refuted": len(getattr(report, "refuted_vulnerabilities", [])),
            "risk_score": getattr(report, "risk_score", 0) or 0,
            "tiers": getattr(report, "tiers", {}),
            "status": getattr(report, "status", "completed"),
            "engine_status": getattr(report, "engine_status", {}),
        }
        for report in reports
    ]

    target_str = normalize_posix_path(ws) if ws else ""
    opts = getattr(result, "options", None)
    if opts is None:
        opts = result.stats.get("options", {}) if isinstance(getattr(result, "stats", None), dict) else {}
    if not isinstance(opts, dict):
        opts = {}

    stats_dict = dict(result.stats) if getattr(result, "stats", None) and isinstance(result.stats, dict) else {}

    std_out = StandardScanOutput(
        schema_version="1.0.0",
        scanner="VulnAgent",
        timestamp=datetime.now(timezone.utc).isoformat(),
        target=target_str,
        options=opts,
        stats=stats_dict,
        files=files,
        findings=findings,
        refuted_findings=refuted,
        chains=chains,
        status=getattr(result, "status", "completed"),
        degraded=getattr(result, "degraded", False),
        counts=counts,
        sources=sources,
        risk_score=round(sum(getattr(r, "risk_score", 0) or 0 for r in reports), 2),
    )
    return std_out.model_dump(mode="json")


def _safe_label(name: str) -> str:
    """
    Reduce a client-supplied name to something safe to store and display.

    The label is persisted to disk and rendered in the job list, so only the
    basename is kept: keeping the rest lets a caller write "../../.." into
    the scan history for no benefit.

    Args:
        name: The name as submitted

    Returns:
        str: The basename, with separators and unprintable characters removed
    """

    base = re.split(r"[\\/]+", str(name or ""))[-1].strip()
    base = "".join(ch for ch in base if ch.isprintable())
    return base[:120] or "snippet.py"


def _safe_relative(name: str) -> Optional[str]:
    """
    Turn a client-supplied upload path into a safe relative path.

    Browsers send the folder structure as part of each filename. That string
    is attacker-controlled, so it is rebuilt from its parts rather than
    trusted: anything absolute, containing "..", or otherwise escaping is
    rejected outright.

    Args:
        name: The filename from the upload

    Returns:
        Optional[str]: A safe relative path, or None to reject the file
    """

    if not name:
        return None

    parts = [p for p in re.split(r"[\\/]+", name) if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    if re.match(r"^[a-zA-Z]:$", parts[0]):     # drive letter
        return None
    if any(p.startswith(("venv", ".git", "node_modules", "__pycache__")) for p in parts):
        return None

    cleaned = [re.sub(r'[<>:"|?*\x00-\x1f]', "_", p) for p in parts]
    return "/".join(cleaned)


def _resolve_mode(mode: str, verify: bool = False) -> tuple[bool, bool, bool]:
    """
    Resolve (use_semgrep, use_llm, verify) from mode name and optional verify flag.

    Supported modes:
        - 'deep-verify' / 'deepverify' / 'verify' / '3-tier' / '3tier': VulnAgent DeepVerify (Semgrep + LLM + Verifier)
        - 'llm' / 'llm-only': LLM only (No Semgrep)
        - 'semgrep' / 'semgrep-only' / 'fast': Semgrep rules only (No LLM)
    """
    m = (mode or "").strip().lower()
    if m in ("semgrep", "semgrep-only", "semgrep_only", "fast"):
        return True, False, False
    elif m in ("llm", "llm-only", "llm_only"):
        return False, True, verify
    else:  # "deep-verify", "deepverify", "verify", "3-tier", "3tier", or default
        return True, True, True


def _start(job: Job, options: ScanOptions, background: BackgroundTasks) -> Dict[str, Any]:
    """
    Attach progress reporting and queue the scan.

    Args:
        job: The job to run
        options: Scan configuration
        background: FastAPI background task registry

    Returns:
        Dict[str, Any]: The job summary to return immediately
    """

    options.progress = lambda event: store.record_event(job, event)

    # Publish what has been found before verification runs, so the page shows
    # accumulating results instead of a bar moving over an empty screen.
    def publish_partial(reports: Any) -> None:
        store.update(job, result={
            **_package(_PartialResult(reports)),
            "partial": True,
        })

    options.on_partial = publish_partial

    async def execute() -> None:
        async def scan_and_auto_name() -> Any:
            res = await Scanner(options).scan()
            if not job.options.get("custom_name"):
                try:
                    smart_title = await generate_smart_scan_title(
                        files=getattr(res, "reports", []),
                        findings=getattr(res, "vulnerabilities", []),
                        kind=job.kind,
                        fallback_seed=job.label,
                        mode=job.options.get("mode", "deep-verify"),
                    )
                    if smart_title and smart_title != job.label:
                        job.label = smart_title
                        store.update(job, label=smart_title)
                except Exception as e:
                    logging.debug(f"Failed to auto-name job with AI: {e}")
            return res

        await run_job(store, job, scan_and_auto_name, _package)

    background.add_task(execute)
    return job.as_summary()


class _PartialResult:
    """
    Enough of a ScanResult to package interim findings for the UI.
    """

    def __init__(self, reports: Any) -> None:
        self.reports = reports
        self.root = Path(".")
        self.stats: Dict[str, Any] = {}

    @property
    def vulnerabilities(self) -> List[Vulnerability]:
        return [v for report in self.reports for v in report.vulnerabilities]

    @property
    def degraded(self) -> bool:
        return any(report.degraded for report in self.reports)


@app.get("/")
async def index():
    """
    Serve the dashboard.
    """

    page = STATIC_DIR / "index.html"
    if not page.is_file():
        return JSONResponse({"detail": "UI not installed; see /docs for the API"}, 404)
    return FileResponse(str(page))


@app.post("/api/jobs/folder")
async def scan_folder(request: Request, background: BackgroundTasks) -> Dict[str, Any]:
    """
    Scan an uploaded folder.

    The form is parsed by hand rather than through File()/Form() parameters
    because Starlette caps multipart uploads at 1,000 parts by default and
    that ceiling is not reachable from a dependency signature. Uploading the
    OWASP Benchmark for Python, 1,230 files, failed on that limit with a
    message that looks like it comes from the browser.

    Args:
        request: The incoming request, parsed with raised multipart limits
        background: FastAPI background tasks

    Returns:
        Dict[str, Any]: The created job
    """

    part_cap = MAX_UPLOAD_FILES + 64 if MAX_UPLOAD_FILES else float("inf")
    try:
        form = await request.form(max_files=part_cap, max_fields=part_cap)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not read the upload: {e}")

    files = [v for v in form.getlist("files") if isinstance(v, StarletteUploadFile)]
    mode = str(form.get("mode") or "deep-verify")
    raw_verify = str(form.get("verify") or "false").lower() in ("1", "true", "yes", "on")
    use_semgrep, use_llm, verify = _resolve_mode(mode, raw_verify)
    try:
        concurrency = int(form.get("concurrency") or 16)
    except (TypeError, ValueError):
        concurrency = 16

    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")
    if MAX_UPLOAD_FILES and len(files) > MAX_UPLOAD_FILES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Too many files ({len(files)}); the limit is {MAX_UPLOAD_FILES}. "
                "Raise VULNAGENT_MAX_UPLOAD_FILES, set it to 0 to remove the "
                "limit, or scan the tree with the CLI instead."
            )
        )

    workspace = Path(tempfile.mkdtemp(prefix="vulnagent_upload_"))
    total = 0
    written = 0
    oversized = 0
    root_name = ""

    try:
        for upload in files:
            relative = _safe_relative(upload.filename or "")
            if not relative:
                continue
            if Path(relative).suffix.lower() not in SCANNABLE_SUFFIXES:
                continue

            raw = await upload.read()
            if MAX_SINGLE_FILE_BYTES and len(raw) > MAX_SINGLE_FILE_BYTES:
                oversized += 1
                continue
            total += len(raw)
            if MAX_TOTAL_UPLOAD_BYTES and total > MAX_TOTAL_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=(
                        f"Upload exceeds {MAX_TOTAL_UPLOAD_BYTES // (1024 * 1024)} MB. "
                        "Raise VULNAGENT_MAX_UPLOAD_BYTES or set it to 0."
                    )
                )

            destination = workspace / relative
            # Belt and braces: confirm the resolved path is still inside.
            if workspace.resolve() not in destination.resolve().parents:
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            written += 1
            if not root_name:
                root_name = relative.split("/")[0]

        if not written:
            raise HTTPException(
                status_code=400,
                detail="No scannable source files found in the upload"
            )
    except HTTPException:
        shutil.rmtree(workspace, ignore_errors=True)
        raise

    if oversized:
        logging.warning(
            "%d uploaded file(s) exceeded the per-file limit and were skipped", oversized
        )

    job = store.create(
        kind="folder",
        label=f"{root_name or 'upload'} ({written} files)",
        options={
            "mode": mode, "verify": verify, "files": written,
            "concurrency": concurrency,
            "skipped_oversized": oversized,
        },
        workspace=str(workspace),
    )
    options = ScanOptions(
        target=str(workspace),
        use_llm=use_llm,
        use_semgrep=use_semgrep,
        concurrency=max(1, min(concurrency, 50)),
        verify=verify,
    )
    return _start(job, options, background)


@app.post("/api/jobs/snippet")
async def scan_snippet(
    request: SnippetRequest,
    background: BackgroundTasks
) -> Dict[str, Any]:
    """
    Scan a snippet pasted into the UI.

    Args:
        request: Code and options
        background: FastAPI background tasks

    Returns:
        Dict[str, Any]: The created job
    """

    if not request.code.strip():
        raise HTTPException(status_code=400, detail="No code supplied")
    if MAX_CODE_CHARS and len(request.code) > MAX_CODE_CHARS:
        raise HTTPException(
            status_code=413,
            detail=f"Code too large (max {MAX_CODE_CHARS} characters)"
        )

    workspace = Path(tempfile.mkdtemp(prefix="vulnagent_snippet_"))
    # Only the extension of the supplied name is used; building a path from
    # client text is the traversal defect this tool reports.
    suffix = Path(request.filename or "snippet.py").suffix or ".py"
    (workspace / f"snippet{suffix}").write_text(request.code, encoding="utf-8")

    use_semgrep, use_llm, verify = _resolve_mode(request.mode, request.verify)
    job = store.create(
        kind="snippet",
        # Client text that ends up on disk and on screen. Only the basename
        # is meaningful, and keeping the rest lets a caller write "../../.."
        # into the job list for no benefit.
        label=_safe_label(request.filename),
        options={"mode": request.mode, "verify": verify, "concurrency": request.concurrency},
        workspace=str(workspace),
    )
    options = ScanOptions(
        target=str(workspace),
        use_llm=use_llm,
        use_semgrep=use_semgrep,
        concurrency=max(1, min(getattr(request, "concurrency", 16), 50)),
        verify=verify,
    )
    return _start(job, options, background)


def _validate_repo_url(url: str) -> str:
    """
    Reject repository URLs that should not be fetched.

    Args:
        url: The requested repository URL

    Returns:
        str: The validated URL

    Raises:
        HTTPException: When the URL is not an allowed public code host
    """

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise HTTPException(status_code=400, detail="Repository URL must use https")
    if parsed.hostname not in ALLOWED_GIT_HOSTS:
        raise HTTPException(
            status_code=400,
            detail=f"Host not allowed. Permitted: {', '.join(sorted(ALLOWED_GIT_HOSTS))}"
        )
    if not re.match(r"^/[\w.-]+/[\w.-]+/?$", parsed.path):
        raise HTTPException(status_code=400, detail="Expected a URL of the form /owner/repo")
    return url


@app.post("/api/jobs/repository")
async def scan_repository(
    request: RepositoryRequest,
    background: BackgroundTasks
) -> Dict[str, Any]:
    """
    Clone a public repository and scan it.

    Args:
        request: Repository URL, branch and options
        background: FastAPI background tasks

    Returns:
        Dict[str, Any]: The created job
    """

    url = _validate_repo_url(request.repository_url)
    if not re.match(r"^[\w./-]{1,100}$", request.branch):
        raise HTTPException(status_code=400, detail="Invalid branch name")

    workspace = Path(tempfile.mkdtemp(prefix="vulnagent_repo_"))
    use_semgrep, use_llm, verify = _resolve_mode(request.mode, request.verify)
    job = store.create(
        kind="repository",
        label=f"{url.rstrip('/').split('/')[-1]}@{request.branch}",
        options={"mode": request.mode, "verify": verify, "url": url, "concurrency": request.concurrency},
        workspace=str(workspace),
    )

    options = ScanOptions(
        target=str(workspace),
        use_llm=use_llm,
        use_semgrep=use_semgrep,
        concurrency=max(1, min(getattr(request, "concurrency", 16), 50)),
        max_llm_files=request.max_files,
        verify=verify,
    )
    options.progress = lambda event: store.record_event(job, event)
    options.on_partial = lambda reports: store.update(job, result={
        **_package(_PartialResult(reports)), "partial": True,
    })

    async def execute() -> None:
        import git

        async def scan_after_clone() -> Any:
            store.record_event(job, {
                "phase": "clone", "message": f"Cloning {url}", "percent": 1
            })
            await asyncio.to_thread(
                git.Repo.clone_from, url, str(workspace),
                branch=request.branch, depth=1
            )
            return await Scanner(options).scan()

        await run_job(store, job, scan_after_clone, _package)

    background.add_task(execute)
    return job.as_summary()


@app.get("/api/jobs")
async def list_jobs(limit: int = Query(50, ge=1, le=200)) -> Dict[str, Any]:
    """
    List recent jobs.

    Args:
        limit: Maximum jobs to return

    Returns:
        Dict[str, Any]: Job summaries, newest first
    """

    return {"jobs": [job.as_summary() for job in store.list(limit=limit)]}


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str) -> Dict[str, Any]:
    """
    Fetch a job, including its result when finished.

    Args:
        job_id: Job identifier

    Returns:
        Dict[str, Any]: The full job record
    """

    job = store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job")

    bench_eval = None
    if job.status == "done" and job.result:
        bench_eval = evaluate_job_benchmark_data(job)

    return {
        **job.as_summary(),
        "options": job.options,
        "result": job.result,
        "events": job.events[-80:],
        "benchmark_evaluation": bench_eval,
    }


def evaluate_job_benchmark_data(job: Any) -> Dict[str, Any]:
    """
    Automatically evaluate a job against benchmark ground truth.
    Strictly supports ONLY benchmark100 and benchmark1000 datasets.
    """
    try:
        import math
        from eval.evaluate_scan import (
            resolve_dataset_dir,
            extract_findings_from_payload,
            finding_to_detection,
            compute_per_cwe_breakdown,
        )
        from eval.run_eval import (
            load_dataset,
            match,
            LINE_TOLERANCE,
            _min_cost_max_bipartite_matching,
        )
    except ImportError as e:
        return {"supported": False, "reason": f"Evaluation engine unavailable: {e}"}

    job_options = getattr(job, "options", {}) or {}
    job_label = getattr(job, "label", "") or ""
    job_workspace = getattr(job, "workspace", "") or ""
    job_result = getattr(job, "result", None) or {}

    target = str(job_options.get("target", "")).lower()
    label = str(job_label).lower()
    workspace = str(job_workspace).lower()

    files = job_result.get("files", [])
    file_names = [f.get("file", "") if isinstance(f, dict) else str(f) for f in files]
    has_benchmark_files = any("benchmarktest" in fn.lower() for fn in file_names)

    dataset_key = None
    # Strictly identify benchmark100 and benchmark1000 ONLY
    if "benchmark100" in target or "benchmark100" in label or "benchmark100" in workspace:
        dataset_key = "benchmark100"
    elif "benchmark1000" in target or "benchmark1000" in label or "benchmark1230" in label or "1230" in label or "1,230" in label:
        dataset_key = "benchmark1000"
    elif has_benchmark_files:
        dataset_key = "benchmark100" if len(files) <= 150 else "benchmark1000"
    elif "100 files" in label or "100 selected" in label:
        dataset_key = "benchmark100"

    if not dataset_key:
        return {
            "supported": False,
            "reason": "Automatic benchmark evaluation is only supported for benchmark100 and benchmark1000 datasets."
        }

    try:
        dataset_name = "benchmark100" if dataset_key == "benchmark100" else "benchmark"
        dataset_dir = resolve_dataset_dir(dataset_name)
        labels, dataset_meta = load_dataset(dataset_dir)
        findings_raw = extract_findings_from_payload(job_result)
        label_files = {l.file for l in labels}
        detections = []
        for f in findings_raw:
            det = finding_to_detection(f, dataset_dir, label_files=label_files)
            if det:
                detections.append(det)

        match_mode = dataset_meta.get("match_mode", "line")
        partial_labels = dataset_meta.get("partial_labels", False)
        clean_files = dataset_meta.get("clean_files", [])

        metrics = match(
            detections=detections,
            labels=labels,
            name=getattr(job, "id", "scan"),
            match_mode=match_mode,
            partial_labels=partial_labels,
            exact_cwe=False,
            clean_files=clean_files,
            raw_findings=findings_raw,
        )
        matched_pairs = _min_cost_max_bipartite_matching(
            detections=detections,
            labels=labels,
            match_mode=match_mode,
            exact_cwe=False,
            tolerance=LINE_TOLERANCE,
        )
        claimed_label_indices = {l_idx for _, l_idx in matched_pairs}
        per_cwe = compute_per_cwe_breakdown(labels, claimed_label_indices)

        return {
            "supported": True,
            "dataset_key": dataset_key,
            "dataset_name": dataset_meta.get("name", "OWASP Benchmark"),
            "total_ground_truth": len(labels),
            "findings_count": len(findings_raw),
            "detections_count": len(detections),
            "metrics": {
                "tp": metrics.true_positives,
                "fp": metrics.false_positives,
                "fn": metrics.false_negatives,
                "precision": round(metrics.precision, 4) if (metrics.precision and not math.isnan(metrics.precision)) else 0.0,
                "recall": round(metrics.recall, 4) if (metrics.recall and not math.isnan(metrics.recall)) else 0.0,
                "f1": round(metrics.f1, 4) if (metrics.f1 and not math.isnan(metrics.f1)) else 0.0,
                "fp_on_clean_files": metrics.fp_on_clean,
                "fp_duplicate_sink": metrics.fp_duplicate,
                "fp_wrong_line_tolerance": metrics.fp_wrong_line,
                "fp_wrong_type_right_file": metrics.fp_wrong_type,
                "unmatched": metrics.unmatched,
            },
            "per_cwe": per_cwe,
            "missed": (metrics.missed or [])[:50],
            "spurious": (metrics.spurious or [])[:50],
        }
    except Exception as e:
        return {"supported": False, "reason": f"Benchmark evaluation failed: {e}"}


@app.get("/api/jobs/{job_id}/benchmark")
async def get_job_benchmark(job_id: str) -> Dict[str, Any]:
    """
    Get automated benchmark evaluation for a job if it belongs to benchmark100 or benchmark1000.
    """
    job = store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job")
    if job.status != "done" or not job.result:
        return {"supported": False, "reason": "Job is still in progress or has no result."}
    return evaluate_job_benchmark_data(job)


@app.get("/api/benchmarks")
async def list_benchmark_evaluations() -> Dict[str, Any]:
    """
    List all completed benchmark jobs with their ground-truth evaluations (benchmark100 and benchmark1000).
    """
    jobs = store.list(limit=200)
    bench_jobs = []
    for j in jobs:
        if j.status == "done" and j.result:
            ev = evaluate_job_benchmark_data(j)
            if ev.get("supported"):
                bench_jobs.append({
                    "id": j.id,
                    "label": j.label,
                    "kind": j.kind,
                    "status": j.status,
                    "dataset_key": ev["dataset_key"],
                    "dataset_name": ev["dataset_name"],
                    "created_at": j.created_at,
                    "finished_at": j.finished_at,
                    "metrics": ev["metrics"],
                    "findings_count": ev["findings_count"],
                    "total_ground_truth": ev["total_ground_truth"]
                })
    return {"benchmark_jobs": bench_jobs}


@app.delete("/api/jobs/{job_id}")
async def delete_job(job_id: str) -> Dict[str, Any]:
    """
    Delete a job and its stored result.

    Args:
        job_id: Job identifier

    Returns:
        Dict[str, Any]: Confirmation
    """

    job = store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job")

    JobStore.cleanup_workspace(job)
    store._jobs.pop(job_id, None)
    try:
        (store.directory / f"{job_id}.json").unlink(missing_ok=True)
    except OSError:
        pass
    return {"deleted": job_id}


@app.patch("/api/jobs/{job_id}")
@app.put("/api/jobs/{job_id}/rename")
@app.post("/api/jobs/{job_id}/rename")
async def rename_job(job_id: str, req: RenameJobRequest) -> Dict[str, Any]:
    """
    Rename an existing scan job.
    """
    job = store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job")
    new_label = (req.label or "").strip()
    if not new_label:
        raise HTTPException(status_code=400, detail="Label cannot be blank")
    job.options["custom_name"] = True
    store.update(job, label=new_label, options=job.options)
    return {"status": "ok", "id": job_id, "label": job.label}


async def generate_smart_scan_title(
    files: Any,
    findings: Any,
    kind: str = "folder",
    fallback_seed: str = "Scan",
    mode: str = "deep-verify"
) -> str:
    """
    Generate a smart, concise, professional report title (4 to 7 words)
    using AI reasoning or intelligent heuristics based on target files and detected security defects.
    """
    file_names = []
    for f in (files or [])[:6]:
        if isinstance(f, dict):
            fn = f.get("file") or f.get("file_name") or ""
        elif hasattr(f, "file_name"):
            fn = f.file_name or ""
        elif hasattr(f, "location") and getattr(f.location, "file_path", None):
            fn = f.location.file_path or ""
        else:
            fn = Path(str(f)).name
        if fn:
            file_names.append(Path(fn).name)
    file_names = [f for f in file_names if f]

    findings_summary = []
    for f in (findings or [])[:6]:
        if isinstance(f, dict):
            f_type = f.get("type") or "Vulnerability"
            f_cwe = f.get("cwe") or ""
            f_file = Path(f.get("file", "")).name
        elif hasattr(f, "type"):
            f_type = f.type.value if hasattr(f.type, "value") else str(f.type)
            f_cwe = getattr(f, "cwe_id", "") or ""
            f_file = Path(getattr(f.location, "file_path", "")).name
        else:
            continue
        findings_summary.append(f"{f_type} {f_cwe} in {f_file}".strip())

    files_str = ", ".join(file_names) if file_names else str(fallback_seed)
    findings_str = "; ".join(findings_summary) if findings_summary else "Clean code / No vulnerabilities detected"

    clean_seed = Path(fallback_seed).stem if fallback_seed else "Application"
    fallback_title = f"{clean_seed.replace('_', ' ').title()} Security Audit"
    if findings:
        first_f = findings[0]
        first_type = (first_f.get("type") if isinstance(first_f, dict) else getattr(first_f.type, "value", str(first_f.type))).replace("_", " ").title()
        target_fn = Path((first_f.get("file") if isinstance(first_f, dict) else getattr(first_f.location, "file_path", ""))).stem
        if target_fn and target_fn.lower() not in ("app", "main", "test", "snippet"):
            fallback_title = f"{target_fn.replace('_', ' ').title()} {first_type} Audit"
        else:
            fallback_title = f"{first_type} Security Audit"

    prompt = f"""You are a senior security engineer and audit report specialist.
Generate a concise, highly professional, descriptive title (maximum 4 to 7 words) for a security scan report based on the audited components and detected defects:

Scanned Target / Components: {files_str}
Security Findings / Flaws: {findings_str}
Scan Type: {kind} ({mode})

Requirements:
1. Clearly identify the primary subject, service, or component being audited (e.g. 'Django ORM Datetime SQLi Audit', 'Airflow Task Instance IDOR Scan', 'FastAPI User Authentication Security Review', 'OWASP Benchmark Suite Evaluation', 'Clean Application Security Verification').
2. Keep it strictly between 4 and 7 words.
3. Return ONLY the exact title text string. Do not include quotes, markdown bold, labels like 'Title:', or trailing punctuation."""

    try:
        from utils.ai_client import AIClient
        client = AIClient()
        model = os.getenv("OPENAI_MODEL", "cmc/reflection/beam:free")
        messages = [
            {"role": "system", "content": "You are a professional security report naming assistant. Respond with ONLY the concise title."},
            {"role": "user", "content": prompt}
        ]
        kwargs = {"model": model, "messages": messages, "stream": False}
        if not client._is_reasoning_model(model):
            kwargs["temperature"] = 0.2

        response = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.openai_client.chat.completions.create(**kwargs)),
            timeout=8.0
        )
        raw_title = response.choices[0].message.content or ""
        raw_title = re.sub(r'<(?:think|thought)>[\s\S]*?</(?:think|thought)>', '', raw_title, flags=re.I).strip()
        clean_title = raw_title.strip("\"'`").split("\n")[0].strip()
        clean_title = re.sub(r'^(Title|Suggested Title|Report Name):\s*', '', clean_title, flags=re.I).strip()
        if clean_title and len(clean_title) >= 3:
            return clean_title
    except Exception as e:
        logging.debug(f"AI auto-naming failed ({e}); falling back to heuristic title")

    return fallback_title


@app.post("/api/jobs/{job_id}/suggest_name")
async def suggest_job_name(job_id: str) -> Dict[str, Any]:
    """
    Use AI or intelligent heuristics to generate a concise, fitting name for a scan based on its target and findings.
    """
    job = store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job")

    result = job.result or {}
    files_list = result.get("files", [])
    findings = result.get("findings", [])
    mode = job.options.get("mode", "deep-verify")

    smart_title = await generate_smart_scan_title(
        files=files_list,
        findings=findings,
        kind=job.kind,
        fallback_seed=job.label,
        mode=mode
    )

    return {"status": "ok", "suggested_label": smart_title, "model": os.getenv("OPENAI_MODEL", "ai")}


@app.post("/api/jobs/clear")
@app.delete("/api/jobs")
async def clear_all_jobs() -> Dict[str, Any]:
    """
    Delete all stored jobs and clean up their workspaces.
    """
    deleted_ids = []
    for job in list(store._jobs.values()):
        JobStore.cleanup_workspace(job)
        try:
            (store.directory / f"{job.id}.json").unlink(missing_ok=True)
            deleted_ids.append(job.id)
        except OSError:
            pass
    store._jobs.clear()
    return {"status": "ok", "deleted_count": len(deleted_ids), "deleted": deleted_ids}


@app.get("/api/jobs/{job_id}/events")
async def stream_job(job_id: str) -> StreamingResponse:
    """
    Stream live progress for one job as server-sent events.

    The first frame is the current state, so a browser that reconnects after
    a reload is immediately correct rather than blank until the next update.

    Args:
        job_id: Job identifier

    Returns:
        StreamingResponse: An SSE stream
    """

    job = store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="No such job")

    async def events():
        queue = store.subscribe(job_id)
        try:
            yield f"data: {json.dumps(job.as_summary())}\n\n"
            if job.status in ("done", "failed", "cancelled"):
                return
            while True:
                try:
                    update = await asyncio.wait_for(queue.get(), timeout=20)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                yield f"data: {json.dumps(update)}\n\n"
                if update.get("status") in ("done", "failed", "cancelled"):
                    return
        finally:
            store.unsubscribe(job_id, queue)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/stats")
async def stats() -> Dict[str, Any]:
    """
    Aggregate metrics across every completed job.

    Returns:
        Dict[str, Any]: Dashboard totals
    """

    return store.aggregate()


@app.get("/api/file_context")
@app.get("/api/jobs/{job_id}/file")
async def get_file_context(
    file: str,
    line: int = 1,
    job_id: Optional[str] = None,
    context_lines: int = 3
) -> Dict[str, Any]:
    """
    Fetch exact code lines around a target line for dataflow step inspection.
    """
    ws = None
    if job_id:
        job = store.get(job_id)
        if job and job.workspace:
            ws = Path(job.workspace)
    code = _read_code_snippet(file, line, workspace=ws, context_lines=context_lines)
    if not code:
        return {"status": "error", "message": f"Could not locate {file} or line {line}", "code": ""}
    return {
        "status": "ok",
        "file": file,
        "line": line,
        "code": code
    }


@app.get("/api/settings")
async def get_settings() -> Dict[str, Any]:
    """
    Get current AI model and backend configuration.
    """
    api_key = os.getenv("OPENAI_API_KEY", "")
    masked_key = ""
    if api_key:
        if len(api_key) <= 8:
            masked_key = "****"
        else:
            masked_key = api_key[:4] + "*" * (len(api_key) - 8) + api_key[-4:]
    return {
        "openai_base_url": os.getenv("OPENAI_BASE_URL", "http://127.0.0.1:20128/v1"),
        "openai_model": os.getenv("OPENAI_MODEL", "cmc/reflection/beam:free"),
        "openai_api_key": api_key,
        "masked_api_key": masked_key,
        "is_configured": bool(api_key),
    }


@app.post("/api/settings")
async def update_settings(req: SettingsRequest) -> Dict[str, Any]:
    """
    Update AI model configuration in-memory and persist to .env file.
    """
    new_base_url = (req.openai_base_url or "").strip()
    new_model = (req.openai_model or "").strip()
    new_key = (req.openai_api_key or "").strip()

    if new_base_url:
        os.environ["OPENAI_BASE_URL"] = new_base_url
    if new_model:
        os.environ["OPENAI_MODEL"] = new_model
    if new_key and not new_key.startswith("****"):
        os.environ["OPENAI_API_KEY"] = new_key

    # Update or append to .env file
    env_path = Path(".env")
    env_lines = []
    if env_path.is_file():
        env_lines = env_path.read_text(encoding="utf-8").splitlines()

    env_dict = {}
    for line in env_lines:
        line_s = line.strip()
        if line_s and not line_s.startswith("#") and "=" in line_s:
            k, v = line_s.split("=", 1)
            env_dict[k.strip()] = v.strip()

    if new_base_url:
        env_dict["OPENAI_BASE_URL"] = new_base_url
    if new_model:
        env_dict["OPENAI_MODEL"] = new_model
    if new_key and not new_key.startswith("****"):
        env_dict["OPENAI_API_KEY"] = new_key

    lines_to_write = []
    for k in ["OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL"]:
        if k in env_dict:
            lines_to_write.append(f"{k}={env_dict.pop(k)}")
    for k, v in env_dict.items():
        lines_to_write.append(f"{k}={v}")

    try:
        env_path.write_text("\n".join(lines_to_write) + "\n", encoding="utf-8")
    except Exception as e:
        logging.warning(f"Failed to persist settings to .env: {e}")

    return {
        "status": "ok",
        "message": "Settings updated successfully",
        "settings": {
            "openai_base_url": os.getenv("OPENAI_BASE_URL"),
            "openai_model": os.getenv("OPENAI_MODEL"),
            "is_configured": bool(os.getenv("OPENAI_API_KEY")),
        }
    }


@app.post("/api/settings/test")
async def test_settings_connection(req: SettingsRequest) -> Dict[str, Any]:
    """
    Probe the specified model endpoint to test responsiveness.
    """
    base_url = (req.openai_base_url or os.getenv("OPENAI_BASE_URL") or "http://127.0.0.1:20128/v1").strip()
    model = (req.openai_model or os.getenv("OPENAI_MODEL") or "cmc/reflection/beam:free").strip()
    api_key = (req.openai_api_key or os.getenv("OPENAI_API_KEY") or "").strip()
    if api_key.startswith("****"):
        api_key = os.getenv("OPENAI_API_KEY", "")

    import urllib.request, urllib.error, time
    base_clean = base_url.rstrip("/")
    if not base_clean.endswith("/v1") and "/v1" not in base_clean:
        test_url = f"{base_clean}/v1/chat/completions"
    else:
        test_url = f"{base_clean}/chat/completions"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}" if api_key else ""
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Respond with OK"}],
        "stream": False
    }
    t0 = time.time()
    try:
        req_obj = urllib.request.Request(test_url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        with urllib.request.urlopen(req_obj, timeout=12) as res:
            dur = time.time() - t0
            raw_body = json.loads(res.read().decode("utf-8", errors="replace"))
            choices = raw_body.get("choices", [])
            reply = choices[0].get("message", {}).get("content", "OK") if choices else "Connected"
            return {
                "status": "ok",
                "latency_sec": round(dur, 2),
                "reply": reply[:100],
                "message": f"Connection successful ({dur:.2f}s)"
            }
    except urllib.error.HTTPError as e:
        dur = time.time() - t0
        err_msg = str(e)
        try:
            err_body = e.read().decode("utf-8", errors="replace")
            err_json = json.loads(err_body)
            err_msg = err_json.get("error", {}).get("message") or err_json.get("message") or err_body
        except Exception:
            pass
        return {
            "status": "error",
            "latency_sec": round(dur, 2),
            "message": f"HTTP {e.code}: {err_msg[:120]}"
        }
    except Exception as e:
        dur = time.time() - t0
        return {
            "status": "error",
            "latency_sec": round(dur, 2),
            "message": f"Connection failed ({dur:.2f}s): {str(e)}"
        }


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Report service and engine availability.

    Returns:
        Dict[str, Any]: Health information
    """

    from analyzer.semgrep_runner import SemgrepRunner

    runner = SemgrepRunner()
    return {
        "status": "healthy",
        "rule_engine": runner.available,
        "llm_configured": bool(os.getenv("OPENAI_API_KEY")),
        "model": os.getenv("OPENAI_MODEL", "o1-mini-2024-09-12"),
        "jobs": len(store.list(limit=1000)),
    }


def main() -> None:
    """
    Run the development server.
    """

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
