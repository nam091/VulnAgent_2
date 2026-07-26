"""HTTP API and web dashboard.

Wraps the same Scanner the CLI and MCP server use. Nothing analytical lives
here - this layer handles transport, input validation, job lifecycle and
progress streaming.

Scans run as background jobs rather than inside a request, so the browser
can be refreshed, closed or reopened without losing one.
"""

import asyncio
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
from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from analyzer.fixer import classify_patch, unified_diff
from analyzer.scanner import ScanOptions, Scanner
from jobs import Job, JobStore, run_job
from models.vulnerability import FindingSource, Vulnerability

STATIC_DIR = Path(__file__).resolve().parent / "web"

# Cloning arbitrary URLs on request is a server-side request forgery
# primitive, so only well-known code hosts over https are accepted.
ALLOWED_GIT_HOSTS = {
    "github.com", "www.github.com",
    "gitlab.com", "www.gitlab.com",
    "bitbucket.org", "www.bitbucket.org",
}
MAX_UPLOAD_FILES = 2000
MAX_TOTAL_UPLOAD_BYTES = 60 * 1024 * 1024
MAX_SINGLE_FILE_BYTES = 2 * 1024 * 1024
MAX_CODE_CHARS = 200_000
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
    mode: str = Field("deep", description="'fast' for rules only, 'deep' for both tiers")
    verify: bool = Field(False, description="Run the adversarial verification agent")


class RepositoryRequest(BaseModel):
    repository_url: str
    branch: str = "main"
    mode: str = "deep"
    verify: bool = False
    max_files: int = Field(40, ge=1, le=200)


def _serialise(vuln: Vulnerability) -> Dict[str, Any]:
    """
    Render a finding for the web client.

    Args:
        vuln: The finding

    Returns:
        Dict[str, Any]: JSON-safe representation
    """

    label = {
        FindingSource.CONFIRMED: "confirmed",
        FindingSource.SEMGREP: "rule-only",
        FindingSource.LLM: "llm-only",
    }.get(vuln.source, vuln.source.value)

    return {
        "id": vuln.id,
        "type": vuln.type.value,
        "severity": vuln.severity.value,
        "source": label,
        "confidence": round(vuln.confidence, 2),
        "file": vuln.location.file_path,
        "start_line": vuln.location.start_line,
        "end_line": vuln.location.end_line,
        "cwe": vuln.cwe_id,
        "owasp": vuln.owasp_category,
        "cvss": vuln.cvss_score,
        "description": vuln.description,
        "impact": vuln.impact,
        "remediation": vuln.remediation,
        "secure_code_example": vuln.secure_code_example,
        "snippet": vuln.location.context,
        "verification": vuln.verification,
        "taint_path": vuln.taint_path,
        "fix": _fix_payload(vuln),
    }


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
    Build the response body shared by every scan.

    Args:
        result: A ScanResult

    Returns:
        Dict[str, Any]: The response payload
    """

    vulns = result.vulnerabilities
    counts: Dict[str, int] = {}
    sources: Dict[str, int] = {}
    for vuln in vulns:
        counts[vuln.severity.value] = counts.get(vuln.severity.value, 0) + 1
        label = _serialise(vuln)["source"]
        sources[label] = sources.get(label, 0) + 1

    chains = [
        {
            "severity": chain.combined_severity.value,
            "likelihood": chain.likelihood,
            "mitigation_priority": chain.mitigation_priority,
            "prerequisites": chain.prerequisites,
            "steps": [
                {
                    "type": v.type.value,
                    "severity": v.severity.value,
                    "file": v.location.file_path,
                    "line": v.location.start_line,
                }
                for v in chain.vulnerabilities
            ],
        }
        for report in result.reports
        for chain in report.chained_vulnerabilities
    ]

    files = [
        {
            "file": report.file_name,
            "findings": len(report.vulnerabilities),
            "risk_score": report.risk_score or 0,
            "tiers": report.tiers,
        }
        for report in result.reports
    ]

    return {
        "findings": [_serialise(v) for v in vulns],
        "counts": counts,
        "sources": sources,
        "chains": chains,
        "files": files,
        "risk_score": round(sum(r.risk_score or 0 for r in result.reports), 2),
        "stats": result.stats,
        "degraded": result.degraded,
    }


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

    async def execute() -> None:
        await run_job(store, job, lambda: Scanner(options).scan(), _package)

    background.add_task(execute)
    return job.as_summary()


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
async def scan_folder(
    background: BackgroundTasks,
    files: List[UploadFile] = File(...),
    mode: str = Form("deep"),
    verify: bool = Form(False),
    concurrency: int = Form(5)
) -> Dict[str, Any]:
    """
    Scan an uploaded folder.

    Args:
        background: FastAPI background tasks
        files: Uploaded files, named with their path inside the folder
        mode: "fast" or "deep"
        verify: Run the verification agent
        concurrency: Concurrent LLM calls

    Returns:
        Dict[str, Any]: The created job
    """

    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")
    if len(files) > MAX_UPLOAD_FILES:
        raise HTTPException(
            status_code=413,
            detail=f"Too many files ({len(files)}); the limit is {MAX_UPLOAD_FILES}"
        )

    workspace = Path(tempfile.mkdtemp(prefix="vulnagent_upload_"))
    total = 0
    written = 0
    root_name = ""

    try:
        for upload in files:
            relative = _safe_relative(upload.filename or "")
            if not relative:
                continue
            if Path(relative).suffix.lower() not in SCANNABLE_SUFFIXES:
                continue

            raw = await upload.read()
            if len(raw) > MAX_SINGLE_FILE_BYTES:
                continue
            total += len(raw)
            if total > MAX_TOTAL_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="Upload exceeds 20 MB")

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

    job = store.create(
        kind="folder",
        label=f"{root_name or 'upload'} ({written} files)",
        options={"mode": mode, "verify": verify, "files": written},
        workspace=str(workspace),
    )
    options = ScanOptions(
        target=str(workspace),
        use_llm=(mode != "fast"),
        use_semgrep=True,
        concurrency=max(1, min(concurrency, 10)),
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
    if len(request.code) > MAX_CODE_CHARS:
        raise HTTPException(status_code=413, detail="Code too large (max 200k characters)")

    workspace = Path(tempfile.mkdtemp(prefix="vulnagent_snippet_"))
    # Only the extension of the supplied name is used; building a path from
    # client text is the traversal defect this tool reports.
    suffix = Path(request.filename or "snippet.py").suffix or ".py"
    (workspace / f"snippet{suffix}").write_text(request.code, encoding="utf-8")

    job = store.create(
        kind="snippet",
        # Client text that ends up on disk and on screen. Only the basename
        # is meaningful, and keeping the rest lets a caller write "../../.."
        # into the job list for no benefit.
        label=_safe_label(request.filename),
        options={"mode": request.mode, "verify": request.verify},
        workspace=str(workspace),
    )
    options = ScanOptions(
        target=str(workspace),
        use_llm=(request.mode != "fast"),
        use_semgrep=True,
        verify=request.verify,
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
    job = store.create(
        kind="repository",
        label=f"{url.rstrip('/').split('/')[-1]}@{request.branch}",
        options={"mode": request.mode, "verify": request.verify, "url": url},
        workspace=str(workspace),
    )

    options = ScanOptions(
        target=str(workspace),
        use_llm=(request.mode != "fast"),
        use_semgrep=True,
        concurrency=5,
        max_llm_files=request.max_files,
        verify=request.verify,
    )
    options.progress = lambda event: store.record_event(job, event)

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

    return {
        **job.as_summary(),
        "options": job.options,
        "result": job.result,
        "events": job.events[-80:],
    }


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
