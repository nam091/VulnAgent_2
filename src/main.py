"""HTTP API and web UI.

Wraps the same Scanner the CLI and MCP server use. Nothing analytical lives
here - this layer only handles transport, input validation and rendering.
"""

import asyncio
import logging
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from analyzer.scanner import ScanOptions, Scanner
from models.vulnerability import FindingSource, Vulnerability

STATIC_DIR = Path(__file__).resolve().parent / "web"

# Cloning arbitrary URLs on request is a server-side request forgery primitive.
# Only well-known code hosts over https are accepted.
ALLOWED_GIT_HOSTS = {
    "github.com", "www.github.com",
    "gitlab.com", "www.gitlab.com",
    "bitbucket.org", "www.bitbucket.org",
}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_CODE_CHARS = 200_000
REPO_SCAN_TIMEOUT = 600

app = FastAPI(
    title="VulnAgent",
    description="Hybrid vulnerability detection: rule-based static analysis + LLM",
    version="1.0.0"
)

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class CodeScanRequest(BaseModel):
    code: str = Field(..., description="Source code to analyse")
    filename: str = Field("snippet.py", description="Name used for language detection")
    mode: str = Field("deep", description="'fast' for rules only, 'deep' for both tiers")


class RepositoryScanRequest(BaseModel):
    repository_url: str
    branch: str = "main"
    mode: str = "deep"
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
    }


def _package(result, elapsed_note: Optional[str] = None) -> Dict[str, Any]:
    """
    Build the response body shared by every scan endpoint.

    Args:
        result: A ScanResult
        elapsed_note: Optional extra note for the client

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

    risk = round(sum(r.risk_score or 0 for r in result.reports), 2)

    return {
        "findings": [_serialise(v) for v in vulns],
        "counts": counts,
        "sources": sources,
        "chains": chains,
        "risk_score": risk,
        "stats": result.stats,
        "degraded": result.degraded,
        "note": elapsed_note,
    }


async def _scan_path(target: str, mode: str, concurrency: int = 5) -> Dict[str, Any]:
    """
    Run a scan over a path and package the result.

    Args:
        target: File or directory to scan
        mode: "fast" or "deep"
        concurrency: Concurrent LLM calls

    Returns:
        Dict[str, Any]: The response payload
    """

    options = ScanOptions(
        target=target,
        use_llm=(mode != "fast"),
        use_semgrep=True,
        concurrency=concurrency,
    )
    result = await Scanner(options).scan()
    return _package(result)


@app.get("/")
async def index():
    """
    Serve the web UI.
    """

    page = STATIC_DIR / "index.html"
    if not page.is_file():
        return JSONResponse({"detail": "UI not installed; see /docs for the API"}, 404)
    return FileResponse(str(page))


@app.post("/api/scan/code")
async def scan_code(request: CodeScanRequest) -> Dict[str, Any]:
    """
    Analyse a snippet of code supplied in the request body.

    Args:
        request: The code and options

    Returns:
        Dict[str, Any]: Findings and summary
    """

    if not request.code.strip():
        raise HTTPException(status_code=400, detail="No code supplied")
    if len(request.code) > MAX_CODE_CHARS:
        raise HTTPException(status_code=413, detail="Code too large (max 200k characters)")

    # Only the extension of the supplied name is used; building a path out
    # of client-controlled text is the traversal bug this tool reports.
    suffix = Path(request.filename or "snippet.py").suffix or ".py"
    tmp_dir = Path(tempfile.mkdtemp(prefix="vulnagent_api_"))
    tmp_file = tmp_dir / f"snippet{suffix}"

    try:
        tmp_file.write_text(request.code, encoding="utf-8")
        payload = await _scan_path(str(tmp_file), request.mode)
        for finding in payload["findings"]:
            finding["file"] = request.filename
        return payload
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.post("/api/scan/file")
async def scan_file(file: UploadFile = File(...), mode: str = "deep") -> Dict[str, Any]:
    """
    Analyse an uploaded file.

    Args:
        file: The uploaded file
        mode: "fast" or "deep"

    Returns:
        Dict[str, Any]: Findings and summary
    """

    if not file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded")

    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 2MB)")

    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 text")

    suffix = Path(file.filename).suffix or ".py"
    tmp_dir = Path(tempfile.mkdtemp(prefix="vulnagent_api_"))
    tmp_file = tmp_dir / f"upload{suffix}"

    try:
        tmp_file.write_text(content, encoding="utf-8")
        payload = await _scan_path(str(tmp_file), mode)
        for finding in payload["findings"]:
            finding["file"] = file.filename
        return payload
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


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


@app.post("/api/scan/repository")
async def scan_repository(request: RepositoryScanRequest) -> Dict[str, Any]:
    """
    Clone a public repository and analyse it.

    Args:
        request: Repository URL, branch and options

    Returns:
        Dict[str, Any]: Findings and summary
    """

    import git

    url = _validate_repo_url(request.repository_url)
    if not re.match(r"^[\w./-]{1,100}$", request.branch):
        raise HTTPException(status_code=400, detail="Invalid branch name")

    tmp_dir = Path(tempfile.mkdtemp(prefix="vulnagent_repo_"))
    try:
        try:
            await asyncio.to_thread(
                git.Repo.clone_from,
                url, str(tmp_dir), branch=request.branch, depth=1
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Clone failed: {e}")

        options = ScanOptions(
            target=str(tmp_dir),
            use_llm=(request.mode != "fast"),
            use_semgrep=True,
            concurrency=5,
            max_llm_files=request.max_files,
        )
        try:
            result = await asyncio.wait_for(
                Scanner(options).scan(), timeout=REPO_SCAN_TIMEOUT
            )
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=504,
                detail=f"Scan exceeded {REPO_SCAN_TIMEOUT}s. Try mode='fast' or a smaller repo."
            )

        return _package(result, elapsed_note=f"{request.repository_url}@{request.branch}")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Report service and engine availability.

    Returns:
        Dict[str, Any]: Health information
    """

    from analyzer.semgrep_runner import SemgrepRunner
    import os

    runner = SemgrepRunner()
    return {
        "status": "healthy",
        "rule_engine": runner.available,
        "llm_configured": bool(os.getenv("OPENAI_API_KEY")),
        "model": os.getenv("OPENAI_MODEL", "o1-mini-2024-09-12"),
    }


def main() -> None:
    """
    Run the development server.
    """

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
