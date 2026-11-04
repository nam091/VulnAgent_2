"""Background scan jobs with durable state.

Scans take minutes, so the web UI cannot hold one open in a request. Every
scan becomes a job with an id: the browser gets that id immediately, and
progress and results are fetched against it afterwards.

State is written to disk after every update, which is what makes the page
reload-safe. A refresh, a closed laptop, or a server restart mid-scan all
recover to the same job rather than losing it — a scan that vanishes because
someone pressed F5 is worse than no scan at all.
"""

import asyncio
import json
import logging
import shutil
import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

JOBS_DIRNAME = ".vulnagent-jobs"
MAX_EVENTS = 1500
DEFAULT_RETENTION = 50


def _resolve_model_name(raw_model: Optional[str]) -> str:
    if not raw_model:
        return ""
    m_str = str(raw_model).strip()
    if not m_str or m_str.lower() in ("default", "none", "null"):
        return ""
    m_low = m_str.lower()
    try:
        models_file = Path(".vulnagent-models.json")
        if models_file.is_file():
            profiles = json.loads(models_file.read_text(encoding="utf-8"))
            for p in profiles:
                if (p.get("model") or "").lower() == m_low:
                    return p.get("name") or m_str
                if (p.get("id") or "").lower() == m_low:
                    return p.get("name") or m_str
                if (p.get("name") or "").lower() == m_low:
                    return p.get("name") or m_str
    except Exception:
        pass

    if "hy3" in m_low or "hunyuan" in m_low:
        return "hy3"
    if "deepseek" in m_low:
        return "DeepSeek v4.1 Flash"
    if "beam" in m_low:
        return "Beam Free"
    if "glm-5.3-flash" in m_low:
        return "GLM-5.3 Flash"
    if "glm-5.3" in m_low:
        return "GLM-5.3"
    if "luna" in m_low:
        return "gpt-5.6-luna"
    if "solar" in m_low:
        return "Solar Mini"
    if "gemma" in m_low:
        return "Gemma4"
    if "gemini-3.8-flash" in m_low:
        return "gemini-3.8-flash"
    if m_low == "semgrep":
        return "Semgrep (Static)"

    if "/" in m_str:
        return m_str.split("/")[-1].split(":")[0]
    return m_str


def _extract_model_from_job(job: Any) -> str:
    opts = getattr(job, "options", None) or {}
    mode = (opts.get("mode") or "").strip().lower()
    label = getattr(job, "label", "") or ""

    if mode in ("semgrep", "semgrep-only", "semgrep_only") or label.strip().lower().endswith("· semgrep"):
        return "Semgrep (Static)"

    raw_model = opts.get("model")
    if raw_model:
        m = _resolve_model_name(raw_model)
        if m:
            return m

    if " by " in label:
        candidate = label.split(" by ")[-1].strip()
        if candidate:
            m = _resolve_model_name(candidate)
            if m:
                return m

    res = getattr(job, "result", None) or {}
    res_opts = res.get("options") or {}
    if res_opts.get("model"):
        m = _resolve_model_name(res_opts.get("model"))
        if m:
            return m

    # Fallback to active system default model profile from .vulnagent-models.json instead of "Default"
    try:
        models_file = Path(".vulnagent-models.json")
        if models_file.is_file():
            profiles = json.loads(models_file.read_text(encoding="utf-8"))
            for p in profiles:
                if p.get("is_default"):
                    return p.get("name") or "DeepSeek v4.1 Flash"
            if profiles:
                return profiles[0].get("name") or "DeepSeek v4.1 Flash"
    except Exception:
        pass

    return "DeepSeek v4.1 Flash"


@dataclass
class Job:
    """
    One scan, from submission to result.
    """

    id: str
    kind: str                       # "folder" | "snippet" | "repository"
    label: str                      # what the user sees in the job list
    status: str = "queued"          # queued | running | done | failed | cancelled
    percent: float = 0.0
    phase: str = "queued"
    message: str = "Waiting to start"
    created_at: str = ""
    updated_at: str = ""
    finished_at: str = ""
    options: Dict[str, Any] = field(default_factory=dict)
    result: Optional[Dict[str, Any]] = None
    error: str = ""
    events: List[Dict[str, Any]] = field(default_factory=list)
    debug_traces: List[Dict[str, Any]] = field(default_factory=list)
    latest_event: Optional[Dict[str, Any]] = None
    latest_trace: Optional[Dict[str, Any]] = None
    workspace: str = ""

    def as_summary(self) -> Dict[str, Any]:
        """
        A compact view for the job list, without the full result payload.

        Returns:
            Dict[str, Any]: Summary fields
        """

        counts = (self.result or {}).get("counts", {})
        opts = self.options or {}
        res = self.result or {}
        stats = res.get("stats") or {}
        telemetry = res.get("telemetry") or stats.get("telemetry") or {}
        input_tokens = telemetry.get("input_tokens") or stats.get("input_tokens") or 0
        output_tokens = telemetry.get("output_tokens") or stats.get("output_tokens") or 0
        thinking_tokens = (
            telemetry.get("thinking_tokens")
            or telemetry.get("reasoning_tokens")
            or stats.get("thinking_tokens")
            or stats.get("reasoning_tokens")
            or 0
        )
        total_tokens = telemetry.get("total_tokens") or stats.get("total_tokens") or (input_tokens + output_tokens)

        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "status": self.status,
            "percent": self.percent,
            "phase": self.phase,
            "message": self.message,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "findings": len(res.get("findings", [])),
            "counts": counts,
            "risk_score": res.get("risk_score", 0),
            "error": self.error,
            "model": _extract_model_from_job(self),
            "raw_model": opts.get("model"),
            "verify_model": _resolve_model_name(opts.get("verify_model")),
            "raw_verify_model": opts.get("verify_model"),
            "mode": opts.get("mode"),
            "source_name": opts.get("source_name"),
            "tokens": {
                "input": input_tokens,
                "output": output_tokens,
                "thinking": thinking_tokens,
                "total": total_tokens,
            },
            "debug_traces_count": len(self.debug_traces),
            "latest_event": self.latest_event,
            "latest_trace": self.latest_trace,
        }


class JobStore:
    """
    Durable job registry backed by one JSON file per job.
    """

    def __init__(self, directory: Optional[Path] = None, retention: int = DEFAULT_RETENTION) -> None:
        """
        Args:
            directory: Where job files live
            retention: How many finished jobs to keep before pruning
        """

        self.directory = Path(directory or Path.cwd() / JOBS_DIRNAME)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.retention = retention
        self._jobs: Dict[str, Job] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._deleted_ids: Set[str] = set()
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
        self._load()

    def _load(self) -> None:
        """
        Read persisted jobs back into memory at startup.

        A job left "running" when the process died did not survive it, so it
        is marked failed rather than left spinning forever in the UI.
        """

        for path in sorted(self.directory.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                job_fields = {f.name for f in fields(Job)}
                job = Job(**{k: v for k, v in payload.items() if k in job_fields})
            except (OSError, json.JSONDecodeError, TypeError) as e:
                logging.debug(f"Skipping unreadable job file {path}: {e}")
                continue

            if job.status in ("running", "queued"):
                job.status = "failed"
                job.error = "Interrupted by a server restart"
                job.phase = "failed"
                job.message = job.error
                self._persist(job)
            self._jobs[job.id] = job

        logging.info(f"Loaded {len(self._jobs)} job(s) from {self.directory}")

    def _persist(self, job: Job) -> None:
        """
        Write a job to disk.

        Args:
            job: The job to save
        """

        try:
            (self.directory / f"{job.id}.json").write_text(
                json.dumps(asdict(job), ensure_ascii=False, default=str),
                encoding="utf-8"
            )
        except OSError as e:
            logging.warning(f"Could not persist job {job.id}: {e}")

    def create(self, kind: str, label: str, options: Dict[str, Any], workspace: str = "") -> Job:
        """
        Register a new job.

        Args:
            kind: Job kind
            label: Display label
            options: Scan options recorded for the UI
            workspace: Temporary directory to clean up when the job ends

        Returns:
            Job: The created job
        """

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        job = Job(
            id=uuid.uuid4().hex[:12],
            kind=kind,
            label=label[:200],
            created_at=now,
            updated_at=now,
            options=options,
            workspace=workspace,
        )
        self._jobs[job.id] = job
        self._persist(job)
        self._prune()
        return job

    def get(self, job_id: str) -> Optional[Job]:
        """
        Look up a job.

        Args:
            job_id: Job identifier

        Returns:
            Optional[Job]: The job, or None
        """

        if job_id not in self._jobs:
            path = self.directory / f"{job_id}.json"
            if path.is_file():
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    self._jobs[job_id] = Job(**payload)
                except Exception:
                    pass

        return self._jobs.get(job_id)

    def register_task(self, job_id: str, task: asyncio.Task) -> None:
        """Track an active background task executing for this job."""
        self._tasks[job_id] = task

    def unregister_task(self, job_id: str) -> None:
        """Remove a completed background task."""
        self._tasks.pop(job_id, None)

    def cancel_task(self, job_id: str) -> bool:
        """Cancel an in-flight background task if currently running."""
        task = self._tasks.pop(job_id, None)
        if task and not task.done():
            task.cancel()
            return True
        return False

    def delete(self, job_id: str) -> bool:
        """
        Delete a job, stop any running background execution immediately,
        clean up temporary workspaces and remove files from disk.
        """
        self._deleted_ids.add(job_id)
        self.cancel_task(job_id)
        job = self._jobs.pop(job_id, None)
        if job:
            JobStore.cleanup_workspace(job)
        try:
            (self.directory / f"{job_id}.json").unlink(missing_ok=True)
        except OSError:
            pass
        return True

    def _sync_disk_jobs(self) -> None:
        """Discover new jobs saved to disk by other processes (e.g. CLI scans)."""
        for path in self.directory.glob("*.json"):
            job_id = path.stem
            if job_id in self._deleted_ids:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
                continue
            if job_id not in self._jobs:
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    job_fields = {f.name for f in fields(Job)}
                    loaded_job = Job(**{k: v for k, v in payload.items() if k in job_fields})
                    if loaded_job.id not in self._tasks and loaded_job.status in ("running", "queued"):
                        loaded_job.status = "done" if loaded_job.result else "failed"
                        loaded_job.message = "Completed/Archived" if loaded_job.result else "Interrupted by server restart"
                    self._jobs[job_id] = loaded_job
                except Exception:
                    pass

    def list(self, limit: int = 50) -> List[Job]:
        """
        List jobs, newest first.

        Args:
            limit: Maximum jobs to return

        Returns:
            List[Job]: Recent jobs
        """

        self._sync_disk_jobs()
        # A negative or zero limit would slice from the wrong end and drop
        # jobs silently rather than returning nothing.
        limit = max(1, int(limit))
        return sorted(
            self._jobs.values(), key=lambda j: j.created_at, reverse=True
        )[:limit]

    def update(self, job: Job, **changes: Any) -> None:
        """
        Apply changes to a job, persist it and notify subscribers.

        Args:
            job: The job to update
            **changes: Fields to set
        """

        if job.id in self._deleted_ids or job.id not in self._jobs:
            return

        for key, value in changes.items():
            setattr(job, key, value)
        job.updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._persist(job)
        self._publish(job)

    def record_event(self, job: Job, event: Dict[str, Any]) -> None:
        """
        Append a progress event and update the job's headline state.

        Args:
            job: The job
            event: A progress event from the scanner
        """

        if job.id in self._deleted_ids or job.id not in self._jobs:
            return

        if event.get("trace"):
            job.debug_traces.append(event["trace"])
        stamped = {**event, "at": time.time()}
        job.events.append(stamped)
        if len(job.events) > MAX_EVENTS:
            # Keep the first few so the start of the run stays visible.
            job.events = job.events[:50] + job.events[-(MAX_EVENTS - 50):]

        try:
            pct_val = float(event.get("percent", job.percent))
        except (ValueError, TypeError):
            pct_val = job.percent

        job.latest_event = stamped
        job.latest_trace = event.get("trace")

        self.update(
            job,
            phase=event.get("phase", job.phase),
            message=event.get("message", job.message),
            percent=pct_val,
            latest_event=stamped,
            latest_trace=event.get("trace"),
        )

    # ---- live subscriptions -------------------------------------------------

    def subscribe(self, job_id: str) -> asyncio.Queue:
        """
        Open a queue that receives updates for one job.

        Args:
            job_id: Job identifier

        Returns:
            asyncio.Queue: Queue of job summaries
        """

        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers.setdefault(job_id, []).append(queue)
        return queue

    def unsubscribe(self, job_id: str, queue: asyncio.Queue) -> None:
        """
        Close a subscription.

        Args:
            job_id: Job identifier
            queue: The queue returned by subscribe
        """

        listeners = self._subscribers.get(job_id, [])
        if queue in listeners:
            listeners.remove(queue)
        if not listeners:
            self._subscribers.pop(job_id, None)

    def _publish(self, job: Job) -> None:
        """
        Push a job summary to every live subscriber.

        Args:
            job: The updated job
        """

        summary = job.as_summary()
        for queue in list(self._subscribers.get(job.id, [])):
            try:
                queue.put_nowait(summary)
            except asyncio.QueueFull:
                # A client too slow to keep up will catch up on its next poll;
                # dropping an intermediate frame is better than blocking the scan.
                pass

    def _prune(self) -> None:
        """
        Delete the oldest finished jobs beyond the retention limit.
        """

        finished = [
            j for j in sorted(self._jobs.values(), key=lambda j: j.created_at)
            if j.status in ("done", "failed", "cancelled")
        ]
        for job in finished[:-self.retention] if len(finished) > self.retention else []:
            self.cleanup_workspace(job)
            self._jobs.pop(job.id, None)
            try:
                (self.directory / f"{job.id}.json").unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def cleanup_workspace(job: Job) -> None:
        """
        Remove temporary workspace directories created during upload/snippet/repo scans.
        Guards against deleting directories inside the project or dataset repositories.

        Args:
            job: The job whose workspace should be deleted
        """

        if not job.workspace:
            return
        ws_path = Path(job.workspace).resolve()
        name = ws_path.name
        is_temp_workspace = any(
            name.startswith(prefix)
            for prefix in ("vulnagent_upload_", "vulnagent_snippet_", "vulnagent_repo_")
        )
        if not is_temp_workspace:
            # Protect repository files, benchmark datasets, and user project directories
            return
        try:
            shutil.rmtree(ws_path, ignore_errors=True)
        except OSError as e:
            logging.debug(f"Could not clean workspace for {job.id}: {e}")

    def aggregate(self) -> Dict[str, Any]:
        """
        Summarise every completed job, for the dashboard.

        Returns:
            Dict[str, Any]: Totals across all stored jobs
        """

        self._sync_disk_jobs()
        severity_totals: Dict[str, int] = {}
        source_totals: Dict[str, int] = {}
        type_totals: Dict[str, int] = {}
        scans = findings = chains = 0
        seconds = 0.0

        for job in self._jobs.values():
            if job.status != "done" or not job.result:
                continue
            scans += 1
            result = job.result
            findings += len(result.get("findings", []))
            chains += len(result.get("chains", []))
            seconds += float(result.get("stats", {}).get("total_seconds", 0) or 0)

            for key, count in (result.get("counts") or {}).items():
                severity_totals[key] = severity_totals.get(key, 0) + count
            for key, count in (result.get("sources") or {}).items():
                source_totals[key] = source_totals.get(key, 0) + count
            for finding in result.get("findings", []):
                name = finding.get("type", "UNKNOWN")
                type_totals[name] = type_totals.get(name, 0) + 1

        top_types = sorted(type_totals.items(), key=lambda kv: -kv[1])[:10]
        return {
            "scans": scans,
            "findings": findings,
            "chains": chains,
            "total_seconds": round(seconds, 1),
            "severity": severity_totals,
            "sources": source_totals,
            "top_types": [{"type": t, "count": c} for t, c in top_types],
        }


async def run_job(
    store: JobStore,
    job: Job,
    scan: Callable[..., Any],
    package: Callable[[Any], Dict[str, Any]]
) -> None:
    """
    Execute a job's scan and record the outcome.

    Args:
        store: Job store to update
        job: The job to run
        scan: Coroutine function that performs the scan and returns a result
        package: Converts a ScanResult into the response payload
    """

    store.update(job, status="running", phase="starting", message="Starting scan", percent=1)

    try:
        result = await scan()
        payload = package(result)
        traces_from_stats = payload.get("stats", {}).get("debug_traces") or []
        if traces_from_stats and not job.debug_traces:
            job.debug_traces = traces_from_stats

        store.update(
            job,
            status="done",
            percent=100,
            phase="done",
            message=f"{len(payload.get('findings', []))} finding(s)",
            result=payload,
            debug_traces=job.debug_traces,
            finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
    except asyncio.CancelledError:
        store.update(job, status="cancelled", phase="cancelled", message="Cancelled")
        raise
    except Exception as e:
        logging.exception(f"Job {job.id} failed")
        store.update(
            job,
            status="failed",
            phase="failed",
            message=str(e)[:300],
            error=str(e)[:2000],
            finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
    finally:
        JobStore.cleanup_workspace(job)
