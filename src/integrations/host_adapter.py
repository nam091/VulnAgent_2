from contextlib import contextmanager
import hashlib
import json
import logging
import os
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Tuple




CURSOR_RULES_CONTENT = """# VulnAgent Security Guidelines for AI Coding

When writing or editing Python code:
1. After editing code that handles user input, database queries, file access, or system commands, call `scan_changes` via the VulnAgent MCP server.
2. For each candidate finding returned:
   - Call `get_finding_context(scan_id, finding_id)` to view AST scope and initial evidence.
   - If needed, call `read_evidence(scan_id, path, start_line, end_line)` to inspect upstream sanitizers or authenticators.
   - If safe: call `submit_assessment(scan_id, finding_id, verdict='refuted', mitigating_control='...', evidence_ids=[...])`.
   - If vulnerable: repair the defect using secure standard patterns (e.g. parameterized queries, path containment check, shlex.quote).
3. Call `check_fix(scan_id, finding_ids=[...])` to ensure the vulnerability is resolved and no regressions were introduced.
"""

CLAUDE_CODE_INSTRUCTIONS = """VulnAgent MCP Integration:
- Use `scan_changes` to identify security candidates in modified Python files.
- Inspect context with `get_finding_context` and `read_evidence`.
- Submit verified verdicts with `submit_assessment`.
- Verify repairs with `check_fix`.
"""


class HostAdapter:
    """
    Configures host environments (Cursor, Claude Code, CLI) to integrate
    VulnAgent seamlessly via MCP without requiring host API keys in the backend.
    """

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root).resolve() if root else Path.cwd().resolve()

    def detect_host(self) -> str:
        """
        Detect whether workspace is configured for Cursor or Claude Code.
        """
        if (self.root / ".cursor").exists() or (self.root / ".cursorrules").exists():
            return "cursor"
        if (self.root / ".claude").exists():
            return "claude"
        return "cursor"  # default target for MVP

    def configure_cursor(self) -> Dict[str, Any]:
        """
        Configure Cursor MCP server and security rules without overwriting existing settings.
        """
        cursor_dir = self.root / ".cursor"
        cursor_dir.mkdir(parents=True, exist_ok=True)
        mcp_config_path = cursor_dir / "mcp.json"

        config: Dict[str, Any] = {"mcpServers": {}}
        if mcp_config_path.is_file():
            try:
                config = json.loads(mcp_config_path.read_text(encoding="utf-8"))
            except Exception:
                config = {"mcpServers": {}}

        python_exec = sys.executable
        server_script = str((Path(__file__).resolve().parents[1] / "mcp_server.py").as_posix())

        config.setdefault("mcpServers", {})["vulnagent"] = {
            "command": python_exec,
            "args": [server_script],
            "env": {
                "PYTHONPATH": str(Path(__file__).resolve().parents[1].as_posix())
            }
        }

        # Backup existing if present
        if mcp_config_path.exists():
            shutil.copy2(mcp_config_path, mcp_config_path.with_suffix(".json.bak"))

        mcp_config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

        # Write .cursorrules if not present
        cursor_rules = self.root / ".cursorrules"
        if not cursor_rules.exists():
            cursor_rules.write_text(CURSOR_RULES_CONTENT, encoding="utf-8")

        return {
            "mcp_config": str(mcp_config_path),
            "rules_file": str(cursor_rules),
            "configured": True,
        }

    def configure_claude_code(self) -> Dict[str, Any]:
        """
        Configure Claude Code MCP settings.
        """
        claude_dir = self.root / ".claude"
        claude_dir.mkdir(parents=True, exist_ok=True)
        config_path = claude_dir / "mcp.json"

        config: Dict[str, Any] = {"mcpServers": {}}
        if config_path.is_file():
            try:
                config = json.loads(config_path.read_text(encoding="utf-8"))
            except Exception:
                config = {"mcpServers": {}}

        python_exec = sys.executable
        server_script = str((Path(__file__).resolve().parents[1] / "mcp_server.py").as_posix())

        config.setdefault("mcpServers", {})["vulnagent"] = {
            "command": python_exec,
            "args": [server_script],
            "env": {
                "PYTHONPATH": str(Path(__file__).resolve().parents[1].as_posix())
            }
        }

        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

        instructions_path = claude_dir / "CLAUDE.md"
        if not instructions_path.exists():
            instructions_path.write_text(CLAUDE_CODE_INSTRUCTIONS, encoding="utf-8")

        return {
            "mcp_config": str(config_path),
            "instructions": str(instructions_path),
            "configured": True,
        }


def _is_pid_alive(pid: int) -> bool:
    """
    Check whether a process with given PID is actively running on the system.
    """
    if pid <= 0:
        return False
    try:
        import psutil
        return psutil.pid_exists(pid)
    except Exception:
        pass

    if sys.platform == "win32":
        import ctypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        SYNCHRONIZE = 0x00100000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
        if handle:
            exit_code = ctypes.c_ulong()
            if ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                STILL_ACTIVE = 259
                alive = (exit_code.value == STILL_ACTIVE)
                ctypes.windll.kernel32.CloseHandle(handle)
                return alive
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False


class EditorHookRunner:
    """
    Orchestrates editor save/hook execution with:
      - Debounce mechanism (skips execution if triggered repeatedly within window)
      - Dirty snapshotting (skips when workspace/files have not changed)
      - Process-safe repository lock (.vulnagent.lock) with owner liveness check and token ownership
      - Strict failure gating (never reports clean when scan fails or coverage is degraded)
      - Maximum 2-round iteration limit (scan -> fix -> verify)
      - No-progress termination (aborts if findings do not decrease or IDs are unchanged)
    """

    def __init__(
        self,
        root: Optional[Path] = None,
        debounce_seconds: float = 1.5,
        max_rounds: int = 2,
    ) -> None:
        self.root = Path(root).resolve() if root else Path.cwd().resolve()
        self.debounce_seconds = debounce_seconds
        self.max_rounds = max_rounds
        self._last_run_time: float = 0.0
        self._last_snapshot: Dict[str, str] = {}
        self._active_lock_token: Optional[str] = None
        self.lock_path = self.root / ".vulnagent.lock"
        self._state_file = self.root / ".vulnagent-audit" / "runner_state.json"
        self._load_state()

    def _load_state(self) -> None:
        if self._state_file.is_file():
            try:
                data = json.loads(self._state_file.read_text(encoding="utf-8"))
                self._last_run_time = float(data.get("last_run_time", 0.0))
                self._last_snapshot = dict(data.get("last_snapshot", {}))
            except Exception:
                pass

    def _save_state(self) -> None:
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            self._state_file.write_text(
                json.dumps({
                    "last_run_time": self._last_run_time,
                    "last_snapshot": self._last_snapshot,
                }),
                encoding="utf-8"
            )
        except Exception:
            pass

    def capture_snapshot(self, files: Optional[Sequence[Path]] = None) -> Dict[str, str]:
        """
        Compute hash snapshot for specified files or python files in workspace.
        """
        snapshot: Dict[str, str] = {}
        target_files = list(files) if files is not None else [
            p for p in self.root.rglob("*.py")
            if not any(part in p.parts for part in ("venv", ".venv", ".git", "__pycache__", "build", "dist"))
        ]
        for f in target_files:
            fp = Path(f).resolve()
            if fp.is_file():
                try:
                    rel = fp.relative_to(self.root).as_posix()
                except ValueError:
                    rel = fp.as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace").encode("utf-8")
                    snapshot[rel] = hashlib.sha256(content).hexdigest()
                except OSError:
                    continue
        return snapshot

    @contextmanager
    def lock(self, timeout_seconds: float = 0.0):
        """
        Acquire a process-safe lock using .vulnagent.lock.
        If held by an active process, raises PermissionError.
        Only unlinks the lock file on release if this runner is still the token owner.
        """
        start = time.time()
        token = uuid.uuid4().hex
        acquired = False
        while True:
            try:
                fd = os.open(str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(json.dumps({"pid": os.getpid(), "token": token, "timestamp": time.time()}))
                acquired = True
                self._active_lock_token = token
                break
            except FileExistsError:
                owner_alive = False
                try:
                    if self.lock_path.is_file():
                        raw = self.lock_path.read_text(encoding="utf-8").strip()
                        if raw:
                            data = json.loads(raw)
                            owner_pid = data.get("pid")
                            if owner_pid and _is_pid_alive(int(owner_pid)):
                                owner_alive = True
                except (OSError, json.JSONDecodeError, ValueError):
                    pass

                # If the owner process is confirmed dead or lock file corrupted, safe to clean up
                if not owner_alive:
                    try:
                        self.lock_path.unlink(missing_ok=True)
                        continue
                    except OSError:
                        pass

                # If owner is active, cannot break lock
                if time.time() - start >= timeout_seconds:
                    raise PermissionError(f"Workspace repository is locked by active process: {self.lock_path}")
                time.sleep(0.05)

        try:
            yield
        finally:
            if acquired:
                try:
                    if self.lock_path.is_file():
                        raw = self.lock_path.read_text(encoding="utf-8").strip()
                        if raw:
                            data = json.loads(raw)
                            if data.get("token") == token:
                                self.lock_path.unlink(missing_ok=True)
                except OSError:
                    pass
                self._active_lock_token = None

    def _is_scan_failed_or_degraded(self, result: Any) -> Tuple[bool, str]:
        """
        Detect if scan outcome represents a failure, degraded coverage, or engine error.
        """
        if result is None:
            return True, "Scan returned no result"
        if getattr(result, "status", None) in ("failed", "error"):
            return True, f"Scan failed with status '{result.status}'"
        if getattr(result, "degraded", False):
            return True, "Scan completed with degraded coverage"
        if isinstance(result, dict):
            if result.get("engine_failure"):
                return True, "Engine failure reported"
            if result.get("rule_error"):
                return True, f"Rule error: {result['rule_error']}"
            if result.get("status") in ("failed", "error") or result.get("degraded"):
                reason = result.get("reason") or result.get("error") or f"Scan failed with status '{result.get('status')}'"
                return True, reason
        stats = getattr(result, "stats", None)
        if isinstance(stats, dict):
            if stats.get("rule_error"):
                return True, f"Rule error: {stats['rule_error']}"
            if stats.get("engine_failure"):
                return True, "Engine failure detected in scan stats"
        if hasattr(result, "engine_failure") and result.engine_failure:
            return True, "Engine failure reported"
        return False, ""

    async def run(
        self,
        scan_fn: Callable[[], Awaitable[Any]],
        fix_fn: Optional[Callable[[Any], Awaitable[Any]]] = None,
        files: Optional[Sequence[Path]] = None,
    ) -> Dict[str, Any]:
        """
        Run the editor hook workflow with debounce, lock, dirty snapshot, max 2 rounds, and failure gating.
        """
        now = time.time()
        if now - self._last_run_time < self.debounce_seconds:
            return {"status": "skipped", "reason": "debounced", "elapsed": round(now - self._last_run_time, 2)}

        snapshot = self.capture_snapshot(files)
        if snapshot and snapshot == self._last_snapshot:
            return {"status": "skipped", "reason": "unmodified"}

        try:
            with self.lock(timeout_seconds=0.0):
                round_num = 1
                try:
                    result = await scan_fn()
                except Exception as e:
                    return {"status": "failed", "rounds": round_num, "reason": f"Scan execution failed: {e}"}

                failed, reason = self._is_scan_failed_or_degraded(result)
                if failed:
                    # Do not update self._last_snapshot to allow retry on same snapshot once engine recovers
                    return {"status": "failed", "rounds": round_num, "reason": reason}

                if isinstance(result, dict):
                    findings = result.get("vulnerabilities", result.get("findings", []))
                else:
                    findings = getattr(result, "vulnerabilities", result)
                if not isinstance(findings, list):
                    findings = list(findings) if hasattr(findings, "__iter__") else []

                def get_fid(f: Any) -> str:
                    if hasattr(f, "fingerprint") and callable(f.fingerprint):
                        return f.fingerprint()
                    return getattr(f, "id", str(f))

                initial_ids = {get_fid(f) for f in findings}
                if not findings:
                    self._last_run_time = time.time()
                    self._last_snapshot = snapshot
                    self._save_state()
                    return {"status": "clean", "rounds": round_num, "findings_count": 0}

                if not fix_fn or self.max_rounds < 2:
                    self._last_run_time = time.time()
                    self._last_snapshot = snapshot
                    self._save_state()
                    return {
                        "status": "findings_detected",
                        "rounds": round_num,
                        "findings_count": len(findings),
                        "finding_ids": list(initial_ids),
                    }

                # Round 1 -> Fix
                round_num = 2
                try:
                    await fix_fn(result)
                except Exception as e:
                    return {"status": "fix_failed", "rounds": round_num, "reason": f"Fix execution failed: {e}"}

                # Rescan
                try:
                    rescan_result = await scan_fn()
                except Exception as e:
                    return {"status": "rescan_failed", "rounds": round_num, "reason": f"Rescan execution failed: {e}"}

                rescan_failed, rescan_reason = self._is_scan_failed_or_degraded(rescan_result)
                if rescan_failed:
                    return {"status": "rescan_failed", "rounds": round_num, "reason": rescan_reason}

                if isinstance(rescan_result, dict):
                    rescan_findings = rescan_result.get("vulnerabilities", rescan_result.get("findings", []))
                else:
                    rescan_findings = getattr(rescan_result, "vulnerabilities", rescan_result)
                if not isinstance(rescan_findings, list):
                    rescan_findings = list(rescan_findings) if hasattr(rescan_findings, "__iter__") else []

                rescan_ids = {get_fid(f) for f in rescan_findings}

                # Termination on no-progress: finding count does not decrease or IDs are unchanged
                if len(rescan_findings) >= len(findings) or rescan_ids == initial_ids:
                    self._last_run_time = time.time()
                    self._last_snapshot = self.capture_snapshot(files)
                    self._save_state()
                    return {
                        "status": "no_progress",
                        "rounds": round_num,
                        "initial_count": len(findings),
                        "final_count": len(rescan_findings),
                        "reason": "Fix attempt produced no reduction in findings",
                        "finding_ids": list(rescan_ids),
                    }

                if not rescan_findings:
                    self._last_run_time = time.time()
                    self._last_snapshot = self.capture_snapshot(files)
                    self._save_state()
                    return {
                        "status": "clean",
                        "rounds": round_num,
                        "initial_count": len(findings),
                        "final_count": 0,
                    }

                # Partial progress after 2 rounds
                self._last_run_time = time.time()
                self._last_snapshot = self.capture_snapshot(files)
                self._save_state()
                return {
                    "status": "partial_progress",
                    "rounds": round_num,
                    "initial_count": len(findings),
                    "final_count": len(rescan_findings),
                    "remaining_ids": list(rescan_ids),
                }

        except PermissionError:
            return {"status": "skipped", "reason": "locked"}


