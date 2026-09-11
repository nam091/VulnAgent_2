from contextlib import contextmanager
import hashlib
import json
import logging
import os
import shutil
import sys
import time
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


class EditorHookRunner:
    """
    Orchestrates editor save/hook execution with:
      - Debounce mechanism (skips execution if triggered repeatedly within window)
      - Dirty snapshotting (skips when workspace/files have not changed)
      - Process-safe repository lock (.vulnagent.lock)
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
        self.lock_path = self.root / ".vulnagent.lock"

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
        If held and not stale, raises PermissionError.
        """
        start = time.time()
        acquired = False
        while True:
            try:
                fd = os.open(str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(json.dumps({"pid": os.getpid(), "timestamp": time.time()}))
                acquired = True
                break
            except FileExistsError:
                try:
                    if self.lock_path.is_file():
                        stat = self.lock_path.stat()
                        if time.time() - stat.st_mtime > 60:
                            self.lock_path.unlink(missing_ok=True)
                            continue
                except OSError:
                    pass

                if time.time() - start >= timeout_seconds:
                    raise PermissionError(f"Workspace repository is locked: {self.lock_path}")
                time.sleep(0.05)

        try:
            yield
        finally:
            if acquired:
                try:
                    if self.lock_path.is_file():
                        self.lock_path.unlink(missing_ok=True)
                except OSError:
                    pass

    async def run(
        self,
        scan_fn: Callable[[], Awaitable[Any]],
        fix_fn: Optional[Callable[[Any], Awaitable[Any]]] = None,
        files: Optional[Sequence[Path]] = None,
    ) -> Dict[str, Any]:
        """
        Run the editor hook workflow with debounce, lock, dirty snapshot, max 2 rounds, and no-progress termination.
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
                result = await scan_fn()
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
                    return {"status": "clean", "rounds": round_num, "findings_count": 0}

                if not fix_fn or self.max_rounds < 2:
                    self._last_run_time = time.time()
                    self._last_snapshot = snapshot
                    return {
                        "status": "findings_detected",
                        "rounds": round_num,
                        "findings_count": len(findings),
                        "finding_ids": list(initial_ids),
                    }

                # Round 1 -> Fix
                round_num = 2
                await fix_fn(result)

                # Rescan
                rescan_result = await scan_fn()
                rescan_findings = getattr(rescan_result, "vulnerabilities", rescan_result)
                if not isinstance(rescan_findings, list):
                    rescan_findings = list(rescan_findings) if hasattr(rescan_findings, "__iter__") else []

                rescan_ids = {get_fid(f) for f in rescan_findings}

                # Termination on no-progress: finding count does not decrease or IDs are unchanged
                if len(rescan_findings) >= len(findings) or rescan_ids == initial_ids:
                    self._last_run_time = time.time()
                    self._last_snapshot = self.capture_snapshot(files)
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
                    return {
                        "status": "clean",
                        "rounds": round_num,
                        "initial_count": len(findings),
                        "final_count": 0,
                    }

                # Partial progress after 2 rounds
                self._last_run_time = time.time()
                self._last_snapshot = self.capture_snapshot(files)
                return {
                    "status": "partial_progress",
                    "rounds": round_num,
                    "initial_count": len(findings),
                    "final_count": len(rescan_findings),
                    "remaining_ids": list(rescan_ids),
                }

        except PermissionError:
            return {"status": "skipped", "reason": "locked"}

