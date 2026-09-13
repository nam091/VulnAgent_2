import asyncio
from contextlib import asynccontextmanager, contextmanager
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


def _clean_jsonc(text: str) -> str:
    """
    Remove single-line comments (//...), block comments (/*...*/), and structural
    trailing commas from JSONC text while strictly preserving all string literal
    contents intact (including commas, quotes, escape sequences, URLs, and comment markers).
    """
    n = len(text)
    i = 0
    tokens = []

    while i < n:
        c = text[i]
        # 1. String literal
        if c == '"':
            start = i
            i += 1
            while i < n:
                if text[i] == '\\':
                    i += 2  # skip escaped character
                elif text[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            tokens.append(('STR', text[start:i]))
        # 2. Single-line comment: // ...
        elif c == '/' and i + 1 < n and text[i + 1] == '/':
            i += 2
            while i < n and text[i] != '\n':
                i += 1
        # 3. Block comment: /* ... */
        elif c == '/' and i + 1 < n and text[i + 1] == '*':
            i += 2
            end = text.find('*/', i)
            if end == -1:
                i = n
            else:
                i = end + 2
        # 4. Comma: candidate for trailing comma
        elif c == ',':
            tokens.append(('COMMA', ','))
            i += 1
        # 5. Whitespace
        elif c.isspace():
            start = i
            while i < n and text[i].isspace():
                i += 1
            tokens.append(('WS', text[start:i]))
        # 6. Any other structural character or token
        else:
            tokens.append(('CHAR', c))
            i += 1

    # Filter out structural trailing commas
    out = []
    num_tokens = len(tokens)
    for idx, (ttype, val) in enumerate(tokens):
        if ttype == 'COMMA':
            is_trailing = False
            for j in range(idx + 1, num_tokens):
                next_type, next_val = tokens[j]
                if next_type == 'WS':
                    continue
                if next_type == 'CHAR' and next_val in ('}', ']'):
                    is_trailing = True
                break
            if not is_trailing:
                out.append(val)
        else:
            out.append(val)

    return "".join(out)


def _parse_jsonc(text: str) -> Dict[str, Any]:
    """
    Parse JSON text that may contain JavaScript-style comments or trailing commas (JSONC).
    Preserves all string values intact (including URLs, comment markers, escapes, and commas)
    while removing JavaScript comments outside strings and structural trailing commas.
    Note: When serialized back out to disk, comments are not preserved by standard JSON;
    all configuration keys, values, and structures are preserved faithfully.
    """
    cleaned = _clean_jsonc(text)
    return json.loads(cleaned)


def _split_cmd_tokens(cmd: str) -> List[str]:
    import shlex
    try:
        raw = shlex.split(cmd, posix=False)
        return [t.strip('"\'') for t in raw]
    except Exception:
        return [t.strip('"\'') for t in cmd.split()]


def _is_vulnagent_save_command(item: Any, current_launcher: str) -> bool:
    """
    Check if a command entry in emeraldwalk.runonsave['commands'] belongs to VulnAgent.
    Only claims ownership for entries with explicit VulnAgent identifiers or where
    the executed launcher path is verified against this VulnAgent installation.
    Preserves all other commands (including 'python -m cli' without proof of ownership).
    """
    if not isinstance(item, dict):
        return False

    # 1. Explicit stable identifier
    if item.get("id") == "vulnagent-on-save" or item.get("name") == "VulnAgent On-Save Security Check":
        return True

    cmd = str(item.get("cmd", "")).strip()
    if not cmd:
        return False

    tokens = _split_cmd_tokens(cmd)
    if not tokens:
        return False

    exe_name = Path(tokens[0]).name.lower()

    cur_launcher_path = None
    if current_launcher:
        try:
            cur_launcher_path = Path(current_launcher).resolve()
        except Exception:
            pass

    if not cur_launcher_path:
        return False

    script_arg = None
    remaining_args: List[str] = []

    is_python_exe = exe_name in ("python", "python.exe", "python3", "python3.exe", "py", "py.exe") or "python" in exe_name

    if is_python_exe and len(tokens) > 1:
        idx = 1
        # Skip optional python interpreter flags (-u, -B, -O, etc.)
        while idx < len(tokens) and tokens[idx].startswith("-"):
            if tokens[idx] in ("-W", "-X") and idx + 1 < len(tokens):
                idx += 2
            else:
                idx += 1

        if idx < len(tokens) and not tokens[idx].startswith("-"):
            script_arg = tokens[idx]
            remaining_args = tokens[idx + 1:]
    else:
        # Direct launcher execution: e.g. /path/to/src/cli.py hook ...
        if exe_name == "cli.py":
            script_arg = tokens[0]
            remaining_args = tokens[1:]

    # Verify that the invoked script resolves to THIS VulnAgent's launcher
    if script_arg:
        try:
            target_path = Path(script_arg).resolve()
            # On Windows, path comparison should be case-insensitive
            if target_path == cur_launcher_path or str(target_path).lower() == str(cur_launcher_path).lower():
                if remaining_args and remaining_args[0].lower() == "hook":
                    return True
        except Exception:
            pass

    return False


class HostAdapter:
    """
    Configures host environments (Cursor, Claude Code, CLI) to integrate
    VulnAgent seamlessly via MCP without requiring host API keys in the backend.
    """

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root).resolve() if root else Path.cwd().resolve()

    def detect_host(self) -> str:
        """
        Detect whether workspace is configured for Cursor, VSCode or Claude Code.
        """
        if (self.root / ".cursor").exists() or (self.root / ".cursorrules").exists():
            return "cursor"
        if (self.root / ".vscode").exists():
            return "vscode"
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

    def configure_editor_save_hook(self, host: str = "cursor", rules: Optional[str] = None) -> Dict[str, Any]:
        """
        Configures an on-save hook in the editor workspace (.cursor or .vscode tasks and settings).
        Maps editor file change event to CLI runner with unified launcher and trailing debounce.
        Preserves existing user tasks, settings, comments, and other on-save commands.
        """
        config_dir = self.root / (".cursor" if host == "cursor" else ".vscode")
        config_dir.mkdir(parents=True, exist_ok=True)
        tasks_path = config_dir / "tasks.json"
        settings_path = config_dir / "settings.json"

        cli_entry = (Path(__file__).resolve().parents[1] / "cli.py").resolve()
        cli_entry_str = cli_entry.as_posix()

        resolved_rules = None
        if rules:
            r_str = str(rules).strip()
            r_path = Path(r_str)
            if r_path.exists():
                resolved_rules = str(r_path.resolve())
            elif (self.root / r_path).exists():
                resolved_rules = str((self.root / r_path).resolve())
            else:
                resolved_rules = r_str

        # 1. Configure tasks.json with process type and explicit absolute CLI launcher
        tasks: Dict[str, Any] = {"version": "2.0.0", "tasks": []}
        if tasks_path.is_file():
            raw_tasks = tasks_path.read_text(encoding="utf-8")
            try:
                tasks = _parse_jsonc(raw_tasks)
            except Exception as e:
                logging.warning(f"Failed to parse existing tasks.json as JSON/JSONC: {e}. Preserving file.")
                return {
                    "tasks_config": str(tasks_path),
                    "settings_config": str(settings_path),
                    "hook_configured": False,
                    "trigger_configured": False,
                    "error": f"Failed to parse existing tasks.json: {e}",
                    "host": host,
                }

        task_args = [
            cli_entry_str,
            "hook",
            "--target", "${workspaceFolder}",
            "--files", "${file}",
            "--trailing"
        ]
        if resolved_rules:
            task_args.extend(["--rules", resolved_rules])

        hook_task = {
            "label": "VulnAgent On-Save Security Check",
            "type": "process",
            "command": sys.executable,
            "args": task_args,
            "group": "build",
            "presentation": {
                "reveal": "silent",
                "panel": "shared"
            }
        }

        existing_tasks = [
            t for t in tasks.get("tasks", [])
            if isinstance(t, dict) and t.get("label") != "VulnAgent On-Save Security Check"
        ]
        existing_tasks.append(hook_task)
        tasks["tasks"] = existing_tasks
        tasks_path.write_text(json.dumps(tasks, indent=2), encoding="utf-8")

        # 2. Configure settings.json: merge command and preserve existing settings
        settings: Dict[str, Any] = {}
        if settings_path.is_file():
            raw_settings = settings_path.read_text(encoding="utf-8")
            try:
                settings = _parse_jsonc(raw_settings)
            except Exception as e:
                logging.warning(f"Failed to parse existing settings.json as JSON/JSONC: {e}. Preserving file.")
                return {
                    "tasks_config": str(tasks_path),
                    "settings_config": str(settings_path),
                    "hook_configured": False,
                    "trigger_configured": False,
                    "error": f"Failed to parse existing settings.json: {e}",
                    "host": host,
                }

        save_cmd = f'"{sys.executable}" "{cli_entry_str}" hook --target "${{workspaceFolder}}" --files "${{file}}" --trailing'
        if resolved_rules:
            save_cmd += f' --rules "{resolved_rules}"'
        runonsave = settings.get("emeraldwalk.runonsave")
        if not isinstance(runonsave, dict):
            runonsave = {}
        existing_cmds = runonsave.get("commands", [])
        if not isinstance(existing_cmds, list):
            existing_cmds = []

        filtered_cmds = [
            c for c in existing_cmds
            if not _is_vulnagent_save_command(c, cli_entry_str)
        ]
        filtered_cmds.append({
            "id": "vulnagent-on-save",
            "name": "VulnAgent On-Save Security Check",
            "match": "\\.py$",
            "cmd": save_cmd
        })
        runonsave["commands"] = filtered_cmds
        settings["emeraldwalk.runonsave"] = runonsave
        settings_path.write_text(json.dumps(settings, indent=2), encoding="utf-8")

        return {
            "tasks_config": str(tasks_path),
            "settings_config": str(settings_path),
            "hook_configured": True,
            "trigger_configured": True,
            "launcher": cli_entry_str,
            "host": host,
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

    def _bump_dirty_generation(self, files: Optional[Sequence[Path]] = None) -> int:
        dirty_file = self.root / ".vulnagent-audit" / "dirty.json"
        gen = 1
        try:
            dirty_file.parent.mkdir(parents=True, exist_ok=True)
            if dirty_file.is_file():
                raw = dirty_file.read_text(encoding="utf-8").strip()
                if raw:
                    data = json.loads(raw)
                    gen = int(data.get("generation", 0)) + 1
            file_strs = [str(f) for f in files] if files else []
            dirty_file.write_text(
                json.dumps({"generation": gen, "timestamp": time.time(), "files": file_strs}),
                encoding="utf-8"
            )
        except Exception:
            pass
        return gen

    def _get_dirty_generation(self) -> int:
        dirty_file = self.root / ".vulnagent-audit" / "dirty.json"
        try:
            if dirty_file.is_file():
                raw = dirty_file.read_text(encoding="utf-8").strip()
                if raw:
                    data = json.loads(raw)
                    return int(data.get("generation", 0))
        except Exception:
            pass
        return 0

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

    @asynccontextmanager
    async def lock_async(self, timeout_seconds: float = 0.0):
        """
        Asynchronously acquire repository lock without blocking the asyncio event loop.
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

                if not owner_alive:
                    try:
                        self.lock_path.unlink(missing_ok=True)
                        continue
                    except OSError:
                        pass

                if time.time() - start >= timeout_seconds:
                    raise PermissionError(f"Workspace repository is locked by active process: {self.lock_path}")
                await asyncio.sleep(0.05)

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
        Detect if scan outcome represents a failure, degraded coverage, incomplete partial scan, or engine error.
        """
        if result is None:
            return True, "Scan returned no result"

        if hasattr(result, "engine_failure") and result.engine_failure:
            return True, "Engine failure reported"
        if isinstance(result, dict) and result.get("engine_failure"):
            return True, "Engine failure reported"
        if isinstance(result, dict) and result.get("rule_error"):
            return True, f"Rule error: {result['rule_error']}"

        status = getattr(result, "status", None)
        if isinstance(result, dict):
            status = result.get("status", status)

        if status in ("failed", "error"):
            return True, f"Scan failed with status '{status}'"
        if status in ("partial", "incomplete"):
            return True, f"Scan coverage incomplete (status: '{status}')"

        if getattr(result, "degraded", False):
            return True, "Scan completed with degraded coverage"

        if isinstance(result, dict):
            if result.get("degraded"):
                return True, "Scan completed with degraded coverage"
            if status not in ("completed", "clean", None):
                reason = result.get("reason") or result.get("error") or f"Scan incomplete with status '{status}'"
                return True, reason

        # Check reports inside ScanResult for partial or failed reports
        reports = getattr(result, "reports", None)
        if isinstance(reports, list):
            for rep in reports:
                rep_status = getattr(rep, "status", None)
                if rep_status in ("failed", "partial", "degraded"):
                    return True, f"Scan report for '{getattr(rep, 'file_name', 'file')}' is {rep_status}"

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
        trailing: bool = False,
    ) -> Dict[str, Any]:
        """
        Run the editor hook workflow with debounce, lock, dirty snapshot, max 2 rounds, and failure gating.
        When trailing=True, waits out remaining debounce interval and lock contention so final save is analyzed.
        """
        self._bump_dirty_generation(files)

        now = time.time()
        elapsed = now - self._last_run_time
        if elapsed < self.debounce_seconds:
            if trailing:
                remaining = self.debounce_seconds - elapsed
                if remaining > 0:
                    await asyncio.sleep(remaining)
            else:
                return {"status": "skipped", "reason": "debounced", "elapsed": round(elapsed, 2)}

        snapshot = self.capture_snapshot(files)
        if snapshot and snapshot == self._last_snapshot:
            return {"status": "skipped", "reason": "unmodified"}

        lock_timeout = 15.0 if trailing else 0.0
        try:
            async with self.lock_async(timeout_seconds=lock_timeout):
                self._load_state()
                snapshot = self.capture_snapshot(files)
                if snapshot and snapshot == self._last_snapshot:
                    return {"status": "skipped", "reason": "unmodified"}

                fixes_attempted = 0
                max_fix_attempts = max(0, self.max_rounds - 1)
                rounds_count = 0

                while True:
                    rounds_count += 1
                    start_gen = self._get_dirty_generation()
                    snapshot_at_start = snapshot

                    try:
                        result = await scan_fn()
                    except Exception as e:
                        return {"status": "failed", "rounds": rounds_count, "reason": f"Scan execution failed: {e}"}

                    failed, reason = self._is_scan_failed_or_degraded(result)
                    if failed:
                        return {"status": "failed", "rounds": rounds_count, "reason": reason}

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

                    snapshot_after_scan = self.capture_snapshot(files)
                    latest_gen = self._get_dirty_generation()
                    if trailing and (snapshot_after_scan != snapshot_at_start or latest_gen > start_gen):
                        snapshot = snapshot_after_scan
                        continue

                    if not findings:
                        self._last_run_time = time.time()
                        self._last_snapshot = snapshot_at_start
                        self._save_state()
                        return {"status": "clean", "rounds": rounds_count, "findings_count": 0}

                    if not fix_fn or fixes_attempted >= max_fix_attempts:
                        self._last_run_time = time.time()
                        self._last_snapshot = snapshot_at_start
                        self._save_state()
                        return {
                            "status": "findings_detected",
                            "rounds": rounds_count,
                            "findings_count": len(findings),
                            "finding_ids": list(initial_ids),
                        }

                    # Attempt Fix within budget
                    fixes_attempted += 1
                    rounds_count += 1
                    try:
                        await fix_fn(result)
                    except Exception as e:
                        return {"status": "fix_failed", "rounds": rounds_count, "reason": f"Fix execution failed: {e}"}

                    snapshot_post_fix = self.capture_snapshot(files)
                    fix_gen = self._get_dirty_generation()

                    # Rescan
                    try:
                        rescan_result = await scan_fn()
                    except Exception as e:
                        return {"status": "rescan_failed", "rounds": rounds_count, "reason": f"Rescan execution failed: {e}"}

                    rescan_failed, rescan_reason = self._is_scan_failed_or_degraded(rescan_result)
                    if rescan_failed:
                        return {"status": "rescan_failed", "rounds": rounds_count, "reason": rescan_reason}

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
                        self._last_snapshot = snapshot_post_fix
                        self._save_state()
                        return {
                            "status": "no_progress",
                            "rounds": rounds_count,
                            "initial_count": len(findings),
                            "final_count": len(rescan_findings),
                            "reason": "Fix attempt produced no reduction in findings",
                            "finding_ids": list(rescan_ids),
                        }

                    snapshot_now = self.capture_snapshot(files)
                    latest_gen = self._get_dirty_generation()
                    if trailing and (snapshot_now != snapshot_post_fix or latest_gen > fix_gen):
                        # A new external user edit arrived during fix/rescan: re-scan the new edit
                        snapshot = snapshot_now
                        continue

                    if not rescan_findings:
                        self._last_run_time = time.time()
                        self._last_snapshot = snapshot_post_fix
                        self._save_state()
                        return {
                            "status": "clean",
                            "rounds": rounds_count,
                            "initial_count": len(findings),
                            "final_count": 0,
                        }

                    # Partial progress after round: check if budget remains
                    if fixes_attempted < max_fix_attempts:
                        snapshot = snapshot_post_fix
                        continue

                    self._last_run_time = time.time()
                    self._last_snapshot = snapshot_post_fix
                    self._save_state()
                    return {
                        "status": "partial_progress",
                        "rounds": rounds_count,
                        "initial_count": len(findings),
                        "final_count": len(rescan_findings),
                        "remaining_ids": list(rescan_ids),
                    }

        except PermissionError:
            return {"status": "skipped", "reason": "locked"}


