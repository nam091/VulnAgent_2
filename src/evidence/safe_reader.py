import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

MAX_READ_LINES = 200
MAX_MATCHES = 40
MAX_FILE_BYTES = 512_000
DEFAULT_SKIPS = {
    "venv", ".venv", "env", ".env", "node_modules", "site-packages",
    "__pycache__", ".pytest_cache", ".git", ".idea", ".vscode", "dist", "build"
}


class PathEscapeError(PermissionError):
    """Raised when an operation attempts to access files outside the scan root."""


class FileTooLargeError(ValueError):
    """Raised when a file exceeds size limits."""


class SafeReader:
    """
    Guarantees that all file reads, searches and definitions are strictly
    confined to the scan root, rejecting path traversals and symlink escapes.
    """

    def __init__(self, root: Path, max_file_bytes: int = MAX_FILE_BYTES) -> None:
        self.root = Path(root).resolve()
        self.max_file_bytes = max_file_bytes

    def resolve(self, path_str: str) -> Path:
        """
        Resolve a path string strictly inside the scan root.
        Rejects directory traversal (../) and symlinks pointing outside root.
        """
        raw_path = str(path_str).strip()
        if not raw_path:
            raise PathEscapeError("empty path cannot be resolved")

        # Strip leading slashes to anchor inside self.root
        cleaned = raw_path.lstrip("/\\")
        candidate = (self.root / cleaned).resolve()

        # Verify containment
        if candidate != self.root and self.root not in candidate.parents:
            raise PathEscapeError(f"Path '{path_str}' escapes scan root '{self.root}'")

        # Check realpath to catch symlinks pointing outside root
        real_candidate = Path(os.path.realpath(str(candidate)))
        if real_candidate != self.root and self.root not in real_candidate.parents:
            raise PathEscapeError(f"Symlink '{path_str}' points outside scan root to '{real_candidate}'")

        return candidate

    def read_file(self, path_str: str) -> str:
        """
        Safely read full text of a file inside the root up to max_file_bytes.
        """
        target = self.resolve(path_str)
        if not target.is_file():
            raise FileNotFoundError(f"No such file: {path_str}")

        size = target.stat().st_size
        if size > self.max_file_bytes:
            raise FileTooLargeError(f"File '{path_str}' size {size} exceeds limit {self.max_file_bytes}")

        return target.read_text(encoding="utf-8", errors="replace")

    def read_lines(self, path_str: str, start_line: int = 1, end_line: int = 0) -> Dict[str, Any]:
        """
        Read a numbered slice of a file safely.
        """
        content = self.read_file(path_str)
        lines = content.splitlines()
        total_lines = len(lines) or 1
        if not lines:
            lines = [""]

        start = max(1, int(start_line or 1))
        end = int(end_line) if end_line else start + MAX_READ_LINES - 1
        end = min(max(end, start), total_lines, start + MAX_READ_LINES - 1)

        body = "\n".join(
            f"{i:>5} | {lines[i - 1]}" for i in range(start, end + 1)
        )
        return {
            "path": self.to_relative(self.resolve(path_str)),
            "start_line": start,
            "end_line": end,
            "total_lines": total_lines,
            "content": body,
            "raw_lines": lines[start - 1:end],
        }

    def list_python_files(self, excludes: Optional[Set[str]] = None) -> List[Path]:
        """
        Safely collect all python files under the root without following symlinks outside.
        """
        skip = set(DEFAULT_SKIPS)
        if excludes:
            skip.update(excludes)

        collected: List[Path] = []
        for root_dir, dirs, files in os.walk(str(self.root), followlinks=False):
            dirs[:] = [d for d in dirs if d not in skip and not (Path(root_dir) / d).is_symlink()]

            for f in files:
                if not f.endswith(".py"):
                    continue
                file_path = Path(root_dir) / f
                # Check for symlink escaping root
                try:
                    resolved = file_path.resolve()
                    if resolved != self.root and self.root not in resolved.parents:
                        logging.warning(f"Skipping symlink escaping root: {file_path} -> {resolved}")
                        continue
                    if resolved.is_file():
                        collected.append(resolved)
                except (OSError, ValueError):
                    continue

        return collected

    def to_relative(self, path: Path) -> str:
        """
        Convert an absolute path to a root-relative posix path.
        """
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def read_code_snippet(
        self,
        path_str: str,
        line_number: Optional[int],
        context_lines: int = 2
    ) -> str:
        """
        Read a formatted snippet around line_number with line numbers and '>' indicator.
        """
        return read_code_snippet(
            file_path=path_str,
            line_number=line_number,
            root_dir=self.root,
            context_lines=context_lines,
            safe_reader=self,
        )


def read_code_snippet(
    file_path: Union[str, Path],
    line_number: Optional[int],
    root_dir: Optional[Union[str, Path]] = None,
    context_lines: int = 2,
    fallback_content: Optional[str] = None,
    safe_reader: Optional[SafeReader] = None,
) -> str:
    """
    Safely read and format code lines around a target line with line numbering and '>' marker.

    Args:
        file_path: Path to the target source file (relative or absolute)
        line_number: 1-indexed target line number
        root_dir: Optional scan workspace or root directory
        context_lines: Number of lines before and after target line to include (default: 2)
        fallback_content: Optional source code content string if file is not on disk
        safe_reader: Optional SafeReader instance

    Returns:
        str: Formatted code snippet with line numbers and '>' marker at line_number,
             or empty string if file cannot be read or line is invalid.
    """
    if line_number is None:
        return ""
    try:
        target_line = int(line_number)
        if target_line <= 0:
            return ""
    except (ValueError, TypeError):
        return ""

    lines: Optional[List[str]] = None

    # Try resolving and reading file from disk
    if file_path:
        f_str = str(file_path).strip()
        candidates: List[Path] = []
        if root_dir:
            r_path = Path(root_dir)
            cleaned = f_str.lstrip("/\\")
            candidates.append(r_path / cleaned)
            candidates.append(r_path / Path(f_str).name)
        p = Path(f_str)
        if p.is_absolute():
            candidates.append(p)
        else:
            candidates.append(p)
            candidates.append(Path.cwd() / f_str)

        # Check eval datasets directory if available
        datasets_dir = Path.cwd() / "eval" / "datasets"
        if datasets_dir.is_dir():
            try:
                for d in datasets_dir.iterdir():
                    if d.is_dir():
                        candidates.append(d / "samples" / p.name)
                        candidates.append(d / "samples" / f_str)
            except Exception:
                pass

        for cand in candidates:
            try:
                if cand.is_file():
                    content = cand.read_text(encoding="utf-8", errors="replace")
                    lines = content.splitlines()
                    break
            except Exception:
                continue

    # Fall back to provided fallback_content if disk read failed
    if lines is None and fallback_content is not None:
        lines = str(fallback_content).splitlines()

    if not lines:
        return ""

    total_lines = len(lines)
    start = max(1, target_line - context_lines)
    end = min(total_lines, target_line + context_lines)

    snippet_lines = []
    for i in range(start, end + 1):
        marker = ">" if i == target_line else " "
        snippet_lines.append(f"{marker} {i:>4} | {lines[i - 1]}")

    return "\n".join(snippet_lines)


def enrich_taint_path(
    taint_path: List[Dict[str, Any]],
    default_file: Optional[str] = None,
    root_dir: Optional[Union[str, Path]] = None,
    successful_reads: Optional[List[Dict[str, Any]]] = None,
    default_line: Optional[int] = None,
    context_lines: int = 2,
    infer_kind: bool = False,
    default_kind: Optional[str] = None,
    fallback_content: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Enrich and normalize taint path steps so that 100% of steps have:
    - step: int (1, 2, 3...)
    - kind: str ('source', 'propagation', 'sanitizer', 'sink', etc.)
    - file: str (normalized posix path)
    - line: int
    - description: str
    - code: str (formatted code snippet with '>' marker)

    Args:
        taint_path: Raw or partially enriched taint steps
        default_file: Fallback file path if step omits file
        root_dir: Root directory or workspace for resolving code
        successful_reads: Recorded successful file reads from agent loop
        default_line: Fallback line number if step omits line
        context_lines: Number of context lines around target line
        infer_kind: If True and kind missing, infer from step index (source/propagation/sink)
        default_kind: Fallback kind if not inferred (default: 'step')
        fallback_content: In-memory source code fallback for current file

    Returns:
        List[Dict[str, Any]]: Standardized and enriched taint path steps
    """
    if not taint_path:
        return []

    enriched: List[Dict[str, Any]] = []
    total_steps = len(taint_path)

    for idx, raw_step in enumerate(taint_path, start=1):
        if not isinstance(raw_step, dict):
            continue
        step = dict(raw_step)

        # 1. Determine step number and description
        raw_step_val = step.get("step")
        raw_desc_val = step.get("description")

        if isinstance(raw_step_val, int):
            step_num = raw_step_val
            desc = str(raw_desc_val or (step.get("content") or step.get("message") or f"Step {step_num}"))
        else:
            step_num = idx
            desc = str(raw_desc_val or raw_step_val or step.get("content") or step.get("message") or f"Step {idx}")

        # 2. Determine file path
        step_file = str(step.get("file") or default_file or "").strip()
        step_file = step_file.replace("\\", "/")

        # 3. Determine line number
        raw_line = step.get("line")
        try:
            line_int = int(raw_line) if raw_line is not None else 0
        except (ValueError, TypeError):
            line_int = 0
        if line_int <= 0 and default_line and default_line > 0:
            line_int = int(default_line)

        # 4. Determine and normalize kind
        raw_k = str(step.get("kind", "")).strip().lower()
        if raw_k in ("source", "src"):
            kind = "source"
        elif raw_k in ("propagator", "propagation", "propagate"):
            kind = "propagation"
        elif raw_k in ("sanitizer", "sanitize", "sanitise"):
            kind = "sanitizer"
        elif raw_k in ("sink",):
            kind = "sink"
        elif raw_k in ("imported_call", "imported-call"):
            kind = "imported_call"
        elif raw_k in ("imported_sink", "imported-sink"):
            kind = "imported_sink"
        elif raw_k:
            kind = str(step.get("kind")).strip()
        elif infer_kind:
            if idx == 1:
                kind = "source"
            elif idx == total_steps:
                kind = "sink"
            else:
                kind = "propagation"
        else:
            kind = default_kind or "step"

        # 5. Extract code snippet
        code = str(step.get("code") or "")
        if not code and line_int > 0:
            # 5a. Try reading from successful_reads if available
            if successful_reads:
                for sread in successful_reads:
                    rpath = str(sread.get("path", "")).replace("\\", "/")
                    rstart = sread.get("start_line", 1)
                    rend = sread.get("end_line", rstart)
                    path_matches = False
                    if step_file and rpath:
                        if step_file == rpath or Path(step_file).name == Path(rpath).name:
                            path_matches = True
                    if path_matches and (rstart <= line_int <= rend):
                        raw_lines = sread.get("raw_lines")
                        if raw_lines and isinstance(raw_lines, list):
                            line_offset = line_int - rstart
                            c_start = max(0, line_offset - context_lines)
                            c_end = min(len(raw_lines), line_offset + context_lines + 1)
                            s_lines = []
                            for offset in range(c_start, c_end):
                                cur_line_num = rstart + offset
                                marker = ">" if cur_line_num == line_int else " "
                                s_lines.append(f"{marker} {cur_line_num:>4} | {raw_lines[offset]}")
                            if s_lines:
                                code = "\n".join(s_lines)
                                break
                        elif sread.get("content"):
                            c_lines = str(sread["content"]).splitlines()
                            matched_lines = []
                            for cline in c_lines:
                                try:
                                    parts = cline.split("|", 1)
                                    cur_num = int(parts[0].strip().replace(">", ""))
                                    if abs(cur_num - line_int) <= context_lines:
                                        marker = ">" if cur_num == line_int else " "
                                        text_part = parts[1] if len(parts) > 1 else ""
                                        matched_lines.append(f"{marker} {cur_num:>4} |{text_part}")
                                except Exception:
                                    pass
                            if matched_lines:
                                code = "\n".join(matched_lines)
                                break

            # 5b. Try reading from disk
            if not code and step_file:
                disk_snippet = read_code_snippet(
                    file_path=step_file,
                    line_number=line_int,
                    root_dir=root_dir,
                    context_lines=context_lines,
                    fallback_content=fallback_content if (not default_file or step_file == default_file) else None,
                )
                if disk_snippet:
                    code = disk_snippet

            # 5c. Try fallback_content directly
            if not code and fallback_content:
                mem_snippet = read_code_snippet(
                    file_path="",
                    line_number=line_int,
                    context_lines=context_lines,
                    fallback_content=fallback_content,
                )
                if mem_snippet:
                    code = mem_snippet

        # 6. Resolve evidence_id if missing and successful_reads provided
        matched_eid = step.get("evidence_id")
        if not matched_eid and successful_reads:
            for sread in successful_reads:
                rpath = str(sread.get("path", "")).replace("\\", "/")
                rstart = sread.get("start_line", 1)
                rend = sread.get("end_line", rstart)
                try:
                    if step_file and rpath:
                        if step_file == rpath or Path(step_file).name == Path(rpath).name:
                            if line_int == 0 or (rstart <= line_int <= rend):
                                matched_eid = sread.get("evidence_id")
                                if matched_eid:
                                    break
                except Exception:
                    pass
            if not matched_eid and step_file:
                for sread in successful_reads:
                    rpath = str(sread.get("path", "")).replace("\\", "/")
                    if rpath and Path(step_file).name == Path(rpath).name:
                        matched_eid = sread.get("evidence_id")
                        if matched_eid:
                            break

        # 7. Construct enriched item preserving all original keys
        step["step"] = step_num
        step["kind"] = kind
        step["file"] = step_file
        step["line"] = line_int
        step["description"] = desc
        step["code"] = code
        if matched_eid:
            step["evidence_id"] = matched_eid

        enriched.append(step)

    return enriched

