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
