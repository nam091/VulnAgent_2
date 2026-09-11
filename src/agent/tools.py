"""Code-inspection tools the agent can call during analysis.

A single-shot prompt sees one file and nothing else, which is why the LLM
tier both misses cross-file defects and invents findings it cannot check.
These tools let it go and look instead of guessing: read the definition of a
function it does not recognise, follow an import, check whether a sanitiser
exists before it claims one does not.

Every tool is read-only and confined to the scan root. An analysis agent has
no business writing files, and a path escape here would be the traversal
defect this project exists to report.
"""

import ast
import json
import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from evidence.safe_reader import (
    FileTooLargeError,
    MAX_FILE_BYTES,
    MAX_MATCHES,
    MAX_READ_LINES,
    PathEscapeError,
    SafeReader,
)


class ToolError(Exception):
    """Raised when a tool call cannot be satisfied."""


class CodeTools:
    """
    Read-only inspection of a scan root, exposed as callable tools.
    """

    def __init__(
        self,
        root: Path,
        evidence_store: Optional[Any] = None,
        snapshot_id: Optional[str] = None
    ) -> None:
        """
        Args:
            root: Directory that every path argument is resolved inside
            evidence_store: Optional EvidenceStore for recording inspected code slices
            snapshot_id: Optional snapshot identifier
        """

        self.root = Path(root).resolve()
        self.reader = SafeReader(self.root)
        self.call_count = 0
        self.calls: List[Dict[str, Any]] = []
        self.evidence_store = evidence_store
        self.snapshot_id = snapshot_id

    def _resolve(self, relative: str) -> Path:
        """
        Resolve a caller-supplied path inside the scan root.

        Args:
            relative: Path as supplied by the model

        Returns:
            Path: The resolved absolute path

        Raises:
            ToolError: When the path escapes the root, is a symlink escape, or does not exist
        """

        try:
            target = self.reader.resolve(relative)
            if not target.is_file():
                raise ToolError(f"no such file: {relative}")
            if target.stat().st_size > MAX_FILE_BYTES:
                raise ToolError(f"file too large: {relative}")
            return target
        except PathEscapeError as e:
            raise ToolError(f"path escapes the scan root: {relative} ({e})")
        except Exception as e:
            raise ToolError(str(e))

    def read_lines(self, path: str, start_line: int = 1, end_line: int = 0) -> Dict[str, Any]:
        """
        Read a numbered slice of a file.

        Args:
            path: File path relative to the scan root
            start_line: First line, 1-based
            end_line: Last line; 0 reads MAX_READ_LINES from start_line

        Returns:
            Dict[str, Any]: The requested lines, each prefixed with its number
        """

        try:
            return self.reader.read_lines(path, start_line, end_line)
        except (PathEscapeError, FileTooLargeError) as e:
            raise ToolError(str(e))
        except FileNotFoundError:
            raise ToolError(f"no such file: {path}")
        except Exception as e:
            raise ToolError(f"cannot read {path}: {e}")

    def find_definition(self, name: str, path: Optional[str] = None) -> Dict[str, Any]:
        """
        Locate a function or class definition by name.

        Args:
            name: Symbol to find
            path: Restrict the search to one file, or search the tree

        Returns:
            Dict[str, Any]: Matching definitions with their source
        """

        targets = [self._resolve(path)] if path else self._python_files()
        results = []

        for target in targets:
            try:
                source = self.reader.read_file(self._relative(target))
                tree = ast.parse(source)
            except (OSError, SyntaxError, PathEscapeError, FileTooLargeError):
                continue

            lines = source.splitlines()
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if node.name != name:
                    continue
                end = getattr(node, "end_lineno", node.lineno + 30) or node.lineno + 30
                end = min(end, node.lineno + MAX_READ_LINES)
                slice_lines = lines[node.lineno - 1:min(end, len(lines))]
                results.append({
                    "file": self._relative(target),
                    "start_line": node.lineno,
                    "end_line": end,
                    "kind": type(node).__name__,
                    "source": "\n".join(
                        f"{i:>5} | {lines[i - 1]}"
                        for i in range(node.lineno, min(end, len(lines)) + 1)
                    ),
                    "raw_lines": slice_lines,
                })
                if len(results) >= 5:
                    break

        if not results:
            return {"name": name, "found": False, "note": "no definition found in scope"}
        return {"name": name, "found": True, "definitions": results}

    def search(
        self,
        pattern: str,
        path: Optional[str] = None,
        literal: bool = False,
    ) -> Dict[str, Any]:
        """
        Search the tree for a regular expression.

        Args:
            pattern: Python regular expression
            path: Restrict to one file, or search every Python file

        Returns:
            Dict[str, Any]: Matching lines with their locations
        """

        if not pattern or not isinstance(pattern, str):
            raise ToolError("pattern must be a non-empty string")
        if len(pattern) > 200:
            raise ToolError("regular expression exceeds maximum length (200 characters)")

        regex_chars = set(r"^$*+?{}[]\|()")
        is_literal = literal or not any(c in regex_chars for c in pattern)

        targets = [self._resolve(path)] if path else self._python_files()
        targets = targets[:100]
        matches: List[Dict[str, Any]] = []

        if is_literal:
            for target in targets:
                try:
                    content = self.reader.read_file(self._relative(target))
                    lines = content.splitlines()
                except (OSError, PathEscapeError, FileTooLargeError):
                    continue
                for number, line in enumerate(lines, 1):
                    if pattern in line:
                        matches.append({
                            "file": self._relative(target),
                            "line": number,
                            "text": line.strip()[:200],
                        })
                        if len(matches) >= MAX_MATCHES:
                            return {"pattern": pattern, "matches": matches, "truncated": True}
            return {"pattern": pattern, "matches": matches, "truncated": False}

        # Static ReDoS screen: catastrophic nested quantifiers or ambiguous alternations
        if (
            re.search(r"\([^)]*[+*]\)\s*[+*{]", pattern)
            or re.search(r"\((?:[^()]*[+*][^()]*|\([^()]+\)[+*]?)\)\s*[+*{]", pattern)
        ):
            raise ToolError("potentially catastrophic nested repetition in regular expression rejected")
        if re.search(r"\([^)]*\|[^)]*\)\s*[+*{]", pattern):
            raise ToolError("potentially catastrophic ambiguous alternation with repetition in regular expression rejected")

        try:
            re.compile(pattern)
        except re.error as e:
            raise ToolError(f"invalid regular expression: {e}")

        file_payload = []
        for target in targets:
            try:
                content = self.reader.read_file(self._relative(target))
                file_payload.append({"file": self._relative(target), "lines": content.splitlines()})
            except (OSError, PathEscapeError, FileTooLargeError):
                continue

        worker_script = (
            "import sys, json, re\n"
            "data = json.loads(sys.stdin.read())\n"
            "try:\n"
            "    compiled = re.compile(data['pattern'])\n"
            "except Exception as e:\n"
            "    print(json.dumps({'error': str(e)}))\n"
            "    sys.exit(1)\n"
            "matches = []\n"
            "truncated = False\n"
            "for item in data['targets']:\n"
            "    for num, line in enumerate(item['lines'], 1):\n"
            "        if compiled.search(line):\n"
            "            matches.append({'file': item['file'], 'line': num, 'text': line.strip()[:200]})\n"
            "            if len(matches) >= data.get('max_matches', 40):\n"
            "                truncated = True\n"
            "                break\n"
            "    if truncated:\n"
            "        break\n"
            "print(json.dumps({'matches': matches, 'truncated': truncated}))\n"
        )

        input_data = json.dumps({
            "pattern": pattern,
            "targets": file_payload,
            "max_matches": MAX_MATCHES,
        })

        try:
            proc = subprocess.run(
                [sys.executable, "-c", worker_script],
                input=input_data,
                capture_output=True,
                text=True,
                timeout=1.5,
            )
        except subprocess.TimeoutExpired:
            raise ToolError("regular expression search timed out after 1.5s (possible ReDoS pattern)")

        if proc.returncode != 0:
            raise ToolError(f"regex search failed: {proc.stderr.strip() or 'worker error'}")

        try:
            res = json.loads(proc.stdout)
            return {"pattern": pattern, "matches": res.get("matches", []), "truncated": res.get("truncated", False)}
        except Exception as e:
            raise ToolError(f"failed to parse search result: {e}")

    def list_files(self) -> Dict[str, Any]:
        """
        List the Python files inside the scan root.

        Returns:
            Dict[str, Any]: Relative paths
        """

        files = [self._relative(p) for p in self._python_files()]
        return {"count": len(files), "files": files[:200]}

    def _python_files(self) -> List[Path]:
        """
        Every Python file under the root, excluding vendored directories and symlink escapes.

        Returns:
            List[Path]: Absolute paths
        """

        return self.reader.list_python_files()

    def _relative(self, path: Path) -> str:
        """
        Express a path relative to the scan root.

        Args:
            path: Absolute path

        Returns:
            str: Posix relative path
        """

        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def dispatch(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Invoke a tool by name on behalf of the model.

        Args:
            name: Tool name
            arguments: Arguments supplied by the model

        Returns:
            Dict[str, Any]: The tool result, or an error the model can read
        """

        self.call_count += 1
        self.calls.append({"tool": name, "args": arguments})

        handlers = {
            "read_lines": self.read_lines,
            "find_definition": self.find_definition,
            "search": self.search,
            "list_files": self.list_files,
        }
        handler = handlers.get(name)
        if handler is None:
            return {"error": f"unknown tool: {name}"}

        try:
            return handler(**arguments)
        except ToolError as e:
            return {"error": str(e)}
        except TypeError as e:
            return {"error": f"bad arguments for {name}: {e}"}
        except Exception as e:
            logging.debug(f"Tool {name} failed: {e}")
            return {"error": f"{name} failed: {e}"}


# OpenAI-compatible tool schemas.
TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "read_lines",
            "description": (
                "Read a numbered slice of a file in the project. Use this to see "
                "code around a suspected defect, or to check a file you have only "
                "seen imported."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path relative to the project root"},
                    "start_line": {"type": "integer", "description": "First line to read, 1-based"},
                    "end_line": {"type": "integer", "description": "Last line to read; omit for 200 lines"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_definition",
            "description": (
                "Find where a function or class is defined and read its source. Use "
                "this before assuming what a helper does - especially to check "
                "whether a function that looks like a sanitiser actually validates "
                "anything."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Function or class name"},
                    "path": {"type": "string", "description": "Optional file to restrict the search to"},
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search",
            "description": (
                "Search the project for a regular expression. Use this to trace "
                "where a value comes from or where a function is called."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Python regular expression or literal string"},
                    "path": {"type": "string", "description": "Optional file to restrict the search to"},
                    "literal": {"type": "boolean", "description": "If true, treat pattern as literal string (recommended)"},
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "List the Python files in the project.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]
