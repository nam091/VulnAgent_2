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

try:
    from context.project_index import ProjectSymbolIndex
except ImportError:
    try:
        from src.context.project_index import ProjectSymbolIndex
    except ImportError:
        ProjectSymbolIndex = None

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


_SYMBOL_INDEX_CACHE: Dict[Path, Any] = {}


def get_project_symbol_index(root: Path, force_reload: bool = False) -> Any:
    """
    Get or create a cached ProjectSymbolIndex for the given root path.
    """
    root_resolved = Path(root).resolve()
    if force_reload or root_resolved not in _SYMBOL_INDEX_CACHE:
        if ProjectSymbolIndex is None:
            raise ToolError("ProjectSymbolIndex is not available")
        index = ProjectSymbolIndex(root_path=root_resolved, auto_index=True)
        _SYMBOL_INDEX_CACHE[root_resolved] = index
    return _SYMBOL_INDEX_CACHE[root_resolved]


def clear_symbol_index_cache(root: Optional[Path] = None) -> None:
    """Clear cached ProjectSymbolIndex instance(s)."""
    if root is not None:
        _SYMBOL_INDEX_CACHE.pop(Path(root).resolve(), None)
    else:
        _SYMBOL_INDEX_CACHE.clear()


class CodeTools:
    """
    Read-only inspection of a scan root, exposed as callable tools.
    """

    def __init__(
        self,
        root: Path,
        evidence_store: Optional[Any] = None,
        snapshot_id: Optional[str] = None,
        symbol_index: Optional[Any] = None,
        focus_file: Optional[str] = None,
    ) -> None:
        """
        Args:
            root: Directory that every path argument is resolved inside
            evidence_store: Optional EvidenceStore for recording inspected code slices
            snapshot_id: Optional snapshot identifier
            symbol_index: Optional pre-configured or mock ProjectSymbolIndex
            focus_file: Optional target file path for prioritized anti-wandering search
        """

        self.root = Path(root).resolve()
        self.reader = SafeReader(self.root)
        self.call_count = 0
        self.calls: List[Dict[str, Any]] = []
        self.evidence_store = evidence_store
        self.snapshot_id = snapshot_id
        self._symbol_index = symbol_index
        self.focus_file = focus_file

    @property
    def symbol_index(self) -> Any:
        """
        Lazily initialize or retrieve cached ProjectSymbolIndex for self.root.
        """
        if self._symbol_index is not None:
            return self._symbol_index
        self._symbol_index = get_project_symbol_index(self.root)
        return self._symbol_index

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

    def read_imported_symbol(
        self,
        symbol_name: Optional[str] = None,
        from_file: Optional[str] = None,
        max_depth: int = 2,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Resolve and read the definition and source code of an imported symbol.

        Args:
            symbol_name: Name of symbol to resolve (function, class, variable, or Class.method)
            from_file: Optional path of the file where symbol is imported or referenced
            max_depth: Hop depth limit (strictly capped at <= 2 to prevent infinite loops)
            **kwargs: Extra parameters (e.g. name, file, path) for model compatibility

        Returns:
            Dict[str, Any]: Resolved symbol info with source code, or not found message
        """
        target_symbol = symbol_name or kwargs.get("name") or kwargs.get("symbol")
        if not target_symbol or not isinstance(target_symbol, str):
            raise ToolError("symbol_name must be a non-empty string")
        target_symbol = target_symbol.strip()
        if not target_symbol:
            raise ToolError("symbol_name must be a non-empty string")

        source_file = from_file or kwargs.get("file") or kwargs.get("path")
        norm_from_file = ""

        if source_file:
            source_file_str = str(source_file).strip()
            if source_file_str:
                try:
                    resolved_target = self._resolve(source_file_str)
                    norm_from_file = self._relative(resolved_target)
                except ToolError:
                    # Allow virtual files from index (e.g., in unit tests)
                    idx = self._symbol_index
                    if idx and hasattr(idx, "indexed_files"):
                        norm_key = idx._normalize_key(source_file_str)
                        if norm_key in idx.indexed_files or source_file_str in idx.indexed_files:
                            norm_from_file = norm_key
                        else:
                            raise
                    else:
                        raise

        # Strictly enforce hop depth <= 2 to prevent infinite recursion
        hop_limit = min(max(int(max_depth), 0), 2)

        index = self.symbol_index
        # If from_file was provided and not in indexed files, index it now if it exists
        if norm_from_file and hasattr(index, "indexed_files") and norm_from_file not in index.indexed_files:
            file_abs = self.root / norm_from_file
            if file_abs.is_file():
                index.add_file(norm_from_file)

        fallback_global = True if not norm_from_file else False
        resolved = index.resolve_symbol(
            symbol_name=target_symbol,
            current_file=norm_from_file,
            max_depth=hop_limit,
            fallback_global=fallback_global,
        )

        if not resolved:
            return {
                "name": target_symbol,
                "symbol": target_symbol,
                "found": False,
                "note": f"no definition found for imported symbol '{target_symbol}'"
                + (f" from '{norm_from_file}'" if norm_from_file else ""),
            }

        start_line = resolved.get("line", 1)
        end_line = resolved.get("end_line", start_line)
        raw_source = resolved.get("source") or resolved.get("source_code") or ""
        lines = raw_source.splitlines()

        if lines:
            numbered_lines = "\n".join(
                f"{start_line + i:>5} | {line}" for i, line in enumerate(lines)
            )
        else:
            numbered_lines = ""

        res_file = resolved.get("file", "")
        if res_file:
            try:
                cand_path = Path(res_file)
                if not cand_path.is_absolute() and (self.root / cand_path).is_file():
                    res_file = self._relative(self.root / cand_path)
                elif cand_path.is_absolute():
                    res_file = self._relative(cand_path)
            except Exception:
                pass

        return {
            "name": target_symbol,
            "symbol": target_symbol,
            "found": True,
            "file": res_file,
            "start_line": start_line,
            "line": start_line,
            "end_line": end_line,
            "kind": resolved.get("kind", "definition"),
            "source": numbered_lines,
            "source_code": raw_source,
            "raw_lines": lines,
            "from_file": norm_from_file or None,
        }

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

        if path:
            targets = [self._resolve(path)]
            return self._do_search(targets, pattern, is_literal)

        # Anti-wandering guard: search focus_file first when path is omitted
        if self.focus_file:
            try:
                focus_target = self._resolve(self.focus_file)
                focus_res = self._do_search([focus_target], pattern, is_literal)
                if focus_res.get("matches"):
                    focus_res["scope"] = f"local to {self.focus_file}"
                    focus_res["note"] = (
                        f"Matches found within focus file '{self.focus_file}'. "
                        "Specify 'path' explicitly if you need to search imported modules or other files."
                    )
                    return focus_res
            except Exception:
                pass
            targets = [t for t in self._python_files() if not self.focus_file or self._relative(t) != self.focus_file][:25]
        else:
            targets = self._python_files()[:50]

        return self._do_search(targets, pattern, is_literal)

    def _do_search(
        self,
        targets: List[Path],
        pattern: str,
        is_literal: bool
    ) -> Dict[str, Any]:
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
            "read_imported_symbol": self.read_imported_symbol,
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

    def execute_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Execute a tool by name with supplied arguments or kwargs.

        Args:
            name: Tool name to execute
            arguments: Optional dictionary of arguments
            **kwargs: Extra arguments merged with arguments dict

        Returns:
            Dict[str, Any]: Result of tool execution or error dict
        """
        args = dict(arguments or {})
        args.update(kwargs)
        return self.dispatch(name, args)

    def tools_schema(self) -> List[Dict[str, Any]]:
        """Return the list of OpenAI-compatible tool schemas."""
        return TOOL_SCHEMAS


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
            "name": "read_imported_symbol",
            "description": (
                "Resolve and read the definition and source code of an imported symbol "
                "(function, class, or variable) across the project workspace. "
                "Follows import chains up to 2 hops. Optionally specify from_file to trace "
                "the import from a specific file."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "Name of the symbol (function, class, or variable) to resolve",
                    },
                    "from_file": {
                        "type": "string",
                        "description": "Optional file path where the symbol is imported or referenced",
                    },
                },
                "required": ["symbol_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search",
            "description": (
                "Search the project for a regular expression or literal string. "
                "Always specify 'path' to search within the file under investigation or an imported module; "
                "omit path only when tracing an unknown symbol across files."
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


def tools_schema() -> List[Dict[str, Any]]:
    """Return OpenAI-compatible tool schemas for agent tools."""
    return TOOL_SCHEMAS


def tools_schemas() -> List[Dict[str, Any]]:
    """Alias for tools_schema."""
    return TOOL_SCHEMAS
