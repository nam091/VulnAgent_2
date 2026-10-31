"""
Project-wide AST Symbol Index and Resolver.

Scans Python files across workspace/project, extracting definitions (functions,
classes, variables) and import statements to allow global and import-scoped
symbol resolution with source code retrieval.
"""

from __future__ import annotations

import ast
import logging
import os
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

try:
    from evidence.safe_reader import SafeReader, DEFAULT_SKIPS
except ImportError:
    try:
        from src.evidence.safe_reader import SafeReader, DEFAULT_SKIPS
    except ImportError:
        SafeReader = None
        DEFAULT_SKIPS = {
            "venv", ".venv", "env", ".env", "node_modules", "site-packages",
            "__pycache__", ".pytest_cache", ".git", ".idea", ".vscode", "dist", "build"
        }

logger = logging.getLogger(__name__)

# Standard directory exclusions
EXCLUDE_DIRS = set(DEFAULT_SKIPS) | {
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".eggs",
    ".cache",
}


class ProjectSymbolIndex:
    """
    Project-level symbol index and resolver.

    Attributes:
        definitions: Mapping from symbol_name to list of definitions:
            [{'file': str, 'line': int, 'end_line': int, 'kind': 'function'|'class'|'variable'}]
        imports: Mapping from file to list of import statements:
            [{'names': [...], 'module': str, 'level': int}]
    """

    def __init__(
        self,
        root_path: Optional[Union[Path, str]] = None,
        auto_index: bool = False,
    ) -> None:
        self.root_path: Optional[Path] = Path(root_path).resolve() if root_path else None
        self.reader = SafeReader(self.root_path) if (SafeReader and self.root_path) else None

        self.definitions: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.imports: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.indexed_files: Set[str] = set()

        self._file_contents: Dict[str, str] = {}
        self._file_lines_cache: Dict[str, List[str]] = {}

        if auto_index and self.root_path:
            self.index_project()

    def _normalize_key(self, p: Union[str, Path]) -> str:
        """Convert a path into a canonical relative POSIX string if under root_path, else POSIX path."""
        path_obj = Path(p)
        if self.root_path:
            try:
                resolved = path_obj.resolve() if path_obj.is_absolute() else (self.root_path / path_obj).resolve()
                return resolved.relative_to(self.root_path).as_posix()
            except (ValueError, RuntimeError):
                pass
        if path_obj.is_absolute():
            return path_obj.resolve().as_posix()
        return path_obj.as_posix()

    def index_project(self, root_path: Optional[Union[Path, str]] = None) -> "ProjectSymbolIndex":
        """
        Scan AST of all Python files in root_path (skipping venv, .git, node_modules, cache).
        """
        if root_path is not None:
            self.root_path = Path(root_path).resolve()
            if SafeReader:
                self.reader = SafeReader(self.root_path)
        elif self.root_path is None:
            self.root_path = Path.cwd().resolve()
            if SafeReader:
                self.reader = SafeReader(self.root_path)

        files = self._collect_python_files(self.root_path)
        return self.build_index(files)

    def build_index(self, files: Sequence[Union[Path, str]]) -> "ProjectSymbolIndex":
        """
        Build index from a sequence of Python file paths.
        """
        for f in files:
            self.add_file(f)
        return self

    def _collect_python_files(self, root: Path) -> List[Path]:
        """Collect all .py files under root avoiding excluded directories and symlinks."""
        if self.reader:
            try:
                return self.reader.list_python_files(excludes=EXCLUDE_DIRS)
            except Exception as e:
                logger.debug(f"SafeReader file listing failed, falling back to os.walk: {e}")

        collected: List[Path] = []
        for root_dir, dirs, file_names in os.walk(str(root), followlinks=False):
            dirs[:] = [
                d for d in dirs
                if d not in EXCLUDE_DIRS and not d.startswith(".") and not (Path(root_dir) / d).is_symlink()
            ]
            for f in file_names:
                if f.endswith(".py"):
                    file_path = Path(root_dir) / f
                    if not file_path.is_symlink():
                        collected.append(file_path.resolve())
        return collected

    def add_file(
        self,
        file_path: Union[Path, str],
        content: Optional[str] = None,
    ) -> None:
        """
        Parse AST and index definitions and imports for a single file.
        Accepts optional content for in-memory virtual files or tests.
        """
        norm_key = self._normalize_key(file_path)

        if content is None:
            p = Path(file_path)
            if not p.is_file() and self.root_path:
                p = (self.root_path / file_path).resolve()
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                logger.warning(f"Failed to read file {file_path}: {e}")
                return

        # Cache content and lines
        self._file_contents[norm_key] = content
        self._file_lines_cache[norm_key] = content.splitlines(keepends=True)

        # Clear old definitions for this file if re-indexing
        if norm_key in self.indexed_files:
            for sym, def_list in list(self.definitions.items()):
                self.definitions[sym] = [d for d in def_list if d["file"] != norm_key]
                if not self.definitions[sym]:
                    del self.definitions[sym]

        self.indexed_files.add(norm_key)

        try:
            tree = ast.parse(content, filename=norm_key)
        except SyntaxError as e:
            logger.warning(f"Syntax error parsing {norm_key}: {e}")
            return

        self._extract_definitions(tree, norm_key)
        self._extract_imports(tree, norm_key)

    def _extract_names(self, node: ast.AST) -> List[str]:
        """Extract variable name strings from an assignment target AST node."""
        if isinstance(node, ast.Name):
            return [node.id]
        elif isinstance(node, (ast.Tuple, ast.List)):
            names: List[str] = []
            for elt in node.elts:
                names.extend(self._extract_names(elt))
            return names
        return []

    def _extract_definitions(self, tree: ast.AST, file_str: str) -> None:
        """Extract functions, classes, and variables from the AST."""
        def visit_block(nodes: List[ast.AST], class_prefix: str = "") -> None:
            for node in nodes:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    full_name = f"{class_prefix}.{node.name}" if class_prefix else node.name
                    def_info = {
                        "name": full_name,
                        "file": file_str,
                        "line": node.lineno,
                        "end_line": getattr(node, "end_lineno", node.lineno),
                        "kind": "function",
                    }
                    self.definitions[full_name].append(def_info)
                    if class_prefix:
                        bare_info = dict(def_info, name=node.name)
                        self.definitions[node.name].append(bare_info)
                    # Do not descend into function bodies for local variable definitions

                elif isinstance(node, ast.ClassDef):
                    full_name = f"{class_prefix}.{node.name}" if class_prefix else node.name
                    def_info = {
                        "name": full_name,
                        "file": file_str,
                        "line": node.lineno,
                        "end_line": getattr(node, "end_lineno", node.lineno),
                        "kind": "class",
                    }
                    self.definitions[full_name].append(def_info)
                    if class_prefix:
                        bare_info = dict(def_info, name=node.name)
                        self.definitions[node.name].append(bare_info)

                    # Visit class body (methods, class-level attributes)
                    visit_block(node.body, class_prefix=full_name)

                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        for var_name in self._extract_names(target):
                            full_name = f"{class_prefix}.{var_name}" if class_prefix else var_name
                            var_info = {
                                "name": full_name,
                                "file": file_str,
                                "line": node.lineno,
                                "end_line": getattr(node, "end_lineno", node.lineno),
                                "kind": "variable",
                            }
                            self.definitions[full_name].append(var_info)
                            if class_prefix:
                                bare_info = dict(var_info, name=var_name)
                                self.definitions[var_name].append(bare_info)

                elif isinstance(node, ast.AnnAssign):
                    for var_name in self._extract_names(node.target):
                        full_name = f"{class_prefix}.{var_name}" if class_prefix else var_name
                        var_info = {
                            "name": full_name,
                            "file": file_str,
                            "line": node.lineno,
                            "end_line": getattr(node, "end_lineno", node.lineno),
                            "kind": "variable",
                        }
                        self.definitions[full_name].append(var_info)
                        if class_prefix:
                            bare_info = dict(var_info, name=var_name)
                            self.definitions[var_name].append(bare_info)

                elif isinstance(node, (ast.If, ast.Try, ast.With)):
                    for attr in ("body", "orelse", "finalbody"):
                        sub = getattr(node, attr, None)
                        if isinstance(sub, list):
                            visit_block(sub, class_prefix=class_prefix)
                    if isinstance(node, ast.Try):
                        for handler in getattr(node, "handlers", []):
                            if isinstance(getattr(handler, "body", None), list):
                                visit_block(handler.body, class_prefix=class_prefix)

        visit_block(getattr(tree, "body", []))

    def _extract_imports(self, tree: ast.AST, file_str: str) -> None:
        """Extract import statements into the structured list format."""
        file_imports: List[Dict[str, Any]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    names = [alias.name]
                    alias_map: Dict[str, str] = {}
                    if alias.asname:
                        if alias.asname not in names:
                            names.append(alias.asname)
                        alias_map[alias.asname] = alias.name
                    file_imports.append({
                        "names": names,
                        "module": alias.name,
                        "level": 0,
                        "alias_map": alias_map,
                        "line": getattr(node, "lineno", 1),
                    })
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                names: List[str] = []
                alias_map: Dict[str, str] = {}
                for alias in node.names:
                    names.append(alias.name)
                    if alias.asname:
                        if alias.asname not in names:
                            names.append(alias.asname)
                        alias_map[alias.asname] = alias.name
                file_imports.append({
                    "names": names,
                    "module": mod,
                    "level": getattr(node, "level", 0) or 0,
                    "alias_map": alias_map,
                    "line": getattr(node, "lineno", 1),
                })
        self.imports[file_str] = file_imports

    def _find_file_for_module(self, module: str, level: int, current_file: str) -> Optional[str]:
        """Find the indexed file path matching the imported module and relative level."""
        curr_norm = self._normalize_key(current_file)
        curr_path = Path(curr_norm)

        if level > 0:
            base_dir = curr_path.parent
            for _ in range(level - 1):
                base_dir = base_dir.parent

            rel_parts = [p for p in module.split(".") if p]
            candidates = []
            if rel_parts:
                cand_base = base_dir.joinpath(*rel_parts)
                candidates.append(cand_base.with_suffix(".py").as_posix())
                candidates.append((cand_base / "__init__.py").as_posix())
            else:
                candidates.append((base_dir / "__init__.py").as_posix())
                candidates.append(base_dir.with_suffix(".py").as_posix())

            for cand in candidates:
                cand_norm = self._normalize_key(cand)
                if cand_norm in self.indexed_files:
                    return cand_norm
                for f in self.indexed_files:
                    if f == cand_norm or f.endswith("/" + cand_norm.lstrip("/")):
                        return f
        else:
            if not module:
                return None
            parts = module.split(".")
            cand_py = "/".join(parts) + ".py"
            cand_init = "/".join(parts) + "/__init__.py"

            for cand in (cand_py, cand_init):
                cand_norm = self._normalize_key(cand)
                if cand_norm in self.indexed_files:
                    return cand_norm

            for cand in (cand_py, cand_init):
                suffix = "/" + cand
                for f in self.indexed_files:
                    if f == cand or f.endswith(suffix):
                        return f

            last_file = parts[-1] + ".py"
            last_suffix = "/" + last_file
            for f in self.indexed_files:
                if f == last_file or f.endswith(last_suffix):
                    return f

        return None

    def resolve_symbol(
        self,
        symbol_name: str,
        current_file: str,
        depth: int = 0,
        max_depth: int = 10,
        visited: Optional[Set[Tuple[str, str]]] = None,
        fallback_global: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """
        Resolve symbol definition based on imports of current_file or global definitions.
        Returns dictionary with file location, start line, end line, kind, and source code.
        """
        if depth > max_depth:
            return None

        norm_curr = self._normalize_key(current_file)

        if visited is None:
            visited = set()
        visit_key = (symbol_name, norm_curr)
        if visit_key in visited:
            return None
        visited.add(visit_key)

        # 1. Check if defined in current_file directly
        curr_defs = [
            d for d in self.definitions.get(symbol_name, [])
            if self._normalize_key(d["file"]) == norm_curr
        ]
        if curr_defs:
            return self._build_result(curr_defs[0])

        # 2. Check if dotted symbol (e.g. Class.method or module.member)
        if "." in symbol_name:
            prefix, member = symbol_name.split(".", 1)
            prefix_res = self.resolve_symbol(
                prefix,
                current_file,
                depth=depth + 1,
                max_depth=max_depth,
                visited=visited,
                fallback_global=fallback_global,
            )
            if prefix_res and prefix_res.get("file"):
                member_res = self.resolve_symbol(
                    member,
                    prefix_res["file"],
                    depth=depth + 1,
                    max_depth=max_depth,
                    visited=visited,
                    fallback_global=False,
                )
                if member_res:
                    return member_res

        # 3. Check imports of current_file
        imports = self.imports.get(norm_curr, [])
        if not imports:
            for f_key, imps in self.imports.items():
                if f_key == norm_curr or f_key.endswith("/" + norm_curr) or norm_curr.endswith("/" + f_key):
                    imports = imps
                    break

        for imp in imports:
            # 3a. Explicit import match
            if symbol_name in imp["names"]:
                alias_map = imp.get("alias_map", {})
                orig_name = alias_map.get(symbol_name, symbol_name)
                target_file = self._find_file_for_module(imp["module"], imp.get("level", 0), norm_curr)
                if target_file and depth + 1 <= max_depth:
                    target_norm = self._normalize_key(target_file)
                    target_defs = [
                        d for d in self.definitions.get(orig_name, [])
                        if self._normalize_key(d["file"]) == target_norm
                    ]
                    if target_defs:
                        return self._build_result(target_defs[0])

                    # Recursively resolve in target_file (re-exports)
                    res = self.resolve_symbol(
                        orig_name,
                        target_file,
                        depth=depth + 1,
                        max_depth=max_depth,
                        visited=visited,
                        fallback_global=False,
                    )
                    if res:
                        return res

            # 3b. Wildcard / star import
            if "*" in imp["names"]:
                target_file = self._find_file_for_module(imp["module"], imp.get("level", 0), norm_curr)
                if target_file and depth + 1 <= max_depth:
                    target_norm = self._normalize_key(target_file)
                    target_defs = [
                        d for d in self.definitions.get(symbol_name, [])
                        if self._normalize_key(d["file"]) == target_norm
                    ]
                    if target_defs:
                        return self._build_result(target_defs[0])

                    res = self.resolve_symbol(
                        symbol_name,
                        target_file,
                        depth=depth + 1,
                        max_depth=max_depth,
                        visited=visited,
                        fallback_global=False,
                    )
                    if res:
                        return res

        # 4. Fallback to global search in definitions
        if fallback_global and depth == 0:
            global_defs = self.definitions.get(symbol_name, [])
            if global_defs:
                def proximity_key(d: Dict[str, Any]) -> int:
                    d_norm = self._normalize_key(d["file"])
                    curr_parts = norm_curr.split("/")
                    d_parts = d_norm.split("/")
                    common = 0
                    for p1, p2 in zip(curr_parts, d_parts):
                        if p1 == p2:
                            common += 1
                        else:
                            break
                    return -common

                sorted_defs = sorted(global_defs, key=proximity_key)
                return self._build_result(sorted_defs[0])

        return None

    def _build_result(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Construct the resolution dictionary result including source code snippet."""
        file_path = entry["file"]
        line = entry["line"]
        end_line = entry.get("end_line", line)
        kind = entry.get("kind", "variable")
        name = entry.get("name", "")

        source = self._read_source_lines(file_path, line, end_line)

        return {
            "name": name,
            "file": file_path,
            "line": line,
            "end_line": end_line,
            "kind": kind,
            "source": source,
            "source_code": source,
        }

    def _read_source_lines(self, file_path: str, start_line: int, end_line: int) -> Optional[str]:
        """Safely read lines from file or memory cache."""
        norm_key = self._normalize_key(file_path)
        lines = self._file_lines_cache.get(norm_key)

        if lines is None:
            p = Path(norm_key)
            if not p.is_file() and self.root_path:
                p = (self.root_path / norm_key).resolve()
            if not p.is_file():
                p = Path(file_path).resolve()

            if p.is_file():
                try:
                    content = p.read_text(encoding="utf-8", errors="replace")
                    lines = content.splitlines(keepends=True)
                    self._file_lines_cache[norm_key] = lines
                except Exception as e:
                    logger.debug(f"Failed to read file {p}: {e}")
                    return None
            else:
                return None

        if lines is None:
            return None

        start_idx = max(0, start_line - 1)
        end_idx = min(len(lines), max(start_line, end_line))
        if start_idx < len(lines):
            return "".join(lines[start_idx:end_idx])
        return ""

    def get_definitions(self, symbol_name: str) -> List[Dict[str, Any]]:
        """Return all indexed definitions matching symbol_name."""
        return list(self.definitions.get(symbol_name, []))

    def get_imports(self, file_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Return all indexed imports for a given file."""
        norm_key = self._normalize_key(file_path)
        if norm_key in self.imports:
            return list(self.imports[norm_key])
        for k, v in self.imports.items():
            if k == norm_key or k.endswith("/" + norm_key) or norm_key.endswith("/" + k):
                return list(v)
        return []

    def clear(self) -> None:
        """Clear all indexed definitions, imports, and caches."""
        self.definitions.clear()
        self.imports.clear()
        self.indexed_files.clear()
        self._file_contents.clear()
        self._file_lines_cache.clear()

    @property
    def files(self) -> List[str]:
        """List of all indexed files."""
        return sorted(list(self.indexed_files))

    def __len__(self) -> int:
        """Return number of unique indexed files."""
        return len(self.indexed_files)
