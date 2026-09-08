import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from evidence.safe_reader import SafeReader


@dataclass
class FunctionScope:
    name: str
    start_line: int
    end_line: int
    is_async: bool = False
    decorators: List[str] = field(default_factory=list)
    docstring: Optional[str] = None
    parameters: List[str] = field(default_factory=list)


@dataclass
class ClassScope:
    name: str
    start_line: int
    end_line: int
    methods: List[FunctionScope] = field(default_factory=list)
    bases: List[str] = field(default_factory=list)


@dataclass
class ImportStatement:
    module: str
    name: str
    alias: Optional[str] = None
    line: int = 1
    is_from: bool = False


@dataclass
class FileContext:
    path: str
    functions: List[FunctionScope] = field(default_factory=list)
    classes: List[ClassScope] = field(default_factory=list)
    imports: List[ImportStatement] = field(default_factory=list)
    unresolved_symbols: List[str] = field(default_factory=list)
    dynamic_imports: List[str] = field(default_factory=list)
    syntax_error: Optional[str] = None


class ASTContextExtractor:
    """
    Parses Python source using the built-in ast module to provide
    symbol resolution, enclosing function discovery, and dependency tracing.
    """

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root).resolve() if root else Path.cwd().resolve()
        self.reader = SafeReader(self.root)

    def parse_file(self, path_or_relative: str, content: Optional[str] = None) -> FileContext:
        """
        Parse AST for a file and return structured scopes and imports.
        """
        if content is None:
            try:
                content = self.reader.read_file(path_or_relative)
            except Exception as e:
                return FileContext(path=str(path_or_relative), syntax_error=str(e))

        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            return FileContext(path=str(path_or_relative), syntax_error=str(e))

        context = FileContext(path=str(path_or_relative))
        self._extract_scopes(tree, context)
        self._extract_imports(tree, context)
        return context

    def _extract_scopes(self, node: ast.AST, context: FileContext) -> None:
        for item in node.body if hasattr(node, "body") else []:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = self._parse_function(item)
                context.functions.append(scope)
            elif isinstance(item, ast.ClassDef):
                c_scope = self._parse_class(item)
                context.classes.append(c_scope)

    def _parse_function(self, node: ast.AST) -> FunctionScope:
        is_async = isinstance(node, ast.AsyncFunctionDef)
        name = getattr(node, "name", "")
        start_line = getattr(node, "lineno", 1)
        end_line = getattr(node, "end_lineno", start_line)

        decorators = []
        for d in getattr(node, "decorator_list", []):
            if isinstance(d, ast.Name):
                decorators.append(d.id)
            elif isinstance(d, ast.Attribute):
                decorators.append(f"{getattr(d.value, 'id', '')}.{d.attr}")
            elif isinstance(d, ast.Call):
                func = getattr(d, "func", None)
                if isinstance(func, ast.Name):
                    decorators.append(func.id)
                elif isinstance(func, ast.Attribute):
                    decorators.append(f"{getattr(func.value, 'id', '')}.{func.attr}")

        params = [a.arg for a in getattr(node.args, "args", [])]
        doc = ast.get_docstring(node)

        return FunctionScope(
            name=name,
            start_line=start_line,
            end_line=end_line,
            is_async=is_async,
            decorators=decorators,
            docstring=doc,
            parameters=params,
        )

    def _parse_class(self, node: ast.ClassDef) -> ClassScope:
        name = node.name
        start_line = node.lineno
        end_line = getattr(node, "end_lineno", start_line)
        bases = [b.id for b in node.bases if isinstance(b, ast.Name)]

        methods: List[FunctionScope] = []
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods.append(self._parse_function(item))

        return ClassScope(
            name=name,
            start_line=start_line,
            end_line=end_line,
            methods=methods,
            bases=bases,
        )

    def _extract_imports(self, tree: ast.AST, context: FileContext) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    context.imports.append(
                        ImportStatement(
                            module=alias.name,
                            name=alias.name,
                            alias=alias.asname,
                            line=node.lineno,
                            is_from=False,
                        )
                    )
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    context.imports.append(
                        ImportStatement(
                            module=mod,
                            name=alias.name,
                            alias=alias.asname,
                            line=node.lineno,
                            is_from=True,
                        )
                    )
            elif isinstance(node, ast.Call):
                # Detect dynamic imports like __import__('foo') or importlib.import_module('foo')
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = f"{getattr(node.func.value, 'id', '')}.{node.func.attr}"

                if func_name in ("__import__", "importlib.import_module"):
                    target_mod = "(dynamic)"
                    if node.args and isinstance(node.args[0], ast.Constant):
                        target_mod = str(node.args[0].value)
                    context.dynamic_imports.append(f"{func_name}({target_mod}) at L{node.lineno}")

    def find_enclosing_scope(
        self,
        file_path: str,
        line_number: int,
        content: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Find the function or method enclosing a given line number.
        """
        ctx = self.parse_file(file_path, content)
        # Check functions first
        for fn in ctx.functions:
            if fn.start_line <= line_number <= fn.end_line:
                return {
                    "kind": "async_function" if fn.is_async else "function",
                    "name": fn.name,
                    "start_line": fn.start_line,
                    "end_line": fn.end_line,
                    "decorators": fn.decorators,
                    "parameters": fn.parameters,
                }

        # Check classes and their methods
        for cl in ctx.classes:
            if cl.start_line <= line_number <= cl.end_line:
                for m in cl.methods:
                    if m.start_line <= line_number <= m.end_line:
                        return {
                            "kind": "method",
                            "class": cl.name,
                            "name": m.name,
                            "start_line": m.start_line,
                            "end_line": m.end_line,
                            "decorators": m.decorators,
                            "parameters": m.parameters,
                        }
                return {
                    "kind": "class",
                    "name": cl.name,
                    "start_line": cl.start_line,
                    "end_line": cl.end_line,
                }

        return None
