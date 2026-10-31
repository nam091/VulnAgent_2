"""Intra-procedural backward AST slicing for VulnAgent.

This module implements the first analysis tier described in Section 3.1 of
``Phuong_an_2.md``:

* locate a dangerous sink call at ``sink_line``;
* discover the variables that feed the sink;
* walk backwards through the enclosing function (or module) and collect the
  reaching definitions with a worklist based fixpoint analysis;
* expose the resulting slice as structured :class:`SliceNode` objects plus a
  compact source snippet that can be handed to the LLM detector tier.

The implementation is deliberately conservative.  Whenever the slicer cannot
prove that a dependency is fully understood (dynamic dispatch, unknown
inter-procedural calls, iteration-budget exhaustion, ...) the result is marked
``partial`` instead of silently assuming safety.  This is the fail-safe
contract used by the later detector/verifier tiers.
"""

from __future__ import annotations

import ast
import logging
import textwrap
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

logger = logging.getLogger(__name__)

__all__ = [
    "ASTSlicer",
    "SliceNode",
    "SliceResult",
    "SinkAnchor",
    "ABSTRACT_SINK_CATEGORIES",
    "HEURISTIC_SINK_SUFFIXES",
    "HEURISTIC_SINK_OBJECT_PREFIXES",
    "SINK_CALL_SIGNATURES",
    "COMPLETENESS_COMPLETE",
    "COMPLETENESS_PARTIAL",
    "COMPLETENESS_FAILED",
    "get_sink_category",
    "find_sink_anchors",
    "find_call_site_sink_anchors",
]


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

COMPLETENESS_COMPLETE = "complete"
COMPLETENESS_PARTIAL = "partial"
COMPLETENESS_FAILED = "failed"

#: Structured dictionary classifying dangerous sinks into canonical categories.
ABSTRACT_SINK_CATEGORIES: Dict[str, Tuple[str, ...]] = {
    # 1. DATABASE_EXECUTION: SQL queries, ORM raw queries (CWE-89)
    "DATABASE_EXECUTION": (
        "cursor.execute",
        "cursor.executemany",
        "connection.execute",
        "session.execute",
        "db.engine.execute",
        "raw_sql_query",
        "execute",
        "executemany",
        "raw",
        "select",
        "filter",
        "objects.raw",
        "objects.filter",
        "query.filter",
        "query.select",
    ),
    # 2. COMMAND_EXECUTION: Shell & process calls (CWE-78)
    "COMMAND_EXECUTION": (
        "subprocess.*",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_output",
        "subprocess.check_call",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "os.system",
        "os.popen",
        "os.spawn",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "pty.spawn",
        "pty",
        "shlex",
        "shlex.split",
    ),
    # 3. DYNAMIC_EVALUATION: Code execution (CWE-94, CWE-95)
    "DYNAMIC_EVALUATION": (
        "eval",
        "exec",
        "compile",
    ),
    # 4. SERIALIZATION: Object loading (CWE-502)
    "SERIALIZATION": (
        "pickle.*",
        "pickle.loads",
        "pickle.load",
        "_pickle.loads",
        "_pickle.load",
        "yaml.load",
        "yaml.unsafe_load",
        "jsonpickle.decode",
        "marshal.loads",
        "marshal.load",
        "shelve.open",
        "torch.load",
    ),
    # 5. NETWORK_SSRF: Outbound HTTP/socket requests (CWE-918)
    "NETWORK_SSRF": (
        "requests.*",
        "requests.get",
        "requests.post",
        "requests.request",
        "requests.put",
        "requests.delete",
        "requests.head",
        "requests.patch",
        "urllib.request.*",
        "urllib.request.urlopen",
        "urllib.request.Request",
        "urllib.request.urlretrieve",
        "session.get",
        "session.post",
        "session.request",
        "httpx.*",
        "httpx.get",
        "httpx.post",
        "httpx.request",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
        "aiohttp.ClientSession",
        "aiohttp.ClientSession.get",
        "aiohttp.ClientSession.post",
        "aiohttp.request",
        "urllib3.PoolManager",
        "urllib3.PoolManager.request",
    ),
    # 6. FILE_IO: Path & filesystem manipulation (CWE-22)
    "FILE_IO": (
        "open",
        "os.open",
        "os.remove",
        "os.rmdir",
        "os.walk",
        "shutil.*",
        "shutil.rmtree",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.copytree",
        "shutil.move",
        "shutil.unpack_archive",
        "pathlib.Path",
        "flask.send_file",
        "send_file",
        "send_from_directory",
        "tarfile.open",
        "tarfile.TarFile.extractall",
        "zipfile.ZipFile",
        "zipfile.ZipFile.extractall",
        "extractall",
        "django.http.FileResponse",
        "FileResponse",
    ),
    # 7. RESPONSE_RENDER: Web rendering & template engines (CWE-79)
    "RESPONSE_RENDER": (
        "flask.render_template",
        "render_template",
        "flask.render_template_string",
        "render_template_string",
        "flask.make_response",
        "make_response",
        "Markup",
        "markupsafe.Markup",
        "mark_safe",
        "django.utils.safestring.mark_safe",
        "HttpResponse",
        "django.http.HttpResponse",
        "Response",
        "flask.Response",
        "Template",
        "jinja2.Template",
        "flash",
        "flask.flash",
    ),
    # 8. EXCEPTION_HANDLING: Sensitive traceback exposure (CWE-209)
    "EXCEPTION_HANDLING": (
        "traceback.format_exc",
        "traceback.print_exc",
        "format_error",
        "sys.exc_info",
    ),
    # 9. HARDCODED_CREDENTIALS: Static secrets & credentials (CWE-798)
    "HARDCODED_CREDENTIALS": (
        "SECRET_KEY",
        "PASSWORD",
        "API_KEY",
        "TOKEN",
        "PRIVATE_KEY",
        "JWT_SECRET",
        "SECRET",
        "jwt.encode",
        "hashlib.pbkdf2_hmac",
    ),
    # 10. ACCESS_CONTROL: Auth checks & direct object queries (CWE-287, CWE-639)
    "ACCESS_CONTROL": (
        "get_object_or_404",
        "objects.get",
        "query.get",
        "filter_by",
        "find_by_id",
        "findById",
        "authenticate",
        "login",
        "check_password",
        "verify_password",
        "has_perm",
        "is_authenticated",
        "has_permission",
        "login_required",
        "permission_required",
        "auth_required",
    ),
    # 11. WEAK_HASHING: Insecure hash algorithms (CWE-327, CWE-328)
    "WEAK_HASHING": (
        "hashlib.md5",
        "hashlib.sha1",
        "hashlib.new",
        "Crypto.Hash.MD5",
        "Crypto.Hash.SHA",
        "Cryptodome.Hash.MD5",
        "Cryptodome.Hash.SHA",
        "md5",
        "sha1",
        "sha224",
        "ripemd160",
    ),
    # 12. INSECURE_RANDOMNESS: Cryptographically weak PRNG (CWE-330)
    "INSECURE_RANDOMNESS": (
        "random.random",
        "random.choice",
        "random.randint",
        "random.randrange",
        "random.sample",
        "random.getrandbits",
        "random.uniform",
        "random.seed",
        "random.triangular",
        "random.betavariate",
        "random.expovariate",
        "random.gammavariate",
        "random.gauss",
        "random.normalvariate",
        "random.randbytes",
    ),
    # 13. XPATH_INJECTION: Unsanitized XPath queries (CWE-643)
    "XPATH_INJECTION": (
        "xpath",
        "find",
        "findall",
        "findtext",
        "iterfind",
        "getiterator",
        "etree.XPath",
        "lxml.etree.XPath",
        "eval_xpath",
        "xpath_eval",
    ),
    # 14. COOKIE_SECURITY: Insecure cookie attributes & flags (CWE-614, CWE-1004)
    "COOKIE_SECURITY": (
        "set_cookie",
        "response.set_cookie",
        "set_signed_cookie",
    ),
    # 15. LDAP_INJECTION: Unsanitized LDAP queries (CWE-90)
    "LDAP_INJECTION": (
        "ldap.search",
        "ldap.search_s",
        "ldap.search_st",
        "ldap.search_ext",
        "ldap.search_ext_s",
        "ldap.initialize",
        "ldap3.Connection.search",
        "ldap3.Server",
        "ldap3.Connection",
        "connection.search",
        "connection.search_s",
        "conn.search",
        "conn.search_s",
        "client.search",
        "c.search",
        "helpers.ldap.get_connection",
        "ldap_connection.search",
        "search_s",
        "search_st",
        "search_ext",
        "search_ext_s",
    ),
    # 16. OPEN_REDIRECT: Untrusted URL redirection (CWE-601)
    "OPEN_REDIRECT": (
        "redirect",
        "flask.redirect",
        "django.shortcuts.redirect",
        "HttpResponseRedirect",
        "HttpResponsePermanentRedirect",
    ),
    # 17. XML_EXTERNAL_ENTITY: XXE parsing vulnerabilities (CWE-611)
    "XML_EXTERNAL_ENTITY": (
        "xml.etree.ElementTree.parse",
        "xml.etree.ElementTree.fromstring",
        "xml.dom.minidom.parse",
        "xml.dom.minidom.parseString",
        "lxml.etree.parse",
        "lxml.etree.fromstring",
        "xml.sax.parse",
    ),
}

#: Heuristic suffix mapping for custom wrapper methods to sink categories.
HEURISTIC_SINK_SUFFIXES: Dict[str, Tuple[str, ...]] = {
    # 1. DESERIALIZATION: Custom object deserializers & unpackers (CWE-502)
    "DESERIALIZATION": (
        ".loads",
        ".unserialize",
        ".unpickle",
        ".decode_payload",
    ),
    # 2. DATABASE_EXECUTION: Custom query and execution wrappers (CWE-89)
    "DATABASE_EXECUTION": (
        ".execute",
        ".raw_exec",
        ".raw_query",
        ".as_sql",
    ),
    # 3. COMMAND_EXECUTION: Custom command and process execution wrappers (CWE-78)
    "COMMAND_EXECUTION": (
        ".call",
        ".run_cmd",
        ".exec_cmd",
        ".format_cmd",
        ".spawn",
    ),
    # 4. PATH_TRAVERSAL: Custom filesystem and path traversal wrappers (CWE-22)
    "PATH_TRAVERSAL": (
        ".joinpath",
        ".open_file",
        ".get_file",
    ),
}

#: Heuristic object prefix patterns for dangerous sink targets.
HEURISTIC_SINK_OBJECT_PREFIXES: Dict[str, Tuple[str, ...]] = {
    # 1. DESERIALIZATION: Known dangerous serializer/payload object prefixes (CWE-502)
    "DESERIALIZATION": (
        "self.serial.*",
        "pcrypt.*",
        "salt.payload.*",
    ),
}

#: Sink call signatures automatically synthesized from ABSTRACT_SINK_CATEGORIES
#: to maintain 100% backward compatibility across all tiers.
SINK_CALL_SIGNATURES: Tuple[str, ...] = tuple(
    sig for sigs in ABSTRACT_SINK_CATEGORIES.values() for sig in sigs
)

_DYNAMIC_DISPATCH_CALLS: Set[str] = {
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
    "__import__",
    "importlib.import_module",
    "importlib.__import__",
}

_SAFE_CALLS: Set[str] = {
    # Python builtins that do not hide a data-flow transformation
    "abs",
    "all",
    "any",
    "ascii",
    "bin",
    "bool",
    "bytearray",
    "bytes",
    "chr",
    "complex",
    "dict",
    "dir",
    "divmod",
    "enumerate",
    "float",
    "format",
    "frozenset",
    "hash",
    "hex",
    "id",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "list",
    "map",
    "max",
    "min",
    "next",
    "oct",
    "ord",
    "pow",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "slice",
    "sorted",
    "str",
    "sum",
    "tuple",
    "zip",
    # Common sanitizers / explicit guards
    "escape",
    "html.escape",
    "markupsafe.escape",
    "bleach.clean",
    "quote",
    "shlex.quote",
    "shlex.join",
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
    "secure_filename",
    "werkzeug.utils.secure_filename",
    "basename",
    "os.path.basename",
    "normpath",
    "os.path.normpath",
    "realpath",
    "os.path.realpath",
    "json.dumps",
    "json.loads",
    "sanitize",
    "validate",
    "validate_input",
    "check_input",
    "is_safe",
    "allowlist",
    "whitelist",
    "encode",
    "decode",
    "strip",
    "lstrip",
    "rstrip",
    "lower",
    "upper",
    "replace",
    "split",
    "splitlines",
    "join",
    "startswith",
    "endswith",
    "get",
    "getlist",
    "format_map",
    # Common deterministic accessors/transformers whose data-flow is known.
    "input",
    "print",
    "read",
    "readline",
    "readlines",
    "read_text",
    "read_bytes",
    "fetchone",
    "fetchall",
    "fetchmany",
    "keys",
    "values",
    "items",
    "copy",
    "getenv",
    "argv",
}

#: Prefixes that conventionally denote defensive/sanitising helpers.
_SAFE_CALL_PREFIXES: Tuple[str, ...] = (
    "safe_",
    "sanitize_",
    "sanitise_",
    "validate_",
    "clean_",
    "escape_",
    "quote_",
    "normalize_",
    "normalise_",
)

_KNOWN_MODULE_ROOTS: Set[str] = {
    "os",
    "os.path",
    "pathlib",
    "shlex",
    "html",
    "urllib",
    "json",
    "re",
    "math",
    "random",
    "datetime",
    "time",
    "sys",
    "logging",
    "collections",
    "itertools",
    "functools",
    "hashlib",
    "hmac",
    "secrets",
    "uuid",
    "base64",
    "string",
    "typing",
    "flask",
    "werkzeug",
    "django",
    "jinja2",
    "sqlite3",
    "psycopg2",
    "pymysql",
    "sqlalchemy",
    "tempfile",
    "glob",
    "fnmatch",
    "traceback",
    "warnings",
    "contextlib",
    "dataclasses",
    "enum",
    "abc",
    "io",
    "csv",
    "struct",
    "socket",
}

_MUTATING_METHODS: Set[str] = {
    "append",
    "extend",
    "insert",
    "add",
    "update",
    "setdefault",
    "pop",
    "popitem",
    "remove",
    "discard",
    "clear",
    "sort",
    "reverse",
    "__setitem__",
    "write",
    "writelines",
}


# ---------------------------------------------------------------------------
# Public data classes
# ---------------------------------------------------------------------------


@dataclass
class SliceNode:
    """A statement (or predicate) that belongs to the backward slice.

    Attributes match the schema required by the AST-slicer contract.  The
    additional ``dependency_reason`` field mirrors the explanatory field from
    the research design and is useful for prompts and reports.
    """

    id: str
    ast_node: ast.AST
    line_number: int
    code_snippet: str
    variables_defined: Set[str]
    variables_used: Set[str]
    node_type: str
    dependency_reason: str = ""

    def __post_init__(self) -> None:
        if self.variables_defined is None:
            self.variables_defined = set()
        elif not isinstance(self.variables_defined, set):
            self.variables_defined = set(self.variables_defined)
        if self.variables_used is None:
            self.variables_used = set()
        elif not isinstance(self.variables_used, set):
            self.variables_used = set(self.variables_used)

    # Design-document compatibility aliases ---------------------------------
    @property
    def line_no(self) -> int:
        """Alias for ``line_number`` used by the ``SlicedStatement`` schema."""

        return self.line_number

    @property
    def code_str(self) -> str:
        """Alias for ``code_snippet`` used by the ``SlicedStatement`` schema."""

        return self.code_snippet


@dataclass
class SinkAnchor:
    """Represents a candidate sink anchor point in the AST.

    Can represent either a primitive sink (intra-procedural) or a call-site
    invoking a wrapper function that forwards tainted parameters to a sink
    (inter-procedural call-site sink anchor).
    """

    line_number: int
    call_name: str
    target_variable: Optional[str] = None
    sink_category: Optional[str] = None
    is_interprocedural: bool = False
    wrapper_function: Optional[str] = None
    callee_name: Optional[str] = None

    def __iter__(self):
        """Allow unpacking as (line_number, target_variable) for backward compatibility."""
        return iter((self.line_number, self.target_variable))

    def __getitem__(self, index: int):
        return (self.line_number, self.target_variable)[index]


@dataclass
class SliceResult:
    """Complete result of :meth:`ASTSlicer.slice_from_sink`."""

    target_sink_line: int
    target_variable: str
    sliced_lines: List[int]
    sliced_code: str
    nodes: List[SliceNode]
    data_dependencies: Dict[int, List[int]]
    control_dependencies: Dict[int, List[int]]
    completeness_status: str
    reason: str

    # Extra metadata.  These fields have defaults so the nine documented
    # fields above remain usable positionally exactly as specified.
    sink_name: str = ""
    tracked_variables: List[str] = field(default_factory=list)
    is_truncated: bool = False
    token_budget_used: int = 0
    truncation_reason: Optional[str] = None
    source_candidates: List[str] = field(default_factory=list)
    sink_category_override: Optional[str] = None

    # Design-document compatibility aliases ---------------------------------
    @property
    def sliced_statements(self) -> List[SliceNode]:
        """Alias for ``nodes`` used by the ``CodeSlice`` schema."""

        return list(self.nodes)

    @property
    def sink_line(self) -> int:
        """Alias for ``target_sink_line`` used by reporting code."""

        return self.target_sink_line

    @property
    def sink_category(self) -> Optional[str]:
        """Return the abstract sink category for this slice's sink call."""
        if self.sink_category_override:
            return self.sink_category_override
        cat = get_sink_category(self.sink_name) if self.sink_name else None
        if cat is None and self.target_variable:
            cat = get_sink_category(self.target_variable)
        return cat

    @property
    def is_complete(self) -> bool:
        return self.completeness_status == COMPLETENESS_COMPLETE

    def to_facts_prompt(self) -> str:
        """Render the AST-verified facts for the Tier-2 detector prompt."""

        lines: List[str] = []
        for node in sorted(self.nodes, key=lambda item: (item.line_number, item.node_type)):
            reason = f" ({node.dependency_reason})" if node.dependency_reason else ""
            lines.append(
                f"  Line {node.line_number:3d} "
                f"[{node.node_type:10s}]{reason}: {node.code_snippet}"
            )
        return "\n".join(lines)

    def get_verified_facts_str(self) -> str:
        """Backward-compatible alias for :meth:`to_facts_prompt`."""

        return self.to_facts_prompt()


# ---------------------------------------------------------------------------
# Small AST helpers
# ---------------------------------------------------------------------------


def _safe_lineno(node: Optional[ast.AST], default: int = 0) -> int:
    if node is None:
        return default
    try:
        return int(getattr(node, "lineno", default) or default)
    except (TypeError, ValueError):
        return default


def _safe_end_lineno(node: Optional[ast.AST], default: Optional[int] = None) -> int:
    if node is None:
        return int(default or 0)
    end = getattr(node, "end_lineno", None)
    if end is None:
        end = getattr(node, "lineno", default)
    try:
        return int(end or default or 0)
    except (TypeError, ValueError):
        return int(default or 0)


def _dotted_name(node: Optional[ast.AST]) -> str:
    """Return a dotted name for ``Name``/``Attribute``/``Call`` chains."""

    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted_name(node.value)
    if isinstance(node, ast.Starred):
        return _dotted_name(node.value)
    if isinstance(node, ast.Await):
        return _dotted_name(node.value)
    return ""


def _last_component(name: str) -> str:
    return name.rsplit(".", 1)[-1] if name else ""


def _dedupe(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _collect_load_names(node: Optional[ast.AST]) -> List[str]:
    """Collect ``ast.Name`` loads in source order.

    Lambda bodies are not descended into because they are not evaluated where
    the lambda expression itself appears.
    """

    if node is None:
        return []

    names: List[Tuple[int, int, str]] = []
    stack: List[ast.AST] = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.Name):
            if isinstance(current.ctx, ast.Load):
                names.append(
                    (
                        _safe_lineno(current),
                        int(getattr(current, "col_offset", 0) or 0),
                        current.id,
                    )
                )
            continue
        if isinstance(current, ast.Lambda):
            # Defaults are evaluated at lambda creation time; the body is not.
            for default in list(getattr(current.args, "defaults", []) or []):
                stack.append(default)
            for default in list(getattr(current.args, "kw_defaults", []) or []):
                if default is not None:
                    stack.append(default)
            continue
        stack.extend(ast.iter_child_nodes(current))

    names.sort(key=lambda item: (item[0], item[1], item[2]))
    return _dedupe(name for _, _, name in names)


def _target_names(target: Optional[ast.AST]) -> Set[str]:
    """Names bound by an assignment target."""

    if target is None:
        return set()
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        result: Set[str] = set()
        for element in target.elts:
            result |= _target_names(element)
        return result
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    if isinstance(target, ast.Attribute):
        dotted = _dotted_name(target)
        root = _dotted_name(target.value)
        return {name for name in (dotted, root) if name}
    if isinstance(target, ast.Subscript):
        root = _dotted_name(target.value)
        return {root} if root else set()
    if isinstance(target, ast.NamedExpr):
        return _target_names(target.target)
    return set()


def _target_read_names(target: Optional[ast.AST]) -> Set[str]:
    """Names read while evaluating an augmented-assignment target."""

    if target is None:
        return set()
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        result: Set[str] = set()
        for element in target.elts:
            result |= _target_read_names(element)
        return result
    if isinstance(target, ast.Starred):
        return _target_read_names(target.value)
    if isinstance(target, (ast.Attribute, ast.Subscript)):
        root = _dotted_name(target.value)
        return {root} if root else set()
    return set(_collect_load_names(target))


def _named_expr_names(node: Optional[ast.AST]) -> Set[str]:
    if node is None:
        return set()
    result: Set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.NamedExpr):
            result |= _target_names(child.target)
    return result


def _pattern_names(pattern: Optional[ast.AST]) -> Set[str]:
    if pattern is None:
        return set()
    result: Set[str] = set()
    for child in ast.walk(pattern):
        if isinstance(child, ast.MatchAs) and getattr(child, "name", None):
            result.add(child.name)
        elif isinstance(child, ast.MatchStar) and getattr(child, "name", None):
            result.add(child.name)
        elif isinstance(child, ast.MatchMapping) and getattr(child, "rest", None):
            result.add(child.rest)
    return result


def _defined_names(stmt: Optional[ast.AST]) -> Set[str]:
    """Return the names bound by a statement (its GEN set)."""

    if stmt is None:
        return set()

    names: Set[str] = set()

    if isinstance(stmt, ast.Assign):
        for target in stmt.targets:
            names |= _target_names(target)
    elif isinstance(stmt, ast.AnnAssign):
        if getattr(stmt, "value", None) is not None:
            names |= _target_names(stmt.target)
    elif isinstance(stmt, ast.AugAssign):
        names |= _target_names(stmt.target)
    elif isinstance(stmt, (ast.For, ast.AsyncFor)):
        names |= _target_names(stmt.target)
        names |= _named_expr_names(stmt.iter)
    elif isinstance(stmt, ast.While):
        names |= _named_expr_names(stmt.test)
    elif isinstance(stmt, ast.If):
        names |= _named_expr_names(stmt.test)
    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        for item in stmt.items:
            if item.optional_vars is not None:
                names |= _target_names(item.optional_vars)
            names |= _named_expr_names(item.context_expr)
    elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        names.add(stmt.name)
    elif isinstance(stmt, ast.Import):
        for alias in stmt.names:
            names.add(alias.asname or alias.name.split(".", 1)[0])
    elif isinstance(stmt, ast.ImportFrom):
        for alias in stmt.names:
            if alias.name != "*":
                names.add(alias.asname or alias.name)
    elif isinstance(stmt, ast.Match):
        names |= _named_expr_names(stmt.subject)
        for case in stmt.cases:
            names |= _pattern_names(case.pattern)
            if case.guard is not None:
                names |= _named_expr_names(case.guard)
    else:
        names |= _named_expr_names(stmt)

    # Walrus expressions in simple statements can bind names as a side effect.
    if not isinstance(
        stmt,
        (
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.ClassDef,
            ast.Import,
            ast.ImportFrom,
        ),
    ):
        names |= _named_expr_names(stmt)

    return {name for name in names if name}


def _used_names(stmt: Optional[ast.AST]) -> Set[str]:
    """Return the names read by a statement (its USE set)."""

    if stmt is None:
        return set()

    if isinstance(stmt, ast.Assign):
        return set(_collect_load_names(stmt.value))
    if isinstance(stmt, ast.AnnAssign):
        return set(_collect_load_names(stmt.value))
    if isinstance(stmt, ast.AugAssign):
        names = set(_collect_load_names(stmt.value))
        names |= _target_read_names(stmt.target)
        return names
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        return set(_collect_load_names(stmt.iter))
    if isinstance(stmt, ast.While):
        return set(_collect_load_names(stmt.test))
    if isinstance(stmt, ast.If):
        return set(_collect_load_names(stmt.test))
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        names: Set[str] = set()
        for item in stmt.items:
            names |= set(_collect_load_names(item.context_expr))
        return names
    if isinstance(stmt, (ast.Return, ast.Expr)):
        return set(_collect_load_names(stmt.value))
    if isinstance(stmt, ast.Raise):
        names = set(_collect_load_names(stmt.exc))
        names |= set(_collect_load_names(stmt.cause))
        return names
    if isinstance(stmt, ast.Assert):
        names = set(_collect_load_names(stmt.test))
        names |= set(_collect_load_names(stmt.msg))
        return names
    if isinstance(stmt, ast.Delete):
        names: Set[str] = set()
        for target in stmt.targets:
            names |= _target_read_names(target)
        return names
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        names: Set[str] = set()
        for decorator in stmt.decorator_list:
            names |= set(_collect_load_names(decorator))
        args = stmt.args
        for default in list(getattr(args, "defaults", []) or []):
            names |= set(_collect_load_names(default))
        for default in list(getattr(args, "kw_defaults", []) or []):
            if default is not None:
                names |= set(_collect_load_names(default))
        return names
    if isinstance(stmt, ast.ClassDef):
        names: Set[str] = set()
        for decorator in stmt.decorator_list:
            names |= set(_collect_load_names(decorator))
        for base in stmt.bases:
            names |= set(_collect_load_names(base))
        for keyword in stmt.keywords:
            names |= set(_collect_load_names(keyword.value))
        return names
    if isinstance(stmt, (ast.Import, ast.ImportFrom, ast.Pass, ast.Break, ast.Continue)):
        return set()
    if isinstance(stmt, ast.ExceptHandler):
        return set(_collect_load_names(stmt.type))
    if isinstance(stmt, ast.Match):
        return set(_collect_load_names(stmt.subject))
    if isinstance(stmt, (ast.Global, ast.Nonlocal)):
        return set()
    return set(_collect_load_names(stmt))


def _mapped_rhs_names(
    target: Optional[ast.AST],
    value: Optional[ast.AST],
    variable: str,
) -> Optional[Set[str]]:
    """Return the RHS names that contribute to ``variable`` for one target.

    ``None`` means the target does not bind ``variable`` and the caller should
    not use the mapping.  Tuple/list unpacking is mapped by index so
    ``a, b = (payload, "safe")`` only follows ``payload`` for ``a``.
    """

    if target is None:
        return None

    if isinstance(target, ast.Name):
        if target.id != variable:
            return None
        return set(_collect_load_names(value))

    if isinstance(target, ast.Starred):
        return _mapped_rhs_names(target.value, value, variable)

    if isinstance(target, (ast.Tuple, ast.List)):
        if variable not in _target_names(target):
            return None
        if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts):
            for target_element, value_element in zip(target.elts, value.elts):
                mapped = _mapped_rhs_names(target_element, value_element, variable)
                if mapped is not None:
                    return mapped
            return None
        # Composite RHS (a, b = raw_payload) taints the whole source.
        return set(_collect_load_names(value))

    if isinstance(target, (ast.Attribute, ast.Subscript)):
        if variable not in _target_names(target):
            return None
        return set(_collect_load_names(value))

    if isinstance(target, ast.NamedExpr):
        return _mapped_rhs_names(target.target, value, variable)

    return None


def _used_names_for_variable(stmt: Optional[ast.AST], variable: str) -> Set[str]:
    """Precise USE set for the definition of ``variable`` by ``stmt``."""

    if stmt is None:
        return set()
    if isinstance(stmt, ast.Assign):
        if len(stmt.targets) == 1:
            mapped = _mapped_rhs_names(stmt.targets[0], stmt.value, variable)
            if mapped is not None:
                return mapped
        return _used_names(stmt)
    if isinstance(stmt, ast.AnnAssign):
        if stmt.value is not None:
            mapped = _mapped_rhs_names(stmt.target, stmt.value, variable)
            if mapped is not None:
                return mapped
        return _used_names(stmt)
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        names: Set[str] = set()
        for item in stmt.items:
            if item.optional_vars is not None and variable in _target_names(item.optional_vars):
                names |= set(_collect_load_names(item.context_expr))
        return names if names else _used_names(stmt)
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        return _used_names(stmt)
    return _used_names(stmt)


def _function_parameters(node: ast.AST) -> Set[str]:
    args = getattr(node, "args", None)
    if args is None:
        return set()

    names: Set[str] = set()
    for attribute in ("posonlyargs", "args", "kwonlyargs"):
        for arg in list(getattr(args, attribute, []) or []):
            arg_name = getattr(arg, "arg", None)
            if arg_name:
                names.add(arg_name)
    for attribute in ("vararg", "kwarg"):
        arg = getattr(args, attribute, None)
        if arg is not None and getattr(arg, "arg", None):
            names.add(arg.arg)
    return names


def _iter_scope_nodes(scope: Optional[ast.AST]) -> Iterable[ast.AST]:
    """Yield nodes belonging to ``scope``, skipping nested function/class bodies."""

    if scope is None:
        return
    stack: List[ast.AST] = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _iter_calls(node: Optional[ast.AST]) -> Iterable[ast.Call]:
    """Yield calls in an expression, skipping nested function/lambda bodies."""

    if node is None:
        return
    stack: List[ast.AST] = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.Call):
            yield current
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(ast.iter_child_nodes(current))


def _ast_contains(parent: Optional[ast.AST], child: Optional[ast.AST]) -> bool:
    if parent is None or child is None:
        return False
    if parent is child:
        return True
    return any(node is child for node in ast.walk(parent))


def _call_name_matches(call_name: str, signature: str) -> bool:
    call_name = (call_name or "").strip()
    signature = (signature or "").strip()
    if not call_name or not signature:
        return False
    if signature.endswith(".*"):
        prefix = signature[:-2]
        return (
            call_name == prefix
            or call_name.startswith(prefix + ".")
            or (("." + prefix + ".") in call_name)
        )
    return (
        call_name == signature
        or call_name.endswith("." + signature)
        or signature.endswith("." + call_name)
    )


def _match_heuristic_sink_category(call_name: str) -> Optional[str]:
    """Match dangerous method suffixes or object patterns for custom wrappers."""
    call_name = (call_name or "").strip()
    if not call_name:
        return None

    # Exclude explicitly safe calls and json parsing
    if (
        call_name in _SAFE_CALLS
        or call_name == "json.loads"
        or call_name.endswith(".json.loads")
        or call_name.endswith("ujson.loads")
        or call_name.endswith("orjson.loads")
        or call_name.endswith("simplejson.loads")
    ):
        return None

    # Check object prefixes first (e.g. self.serial.*, pcrypt.*, salt.payload.*)
    for category, prefixes in HEURISTIC_SINK_OBJECT_PREFIXES.items():
        for prefix_pat in prefixes:
            if _call_name_matches(call_name, prefix_pat):
                return category

    # Check method suffixes (e.g. .loads, .unserialize, .run_cmd, .raw_query, etc.)
    last_comp = _last_component(call_name)
    has_dot = "." in call_name

    for category, suffixes in HEURISTIC_SINK_SUFFIXES.items():
        for suffix in suffixes:
            method = suffix.lstrip(".")
            # Match dotted suffix: e.g. obj.loads, self.serial.loads
            if has_dot and (call_name.endswith(suffix) or last_comp == method):
                return category
            # Match bare call only for specific unambiguous method names
            # (e.g. raw_exec, raw_query, decode_payload, run_cmd, open_file)
            # but NOT generic words like 'call', 'execute', 'spawn', 'loads'
            if not has_dot and call_name == method and method not in ("call", "loads", "spawn"):
                return category

    return None


def get_sink_category(call_name: str) -> Optional[str]:
    """Return the abstract sink category for a given call name, if recognized.

    Returns one of the canonical categories in :data:`ABSTRACT_SINK_CATEGORIES`,
    or a heuristic sink category for custom wrappers,
    or ``None`` if the call name is not recognized as a dangerous sink.
    """
    call_name = (call_name or "").strip()
    if not call_name:
        return None

    # Priority 1: Exact signature match in canonical categories
    for category, signatures in ABSTRACT_SINK_CATEGORIES.items():
        if call_name in signatures:
            return category

    # Priority 2: Exclude explicitly safe builtin functions/methods
    if call_name in _SAFE_CALLS:
        return None

    # Priority 3: Match via dotted prefix or suffix in canonical categories
    for category, signatures in ABSTRACT_SINK_CATEGORIES.items():
        if any(_call_name_matches(call_name, signature) for signature in signatures):
            return category

    # Priority 4: Heuristic suffix & object matching for custom wrappers
    return _match_heuristic_sink_category(call_name)


def _is_sink_call_name(call_name: str) -> bool:
    return get_sink_category(call_name) is not None


def _is_safe_call_name(call_name: str) -> bool:
    if not call_name:
        return True
    last = _last_component(call_name)
    root = call_name.split(".", 1)[0]
    if call_name in _SAFE_CALLS or last in _SAFE_CALLS:
        return True
    if any(last.startswith(prefix) for prefix in _SAFE_CALL_PREFIXES):
        return True
    if any(call_name.startswith(prefix) for prefix in _SAFE_CALL_PREFIXES):
        return True
    if root in _KNOWN_MODULE_ROOTS:
        return True
    return False


# ---------------------------------------------------------------------------
# Inter-procedural Call-Site Sink Anchoring
# ---------------------------------------------------------------------------


@dataclass
class _WrapperInfo:
    name: str
    category: str
    sink_call_name: str
    sink_param_indices: Set[int] = field(default_factory=set)
    sink_param_names: Set[str] = field(default_factory=set)
    is_method: bool = False


def _collect_all_statements(body: Sequence[ast.stmt]) -> List[ast.stmt]:
    stmts: List[ast.stmt] = []
    for s in body:
        stmts.append(s)
        if isinstance(s, (ast.If, ast.While, ast.For, ast.AsyncFor)):
            stmts.extend(_collect_all_statements(s.body))
            stmts.extend(_collect_all_statements(s.orelse))
        elif isinstance(s, (ast.Try, getattr(ast, "TryStar", type(None)))):
            stmts.extend(_collect_all_statements(s.body))
            stmts.extend(_collect_all_statements(s.orelse))
            stmts.extend(_collect_all_statements(s.finalbody))
            for handler in getattr(s, "handlers", []):
                stmts.extend(_collect_all_statements(handler.body))
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            stmts.extend(_collect_all_statements(s.body))
        elif isinstance(s, getattr(ast, "Match", type(None))):
            for case in getattr(s, "cases", []):
                stmts.extend(_collect_all_statements(case.body))
    return stmts


def _extract_func_params(func: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> Tuple[List[str], bool]:
    params: List[str] = [a.arg for a in getattr(func.args, "posonlyargs", [])]
    for a in func.args.args:
        if a.arg not in params:
            params.append(a.arg)
    for a in getattr(func.args, "kwonlyargs", []):
        if a.arg not in params:
            params.append(a.arg)
    if func.args.vararg and func.args.vararg.arg and func.args.vararg.arg not in params:
        params.append(func.args.vararg.arg)
    if func.args.kwarg and func.args.kwarg.arg and func.args.kwarg.arg not in params:
        params.append(func.args.kwarg.arg)
    is_method = bool(params and params[0] in ("self", "cls"))
    return params, is_method


def _compute_param_flow(params: Sequence[str], stmts: Sequence[ast.stmt]) -> Dict[str, Set[str]]:
    flow: Dict[str, Set[str]] = {p: {p} for p in params}
    for _ in range(3):
        for stmt in stmts:
            if isinstance(stmt, ast.Assign):
                rhs_loads = _collect_load_names(stmt.value)
                origins: Set[str] = set()
                for r in rhs_loads:
                    origins.update(flow.get(r, {r} if r in params else set()))
                for target in stmt.targets:
                    for t in _target_names(target):
                        flow[t] = set(origins)
            elif isinstance(stmt, ast.AugAssign):
                rhs_loads = _collect_load_names(stmt.value)
                origins = set()
                for r in rhs_loads:
                    origins.update(flow.get(r, {r} if r in params else set()))
                for t in _target_names(stmt.target):
                    flow[t] = flow.get(t, set()) | origins
            elif isinstance(stmt, ast.AnnAssign) and stmt.value:
                rhs_loads = _collect_load_names(stmt.value)
                origins = set()
                for r in rhs_loads:
                    origins.update(flow.get(r, {r} if r in params else set()))
                for t in _target_names(stmt.target):
                    flow[t] = set(origins)
    return flow


def _extract_calls_in_func(stmts: Sequence[ast.stmt]) -> List[ast.Call]:
    calls: List[ast.Call] = []
    for stmt in stmts:
        for node in ast.walk(stmt):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(node, ast.Call):
                calls.append(node)
    return calls


def _discover_wrappers(tree: ast.AST) -> Dict[str, _WrapperInfo]:
    """Discover wrapper functions that invoke primitive sinks or forward parameters to sinks."""
    known_wrappers: Dict[str, _WrapperInfo] = {}

    all_funcs: List[Tuple[Union[ast.FunctionDef, ast.AsyncFunctionDef], bool]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    all_funcs.append((item, True))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not any(f is node for f, _ in all_funcs):
                all_funcs.append((node, False))

    # Pass 1: Identify functions directly calling primitive sinks
    for func, is_in_class in all_funcs:
        params, is_method_param = _extract_func_params(func)
        is_method = is_in_class or is_method_param
        stmts = _collect_all_statements(func.body)
        flow = _compute_param_flow(params, stmts)
        calls = _extract_calls_in_func(stmts)

        for call in calls:
            c_name = _dotted_name(call.func)
            cat = get_sink_category(c_name)
            if cat is None and isinstance(call.func, ast.Attribute):
                attr_name = call.func.attr
                cat = _match_heuristic_sink_category("." + attr_name) or _match_heuristic_sink_category(attr_name)
            if cat is not None:
                arg_names = ASTSlicer._call_argument_names(call)
                feeding: Set[str] = set()
                for a in arg_names:
                    feeding.update(flow.get(a, {a} if a in params else set()) & set(params))
                if not feeding and params:
                    for a_expr in list(call.args) + [kw.value for kw in call.keywords]:
                        for l in _collect_load_names(a_expr):
                            feeding.update(flow.get(l, {l} if l in params else set()) & set(params))
                indices = {i for i, p in enumerate(params) if p in feeding}
                if not feeding and params:
                    non_self = [p for p in params if p not in ("self", "cls")]
                    if len(non_self) == 1:
                        feeding = {non_self[0]}
                        indices = {params.index(non_self[0])}

                known_wrappers[func.name] = _WrapperInfo(
                    name=func.name,
                    category=cat,
                    sink_call_name=c_name,
                    sink_param_indices=indices,
                    sink_param_names=feeding,
                    is_method=is_method,
                )
                break

    # Pass 2+: Propagate multi-step wrappers forwarding parameters to call-sites of known wrappers
    for _ in range(5):
        new_found = False
        for func, is_in_class in all_funcs:
            if func.name in known_wrappers:
                continue
            params, is_method_param = _extract_func_params(func)
            is_method = is_in_class or is_method_param
            stmts = _collect_all_statements(func.body)
            flow = _compute_param_flow(params, stmts)
            calls = _extract_calls_in_func(stmts)

            for call in calls:
                c_name = _dotted_name(call.func)
                last_name = _last_component(c_name)
                target_wrapper = known_wrappers.get(c_name) or known_wrappers.get(last_name)
                if target_wrapper is not None:
                    feeding = set()
                    for arg_idx, arg_expr in enumerate(call.args):
                        mapped_idx = arg_idx + (1 if target_wrapper.is_method and isinstance(call.func, ast.Attribute) else 0)
                        if not target_wrapper.sink_param_indices or mapped_idx in target_wrapper.sink_param_indices:
                            for l in _collect_load_names(arg_expr):
                                feeding.update(flow.get(l, {l} if l in params else set()) & set(params))
                    for kw in call.keywords:
                        if not target_wrapper.sink_param_names or kw.arg in target_wrapper.sink_param_names:
                            for l in _collect_load_names(kw.value):
                                feeding.update(flow.get(l, {l} if l in params else set()) & set(params))
                    indices = {i for i, p in enumerate(params) if p in feeding}
                    if not feeding and params:
                        non_self = [p for p in params if p not in ("self", "cls")]
                        if len(non_self) == 1:
                            feeding = {non_self[0]}
                            indices = {params.index(non_self[0])}

                    known_wrappers[func.name] = _WrapperInfo(
                        name=func.name,
                        category=target_wrapper.category,
                        sink_call_name=c_name,
                        sink_param_indices=indices,
                        sink_param_names=feeding,
                        is_method=is_method,
                    )
                    new_found = True
                    break
        if not new_found:
            break

    return known_wrappers


def find_call_site_sink_anchors(tree_or_code: Union[str, ast.AST]) -> List[SinkAnchor]:
    """Identify call-sites that invoke wrapper functions forwarding to dangerous sinks."""
    if isinstance(tree_or_code, str):
        try:
            tree = ast.parse(tree_or_code)
        except Exception:
            return []
    else:
        tree = tree_or_code

    wrappers = _discover_wrappers(tree)
    if not wrappers:
        return []

    call_site_anchors: List[SinkAnchor] = []
    seen: Set[Tuple[int, Optional[str]]] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        c_name = _dotted_name(node.func)
        last_name = _last_component(c_name)
        wrapper = wrappers.get(c_name) or wrappers.get(last_name)
        if wrapper is None:
            continue

        lineno = getattr(node, "lineno", None)
        if lineno is None:
            continue

        target_var: Optional[str] = None
        if wrapper.sink_param_indices:
            for idx in sorted(wrapper.sink_param_indices):
                call_arg_idx = idx - (1 if wrapper.is_method and isinstance(node.func, ast.Attribute) else 0)
                if 0 <= call_arg_idx < len(node.args):
                    loads = _collect_load_names(node.args[call_arg_idx])
                    if loads:
                        target_var = loads[0]
                        break
                    else:
                        d_name = _dotted_name(node.args[call_arg_idx])
                        if d_name:
                            target_var = d_name
                            break

        if not target_var and wrapper.sink_param_names:
            for kw in node.keywords:
                if kw.arg in wrapper.sink_param_names:
                    loads = _collect_load_names(kw.value)
                    if loads:
                        target_var = loads[0]
                        break
                    else:
                        d_name = _dotted_name(kw.value)
                        if d_name:
                            target_var = d_name
                            break

        if not target_var:
            arg_names = ASTSlicer._call_argument_names(node)
            target_var = arg_names[0] if arg_names else None

        key = (lineno, target_var)
        if key not in seen:
            seen.add(key)
            call_site_anchors.append(
                SinkAnchor(
                    line_number=lineno,
                    call_name=c_name,
                    target_variable=target_var,
                    sink_category=wrapper.category,
                    is_interprocedural=True,
                    wrapper_function=wrapper.name,
                    callee_name=c_name,
                )
            )

    call_site_anchors.sort(key=lambda a: (a.line_number, a.target_variable or ""))
    return call_site_anchors


def find_sink_anchors(tree_or_code: Union[str, ast.AST]) -> List[SinkAnchor]:
    """Find all candidate sink anchors (primitive sinks and inter-procedural call-sites)."""
    if isinstance(tree_or_code, str):
        try:
            tree = ast.parse(tree_or_code)
        except Exception:
            return []
    else:
        tree = tree_or_code

    anchors: List[SinkAnchor] = []
    seen: Set[Tuple[int, Optional[str]]] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted_name(node.func)
            cat = get_sink_category(name)
            if cat is None and isinstance(node.func, ast.Attribute):
                attr_name = node.func.attr
                cat = _match_heuristic_sink_category("." + attr_name) or _match_heuristic_sink_category(attr_name)
                if not name:
                    name = attr_name
            if cat is not None:
                lineno = getattr(node, "lineno", None)
                if lineno is not None:
                    arg_names = ASTSlicer._call_argument_names(node)
                    target_vars = arg_names if arg_names else [None]
                    for target_var in target_vars:
                        key = (lineno, target_var)
                        if key not in seen:
                            seen.add(key)
                            anchors.append(
                                SinkAnchor(
                                    line_number=lineno,
                                    call_name=name,
                                    target_variable=target_var,
                                    sink_category=cat,
                                    is_interprocedural=False,
                                    callee_name=name,
                                )
                            )
        elif isinstance(node, ast.Assign):
            is_static_str = (
                isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
            ) or isinstance(node.value, getattr(ast, "Str", type(None)))
            if is_static_str:
                for target in node.targets:
                    t_name = _dotted_name(target)
                    if t_name:
                        upper = t_name.upper()
                        if any(k in upper for k in ("SECRET_KEY", "PASSWORD", "API_KEY", "PRIVATE_KEY")) or upper in ("TOKEN", "JWT_SECRET", "SECRET"):
                            lineno = getattr(node, "lineno", None)
                            if lineno is not None:
                                key = (lineno, t_name)
                                if key not in seen:
                                    seen.add(key)
                                    anchors.append(
                                        SinkAnchor(
                                            line_number=lineno,
                                            call_name=t_name,
                                            target_variable=t_name,
                                            sink_category="HARDCODED_CREDENTIALS",
                                            is_interprocedural=False,
                                        )
                                    )
        elif isinstance(node, ast.AnnAssign):
            is_static_str = (
                isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
            ) or isinstance(node.value, getattr(ast, "Str", type(None)))
            if is_static_str:
                t_name = _dotted_name(node.target)
                if t_name:
                    upper = t_name.upper()
                    if any(k in upper for k in ("SECRET_KEY", "PASSWORD", "API_KEY", "PRIVATE_KEY")) or upper in ("TOKEN", "JWT_SECRET", "SECRET"):
                        lineno = getattr(node, "lineno", None)
                        if lineno is not None:
                            key = (lineno, t_name)
                            if key not in seen:
                                seen.add(key)
                                anchors.append(
                                    SinkAnchor(
                                        line_number=lineno,
                                        call_name=t_name,
                                        target_variable=t_name,
                                        sink_category="HARDCODED_CREDENTIALS",
                                        is_interprocedural=False,
                                    )
                                )
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in getattr(node, "decorator_list", []):
                dec_name = _dotted_name(dec.func if isinstance(dec, ast.Call) else dec)
                if dec_name and _is_sink_call_name(dec_name):
                    dec_lineno = getattr(dec, "lineno", node.lineno)
                    key = (dec_lineno, None)
                    if key not in seen:
                        seen.add(key)
                        anchors.append(
                            SinkAnchor(
                                line_number=dec_lineno,
                                call_name=dec_name,
                                target_variable=None,
                                sink_category=get_sink_category(dec_name),
                                is_interprocedural=False,
                            )
                        )

    # 2. Inter-procedural call-site sink anchors
    call_sites = find_call_site_sink_anchors(tree)
    for cs in call_sites:
        key = (cs.line_number, cs.target_variable)
        if key not in seen:
            seen.add(key)
            anchors.append(cs)

    anchors.sort(key=lambda a: (a.line_number, a.target_variable or ""))
    return anchors


# ---------------------------------------------------------------------------
# Lightweight control-flow graph used for reaching definitions
# ---------------------------------------------------------------------------


class _CFGNode:
    """A statement or predicate in the intra-procedural CFG."""

    __slots__ = (
        "id",
        "ast_node",
        "node_type",
        "line",
        "end_line",
        "defined",
        "used",
        "controls",
        "kind",
        "successors",
        "predecessors",
        "gen",
        "kill",
    )

    def __init__(
        self,
        node_id: int,
        ast_node: ast.AST,
        node_type: str,
        defined: Set[str],
        used: Set[str],
        controls: Tuple[int, ...],
        kind: str,
    ) -> None:
        self.id = node_id
        self.ast_node = ast_node
        self.node_type = node_type
        self.line = _safe_lineno(ast_node, 1)
        self.end_line = _safe_end_lineno(ast_node, self.line)
        self.defined = set(defined)
        self.used = set(used)
        self.controls = tuple(controls)
        self.kind = kind
        self.successors: List[int] = []
        self.predecessors: List[int] = []
        self.gen: Set[Tuple[str, int]] = set()
        self.kill: Set[str] = set()


class _ControlFlowGraph:
    """Build a structured CFG and solve a classic reaching-definitions dataflow.

    The analysis follows the equations from Section 3.1.3::

        OUT(s) = GEN(s) U (IN(s) - KILL(s))
        IN(s)  = U_{p in Pred(s)} OUT(p)

    A wave-based worklist is used for fixpoint iteration.  Every wave counts
    against ``max_loop_iterations`` so pathological cyclic structures terminate
    safely.
    """

    def __init__(self, scope: ast.AST) -> None:
        self.scope = scope
        self.nodes: Dict[int, _CFGNode] = {}
        self._next_id = 0
        self.entry_id: Optional[int] = None
        self.scope_params: Set[str] = set()
        self._build()

    # -- construction -------------------------------------------------------
    def _new_node(
        self,
        ast_node: ast.AST,
        node_type: str,
        defined: Optional[Set[str]] = None,
        used: Optional[Set[str]] = None,
        controls: Tuple[int, ...] = (),
        kind: str = "simple",
    ) -> int:
        node_id = self._next_id
        self._next_id += 1
        self.nodes[node_id] = _CFGNode(
            node_id=node_id,
            ast_node=ast_node,
            node_type=node_type,
            defined=set(defined or ()),
            used=set(used or ()),
            controls=controls,
            kind=kind,
        )
        return node_id

    def _connect(self, source: Optional[int], target: Optional[int]) -> None:
        if source is None or target is None or source == target:
            return
        if source not in self.nodes or target not in self.nodes:
            return
        if target not in self.nodes[source].successors:
            self.nodes[source].successors.append(target)
        if source not in self.nodes[target].predecessors:
            self.nodes[target].predecessors.append(source)

    def _build(self) -> None:
        scope = self.scope
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.scope_params = _function_parameters(scope)
            entry = self._new_node(
                scope,
                "FunctionDef",
                defined=self.scope_params,
                used=set(),
                controls=(),
                kind="entry",
            )
            self.entry_id = entry
            self._build_sequence(scope.body, [entry], ())
        else:
            self._build_sequence(getattr(scope, "body", []) or [], [], ())

    def _build_sequence(
        self,
        statements: Sequence[ast.stmt],
        incoming: Sequence[int],
        controls: Tuple[int, ...],
    ) -> List[int]:
        current: List[int] = list(incoming)
        for statement in statements:
            current = self._build_statement(statement, current, controls)
        return current

    def _build_statement(
        self,
        statement: ast.stmt,
        incoming: Sequence[int],
        controls: Tuple[int, ...],
    ) -> List[int]:
        if isinstance(statement, ast.If):
            return self._build_if(statement, incoming, controls)
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            return self._build_for(statement, incoming, controls)
        if isinstance(statement, ast.While):
            return self._build_while(statement, incoming, controls)
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            return self._build_with(statement, incoming, controls)
        if isinstance(statement, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            return self._build_try(statement, incoming, controls)
        if isinstance(statement, ast.Match):
            return self._build_match(statement, incoming, controls)

        node_type = _statement_node_type(statement)
        node_id = self._new_node(
            statement,
            node_type,
            defined=_defined_names(statement),
            used=_used_names(statement),
            controls=controls,
            kind="simple",
        )
        for predecessor in incoming:
            self._connect(predecessor, node_id)
        return [node_id]

    def _build_if(
        self,
        statement: ast.If,
        incoming: Sequence[int],
        controls: Tuple[int, ...],
    ) -> List[int]:
        guard = self._new_node(
            statement,
            "IfGuard",
            defined=_named_expr_names(statement.test),
            used=set(_collect_load_names(statement.test)),
            controls=controls,
            kind="if",
        )
        for predecessor in incoming:
            self._connect(predecessor, guard)

        branch_controls = controls + (guard,)
        body_exits = self._build_sequence(statement.body, [guard], branch_controls)
        if statement.orelse:
            else_exits = self._build_sequence(statement.orelse, [guard], branch_controls)
        else:
            else_exits = [guard]
        return list(body_exits) + list(else_exits)

    def _build_for(
        self,
        statement: ast.AST,
        incoming: Sequence[int],
        controls: Tuple[int, ...],
    ) -> List[int]:
        header = self._new_node(
            statement,
            "For",
            defined=_target_names(getattr(statement, "target", None))
            | _named_expr_names(getattr(statement, "iter", None)),
            used=set(_collect_load_names(getattr(statement, "iter", None))),
            controls=controls,
            kind="for",
        )
        for predecessor in incoming:
            self._connect(predecessor, header)

        body_controls = controls + (header,)
        body_exits = self._build_sequence(
            getattr(statement, "body", []) or [], [header], body_controls
        )
        if not body_exits:
            body_exits = [header]

        # Back edge: loop body may execute again.
        for exit_id in body_exits:
            self._connect(exit_id, header)

        orelse = getattr(statement, "orelse", []) or []
        if orelse:
            else_incoming = [header] + list(body_exits)
            return self._build_sequence(orelse, else_incoming, controls)

        # Both the "iteration happened" and "zero iterations" paths continue
        # after the loop.  The header's OUT set already accumulates body
        # definitions through the back edge; body exits are included too for
        # robustness against break/continue constructs.
        return [header] + list(body_exits)

    def _build_while(
        self,
        statement: ast.While,
        incoming: Sequence[int],
        controls: Tuple[int, ...],
    ) -> List[int]:
        header = self._new_node(
            statement,
            "While",
            defined=_named_expr_names(statement.test),
            used=set(_collect_load_names(statement.test)),
            controls=controls,
            kind="while",
        )
        for predecessor in incoming:
            self._connect(predecessor, header)

        body_controls = controls + (header,)
        body_exits = self._build_sequence(statement.body, [header], body_controls)
        if not body_exits:
            body_exits = [header]
        for exit_id in body_exits:
            self._connect(exit_id, header)

        if statement.orelse:
            else_incoming = [header] + list(body_exits)
            return self._build_sequence(statement.orelse, else_incoming, controls)

        return [header] + list(body_exits)

    def _build_with(
        self,
        statement: ast.AST,
        incoming: Sequence[int],
        controls: Tuple[int, ...],
    ) -> List[int]:
        defined: Set[str] = set()
        used: Set[str] = set()
        for item in getattr(statement, "items", []) or []:
            context_expr = getattr(item, "context_expr", None)
            optional_vars = getattr(item, "optional_vars", None)
            used |= set(_collect_load_names(context_expr))
            used |= _named_expr_names(context_expr)
            if optional_vars is not None:
                defined |= _target_names(optional_vars)

        header = self._new_node(
            statement,
            "With",
            defined=defined,
            used=used,
            controls=controls,
            kind="with",
        )
        for predecessor in incoming:
            self._connect(predecessor, header)

        body_controls = controls + (header,)
        body_exits = self._build_sequence(
            getattr(statement, "body", []) or [], [header], body_controls
        )
        return list(body_exits) if body_exits else [header]

    def _build_try(
        self,
        statement: ast.AST,
        incoming: Sequence[int],
        controls: Tuple[int, ...],
    ) -> List[int]:
        body_exits = self._build_sequence(
            getattr(statement, "body", []) or [], incoming, controls
        )
        all_exits: List[int] = list(body_exits)

        for handler in getattr(statement, "handlers", []) or []:
            handler_defined: Set[str] = set()
            handler_name = getattr(handler, "name", None)
            if isinstance(handler_name, str) and handler_name:
                handler_defined.add(handler_name)
            handler_node = self._new_node(
                handler,
                "ExceptHandler",
                defined=handler_defined,
                used=set(_collect_load_names(getattr(handler, "type", None))),
                controls=controls,
                kind="handler",
            )
            for predecessor in list(incoming) + list(body_exits):
                self._connect(predecessor, handler_node)
            handler_exits = self._build_sequence(
                getattr(handler, "body", []) or [], [handler_node], controls
            )
            all_exits.extend(handler_exits if handler_exits else [handler_node])

        orelse = getattr(statement, "orelse", []) or []
        if orelse:
            all_exits.extend(self._build_sequence(orelse, body_exits, controls))

        finalbody = getattr(statement, "finalbody", []) or []
        if finalbody:
            return self._build_sequence(finalbody, all_exits or list(incoming), controls)
        return all_exits or list(body_exits)

    def _build_match(
        self,
        statement: ast.Match,
        incoming: Sequence[int],
        controls: Tuple[int, ...],
    ) -> List[int]:
        header = self._new_node(
            statement,
            "Match",
            defined=_named_expr_names(statement.subject),
            used=set(_collect_load_names(statement.subject)),
            controls=controls,
            kind="match",
        )
        for predecessor in incoming:
            self._connect(predecessor, header)

        exits: List[int] = [header]  # path where no case matches
        case_controls = controls + (header,)
        for case in statement.cases:
            pattern_defined = _pattern_names(case.pattern)
            guard_used = set(_collect_load_names(case.guard))
            case_node = self._new_node(
                case,
                "MatchCase",
                defined=pattern_defined,
                used=guard_used,
                controls=case_controls,
                kind="case",
            )
            self._connect(header, case_node)
            case_exits = self._build_sequence(case.body, [case_node], case_controls)
            exits.extend(case_exits if case_exits else [case_node])
        return exits

    # -- lookup helpers -----------------------------------------------------
    def find_node_for_ast(self, target: Optional[ast.AST]) -> Optional[int]:
        if target is None:
            return None
        for node_id, node in self.nodes.items():
            if node.ast_node is target:
                return node_id

        best_id: Optional[int] = None
        best_span: Optional[int] = None
        for node_id, node in self.nodes.items():
            if _ast_contains(node.ast_node, target):
                span = max(1, node.end_line - node.line + 1)
                if best_span is None or span < best_span:
                    best_span = span
                    best_id = node_id
        return best_id

    def find_node_for_line(self, line: int) -> Optional[int]:
        best_id: Optional[int] = None
        best_span: Optional[int] = None
        for node_id, node in self.nodes.items():
            if node.line <= line <= node.end_line:
                span = max(1, node.end_line - node.line + 1)
                if best_span is None or span < best_span:
                    best_span = span
                    best_id = node_id
        return best_id

    # -- dataflow -----------------------------------------------------------
    def solve_reaching_definitions(
        self, max_iterations: int
    ) -> Tuple[Dict[int, Set[Tuple[str, int]]], Dict[int, Set[Tuple[str, int]]], bool, int]:
        """Compute reaching definitions with a wave-based worklist.

        Returns ``(IN, OUT, converged, iterations)``.  ``converged`` is false
        when ``max_iterations`` waves were exhausted before a fixpoint was
        reached; callers must surface that as ``completeness_status="partial"``.
        """

        for node_id, node in self.nodes.items():
            node.gen = {(name, node_id) for name in node.defined if name}
            node.kill = set(node.defined)

        in_sets: Dict[int, Set[Tuple[str, int]]] = {node_id: set() for node_id in self.nodes}
        out_sets: Dict[int, Set[Tuple[str, int]]] = {node_id: set() for node_id in self.nodes}

        if not self.nodes:
            return in_sets, out_sets, True, 0

        worklist: Deque[int] = deque(sorted(self.nodes))
        queued: Set[int] = set(worklist)
        iterations = 0
        limit = max(0, int(max_iterations))

        while worklist:
            if iterations >= limit:
                return in_sets, out_sets, False, iterations

            wave_size = len(worklist)
            iterations += 1
            changed_in_wave = False

            for _ in range(wave_size):
                node_id = worklist.popleft()
                queued.discard(node_id)
                node = self.nodes[node_id]

                new_in: Set[Tuple[str, int]] = set()
                for predecessor in node.predecessors:
                    new_in |= out_sets[predecessor]

                new_out = set(new_in)
                if node.kill:
                    new_out = {item for item in new_out if item[0] not in node.kill}
                new_out |= node.gen

                if new_in != in_sets[node_id] or new_out != out_sets[node_id]:
                    in_sets[node_id] = new_in
                    out_sets[node_id] = new_out
                    changed_in_wave = True
                    for successor in node.successors:
                        if successor not in queued:
                            worklist.append(successor)
                            queued.add(successor)

            if not changed_in_wave and not worklist:
                break

        # A fixpoint is only guaranteed when the worklist emptied without
        # being cut short by the iteration budget.
        return in_sets, out_sets, True, iterations


def _statement_node_type(statement: ast.AST) -> str:
    if isinstance(statement, ast.Assign):
        return "Assign"
    if isinstance(statement, ast.AnnAssign):
        return "AnnAssign"
    if isinstance(statement, ast.AugAssign):
        return "AugAssign"
    if isinstance(statement, ast.Expr):
        if isinstance(getattr(statement, "value", None), ast.Call):
            return "Call"
        return "Expr"
    return type(statement).__name__


# ---------------------------------------------------------------------------
# Internal slicing bookkeeping
# ---------------------------------------------------------------------------


@dataclass
class _UseTask:
    variable: str
    point: int
    depth: int


@dataclass
class _SliceEntry:
    key: Tuple[str, int]
    node: SliceNode
    depth: int
    priority: int
    is_control: bool
    line_numbers: List[int]


# ---------------------------------------------------------------------------
# Main slicer
# ---------------------------------------------------------------------------


class ASTSlicer:
    """Intra-procedural backward taint slicer.

    Parameters
    ----------
    max_loop_iterations:
        Maximum number of fixpoint waves.  Exceeding it marks the result as
        ``partial`` with ``fixpoint_iteration_budget_exceeded`` instead of
        pretending the analysis converged.
    max_slice_lines:
        Physical source-line budget for the rendered slice.  Mandatory sink
        lines are always preserved; lower-priority definitions and guards are
        pruned first when the budget is exceeded.
    """

    @staticmethod
    def get_sink_category(call_name: str) -> Optional[str]:
        """Return the abstract sink category for a given call name."""
        return get_sink_category(call_name)

    @staticmethod
    def find_sink_anchors(tree_or_code: Union[str, ast.AST]) -> List[SinkAnchor]:
        """Find candidate sink anchors including primitive sinks and inter-procedural call-sites."""
        return find_sink_anchors(tree_or_code)

    @staticmethod
    def find_call_site_sink_anchors(tree_or_code: Union[str, ast.AST]) -> List[SinkAnchor]:
        """Identify inter-procedural call-sites that invoke wrapper functions forwarding to sinks."""
        return find_call_site_sink_anchors(tree_or_code)

    def __init__(self, max_loop_iterations: int = 10, max_slice_lines: int = 150) -> None:
        try:
            self.max_loop_iterations = max(0, int(max_loop_iterations))
        except (TypeError, ValueError):
            self.max_loop_iterations = 10
        try:
            self.max_slice_lines = max(0, int(max_slice_lines))
        except (TypeError, ValueError):
            self.max_slice_lines = 150

    # -- public API ---------------------------------------------------------
    def slice_from_sink(
        self,
        source_code: str,
        sink_line: int,
        target_var: Optional[str] = None,
    ) -> SliceResult:
        """Slice ``source_code`` backwards from ``sink_line``.

        The function never raises for malformed user input.  A syntax error is
        represented by ``completeness_status="failed"`` and an explanatory
        ``reason``.
        """

        if not isinstance(source_code, str) or not source_code.strip():
            return self._failed_result(
                sink_line=sink_line,
                target_variable=target_var or "",
                reason="invalid_source: source code is empty or not a string",
            )

        try:
            sink_line_int = int(sink_line)
        except (TypeError, ValueError):
            return self._failed_result(
                sink_line=0,
                target_variable=target_var or "",
                reason=f"invalid_sink_line: {sink_line!r} is not an integer",
            )

        source_lines = source_code.splitlines()
        if sink_line_int < 1:
            return self._failed_result(
                sink_line=sink_line_int,
                target_variable=target_var or "",
                reason="invalid_sink_line: line numbers start at 1",
            )
        if sink_line_int > max(1, len(source_lines)):
            return self._failed_result(
                sink_line=sink_line_int,
                target_variable=target_var or "",
                reason=(
                    "sink_line_out_of_range: "
                    f"line {sink_line_int} exceeds file length {len(source_lines)}"
                ),
            )

        try:
            tree = ast.parse(source_code)
        except SyntaxError as exc:
            return self._failed_result(
                sink_line=sink_line_int,
                target_variable=target_var or "",
                reason=f"syntax_error: {exc.msg} (line {getattr(exc, 'lineno', None)})",
            )
        except (ValueError, TypeError, MemoryError, RecursionError) as exc:
            return self._failed_result(
                sink_line=sink_line_int,
                target_variable=target_var or "",
                reason=f"parse_error: {type(exc).__name__}: {exc}",
            )
        except Exception as exc:  # pragma: no cover - defensive fallback
            logger.debug("Unexpected AST parse failure", exc_info=True)
            return self._failed_result(
                sink_line=sink_line_int,
                target_variable=target_var or "",
                reason=f"parse_error: {type(exc).__name__}: {exc}",
            )

        wrapper_map = _discover_wrappers(tree)
        scope = self._find_enclosing_scope(tree, sink_line_int) or tree
        statements = self._find_statements_at_line(scope, sink_line_int)
        calls = self._find_calls_at_line(scope, sink_line_int)
        sink_call = self._select_sink_call(
            calls, sink_line_int, target_var, known_wrappers=wrapper_map
        )

        primary_target, tracked_variables = self._extract_target_variables(
            sink_call=sink_call,
            statements=statements,
            target_var=target_var,
        )
        target_variable_field = target_var if target_var else primary_target

        try:
            cfg = _ControlFlowGraph(scope)
        except (RecursionError, MemoryError) as exc:  # pragma: no cover - defensive
            return self._failed_result(
                sink_line=sink_line_int,
                target_variable=target_variable_field,
                reason=f"cfg_build_failed: {type(exc).__name__}: {exc}",
            )

        sink_cfg_id = self._resolve_sink_cfg_id(cfg, sink_call, statements, sink_line_int)
        if sink_cfg_id is None:
            return self._failed_result(
                sink_line=sink_line_int,
                target_variable=target_variable_field,
                reason=f"sink_line_not_found: no executable AST node at line {sink_line_int}",
            )

        reach_in, _reach_out, converged, _iterations = cfg.solve_reaching_definitions(
            self.max_loop_iterations
        )

        if sink_call is not None:
            sink_name = _dotted_name(sink_call.func)
        else:
            sink_name = ""
            for stmt in statements:
                if isinstance(stmt, ast.Assign):
                    for tgt in stmt.targets:
                        t_name = _dotted_name(tgt)
                        if t_name and get_sink_category(t_name):
                            sink_name = t_name
                            break
                        if not sink_name and t_name:
                            sink_name = t_name
                    if sink_name:
                        break
                elif isinstance(stmt, ast.AnnAssign):
                    t_name = _dotted_name(stmt.target)
                    if t_name:
                        sink_name = t_name
                        break
                elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for dec in getattr(stmt, "decorator_list", []):
                        dec_name = _dotted_name(dec.func if isinstance(dec, ast.Call) else dec)
                        if dec_name and get_sink_category(dec_name):
                            sink_name = dec_name
                            break
                    if not sink_name:
                        sink_name = getattr(stmt, "name", "")
        sink_cfg_node = cfg.nodes[sink_cfg_id]

        hazards: Set[str] = set()
        if not converged:
            hazards.add("fixpoint_iteration_budget_exceeded")

        if sink_call is not None:
            self._inspect_sink_hazards(sink_call, hazards)

        entries, data_dependency_sets, control_dependency_sets = self._backward_slice(
            cfg=cfg,
            sink_cfg_id=sink_cfg_id,
            sink_line=sink_line_int,
            sink_call=sink_call,
            sink_cfg_node=sink_cfg_node,
            target_variables=tracked_variables,
            reach_in=reach_in,
            hazards=hazards,
            source_lines=source_lines,
        )

        # Container mutation aliasing is not fully representable in a pure
        # def-use graph.  Include obvious mutations as alias-escape context so
        # downstream tiers are aware of the gap.
        self._augment_alias_escape(
            cfg=cfg,
            sink_cfg_id=sink_cfg_id,
            sink_line=sink_line_int,
            entries=entries,
            reach_in=reach_in,
            data_dependency_sets=data_dependency_sets,
            control_dependency_sets=control_dependency_sets,
            hazards=hazards,
            source_lines=source_lines,
        )

        # --------------------------------------------------------------
        # Apply the source-line budget with the documented priority order.
        # --------------------------------------------------------------
        truncated = False
        truncation_reason: Optional[str] = None
        entries, truncated, truncation_reason = self._prune_to_budget(
            entries=entries,
            sink_line=sink_line_int,
        )
        if truncated:
            hazards.add("slice_line_budget_exceeded")

        # --------------------------------------------------------------
        # Materialise the final result.
        # --------------------------------------------------------------
        final_entries = sorted(
            entries.values(),
            key=lambda entry: (
                entry.node.line_number,
                entry.node.node_type,
                entry.node.id,
            ),
        )
        nodes = [entry.node for entry in final_entries]
        sliced_line_set: Set[int] = set()
        for entry in final_entries:
            sliced_line_set.update(entry.line_numbers)
        sliced_lines = sorted(line for line in sliced_line_set if 1 <= line <= len(source_lines))
        sliced_code = "\n".join(source_lines[line - 1] for line in sliced_lines)

        selected_lines = {entry.node.line_number for entry in final_entries}
        data_dependencies = self._materialise_dependency_map(
            data_dependency_sets, selected_lines
        )
        control_dependencies = self._materialise_dependency_map(
            control_dependency_sets, selected_lines
        )
        for line in selected_lines:
            data_dependencies.setdefault(line, [])
            control_dependencies.setdefault(line, [])

        # Every selected node gets a control-dependency entry so callers can
        # safely index the map; guards record their enclosing guards too.
        for entry in final_entries:
            key = entry.node.line_number
            data_dependencies.setdefault(key, [])
            control_dependencies.setdefault(key, [])

        # Ensure direct sink data dependencies survive even if a def line was
        # pruned; the sink itself and its nearest definitions are mandatory.
        for line, dependencies in list(data_dependency_sets.items()):
            if line not in selected_lines:
                continue
            kept = [dep for dep in dependencies if dep in selected_lines]
            data_dependencies[line] = sorted(set(kept))

        for line, dependencies in list(control_dependency_sets.items()):
            if line not in selected_lines:
                continue
            kept = [dep for dep in dependencies if dep in selected_lines]
            control_dependencies[line] = sorted(set(kept))

        # Drop keys that do not correspond to a selected source line.
        data_dependencies = {
            line: deps for line, deps in data_dependencies.items() if line in selected_lines
        }
        control_dependencies = {
            line: deps for line, deps in control_dependencies.items() if line in selected_lines
        }

        reason_parts: List[str] = []
        if hazards:
            reason_parts.extend(sorted(hazards))
        if not tracked_variables:
            reason_parts.append("no_tainted_variables")
        if not reason_parts:
            reason_parts.append("backward_slice_complete")

        completeness = COMPLETENESS_PARTIAL if hazards else COMPLETENESS_COMPLETE
        reason = "; ".join(_dedupe(reason_parts))

        # Estimate token use with a cheap, deterministic heuristic.  This is
        # not used for decisions inside this module; it is metadata for the
        # budget-aware Tier 2 prompt builder.
        token_budget_used = max(1, (len(sliced_code) + 3) // 4) if sliced_code else 0

        source_candidates: List[str] = []
        for n in nodes:
            if n.node_type in ("FunctionDef", "AsyncFunctionDef"):
                for var in n.variables_defined:
                    if var not in ("self", "cls"):
                        source_candidates.append(f"parameter:{var}")
            for v in n.variables_used:
                if any(kw in v.lower() for kw in ("request", "argv", "cookie", "header", "input", "environ")):
                    source_candidates.append(f"input:{v}")
            for kw in (
                "request.args",
                "request.form",
                "request.values",
                "request.cookies",
                "request.headers",
                "request.json",
                "request.data",
                "request.GET",
                "request.POST",
                "sys.argv",
                "input()",
                "os.environ",
            ):
                if kw in n.code_snippet and kw not in source_candidates:
                    source_candidates.append(kw)
        source_candidates = _dedupe(source_candidates)

        wrapper_cat: Optional[str] = None
        if sink_call is not None:
            c_name = _dotted_name(sink_call.func)
            last_c_name = _last_component(c_name)
            w = wrapper_map.get(c_name) or wrapper_map.get(last_c_name)
            if w is not None:
                wrapper_cat = w.category

        return SliceResult(
            target_sink_line=sink_line_int,
            target_variable=target_variable_field,
            sliced_lines=sliced_lines,
            sliced_code=sliced_code,
            nodes=nodes,
            data_dependencies=data_dependencies,
            control_dependencies=control_dependencies,
            completeness_status=completeness,
            reason=reason,
            sink_name=sink_name,
            tracked_variables=list(tracked_variables),
            is_truncated=truncated
            or "fixpoint_iteration_budget_exceeded" in hazards,
            token_budget_used=token_budget_used,
            truncation_reason=truncation_reason
            or (
                "fixpoint_iteration_budget_exceeded"
                if "fixpoint_iteration_budget_exceeded" in hazards
                else None
            ),
            source_candidates=source_candidates,
            sink_category_override=wrapper_cat,
        )

    # ------------------------------------------------------------------
    # Scope / sink discovery
    # ------------------------------------------------------------------
    def _find_enclosing_scope(self, tree: ast.AST, sink_line: int) -> Optional[ast.AST]:
        candidates: List[ast.AST] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = _safe_lineno(node, 1)
                end = _safe_end_lineno(node, start)
                if start <= sink_line <= end:
                    candidates.append(node)
        if not candidates:
            # A sink directly in a class body (not inside a method) still gets
            # an intra-class slice rather than failing scope discovery.
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    start = _safe_lineno(node, 1)
                    end = _safe_end_lineno(node, start)
                    if start <= sink_line <= end:
                        candidates.append(node)
        if not candidates:
            return None
        # Innermost scope: latest start, then smallest span.
        return max(
            candidates,
            key=lambda node: (
                _safe_lineno(node, 1),
                -(_safe_end_lineno(node, _safe_lineno(node, 1))),
            ),
        )

    def _find_statements_at_line(self, scope: ast.AST, sink_line: int) -> List[ast.stmt]:
        matches: List[ast.stmt] = []
        for node in _iter_scope_nodes(scope):
            if not isinstance(node, ast.stmt):
                continue
            start = _safe_lineno(node, 0)
            end = _safe_end_lineno(node, start)
            if start <= sink_line <= end:
                matches.append(node)
        # Innermost/smallest statement first.
        matches.sort(
            key=lambda node: (
                max(1, _safe_end_lineno(node, _safe_lineno(node, 1)) - _safe_lineno(node, 1) + 1),
                _safe_lineno(node, 0),
            )
        )
        return matches

    def _find_calls_at_line(self, scope: ast.AST, sink_line: int) -> List[ast.Call]:
        calls: List[ast.Call] = []
        for node in _iter_scope_nodes(scope):
            if not isinstance(node, ast.Call):
                continue
            start = _safe_lineno(node, 0)
            end = _safe_end_lineno(node, start)
            if start <= sink_line <= end:
                calls.append(node)
        calls.sort(
            key=lambda node: (
                _safe_lineno(node, 0),
                int(getattr(node, "col_offset", 0) or 0),
                -(_safe_end_lineno(node, _safe_lineno(node, 0)) - _safe_lineno(node, 0)),
            )
        )
        return calls

    def _select_sink_call(
        self,
        calls: Sequence[ast.Call],
        sink_line: int,
        target_var: Optional[str],
        known_wrappers: Optional[Dict[str, Any]] = None,
    ) -> Optional[ast.Call]:
        if not calls:
            return None

        wrappers = known_wrappers or {}

        def score(call: ast.Call) -> Tuple[int, int, int]:
            name = _dotted_name(call.func)
            last_name = _last_component(name)
            value = 0
            if _is_sink_call_name(name) or name in wrappers or last_name in wrappers:
                value += 1000
            argument_names = set(self._call_argument_names(call))
            if target_var and any(
                target_var == candidate
                or target_var == _last_component(candidate)
                or candidate.endswith("." + target_var)
                for candidate in argument_names
            ):
                value += 500
            if _safe_lineno(call, 0) == sink_line:
                value += 100
            if not call.args and not call.keywords:
                value -= 10
            span = max(
                1,
                _safe_end_lineno(call, _safe_lineno(call, 0)) - _safe_lineno(call, 0) + 1,
            )
            value += min(span, 50)
            # Prefer the outer call (smaller col_offset) when scores tie.
            return (-value, int(getattr(call, "col_offset", 0) or 0), span)

        return min(calls, key=score)

    @staticmethod
    def _call_argument_names(call: ast.Call) -> List[str]:
        names: List[str] = []
        for argument in call.args:
            names.extend(_collect_load_names(argument))
        for keyword in call.keywords:
            names.extend(_collect_load_names(keyword.value))
        return _dedupe(names)

    def _extract_target_variables(
        self,
        sink_call: Optional[ast.Call],
        statements: Sequence[ast.stmt],
        target_var: Optional[str],
    ) -> Tuple[str, List[str]]:
        if target_var is not None and str(target_var).strip():
            explicit = str(target_var).strip()
            return explicit, self._expand_tracking_variables([explicit])

        argument_names: List[str] = []
        callee_names: List[str] = []

        if sink_call is not None:
            argument_names = self._call_argument_names(sink_call)
            function = sink_call.func
            if isinstance(function, ast.Name):
                callee_names.append(function.id)
            elif isinstance(function, (ast.Call, ast.Subscript, ast.Lambda)):
                callee_names.extend(_collect_load_names(function))
        else:
            for statement in statements:
                if isinstance(statement, ast.Expr):
                    argument_names.extend(_collect_load_names(statement.value))
                elif isinstance(statement, ast.Assign):
                    argument_names.extend(_collect_load_names(statement.value))
                    for tgt in statement.targets:
                        callee_names.extend(sorted(_target_names(tgt)))
                elif isinstance(statement, ast.AnnAssign):
                    argument_names.extend(_collect_load_names(statement.value))
                    callee_names.extend(sorted(_target_names(statement.target)))
                elif isinstance(statement, ast.Return):
                    argument_names.extend(_collect_load_names(statement.value))
                elif isinstance(statement, ast.If):
                    argument_names.extend(_collect_load_names(statement.test))
                elif isinstance(statement, ast.While):
                    argument_names.extend(_collect_load_names(statement.test))
                elif isinstance(statement, (ast.For, ast.AsyncFor)):
                    argument_names.extend(_collect_load_names(statement.iter))

        tracked = self._expand_tracking_variables(
            _dedupe(list(argument_names) + list(callee_names))
        )
        if argument_names:
            primary = _dedupe(argument_names)[0]
        elif callee_names:
            primary = _dedupe(callee_names)[0]
        elif tracked:
            primary = tracked[0]
        else:
            primary = ""
        return primary, tracked

    @staticmethod
    def _expand_tracking_variables(variables: Sequence[str]) -> List[str]:
        expanded: List[str] = []
        for variable in variables:
            variable = (variable or "").strip()
            if not variable:
                continue
            expanded.append(variable)
            root = variable.split(".", 1)[0]
            if root and root != variable:
                expanded.append(root)
        return _dedupe(expanded)

    def _resolve_sink_cfg_id(
        self,
        cfg: _ControlFlowGraph,
        sink_call: Optional[ast.Call],
        statements: Sequence[ast.stmt],
        sink_line: int,
    ) -> Optional[int]:
        if sink_call is not None:
            node_id = cfg.find_node_for_ast(sink_call)
            if node_id is not None:
                return node_id
        for statement in statements:
            node_id = cfg.find_node_for_ast(statement)
            if node_id is not None:
                return node_id
        return cfg.find_node_for_line(sink_line)

    # ------------------------------------------------------------------
    # Backward slicing
    # ------------------------------------------------------------------
    def _backward_slice(
        self,
        cfg: _ControlFlowGraph,
        sink_cfg_id: int,
        sink_line: int,
        sink_call: Optional[ast.Call],
        sink_cfg_node: _CFGNode,
        target_variables: Sequence[str],
        reach_in: Dict[int, Set[Tuple[str, int]]],
        hazards: Set[str],
        source_lines: Sequence[str],
    ) -> Tuple[
        Dict[Tuple[str, int], _SliceEntry],
        Dict[int, Set[int]],
        Dict[int, Set[int]],
    ]:
        entries: Dict[Tuple[str, int], _SliceEntry] = {}
        data_dependency_sets: Dict[int, Set[int]] = {}
        control_dependency_sets: Dict[int, Set[int]] = {}

        # The sink is always the first mandatory node in the slice.
        sink_entry = self._make_sink_entry(
            cfg_node=sink_cfg_node,
            sink_call=sink_call,
            sink_line=sink_line,
            target_variables=target_variables,
            source_lines=source_lines,
        )
        entries[sink_entry.key] = sink_entry

        queue: Deque[_UseTask] = deque()
        for variable in target_variables:
            queue.append(_UseTask(variable=variable, point=sink_cfg_id, depth=1))

        visited_uses: Set[Tuple[int, str]] = set()
        visited_controls: Set[int] = set()
        callee_variables: Set[str] = set()
        if sink_call is not None and isinstance(sink_call.func, ast.Name):
            callee_variables.add(sink_call.func.id)

        def add_dependency(mapping: Dict[int, Set[int]], source_line: int, target_line: int) -> None:
            if source_line == target_line:
                return
            if source_line <= 0 or target_line <= 0:
                return
            mapping.setdefault(source_line, set()).add(target_line)

        def add_cfg_selection(
            node_id: int,
            depth: int,
            reason: str,
            is_control: bool = False,
        ) -> _SliceEntry:
            key: Tuple[str, int] = ("cfg", node_id)
            if node_id == sink_cfg_id and sink_entry.key in entries:
                # The synthetic sink entry already represents this statement.
                return sink_entry

            cfg_node = cfg.nodes[node_id]
            existing = entries.get(key)
            priority = self._entry_priority(reason, is_control)
            if existing is not None:
                if depth < existing.depth:
                    existing.depth = depth
                if not is_control and existing.is_control:
                    existing.is_control = False
                    existing.node.dependency_reason = reason
                    existing.priority = priority
                elif priority < existing.priority:
                    existing.node.dependency_reason = reason
                    existing.priority = priority
                return existing

            slice_node, line_numbers = self._build_cfg_slice_node(
                cfg_node, reason, source_lines
            )
            entry = _SliceEntry(
                key=key,
                node=slice_node,
                depth=depth,
                priority=priority,
                is_control=is_control,
                line_numbers=line_numbers,
            )
            entries[key] = entry
            self._inspect_definition_hazards(cfg_node, hazards)
            return entry

        def include_control(control_id: int, depth: int, source_line: int) -> None:
            control_node = cfg.nodes[control_id]
            reason = self._control_reason(control_node)
            add_cfg_selection(control_id, depth, reason, is_control=True)
            add_dependency(control_dependency_sets, source_line, control_node.line)
            if control_id in visited_controls:
                return
            visited_controls.add(control_id)
            for variable in control_node.used:
                queue.append(_UseTask(variable=variable, point=control_id, depth=depth + 1))
            for outer_control in control_node.controls:
                include_control(outer_control, depth + 1, control_node.line)

        # A sink nested in a guard/loop still needs that control context.
        for control_id in sink_cfg_node.controls:
            include_control(control_id, 1, sink_line)

        while queue:
            task = queue.popleft()
            use_key = (task.point, task.variable)
            if use_key in visited_uses:
                continue
            visited_uses.add(use_key)

            if task.point not in reach_in:
                continue

            definitions = sorted(
                {
                    definition_id
                    for variable, definition_id in reach_in.get(task.point, set())
                    if variable == task.variable
                },
                key=lambda node_id: (cfg.nodes[node_id].line, cfg.nodes[node_id].id),
            )

            if not definitions:
                # Function parameters are legitimate slice roots.  A callable
                # parameter used as the sink target is also a dynamic dispatch
                # boundary worth flagging.
                if task.variable in cfg.scope_params and cfg.entry_id is not None:
                    entry = add_cfg_selection(
                        cfg.entry_id,
                        task.depth,
                        f"param_def:{task.variable}",
                    )
                    add_dependency(
                        data_dependency_sets,
                        self._task_source_line(cfg, task.point, sink_cfg_id, sink_line),
                        entry.node.line_number,
                    )
                    if task.variable in callee_variables and task.point == sink_cfg_id:
                        hazards.add(f"dynamic_dispatch:{task.variable}")
                continue

            use_line = self._task_source_line(cfg, task.point, sink_cfg_id, sink_line)
            for definition_id in definitions:
                definition_node = cfg.nodes[definition_id]
                reason = self._definition_reason(
                    cfg, definition_node, task.variable, task.depth
                )
                entry = add_cfg_selection(definition_id, task.depth, reason)
                add_dependency(
                    data_dependency_sets,
                    use_line,
                    entry.node.line_number,
                )

                # Calling a parameter / a locally defined function through a
                # bare Name is an inter-procedural boundary.
                if task.point == sink_cfg_id and task.variable in callee_variables:
                    if definition_node.kind == "entry":
                        hazards.add(f"dynamic_dispatch:{task.variable}")
                    elif isinstance(
                        definition_node.ast_node,
                        (ast.FunctionDef, ast.AsyncFunctionDef),
                    ):
                        hazards.add(f"interprocedural_call:{task.variable}")

                # Control dependencies of the definition (guards, loops, ...).
                for control_id in definition_node.controls:
                    include_control(control_id, task.depth + 1, definition_node.line)

                # Reverse def-use propagation: every variable read by the
                # definition becomes a new backward obligation.  Tuple/list
                # unpacking is mapped per index for precision.
                for variable in sorted(
                    _used_names_for_variable(definition_node.ast_node, task.variable)
                ):
                    queue.append(
                        _UseTask(
                            variable=variable,
                            point=definition_id,
                            depth=task.depth + 1,
                        )
                    )

                # Unknown inter-procedural transformations are fail-safe.
                self._inspect_definition_hazards(definition_node, hazards)

        # Any sink callee defined through a dynamic construct (getattr/...)
        # will have been caught by the hazard inspection above.  However, a
        # dynamic sink callee that has no local definition is still a boundary.
        if sink_call is not None and not isinstance(sink_call.func, (ast.Name, ast.Attribute)):
            hazards.add("dynamic_dispatch")

        return entries, data_dependency_sets, control_dependency_sets

    def _make_sink_entry(
        self,
        cfg_node: _CFGNode,
        sink_call: Optional[ast.Call],
        sink_line: int,
        target_variables: Sequence[str],
        source_lines: Sequence[str],
    ) -> _SliceEntry:
        ast_node: ast.AST = sink_call if sink_call is not None else cfg_node.ast_node
        node_type = "Call" if sink_call is not None else cfg_node.node_type
        line_number = sink_line if sink_line > 0 else (_safe_lineno(ast_node, 1) or 1)

        snippet, line_numbers = self._snippet_for_ast(
            cfg_node.ast_node,
            source_lines,
            header_only=self._is_compound_statement(cfg_node.ast_node),
        )
        if not snippet:
            snippet, line_numbers = self._snippet_for_lines(
                source_lines, [line_number]
            )

        used = set(target_variables) if target_variables else set(cfg_node.used)
        slice_node = SliceNode(
            id=f"L{line_number}:{node_type}:sink",
            ast_node=ast_node,
            line_number=line_number,
            code_snippet=snippet,
            variables_defined=set(cfg_node.defined),
            variables_used=used,
            node_type=node_type,
            dependency_reason="sink_call" if sink_call is not None else "sink_statement",
        )
        return _SliceEntry(
            key=("sink", cfg_node.id),
            node=slice_node,
            depth=0,
            priority=0,
            is_control=False,
            line_numbers=line_numbers or [line_number],
        )

    def _build_cfg_slice_node(
        self,
        cfg_node: _CFGNode,
        reason: str,
        source_lines: Sequence[str],
    ) -> Tuple[SliceNode, List[int]]:
        header_only = self._is_compound_statement(cfg_node.ast_node)
        snippet, line_numbers = self._snippet_for_ast(
            cfg_node.ast_node,
            source_lines,
            header_only=header_only,
        )
        if not snippet:
            snippet, line_numbers = self._snippet_for_lines(
                source_lines, [cfg_node.line]
            )
        node = SliceNode(
            id=f"L{cfg_node.line}:{cfg_node.node_type}:{cfg_node.id}",
            ast_node=cfg_node.ast_node,
            line_number=cfg_node.line,
            code_snippet=snippet,
            variables_defined=set(cfg_node.defined),
            variables_used=set(cfg_node.used),
            node_type=cfg_node.node_type,
            dependency_reason=reason,
        )
        return node, line_numbers or [cfg_node.line]

    @staticmethod
    def _task_source_line(
        cfg: _ControlFlowGraph,
        point: int,
        sink_cfg_id: int,
        sink_line: int,
    ) -> int:
        if point == sink_cfg_id:
            return sink_line
        node = cfg.nodes.get(point)
        return node.line if node is not None else 0

    def _control_reason(self, cfg_node: _CFGNode) -> str:
        if isinstance(cfg_node.ast_node, ast.If):
            return "guard_condition"
        if isinstance(cfg_node.ast_node, (ast.For, ast.AsyncFor, ast.While)):
            return "loop_condition"
        if isinstance(cfg_node.ast_node, (ast.With, ast.AsyncWith)):
            return "context_manager"
        return "control_condition"

    def _definition_reason(
        self,
        cfg: _ControlFlowGraph,
        cfg_node: _CFGNode,
        variable: str,
        depth: int,
    ) -> str:
        statement = cfg_node.ast_node
        if isinstance(statement, ast.AugAssign):
            inside_loop = any(
                isinstance(cfg.nodes[control_id].ast_node, (ast.For, ast.AsyncFor, ast.While))
                for control_id in cfg_node.controls
                if control_id in cfg.nodes
            )
            return f"{'loop_accum' if inside_loop else 'accum_def'}:{variable}"
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            return f"loop_iter:{variable}"
        if isinstance(statement, ast.While):
            return f"loop_condition:{variable}"
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            return f"context_def:{variable}"
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if cfg_node.kind == "entry":
                return f"param_def:{variable}"
            return f"function_def:{variable}"
        if isinstance(statement, (ast.Import, ast.ImportFrom)):
            return f"import_def:{variable}"
        if depth <= 1:
            return f"direct_def:{variable}"
        return f"transitive_def:{variable}"

    @staticmethod
    def _entry_priority(reason: str, is_control: bool) -> int:
        if reason.startswith("sink"):
            return 0
        if reason.startswith("direct_def") or reason.startswith("param_def"):
            return 1
        if reason.startswith("transitive_def") or reason.startswith("accum_def") or reason.startswith(
            "loop_accum"
        ) or reason.startswith("loop_iter") or reason.startswith("context_def") or reason.startswith(
            "import_def"
        ) or reason.startswith("function_def"):
            return 2
        if is_control or reason in {
            "guard_condition",
            "loop_condition",
            "context_manager",
            "control_condition",
        }:
            return 3
        return 4

    # ------------------------------------------------------------------
    # Safety / hazard inspection
    # ------------------------------------------------------------------
    def _expression_for_definitions(self, cfg_node: _CFGNode) -> List[ast.AST]:
        statement = cfg_node.ast_node
        expressions: List[ast.AST] = []
        if isinstance(statement, ast.Assign):
            expressions.append(statement.value)
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            expressions.append(statement.value)
        elif isinstance(statement, ast.AugAssign):
            expressions.append(statement.value)
        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            expressions.append(statement.iter)
        elif isinstance(statement, ast.While):
            expressions.append(statement.test)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                expressions.append(item.context_expr)
        elif isinstance(statement, ast.Expr):
            expressions.append(statement.value)
        elif isinstance(statement, ast.Return) and statement.value is not None:
            expressions.append(statement.value)
        elif isinstance(statement, ast.If):
            expressions.append(statement.test)
        elif isinstance(statement, ast.Match):
            expressions.append(statement.subject)
        return [expression for expression in expressions if expression is not None]

    def _inspect_definition_hazards(self, cfg_node: _CFGNode, hazards: Set[str]) -> None:
        for expression in self._expression_for_definitions(cfg_node):
            for call in _iter_calls(expression):
                self._inspect_call_hazard(call, hazards)

    def _inspect_sink_hazards(self, sink_call: ast.Call, hazards: Set[str]) -> None:
        function = sink_call.func
        if isinstance(function, ast.Name):
            name = function.id
            if name in _DYNAMIC_DISPATCH_CALLS:
                hazards.add(f"dynamic_dispatch:{name}")
        elif isinstance(function, ast.Attribute):
            name = _dotted_name(function)
            last = _last_component(name)
            if last in _DYNAMIC_DISPATCH_CALLS:
                hazards.add(f"dynamic_dispatch:{name}")
        else:
            hazards.add("dynamic_dispatch")

        for argument in list(sink_call.args):
            for call in _iter_calls(argument):
                self._inspect_call_hazard(call, hazards)
        for keyword in list(sink_call.keywords):
            for call in _iter_calls(keyword.value):
                self._inspect_call_hazard(call, hazards)

    def _inspect_call_hazard(self, call: ast.Call, hazards: Set[str]) -> None:
        name = _dotted_name(call.func)
        last = _last_component(name)
        if not name:
            hazards.add("dynamic_dispatch")
            return
        if name in _DYNAMIC_DISPATCH_CALLS or last in _DYNAMIC_DISPATCH_CALLS:
            hazards.add(f"dynamic_dispatch:{name}")
            if last == "getattr":
                hazards.add("alias_escape")
            return
        if _is_sink_call_name(name):
            # A nested sink call is still an external transformation from the
            # point of view of the slice, but do not flag ordinary constructors.
            return
        if _is_safe_call_name(name):
            return
        hazards.add(f"interprocedural_call:{name}")

    def _augment_alias_escape(
        self,
        cfg: _ControlFlowGraph,
        sink_cfg_id: int,
        sink_line: int,
        entries: Dict[Tuple[str, int], _SliceEntry],
        reach_in: Dict[int, Set[Tuple[str, int]]],
        data_dependency_sets: Dict[int, Set[int]],
        control_dependency_sets: Dict[int, Set[int]],
        hazards: Set[str],
        source_lines: Sequence[str],
    ) -> None:
        """Include obvious mutable-container mutations as alias context.

        Example::

            items = []
            items.append(user_value)
            target = items[0]
            sink(target)

        A pure def-use graph only sees ``items = []`` because ``append`` does
        not rebind ``items``.  We conservatively pull such mutations into the
        slice and mark the result partial instead of claiming completeness.
        """

        if not entries:
            return

        container_roots: Set[str] = set()
        for entry in entries.values():
            if entry.key[0] == "sink":
                continue
            for expression in self._expression_for_definitions(cfg.nodes[entry.key[1]]):
                for node in ast.walk(expression):
                    if isinstance(node, ast.Subscript):
                        root = _dotted_name(node.value)
                        if root:
                            container_roots.add(root.split(".", 1)[0])
        # A sink that directly consumes ``items[0]`` also identifies a container.
        sink_entry = next((entry for key, entry in entries.items() if key[0] == "sink"), None)
        if sink_entry is not None:
            for variable in sink_entry.node.variables_used:
                container_roots.add(variable.split(".", 1)[0])

        container_roots = {root for root in container_roots if root}
        if not container_roots:
            return

        added_any = False
        for node_id, cfg_node in sorted(cfg.nodes.items(), key=lambda item: item[1].line):
            if cfg_node.line > sink_line:
                continue
            if not isinstance(cfg_node.ast_node, ast.Expr):
                continue
            value = cfg_node.ast_node.value
            if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
                continue
            method_name = value.func.attr
            if method_name not in _MUTATING_METHODS:
                continue
            base = _dotted_name(value.func.value).split(".", 1)[0]
            if base not in container_roots:
                continue

            key: Tuple[str, int] = ("cfg", node_id)
            if key in entries:
                continue
            slice_node, line_numbers = self._build_cfg_slice_node(
                cfg_node, f"alias_escape:{base}", source_lines
            )
            entries[key] = _SliceEntry(
                key=key,
                node=slice_node,
                depth=3,
                priority=4,
                is_control=False,
                line_numbers=line_numbers,
            )
            added_any = True
            hazards.add(f"alias_escape:{base}")

            # The mutation is a reaching state change for every selected
            # statement that consumes the container afterwards.
            for other_key, other_entry in list(entries.items()):
                if other_key == key:
                    continue
                if other_key[0] != "cfg":
                    continue
                other_cfg_node = cfg.nodes.get(other_key[1])
                if other_cfg_node is None:
                    continue
                if not any(
                    used.split(".", 1)[0] == base for used in other_cfg_node.used
                ):
                    continue
                if other_cfg_node.line < cfg_node.line:
                    continue
                data_dependency_sets.setdefault(
                    other_entry.node.line_number, set()
                ).add(cfg_node.line)

            # The mutation arguments are part of the tainted container state.
            for used_variable in sorted(cfg_node.used):
                for name, definition_id in reach_in.get(node_id, set()):
                    if name != used_variable:
                        continue
                    definition_node = cfg.nodes[definition_id]
                    dep_key = f"transitive_def:{used_variable}"
                    dep_entry, dep_lines = self._build_cfg_slice_node(
                        definition_node, dep_key, source_lines
                    )
                    existing = entries.get(("cfg", definition_id))
                    if existing is None:
                        entries[("cfg", definition_id)] = _SliceEntry(
                            key=("cfg", definition_id),
                            node=dep_entry,
                            depth=4,
                            priority=2,
                            is_control=False,
                            line_numbers=dep_lines,
                        )
                    data_dependency_sets.setdefault(cfg_node.line, set()).add(
                        definition_node.line
                    )
            for control_id in cfg_node.controls:
                control_node = cfg.nodes[control_id]
                control_entry = entries.get(("cfg", control_id))
                if control_entry is None:
                    control_slice, control_lines = self._build_cfg_slice_node(
                        control_node, self._control_reason(control_node), source_lines
                    )
                    entries[("cfg", control_id)] = _SliceEntry(
                        key=("cfg", control_id),
                        node=control_slice,
                        depth=4,
                        priority=3,
                        is_control=True,
                        line_numbers=control_lines,
                    )
                control_dependency_sets.setdefault(cfg_node.line, set()).add(
                    control_node.line
                )

        if added_any:
            hazards.add("alias_escape")

    # ------------------------------------------------------------------
    # Budget pruning
    # ------------------------------------------------------------------
    def _prune_to_budget(
        self,
        entries: Dict[Tuple[str, int], _SliceEntry],
        sink_line: int,
    ) -> Tuple[Dict[Tuple[str, int], _SliceEntry], bool, Optional[str]]:
        if not entries:
            return entries, False, None

        all_lines: Set[int] = set()
        for entry in entries.values():
            all_lines.update(entry.line_numbers)

        limit = self.max_slice_lines
        if limit <= 0 or len(all_lines) <= limit:
            if limit <= 0 and all_lines:
                # A zero budget still cannot remove the mandatory sink.
                sink_key = next(
                    (key for key in entries if key[0] == "sink"),
                    next(iter(entries)),
                )
                kept = {sink_key: entries[sink_key]}
                return kept, True, "mandatory_statements_exceeded_budget"
            return entries, False, None

        sink_entries = [entry for key, entry in entries.items() if key[0] == "sink"]
        other_entries = [entry for key, entry in entries.items() if key[0] != "sink"]

        sink_entries.sort(key=lambda entry: entry.priority)
        other_entries.sort(
            key=lambda entry: (
                entry.priority,
                abs(entry.node.line_number - sink_line),
                entry.node.line_number,
                entry.node.id,
            )
        )

        kept_entries: Dict[Tuple[str, int], _SliceEntry] = {}
        kept_lines: Set[int] = set()
        for entry in sink_entries:
            kept_entries[entry.key] = entry
            kept_lines.update(entry.line_numbers)

        overflow_mandatory = len(kept_lines) > limit

        for entry in other_entries:
            candidate_lines = set(entry.line_numbers)
            if len(kept_lines | candidate_lines) <= limit:
                kept_entries[entry.key] = entry
                kept_lines.update(candidate_lines)

        if len(kept_entries) < len(entries):
            reason = (
                "mandatory_statements_exceeded_budget"
                if overflow_mandatory
                else "slice_line_budget_exceeded"
            )
            return kept_entries, True, reason
        return kept_entries, False, None

    # ------------------------------------------------------------------
    # Rendering helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _is_compound_statement(node: ast.AST) -> bool:
        return isinstance(
            node,
            (
                ast.If,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.With,
                ast.AsyncWith,
                ast.Try,
                ast.Match,
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
                ast.ExceptHandler,
            ),
        )

    def _snippet_for_ast(
        self,
        node: ast.AST,
        source_lines: Sequence[str],
        header_only: bool = False,
    ) -> Tuple[str, List[int]]:
        if header_only:
            start, end = self._header_span(node)
        else:
            start = _safe_lineno(node, 1)
            end = max(start, _safe_end_lineno(node, start))
        return self._snippet_for_lines(source_lines, range(start, end + 1))

    @staticmethod
    def _header_span(node: ast.AST) -> Tuple[int, int]:
        start = _safe_lineno(node, 1)
        child_lines: List[int] = []

        for attribute in ("body", "orelse", "finalbody"):
            body = getattr(node, attribute, None)
            if body:
                for child in body:
                    child_line = _safe_lineno(child, 0)
                    if child_line > start:
                        child_lines.append(child_line)
                        break

        for handler in getattr(node, "handlers", []) or []:
            handler_line = _safe_lineno(handler, 0)
            if handler_line > start:
                child_lines.append(handler_line)
                break

        for case in getattr(node, "cases", []) or []:
            case_line = _safe_lineno(case, 0)
            if case_line > start:
                child_lines.append(case_line)
                break

        first_child = min(child_lines) if child_lines else start
        end = max(start, first_child - 1)
        return start, end

    @staticmethod
    def _snippet_for_lines(
        source_lines: Sequence[str],
        line_numbers: Iterable[int],
    ) -> Tuple[str, List[int]]:
        lines: List[int] = sorted(
            {
                int(line)
                for line in line_numbers
                if isinstance(line, int) and 1 <= line <= len(source_lines)
            }
        )
        if not lines:
            return "", []
        raw = "\n".join(source_lines[line - 1] for line in lines)
        snippet = textwrap.dedent(raw).strip()
        return snippet, lines

    # ------------------------------------------------------------------
    # Dependency maps / failure helper
    # ------------------------------------------------------------------
    @staticmethod
    def _materialise_dependency_map(
        dependency_sets: Dict[int, Set[int]],
        selected_lines: Set[int],
    ) -> Dict[int, List[int]]:
        result: Dict[int, List[int]] = {}
        for line, dependencies in dependency_sets.items():
            if line not in selected_lines:
                continue
            result[line] = sorted({dep for dep in dependencies if dep in selected_lines})
        return result

    @staticmethod
    def _failed_result(
        sink_line: int,
        target_variable: str,
        reason: str,
    ) -> SliceResult:
        try:
            line = int(sink_line)
        except (TypeError, ValueError):
            line = 0
        return SliceResult(
            target_sink_line=line,
            target_variable=target_variable or "",
            sliced_lines=[],
            sliced_code="",
            nodes=[],
            data_dependencies={},
            control_dependencies={},
            completeness_status=COMPLETENESS_FAILED,
            reason=reason,
            sink_name="",
            tracked_variables=[],
            is_truncated=False,
            token_budget_used=0,
            truncation_reason=None,
        )
