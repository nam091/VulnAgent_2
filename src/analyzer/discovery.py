"""File discovery and risk-based routing.

Deciding *which* files to send to the LLM tier is the main cost lever in the
whole pipeline. The rule tier is free and runs over everything; the LLM tier
is metered, so it is pointed at the files where semantic analysis can
actually pay off.
"""

import fnmatch
import logging
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# Directories that never contain first-party source worth scanning. Without
# these a single repository with a committed virtualenv turns a ten-file scan
# into a four-thousand-file one.
DEFAULT_EXCLUDES = (
    ".git", ".hg", ".svn",
    "venv", ".venv", "env", ".env",
    "node_modules", "site-packages", "dist-info",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
    "build", "dist", ".eggs", "*.egg-info",
    ".idea", ".vscode",
    "migrations",
)

SOURCE_SUFFIXES = (".py",)

# Signals that a file is worth spending an LLM call on. Weighted because a
# file that merely imports `os` is far less interesting than one that builds
# a SQL string out of a request parameter.
RISK_SIGNALS: Tuple[Tuple[str, int, str], ...] = (
    (r"\bsubprocess\b|\bos\.system\b|\bos\.popen\b", 4, "process execution"),
    (r"\beval\s*\(|\bexec\s*\(|\bcompile\s*\(", 4, "dynamic evaluation"),
    (r"\bpickle\b|\bmarshal\b|yaml\.load\s*\(|\bshelve\b", 4, "deserialization"),
    (r"\.execute\s*\(|\braw\s*\(|\bcursor\b|\bSELECT\b|\bINSERT\b", 3, "database access"),
    (r"@(?:app|router|bp|blueprint)\.(?:route|get|post|put|delete|patch)", 3, "http route"),
    (r"\brequest\.(?:args|form|json|data|files|cookies|headers)", 3, "user input"),
    (r"\bpassword\b|\bsecret\b|\btoken\b|\bapi_key\b|\bcredential", 3, "secrets"),
    (r"\bauth|\blogin\b|\bpermission\b|\bis_admin\b|\bsession\b", 2, "authn/authz"),
    (r"\bopen\s*\(|\bPath\s*\(|send_file|sendfile", 2, "file access"),
    (r"\brequests\.|\burllib\b|\bhttpx\b|\baiohttp\b", 2, "outbound http"),
    (r"\bhashlib\b|\bcrypt\b|\bcipher\b|\brandom\.", 2, "crypto/random"),
    (r"render_template_string|\.innerHTML|mark_safe|\|\s*safe", 3, "template injection"),
    (r"\bpermissions?\b|\bCORS\b|allow_origins", 2, "security config"),
)


class DiscoveredFile:
    """
    A source file selected for scanning, with its computed risk profile.
    """

    def __init__(self, path: Path, root: Path, risk_score: int, reasons: List[str]) -> None:
        self.path = path
        self.root = root
        self.risk_score = risk_score
        self.reasons = reasons

    @property
    def relative(self) -> str:
        """
        Path relative to the scan root, in posix form.

        Returns:
            str: Relative path suitable for reports and SARIF output
        """

        try:
            return self.path.relative_to(self.root).as_posix()
        except ValueError:
            return self.path.as_posix()

    def __repr__(self) -> str:
        return f"<DiscoveredFile {self.relative} risk={self.risk_score}>"


def load_gitignore_patterns(root: Path) -> List[str]:
    """
    Read simple ignore patterns from the repository's .gitignore.

    Only the straightforward cases are honoured - full gitignore semantics
    (negation, nested files, path anchoring) are deliberately out of scope,
    since DEFAULT_EXCLUDES already covers what matters for cost control.

    Args:
        root: Directory to look for .gitignore in

    Returns:
        List[str]: Glob patterns to exclude
    """

    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        return []

    patterns = []
    try:
        for raw in gitignore.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            patterns.append(line.rstrip("/"))
    except OSError as e:
        logging.debug(f"Could not read {gitignore}: {e}")

    return patterns


def _is_excluded(path: Path, root: Path, patterns: Sequence[str]) -> bool:
    """
    Whether a path matches any exclusion pattern.

    Args:
        path: Candidate file or directory
        root: Scan root
        patterns: Glob patterns

    Returns:
        bool: True when the path should be skipped
    """

    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path

    parts = relative.parts
    for pattern in patterns:
        if any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
        if fnmatch.fnmatch(relative.as_posix(), pattern):
            return True
    return False


def score_risk(content: str) -> Tuple[int, List[str]]:
    """
    Score how likely a file is to contain a semantically interesting defect.

    Args:
        content: Source code

    Returns:
        Tuple[int, List[str]]: Total score and the signals that fired
    """

    score = 0
    reasons = []
    for pattern, weight, label in RISK_SIGNALS:
        if re.search(pattern, content, re.IGNORECASE):
            score += weight
            reasons.append(label)
    return score, reasons


def discover(
    target: str,
    extra_excludes: Iterable[str] = (),
    use_gitignore: bool = True,
    suffixes: Sequence[str] = SOURCE_SUFFIXES,
    max_file_bytes: int = 512_000
) -> List[DiscoveredFile]:
    """
    Find source files under a path, skipping vendored and generated code.

    Args:
        target: File or directory to scan
        extra_excludes: Additional glob patterns to skip
        use_gitignore: Honour simple .gitignore patterns
        suffixes: File extensions to include
        max_file_bytes: Skip files larger than this

    Returns:
        List[DiscoveredFile]: Discovered files ordered by descending risk
    """

    target_path = Path(target).resolve()

    if target_path.is_file():
        root = target_path.parent
        candidates = [target_path]
    else:
        root = target_path
        candidates = [p for p in target_path.rglob("*") if p.is_file()]

    patterns = list(DEFAULT_EXCLUDES) + list(extra_excludes)
    if use_gitignore:
        patterns.extend(load_gitignore_patterns(root))

    discovered: List[DiscoveredFile] = []
    skipped = 0

    for path in candidates:
        if path.suffix.lower() not in suffixes:
            continue
        # Reject symlinks or files that escape the scan root
        try:
            resolved = path.resolve()
            if resolved != root and root not in resolved.parents:
                logging.warning(f"Skipping path escaping scan root: {path} -> {resolved}")
                skipped += 1
                continue
        except (OSError, ValueError):
            continue

        if _is_excluded(path, root, patterns):
            skipped += 1
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                logging.debug(f"Skipping oversized file: {path}")
                skipped += 1
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logging.debug(f"Unreadable file {path}: {e}")
            continue

        if not content.strip():
            continue

        score, reasons = score_risk(content)
        discovered.append(DiscoveredFile(path, root, score, reasons))

    discovered.sort(key=lambda f: (-f.risk_score, f.relative))
    logging.info(
        "Discovery: %d file(s) selected, %d excluded, under %s",
        len(discovered), skipped, root
    )
    return discovered


def route_to_llm(
    files: Sequence[DiscoveredFile],
    rule_hits: Optional[Dict[str, int]] = None,
    min_risk: int = 3,
    limit: Optional[int] = None
) -> List[DiscoveredFile]:
    """
    Choose which files get an LLM call.

    A file qualifies when the rule tier already flagged something in it, or
    when its own risk signals clear the threshold. Note this selects *which
    files the LLM reads*, not which findings survive - inside a selected file
    the LLM still reports freely, so the recall advantage over a rule-only
    scan is preserved.

    Args:
        files: All discovered files
        rule_hits: Finding counts per relative path from the rule tier
        min_risk: Minimum risk score to qualify on signals alone
        limit: Cap on the number of files routed, highest risk first

    Returns:
        List[DiscoveredFile]: Files to send to the LLM tier
    """

    rule_hits = rule_hits or {}
    selected = [
        f for f in files
        if rule_hits.get(f.relative, 0) > 0 or f.risk_score >= min_risk
    ]

    if limit is not None and len(selected) > limit:
        dropped = len(selected) - limit
        # Never silently truncate coverage.
        logging.warning(
            "LLM routing capped at %d file(s); %d lower-risk file(s) not analysed "
            "by the LLM tier (rule tier still covered them).",
            limit, dropped
        )
        selected = selected[:limit]

    return selected
