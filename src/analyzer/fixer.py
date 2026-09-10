"""Apply the secure rewrites the LLM tier produces.

The model already emits a `secure_code_example` for every finding, but a
suggestion is not a patch: it arrives with its own indentation, sometimes
spans more or less than the reported region, and is occasionally not valid
code at all. Everything here exists to refuse a bad patch rather than
corrupt a source file with it.
"""

import ast
import difflib
import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from models.vulnerability import FindingSource, Vulnerability


class PatchRisk(str):
    """Describes whether a patch passed structural syntax checks or requires human review."""

    def __eq__(self, other: Any) -> bool:
        if str(self) == "passed_structural_check" and other in ("safe", "passed_structural_check"):
            return True
        if str(self) == "review_required" and other in ("review", "review_required"):
            return True
        return super().__eq__(other)

    def __hash__(self) -> int:
        return super().__hash__()


# Text that betrays a suggestion the model never grounded in the real code.
PLACEHOLDER_PATTERN = re.compile(
    r"/safe/dir|/path/to|your[_-]|example\.com|CHANGE[_-]?ME|TODO|\.\.\.|<[a-z_]+>",
    re.IGNORECASE
)
CONTROL_FLOW = re.compile(r"^\s*(if|for|while|try|with|def|class|elif|else|except)\b")


def classify_patch(original: str, replacement: str) -> List[str]:
    """
    List the reasons a suggested rewrite needs a human to read it.

    Syntax validation cannot catch a rewrite that parses but changes
    behaviour - duplicating a `return`, nesting a new `if` inside the block
    it was meant to replace, or hard-coding a placeholder path. Those shapes
    are detected here so a patch can be held back rather than applied blind.

    Kept as a free function so every surface - CLI, API, MCP - classifies a
    patch the same way instead of each inventing its own rule.

    Args:
        original: The code being replaced
        replacement: The proposed code

    Returns:
        List[str]: Reasons, empty when the patch is a clean substitution
    """

    reasons = []
    original_lines = [l for l in original.split("\n") if l.strip()]
    new_lines = [l for l in replacement.split("\n") if l.strip()]

    if PLACEHOLDER_PATTERN.search(replacement):
        reasons.append("contains a placeholder the model invented")

    if len(new_lines) > len(original_lines) + 1:
        reasons.append(f"expands {len(original_lines)} line(s) into {len(new_lines)}")

    added_imports = [
        l.strip() for l in new_lines
        if re.match(r"^\s*(import|from)\s", l) and l.strip() not in original
    ]
    if added_imports:
        reasons.append(f"introduces import(s): {', '.join(added_imports[:2])}")

    original_flow = sum(1 for l in original_lines if CONTROL_FLOW.match(l))
    new_flow = sum(1 for l in new_lines if CONTROL_FLOW.match(l))
    if new_flow > original_flow:
        reasons.append("adds control flow that was not in the original")

    # A `return` appearing in the replacement when the original had none is
    # the shape that silently duplicates the statement below it.
    if "return" in replacement and "return" not in original:
        reasons.append("introduces a return statement")

    # Constant return or trivial bypass (e.g. replacing auth check with return True)
    if re.search(r"^\s*return\s+(True|False|None|\d+|['\"].*['\"])\s*$", replacement, re.MULTILINE):
        if not re.search(r"^\s*return\s+(True|False|None|\d+|['\"].*['\"])\s*$", original, re.MULTILINE):
            reasons.append("replaces dynamic logic with a constant return")

    if re.search(r"^\s*(pass|\.\.\.)\s*$", replacement, re.MULTILINE):
        if not re.search(r"^\s*(pass|\.\.\.)\s*$", original, re.MULTILINE):
            reasons.append("replaces logic with a no-op statement")

    return reasons


def unified_diff(original: str, replacement: str, label: str = "patch") -> str:
    """
    Render a unified diff between two code fragments.

    Args:
        original: Current code
        replacement: Proposed code
        label: Name shown in the diff header

    Returns:
        str: A unified diff
    """

    return "".join(difflib.unified_diff(
        original.splitlines(keepends=True),
        replacement.splitlines(keepends=True),
        fromfile=f"{label} (current)",
        tofile=f"{label} (proposed)",
        n=1
    ))


@dataclass
class Patch:
    """
    One proposed edit to one file.
    """

    vulnerability: Vulnerability
    file_path: Path
    start_line: int
    end_line: int
    original: str
    replacement: str
    reason: str = ""

    @property
    def risk(self) -> PatchRisk:
        """
        Whether this patch passed structural verification or requires human review.
        """
        return PatchRisk("passed_structural_check" if not self.risk_reasons else "review_required")

    @property
    def formal_check_status(self) -> str:
        return "passed_structural_check" if not self.risk_reasons else "review_required"

    @property
    def risk_reasons(self) -> List[str]:
        """
        Why this patch needs a human to look at it.

        Returns:
            List[str]: Reasons, empty when the patch is a clean substitution
        """

        return classify_patch(self.original, self.replacement)

    @property
    def diff(self) -> str:
        """
        Unified diff between the original and replacement text.

        Returns:
            str: A rendered diff
        """

        return "".join(difflib.unified_diff(
            self.original.splitlines(keepends=True),
            self.replacement.splitlines(keepends=True),
            fromfile=f"{self.file_path.name}:{self.start_line} (current)",
            tofile=f"{self.file_path.name}:{self.start_line} (proposed)",
            n=1
        ))


@dataclass
class PatchPlan:
    """
    Every patch that survived validation, plus what was rejected and why.
    """

    patches: List[Patch] = field(default_factory=list)
    rejected: List[Tuple[Vulnerability, str]] = field(default_factory=list)
    snapshot_hashes: Dict[Path, str] = field(default_factory=dict)
    conflicts: List[Tuple[Vulnerability, str]] = field(default_factory=list)
    stale: bool = False

    @property
    def by_file(self) -> Dict[Path, List[Patch]]:
        """
        Group patches by target file.

        Returns:
            Dict[Path, List[Patch]]: Patches keyed by path
        """

        grouped: Dict[Path, List[Patch]] = {}
        for patch in self.patches:
            grouped.setdefault(patch.file_path, []).append(patch)
        return grouped


def _strip_fences(text: str) -> str:
    """
    Remove markdown code fences from a suggested rewrite.

    Args:
        text: The raw suggestion

    Returns:
        str: The suggestion without fences
    """

    fenced = re.match(r"^```(?:\w+)?\s*\n([\s\S]*?)\n?```\s*$", text.strip())
    if fenced:
        return fenced.group(1)
    return text.strip("\n")


def _leading_indent(line: str) -> str:
    """
    Extract the whitespace prefix of a line.

    Args:
        line: A source line

    Returns:
        str: The leading whitespace
    """

    return line[:len(line) - len(line.lstrip())]


def _reindent(replacement: str, target_indent: str) -> str:
    """
    Re-indent a suggestion to sit at the same level as the code it replaces.

    Models emit snippets at whatever indentation reads well in isolation,
    usually column zero. Splicing that into a method body produces a file
    that no longer parses.

    Args:
        replacement: The suggested code
        target_indent: Indentation of the first replaced line

    Returns:
        str: The suggestion re-indented
    """

    lines = replacement.split("\n")
    non_empty = [line for line in lines if line.strip()]
    if not non_empty:
        return replacement

    common = min(len(_leading_indent(line)) for line in non_empty)
    rebased = []
    for line in lines:
        if not line.strip():
            rebased.append("")
        else:
            rebased.append(target_indent + line[common:])
    return "\n".join(rebased)


def build_plan(
    vulnerabilities: Sequence[Vulnerability],
    root: Path,
    confirmed_only: bool = False,
    baseline_hashes: Optional[Dict[Any, str]] = None,
    require_baseline: bool = False,
) -> PatchPlan:
    """
    Turn findings into validated patches.

    Args:
        vulnerabilities: Findings that may carry a secure rewrite
        root: Directory that finding paths are relative to
        confirmed_only: Only patch findings corroborated by both tiers
        baseline_hashes: Expected file hashes from scan analysis snapshot
        require_baseline: Reject patches if baseline analysis hash is missing

    Returns:
        PatchPlan: Accepted patches and rejection reasons
    """

    plan = PatchPlan()
    file_cache: Dict[Path, List[str]] = {}
    claimed: Dict[Path, List[Tuple[int, int]]] = {}

    # Highest line first, so that applying one patch cannot shift the line
    # numbers of a patch that has not been applied yet.
    ordered = sorted(
        vulnerabilities,
        key=lambda v: (str(v.location.file_path), -(v.location.start_line or 0))
    )

    for vuln in ordered:
        if confirmed_only and vuln.source != FindingSource.CONFIRMED:
            plan.rejected.append((vuln, "not corroborated by both tiers"))
            continue

        suggestion = _strip_fences(vuln.secure_code_example or "")
        if not suggestion.strip():
            plan.rejected.append((vuln, "no secure_code_example provided"))
            continue

        file_path = (root / vuln.location.file_path).resolve()
        if not file_path.is_file():
            plan.rejected.append((vuln, f"file not found: {vuln.location.file_path}"))
            continue

        if file_path not in file_cache:
            try:
                content = file_path.read_text(encoding="utf-8")
                file_cache[file_path] = content.split("\n")
                plan.snapshot_hashes[file_path] = hashlib.sha256(content.encode("utf-8")).hexdigest()
            except OSError as e:
                plan.rejected.append((vuln, f"unreadable: {e}"))
                continue

        current_hash = plan.snapshot_hashes[file_path]

        # Check analysis baseline contract (analysis -> plan)
        expected_baseline = getattr(vuln, "file_hash", None)
        if not expected_baseline and baseline_hashes:
            expected_baseline = (
                baseline_hashes.get(file_path)
                or baseline_hashes.get(str(file_path))
                or baseline_hashes.get(vuln.location.file_path)
            )
            if not expected_baseline:
                try:
                    rel_p = file_path.relative_to(root).as_posix()
                    expected_baseline = baseline_hashes.get(rel_p)
                except Exception:
                    pass

        if expected_baseline is not None:
            if current_hash != expected_baseline:
                plan.rejected.append((
                    vuln,
                    f"file modified since analysis: baseline hash mismatch "
                    f"(expected {expected_baseline[:8]}, current {current_hash[:8]}); "
                    f"stale suggestion requires re-scan"
                ))
                plan.conflicts.append((vuln, f"stale baseline mismatch for {vuln.location.file_path}"))
                plan.stale = True
                continue
        elif require_baseline:
            plan.rejected.append((
                vuln,
                f"missing baseline analysis hash for {vuln.location.file_path}; requires re-scan"
            ))
            plan.conflicts.append((vuln, f"missing baseline analysis hash for {vuln.location.file_path}"))
            plan.stale = True
            continue

        lines = file_cache[file_path]
        start = max(1, vuln.location.start_line or 0)
        end = max(start, vuln.location.end_line or start)

        if start > len(lines):
            plan.rejected.append((vuln, "reported line is past end of file"))
            continue
        end = min(end, len(lines))

        spans = claimed.setdefault(file_path, [])
        if any(not (end < s or start > e) for s, e in spans):
            plan.rejected.append((vuln, "overlaps an already-planned patch"))
            continue

        original = "\n".join(lines[start - 1:end])
        replacement = _reindent(suggestion, _leading_indent(lines[start - 1]))

        if replacement.strip() == original.strip():
            plan.rejected.append((vuln, "suggestion is identical to current code"))
            continue

        valid, error = _validate(lines, start, end, replacement, file_path)
        if not valid:
            plan.rejected.append((vuln, f"patched file would not parse: {error}"))
            continue

        spans.append((start, end))
        plan.patches.append(Patch(
            vulnerability=vuln,
            file_path=file_path,
            start_line=start,
            end_line=end,
            original=original,
            replacement=replacement,
            reason=vuln.remediation or ""
        ))

    return plan


def _validate(
    lines: List[str],
    start: int,
    end: int,
    replacement: str,
    file_path: Path
) -> Tuple[bool, str]:
    """
    Check that applying a patch leaves the file syntactically valid.

    This is the safety net that makes automatic application defensible: a
    suggestion that would break the file is discarded before it is written,
    not after.

    Args:
        lines: Current file lines
        start: First replaced line, 1-based
        end: Last replaced line, 1-based
        replacement: Proposed text
        file_path: Used to decide whether syntax checking applies

    Returns:
        Tuple[bool, str]: Validity and an error message when invalid
    """

    if file_path.suffix.lower() != ".py":
        return True, ""  # only Python can be verified here

    candidate = lines[:start - 1] + replacement.split("\n") + lines[end:]
    source = "\n".join(candidate)

    try:
        ast.parse(source)
    except SyntaxError as e:
        return False, f"line {e.lineno}: {e.msg}"
    return True, ""


def apply_plan(
    plan: PatchPlan,
    dry_run: bool = False,
    expected_snapshot_hashes: Optional[Dict[Path, str]] = None,
) -> Dict[str, Any]:
    """
    Write the planned patches to disk.

    The original content of every touched file is returned so the caller can
    put it back if verification shows the patch made things worse.

    Args:
        plan: The validated plan
        dry_run: Report what would change without writing
        expected_snapshot_hashes: Optional file hashes to prevent applying on stale/modified files

    Returns:
        Dict[str, Any]: Counts, plus a backup of each file's prior content and written hashes
    """

    applied = 0
    files_changed = 0
    backups: Dict[Path, str] = {}
    written_hashes: Dict[Path, str] = {}

    expected_hashes = expected_snapshot_hashes if expected_snapshot_hashes is not None else getattr(plan, "snapshot_hashes", None)

    for file_path, patches in plan.by_file.items():
        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError as e:
            logging.error(f"Cannot read {file_path}: {e}")
            continue

        if expected_hashes is not None:
            if file_path not in expected_hashes:
                logging.warning(
                    f"No baseline snapshot hash recorded for {file_path}; skipping patch to protect unverified file."
                )
                continue
            current_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if current_hash != expected_hashes[file_path]:
                logging.warning(
                    f"File {file_path} modified on disk since plan creation (hash mismatch); skipping patch to avoid corrupting stale lines."
                )
                continue

        backups[file_path] = content
        lines = content.split("\n")

        # Descending order keeps earlier line numbers valid as we splice.
        for patch in sorted(patches, key=lambda p: -p.start_line):
            lines[patch.start_line - 1:patch.end_line] = patch.replacement.split("\n")
            applied += 1

        if dry_run:
            files_changed += 1
            continue

        full_text = "\n".join(lines)
        if file_path.suffix.lower() == ".py":
            try:
                ast.parse(full_text)
            except SyntaxError as e:
                logging.error(f"Cannot apply coordinated patches to {file_path}: syntax error: {e}")
                continue

        try:
            file_path.write_text(full_text, encoding="utf-8")
            written_hashes[file_path] = hashlib.sha256(full_text.encode("utf-8")).hexdigest()
            files_changed += 1
        except OSError as e:
            logging.error(f"Cannot write {file_path}: {e}")

    return {
        "patches_applied": applied,
        "files_changed": files_changed,
        "rejected": len(plan.rejected),
        "backups": backups,
        "written_hashes": written_hashes,
    }


def revert(
    backups: Dict[Path, str],
    expected_current_hashes: Optional[Dict[Path, str]] = None,
) -> int:
    """
    Restore files to their pre-patch content.
    Only restores when current file matches expected written content,
    preventing accidental overwriting of concurrent user edits.

    Args:
        backups: Mapping of path to original content
        expected_current_hashes: Hashes written by fixer to verify before rollback

    Returns:
        int: How many files were restored
    """

    restored = 0
    for file_path, content in backups.items():
        try:
            if expected_current_hashes and file_path in expected_current_hashes:
                current_on_disk = file_path.read_text(encoding="utf-8")
                actual_hash = hashlib.sha256(current_on_disk.encode("utf-8")).hexdigest()
                if actual_hash != expected_current_hashes[file_path]:
                    logging.warning(
                        f"File {file_path} was modified concurrently after patch; skipping rollback to preserve edits."
                    )
                    continue
            file_path.write_text(content, encoding="utf-8")
            restored += 1
        except OSError as e:
            logging.error(f"Cannot restore {file_path}: {e}")
    return restored
