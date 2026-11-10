"""Declared CWE scope for benchmark scoring.

The thesis fixes a 10-CWE core scope. Ground truth, clean-file controls and
detections are all filtered to this scope at *scoring* time, so previously
stored scan results can be re-scored without re-running any scan.

Excluded on purpose:
    CWE-328 (weak hashing), CWE-601 (open redirect),
    CWE-614 (secure cookie), CWE-501 (trust boundary violation)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Set, Tuple

#: Canonical order used in reports and the UI.
#:
#: Every entry below exists in BOTH benchmark suites: the OWASP Python 100
#: subset and the full 1230-file suite. The intersection of the two suites is
#: 11 CWEs; CWE-601 is dropped because the 100-file suite ships only 2 cases
#: for it (recall falls in 50-point steps), leaving this 10-CWE scope.
#:
#: CWE-90 (LDAP) is deliberately absent: the 100-file subset contains no LDAP
#: test case, so including it would make the two suites incomparable.
CORE_CWE_SCOPE: Tuple[str, ...] = (
    "22",   # Path Traversal
    "78",   # OS Command Injection
    "79",   # Cross-Site Scripting
    "89",   # SQL Injection
    "94",   # Code Injection
    "328",  # Use of Weak Hashing Algorithm
    "330",  # Secure Randomness
    "502",  # Insecure Deserialization
    "611",  # XML External Entity
    "643",  # XPath Injection
)

CORE_CWE_SET: Set[str] = set(CORE_CWE_SCOPE)

CORE_CWE_TITLES: Dict[str, str] = {
    "22": "Path Traversal",
    "78": "OS Command Injection",
    "79": "Cross-Site Scripting",
    "89": "SQL Injection",
    "94": "Code Injection",
    "328": "Use of Weak Hashing Algorithm",
    "330": "Secure Randomness",
    "502": "Insecure Deserialization",
    "611": "XML External Entity",
    "643": "XPath Injection",
}

EXCLUDED_CWE_TITLES: Dict[str, str] = {
    "90": "LDAP Injection (no case in the 100-file suite)",
    "501": "Trust Boundary Violation (no case in the 100-file suite)",
    "601": "Unvalidated Redirects and Forwards (2 cases only in the 100-file suite)",
    "614": "Secure Cookie (no case in the 100-file suite)",
}

SCOPE_ID = "core10"
SCOPE_LABEL = "10-CWE core scope"


def normalize_cwe(value: Any) -> str:
    """
    Reduce any CWE notation to a bare identifier.

    Args:
        value: "CWE-89", "cwe-89", 89, "89"

    Returns:
        str: "89"
    """

    text = str(value or "").strip().upper()
    if text.startswith("CWE-"):
        text = text[4:]
    elif text.startswith("CWE_"):
        text = text[4:]
    return text.strip()


def in_scope(cwe: Any) -> bool:
    """
    Whether a CWE identifier belongs to the declared core scope.

    Args:
        cwe: Any CWE representation

    Returns:
        bool: True when inside the 10-CWE scope
    """

    return normalize_cwe(cwe) in CORE_CWE_SET


def _entry_cwe(entry: Any) -> str:
    if isinstance(entry, dict):
        return normalize_cwe(entry.get("cwe") or entry.get("cwe_id"))
    return ""


def filter_labels(labels: Sequence[Any]) -> List[Any]:
    """
    Keep only ground-truth labels inside the core scope.

    Args:
        labels: Label objects carrying a .cwe attribute

    Returns:
        List[Any]: Filtered labels, original order preserved
    """

    kept: List[Any] = []
    for label in labels:
        cwe = getattr(label, "cwe", None)
        if cwe is None and isinstance(label, dict):
            cwe = label.get("cwe")
        if in_scope(cwe):
            kept.append(label)
    return kept


def filter_clean_files(meta: Dict[str, Any]) -> List[str]:
    """
    Keep only clean-file controls whose labelled CWE is inside the core scope.

    A clean file with no CWE attribution is kept, because it carries no
    out-of-scope signal to filter on.

    Args:
        meta: Dataset metadata from load_dataset()

    Returns:
        List[str]: Clean-file paths in scope
    """

    controls = meta.get("clean_file_controls") or []
    if controls:
        kept: List[str] = []
        for entry in controls:
            cwe = _entry_cwe(entry)
            path = entry.get("file") if isinstance(entry, dict) else entry
            if not path:
                continue
            if cwe and cwe not in CORE_CWE_SET:
                continue
            kept.append(Path(str(path)).as_posix())
        return kept

    return [Path(str(entry)).as_posix() for entry in (meta.get("clean_files") or [])]


def filter_detections(detections: Sequence[Any]) -> List[Any]:
    """
    Keep only detections whose CWE is inside the core scope.

    Out-of-scope detections are dropped rather than counted as false
    positives: scoring a 10-CWE scope must not punish a scanner for reporting
    a real defect from a CWE this scope never declared.

    Args:
        detections: Detection objects carrying a .cwe attribute

    Returns:
        List[Any]: Filtered detections
    """

    return [d for d in detections if in_scope(getattr(d, "cwe", None))]


def scope_coverage(labels: Sequence[Any]) -> Dict[str, Any]:
    """
    Report which declared CWEs actually have ground truth in this dataset.

    The 100-file OWASP subset ships no LDAP case, so a scope can be declared
    as 10 CWEs while a given dataset only exercises 9 of them. Saying so
    explicitly keeps the report honest.

    Args:
        labels: Filtered labels

    Returns:
        Dict[str, Any]: Coverage summary
    """

    present: List[str] = []
    for cwe in CORE_CWE_SCOPE:
        if any(normalize_cwe(getattr(l, "cwe", None)) == cwe for l in labels):
            present.append(cwe)

    return {
        "scope_id": SCOPE_ID,
        "scope_label": SCOPE_LABEL,
        "declared_cwes": list(CORE_CWE_SCOPE),
        "declared_titles": {k: CORE_CWE_TITLES[k] for k in CORE_CWE_SCOPE},
        "excluded_cwes": dict(EXCLUDED_CWE_TITLES),
        "present_cwes": present,
        "absent_cwes": [c for c in CORE_CWE_SCOPE if c not in present],
        "coverage": f"{len(present)}/{len(CORE_CWE_SCOPE)}",
    }
