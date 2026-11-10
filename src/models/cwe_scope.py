"""Declared CWE scope for benchmark scoring.

The thesis fixes a 10-CWE core scope. Ground truth, clean-file controls and
detections are all filtered to this scope at *scoring* time, so previously
stored scan results can be re-scored without re-running any scan. Detection
CWEs equivalent to an in-scope CWE remain eligible when scoring by equivalence.

Excluded on purpose:
    CWE-90 (LDAP injection), CWE-601 (open redirect),
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

# Engines can classify the same defect under different, equally defensible
# CWEs. Equivalence scoring avoids penalizing detections for that difference.
CWE_EQUIVALENCE: Tuple[Set[str], ...] = (
    {"798", "259", "260", "321", "1168"},            # hard-coded credentials / secret keys
    {"326", "327", "328", "916"},                   # weak crypto / hashing
    {"330", "335", "338"},                          # insecure randomness
    {"16", "605", "668", "489", "1188"},            # misconfiguration / exposure
    {"22", "23", "35", "36", "73"},                 # path traversal
    {"79", "80", "116", "83"},                      # cross-site scripting
    {"77", "78", "88"},                             # command injection
    {"94", "95", "96"},                             # code injection
    {"611", "827"},                                 # XML external entity (XXE)
    {"776", "400"},                                 # XML entity expansion / DoS
    {"502", "915"},                                 # deserialization
    {"89", "564", "943"},                           # SQL injection
    {"918", "441"},                                 # SSRF
    {"287", "306", "521", "307"},                   # broken authentication
    {"284", "862", "863", "639", "285"},            # access control / IDOR
    {"200", "209", "532", "213", "359"},            # information exposure
    {"208", "385", "203"},                          # timing attack / observable timing discrepancy
    {"20", "1287", "1288"},                         # improper input validation
    {"90"},                                         # LDAP injection
)


def cwe_matches(detected: str, labelled: str, exact: bool = False) -> bool:
    """
    Decide whether two CWE identifiers denote the same defect.

    Args:
        detected: CWE number reported by an engine
        labelled: CWE number recorded in the dataset
        exact: Require exact numerical match without equivalence class

    Returns:
        bool: True on match, False on mismatch or missing CWE
    """

    det = (detected or "").strip().upper().replace("CWE-", "")
    lab = (labelled or "").strip().upper().replace("CWE-", "")

    if not det or not lab:
        return False  # missing CWE cannot claim a match
    if det == lab:
        return True
    if exact:
        return False
    return any(
        det in group and lab in group
        for group in CWE_EQUIVALENCE
    )


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


def eligible(cwe: Any, scope: str = "core10", exact_cwe: bool = False) -> bool:
    """
    Decide whether a detection CWE may be scored under the given scope.

    A detection stays scoreable when its CWE is equivalent to at least one
    in-scope CWE under the active matching mode. Dropping it before matching
    would turn an equivalence match into a silent false negative.

    ``scope="full"`` declares no CWE restriction at all, so it keeps every
    detection including ones whose engine could not attribute a CWE. Those
    unattributed detections are real output of the engine under test: at full
    scope they must reach matching and be scored as false positives when they
    match no label. Filtering them out first would silently inflate precision.
    """

    if scope == "full":
        return True
    normalized = normalize_cwe(cwe)
    if not normalized:
        return False
    return any(cwe_matches(normalized, c, exact=exact_cwe) for c in CORE_CWE_SCOPE)


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


def filter_detections(detections: Sequence[Any], scope: str = "core10", exact_cwe: bool = False) -> List[Any]:
    """
    Keep detections eligible under the scope and CWE matching mode.

    Out-of-scope detections are dropped rather than counted as false
    positives: scoring a 10-CWE scope must not punish a scanner for reporting
    a real defect from a CWE this scope never declared. Equivalent detections
    remain scoreable unless exact CWE matching is requested.

    At ``scope="full"`` nothing is filtered. That includes detections with no
    CWE at all (Bandit/Semgrep rules without a CWE mapping): they stay and are
    scored as false positives when unmatched, which is what the "full" scope
    claims to measure.

    Args:
        detections: Detection objects carrying a .cwe attribute
        scope: "core10" or "full"
        exact_cwe: Require exact numerical match without equivalence class

    Returns:
        List[Any]: Filtered detections
    """

    return [d for d in detections if eligible(getattr(d, "cwe", None), scope=scope, exact_cwe=exact_cwe)]


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
