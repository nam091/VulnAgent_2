"""Merge findings from the rule tier and the LLM tier into one result set.

The two tiers run independently so that agreement between them carries real
evidential weight. This module decides when two findings describe the same
defect, and how much to trust the result.
"""

import logging
import re
from typing import Dict, List, Optional, Tuple

from models.vulnerability import (
    FindingSource,
    Vulnerability,
    VulnerabilitySeverity,
)

# How far apart two findings may sit and still be considered the same defect.
# The LLM reports approximate lines even when prompted with numbered source,
# so a small window is needed; too wide and unrelated findings in dense code
# start collapsing into each other.
LINE_WINDOW = 4

# Confidence assigned to each provenance class.
CONFIDENCE = {
    FindingSource.CONFIRMED: 0.95,
    FindingSource.SEMGREP: 0.90,
    FindingSource.LLM: 0.55,
}

SEVERITY_RANK = {
    VulnerabilitySeverity.CRITICAL: 0,
    VulnerabilitySeverity.HIGH: 1,
    VulnerabilitySeverity.MEDIUM: 2,
    VulnerabilitySeverity.LOW: 3,
    VulnerabilitySeverity.INFO: 4,
}

# Types that describe the same underlying defect under different names.
# Matching on type alone would otherwise miss agreements where the two tiers
# label a finding at different levels of specificity.
TYPE_ALIASES: Tuple[frozenset, ...] = (
    frozenset({"SQL_INJECTION", "INJECTION", "INJECTION_FLAW"}),
    frozenset({"OS_COMMAND_INJECTION", "CODE_INJECTION", "REMOTE_CODE_EXECUTION_(RCE)"}),
    frozenset({"PATH_TRAVERSAL", "FILE_INCLUSION", "INSECURE_FILE_READ"}),
    frozenset({"HARDCODED_CREDENTIALS", "EXPOSED_SECRET", "BROKEN_AUTHENTICATION"}),
    frozenset({"SECURITY_MISCONFIGURATION", "INSECURE_CONFIGURATION_SETTING", "EXPOSED_FLASK_DEBUG"}),
    frozenset({"SENSITIVE_DATA_EXPOSURE", "EXPOSED_SENSITIVE_INFORMATION", "EXCESSIVE_DATA_EXPOSURE"}),
    frozenset({"WEAK_CRYPTOGRAPHY", "USE_OF_WEAK_HASHING_ALGORITHM"}),
    frozenset({"SECURE_RANDOMNESS", "INSECURE_RANDOM_SEEDING"}),
)


class FusionResult:
    """
    Outcome of merging the two tiers, with the breakdown kept for reporting.
    """

    def __init__(self, vulnerabilities: List[Vulnerability]) -> None:
        self.vulnerabilities = vulnerabilities

    @property
    def stats(self) -> Dict[str, int]:
        """
        Count findings by provenance.

        Returns:
            Dict[str, int]: Counts keyed by source name plus a total
        """

        counts = {source.value: 0 for source in FindingSource}
        for vuln in self.vulnerabilities:
            counts[vuln.source.value] += 1
        counts["TOTAL"] = len(self.vulnerabilities)
        return counts


def fuse(
    semgrep_findings: List[Vulnerability],
    llm_findings: List[Vulnerability]
) -> FusionResult:
    """
    Merge rule-tier and LLM-tier findings.

    Matching pairs become a single CONFIRMED finding that takes the rule
    engine's exact location and the LLM's explanation, remediation and proof
    of concept. Unmatched findings are kept and labelled with their origin -
    dropping LLM-only findings would discard the logic-level defects that no
    rule can express, which is the reason the LLM tier exists at all.

    Args:
        semgrep_findings: Findings from the rule tier
        llm_findings: Findings from the LLM tier

    Returns:
        FusionResult: The merged set
    """

    # Collapse near-duplicates inside each tier first. A model often reports
    # one defect twice under two names - PATH_TRAVERSAL and INSECURE_FILE_READ
    # on the same line - and without this both survive as separate findings.
    semgrep_findings = _deduplicate_tier(semgrep_findings)
    llm_findings = _deduplicate_tier(llm_findings)

    merged: List[Vulnerability] = []
    claimed_llm: set = set()

    for rule_finding in semgrep_findings:
        match = _find_match(rule_finding, llm_findings, claimed_llm)
        if match is None:
            rule_finding.source = FindingSource.SEMGREP
            rule_finding.confidence = CONFIDENCE[FindingSource.SEMGREP]
            merged.append(rule_finding)
            continue

        claimed_llm.add(id(match))
        merged.append(_combine(rule_finding, match))

    for llm_finding in llm_findings:
        if id(llm_finding) in claimed_llm:
            continue
        llm_finding.source = FindingSource.LLM
        llm_finding.confidence = CONFIDENCE[FindingSource.LLM]
        merged.append(llm_finding)

    merged.sort(
        key=lambda v: (
            SEVERITY_RANK[v.severity],
            -v.confidence,
            v.location.file_path,
            v.location.start_line
        )
    )

    logging.info(
        "Fusion: %d rule + %d llm -> %d merged",
        len(semgrep_findings), len(llm_findings), len(merged)
    )
    return FusionResult(merged)


def _deduplicate_tier(findings: List[Vulnerability]) -> List[Vulnerability]:
    """
    Collapse findings within one tier that describe the same defect.

    Two findings are treated as one when they sit in the same file, overlap
    positionally, and carry types that are exact matches or known aliases.
    The more severe finding wins; ties keep the richer description.

    Args:
        findings: Findings from a single tier

    Returns:
        List[Vulnerability]: One finding per distinct defect
    """

    kept: List[Vulnerability] = []
    for finding in sorted(
        findings,
        key=lambda f: (SEVERITY_RANK[f.severity], -len(f.description or ""))
    ):
        if any(
            _same_file(existing, finding)
            and _types_agree(existing, finding)
            and _line_distance(existing, finding) == 0
            for existing in kept
        ):
            logging.debug(
                "Intra-tier duplicate dropped: %s at L%d",
                finding.type.value, finding.location.start_line
            )
            continue
        kept.append(finding)

    return kept


def _find_match(
    rule_finding: Vulnerability,
    llm_findings: List[Vulnerability],
    claimed: set
) -> Optional[Vulnerability]:
    """
    Locate the LLM finding that describes the same defect, if any.

    Args:
        rule_finding: A finding from the rule tier
        llm_findings: All findings from the LLM tier
        claimed: ids of LLM findings already matched to another rule finding

    Returns:
        Optional[Vulnerability]: The best match, or None
    """

    candidates = []
    for llm_finding in llm_findings:
        if id(llm_finding) in claimed:
            continue
        if not _same_file(rule_finding, llm_finding):
            continue
        if not _types_agree(rule_finding, llm_finding):
            continue

        distance = _line_distance(rule_finding, llm_finding)
        if distance is None:
            continue
        candidates.append((distance, llm_finding))

    if not candidates:
        return None

    candidates.sort(key=lambda pair: pair[0])
    return candidates[0][1]


def _same_file(a: Vulnerability, b: Vulnerability) -> bool:
    """
    Compare file paths, tolerating absolute vs relative forms.

    Args:
        a: First finding
        b: Second finding

    Returns:
        bool: True when both refer to the same file
    """

    path_a = str(a.location.file_path).replace("\\", "/").lower()
    path_b = str(b.location.file_path).replace("\\", "/").lower()
    if not path_a or not path_b:
        return True  # single-file scans often omit the path on one side
    return path_a.endswith(path_b) or path_b.endswith(path_a)


def _types_agree(a: Vulnerability, b: Vulnerability) -> bool:
    """
    Decide whether two vulnerability types denote the same defect.

    Args:
        a: First finding
        b: Second finding

    Returns:
        bool: True on an exact match or a known alias pairing
    """

    if a.type == b.type:
        return True

    for alias_group in TYPE_ALIASES:
        if a.type.value in alias_group and b.type.value in alias_group:
            return True

    # CWE agreement is decisive when both sides supply one.
    cwe_a = _cwe_number(a.cwe_id)
    cwe_b = _cwe_number(b.cwe_id)
    return bool(cwe_a) and cwe_a == cwe_b


def _cwe_number(cwe_id: str) -> str:
    """
    Extract the numeric portion of a CWE identifier.

    Args:
        cwe_id: A string such as "CWE-89"

    Returns:
        str: The number, or "" when absent
    """

    match = re.search(r"(\d+)", str(cwe_id or ""))
    return match.group(1) if match else ""


def _line_distance(a: Vulnerability, b: Vulnerability) -> Optional[int]:
    """
    Measure how far apart two findings sit, treating overlap as zero.

    Args:
        a: First finding
        b: Second finding

    Returns:
        Optional[int]: Distance in lines, or None when beyond LINE_WINDOW
    """

    a_start, a_end = a.location.start_line, max(a.location.end_line, a.location.start_line)
    b_start, b_end = b.location.start_line, max(b.location.end_line, b.location.start_line)

    if a_start <= b_end and b_start <= a_end:
        return 0

    gap = b_start - a_end if b_start > a_end else a_start - b_end
    return gap if gap <= LINE_WINDOW else None


def _combine(rule_finding: Vulnerability, llm_finding: Vulnerability) -> Vulnerability:
    """
    Build one CONFIRMED finding from an agreeing pair.

    Position comes from the rule engine, which is exact. Everything a
    developer actually reads - description, impact, remediation, proof of
    concept, secure example - comes from the LLM, which is the only tier
    that produces them. Severity takes the more serious of the two.

    Args:
        rule_finding: The rule-tier finding
        llm_finding: The matching LLM-tier finding

    Returns:
        Vulnerability: The combined finding
    """

    severity = min(
        rule_finding.severity,
        llm_finding.severity,
        key=lambda s: SEVERITY_RANK[s]
    )

    combined = llm_finding.model_copy(deep=True)
    combined.location = rule_finding.location.model_copy(deep=True)
    combined.severity = severity
    combined.source = FindingSource.CONFIRMED
    combined.confidence = CONFIDENCE[FindingSource.CONFIRMED]
    combined.rule_id = rule_finding.rule_id
    combined.merged_rule_ids = list(rule_finding.merged_rule_ids)

    if not combined.cwe_id and rule_finding.cwe_id:
        combined.cwe_id = rule_finding.cwe_id
    if not combined.owasp_category and rule_finding.owasp_category:
        combined.owasp_category = rule_finding.owasp_category

    seen = set(combined.references)
    combined.references.extend(
        ref for ref in rule_finding.references if ref not in seen
    )

    # Recompute the fingerprint: the location just changed, so the id derived
    # from the LLM's approximate snippet is no longer the right anchor.
    combined.id = ""
    combined.id = combined.fingerprint()

    return combined
