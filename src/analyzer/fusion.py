"""Merge findings from the rule tier and the LLM tier into one result set.

The two tiers run independently so that agreement between them carries real
evidential weight. This module decides when two findings describe the same
defect, and how much to trust the result.
"""

import copy
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from models.vulnerability import (
    FindingSource,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityType,
)

# How far apart two findings may sit and still be treated as agreement between
# the tiers. The LLM reports approximate lines even when prompted with numbered
# source, and static analyzers often anchor on imports or variable
# initializations several lines before the actual sink call, so cross-tier
# matching tolerates a window of 12 lines.
#
# The window is NOT an identity proof and is never applied where identity is
# available:
#   - not inside one tier (see is_same_sink), because two distinct sinks in one
#     file sit inside any window and merging them deletes a true positive;
#   - not across tiers when either side's trace names a sink point, because that
#     point is exact and a nearby line is a different program point;
#   - not across tiers when either side's trace records any step but no sink
#     point, because a recorded flow is a claim about a specific point and not
#     evidence that the finding was untraced;
#   - not as a substitute for an identity match: a pair proven the same sink
#     always outranks a pair that is merely close (see _find_match).
LINE_WINDOW = 12

# Confidence assigned to each provenance class.
CONFIDENCE = {
    FindingSource.CONFIRMED: 0.98,
    FindingSource.SEMGREP: 0.90,
    FindingSource.LLM: 0.55,
}

# Kinds that mark the terminal program point of a traced flow. A taint path
# that carries one of these identifies its sink exactly; a path that carries
# none is not proof of identity and is treated as untraced.
SINK_STEP_KINDS = ("sink", "imported_sink")

SEVERITY_RANK = {
    VulnerabilitySeverity.CRITICAL: 0,
    VulnerabilitySeverity.HIGH: 1,
    VulnerabilitySeverity.MEDIUM: 2,
    VulnerabilitySeverity.LOW: 3,
    VulnerabilitySeverity.INFO: 4,
}

# Ordering for collapsing two findings that describe one sink when they carry
# different verification states. The stronger conclusion survives, so a
# survivor is never left at 'unreviewed' while its own verification says the
# finding was confirmed - a self-contradictory pair that the post-verification
# deduplication, which keys on this field, then handles wrongly.
#
# Unknown or empty values rank 0: an unrecognised state is not evidence of a
# stronger conclusion, so it never raises a survivor's rank.
ASSESSMENT_RANK = {
    "supported": 4,
    "uncertain": 3,
    "refuted": 2,
    "unreviewed": 1,
    "": 0,
    None: 0,
}

# Two states that are each other's negation. Both cannot be true of one sink,
# so a pair holding them is not a duplicate to collapse: picking one would
# discard a real verdict on the strength of a sort order that has no evidence
# behind it. These stay two findings for a human to review (fail closed).
CONTRADICTORY_STATUSES = frozenset({"supported", "refuted"})

# The same negation one level down, on the verification record itself. A pair
# holding one 'confirmed' and one 'refuted' verification holds two exclusive
# statements about one sink; folding it would attach one tier's verdict to the
# other tier's evidence. Kept as two findings (fail closed).
CONTRADICTORY_VERDICTS = frozenset({"confirmed", "refuted"})

# Types that describe the same underlying defect under different names.
# Matching on type alone would otherwise miss agreements where the two tiers
# label a finding at different levels of specificity.
TYPE_ALIASES: Tuple[frozenset, ...] = (
    frozenset({"SQL_INJECTION", "INJECTION", "INJECTION_FLAW"}),
    frozenset({"LDAP_INJECTION", "INJECTION", "INJECTION_FLAW"}),
    frozenset({"OS_COMMAND_INJECTION", "REMOTE_CODE_EXECUTION_(RCE)"}),
    frozenset({"CODE_INJECTION"}),
    frozenset({"PATH_TRAVERSAL", "FILE_INCLUSION", "INSECURE_FILE_READ"}),
    frozenset({"HARDCODED_CREDENTIALS", "EXPOSED_SECRET"}),
    frozenset({"BROKEN_AUTHENTICATION"}),
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
    llm_findings: List[Vulnerability],
    suppress_unconfirmed_rules: bool = False,
    file_analyzed_by_llm: bool = False,
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
        suppress_unconfirmed_rules: When True and file was analyzed by LLM,
            suppress rule findings that find no matching LLM finding.
        file_analyzed_by_llm: Whether the file was analyzed by the LLM tier.

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
            # Suppression exists to drop rule findings the LLM tier had a chance
            # to confirm and did not. A finding the LLM tier explicitly
            # contradicted is not in that set: _find_match returns None for it
            # because verdicts_conflict refused to pair the two, and reading
            # that refusal as "the LLM did not confirm" deleted a finding that
            # already carries confirming evidence. Both sides are kept so a
            # reviewer sees the disagreement (fail closed).
            if (
                suppress_unconfirmed_rules
                and file_analyzed_by_llm
                and not _is_reliable_rule_finding(rule_finding)
                and not _has_conflicting_counterpart(rule_finding, llm_findings)
            ):
                # If finding is generic path traversal, warning, or not a reliable
                # high-risk specific rule, suppress it to prevent FP inflation.
                # Only specific reliable high-risk rules (CRITICAL/HIGH specific rule_id)
                # are preserved when unconfirmed by LLM.
                continue
            rule_finding.source = FindingSource.SEMGREP
            rule_finding.engine_sources = ["SEMGREP"]
            rule_finding.confidence = CONFIDENCE[FindingSource.SEMGREP]
            merged.append(rule_finding)
            continue

        claimed_llm.add(id(match))
        merged.append(_combine(rule_finding, match))

    for llm_finding in llm_findings:
        if id(llm_finding) in claimed_llm:
            continue
        llm_finding.source = FindingSource.LLM
        llm_finding.engine_sources = ["LLM"]
        llm_finding.confidence = CONFIDENCE[FindingSource.LLM]
        merged.append(llm_finding)

    # The trailing keys are tie-breaks, not preferences. Two findings kept side
    # by side because their verdicts contradict each other routinely share
    # severity, confidence, file and line, and a sort that stops there leaves
    # their output order to the order the input happened to arrive in - the same
    # scan then serialises differently run to run. No key here decides which
    # finding survives; that is settled earlier, by evidence.
    merged.sort(
        key=lambda v: (
            SEVERITY_RANK[v.severity],
            -v.confidence,
            v.location.file_path,
            v.location.start_line,
            _cwe_number(v.cwe_id),
            str(getattr(v, "assessment_status", "") or ""),
            str(v.id or ""),
        )
    )

    logging.info(
        "Fusion: %d rule + %d llm -> %d merged",
        len(semgrep_findings), len(llm_findings), len(merged)
    )
    return FusionResult(merged)


def _is_reliable_rule_finding(rule_finding: Vulnerability) -> bool:
    """
    Check whether a rule finding is from a specific, reliable, high-risk rule.

    Generic warnings, generic path traversal rules (e.g. CWE-22, os.path.join,
    or generic open), and medium/low severity rules are suppressed to prevent
    false-positive inflation. Only specific high-risk rules (CRITICAL or HIGH
    with a concrete rule identifier) are retained.

    Args:
        rule_finding: Finding produced by the rule engine

    Returns:
        bool: True if finding is a specific reliable rule, False if generic/suppressed
    """

    rule_ids = [rule_finding.rule_id] if rule_finding.rule_id else []
    rule_ids.extend(rule_finding.merged_rule_ids or [])
    rule_ids = [r.strip() for r in rule_ids if r and r.strip()]

    if not rule_ids:
        return False

    # Must be CRITICAL or HIGH severity
    if rule_finding.severity not in (VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH):
        return False

    cwe = _cwe_number(rule_finding.cwe_id)

    # Generic path traversal rules (e.g. CWE-22, os.path.join, generic open)
    if cwe in ("22", "23", "35", "36", "73") or rule_finding.type in (
        VulnerabilityType.PATH_TRAVERSAL,
        VulnerabilityType.INSECURE_FILE_READ,
    ):
        return False

    # Check for generic/audit/warning keywords in rule IDs
    for rid in rule_ids:
        rid_lower = rid.lower()
        if any(k in rid_lower for k in ("path-traversal", "path_traversal", "generic", "audit", "warning", "info")):
            return False

    # Context / snippet / description indicating generic path / os.path.join
    loc_ctx = (getattr(rule_finding.location, "context", "") or "").lower()
    desc_lower = (rule_finding.description or "").lower()
    ctx_lower = (getattr(rule_finding, "context", "") or "").lower()
    if "os.path.join" in loc_ctx or "os.path.join" in desc_lower or "os.path.join" in ctx_lower:
        return False

    return True


def _has_conflicting_counterpart(
    rule_finding: Vulnerability,
    llm_findings: List[Vulnerability],
) -> bool:
    """
    Test whether the LLM tier holds an opposite conclusion on this sink.

    A rule finding and an LLM finding describing one sink are still not the same
    finding when they disagree about the outcome, and _find_match refuses such a
    pair (see verdicts_conflict). That refusal leaves the rule finding
    unmatched, and the suppression branch used to read "unmatched" as "the LLM
    tier did not confirm it" and drop it - while the LLM tier had in fact
    reached the opposite conclusion, which is a disagreement to report and not
    an absence of evidence. Dropping it lost the rule tier's evidence ids from
    the report with nothing recording that the finding had existed.

    The disagreement has to be about the same sink, not merely about the same
    file. A conclusion the LLM tier reached elsewhere in the file - refuting an
    unrelated call eighty lines down - says nothing about this sink, and reading
    it as a counterpart exempted the rule finding from suppression for a reason
    that never applied to it. That is false-positive inflation of exactly the
    kind suppression exists to prevent, so identity of the sink is required
    (_same_sink_point: the same program point, whatever data reached it).

    The weaker predicate is deliberate. The two flows that reach this sink are
    evidence about this sink, so an opposite conclusion delivered on a different
    path still contradicts the rule finding - which is why the answer is not
    is_same_sink. That predicate also demands one and the same flow, because
    folding two flows into one deletes a trace; nothing is folded here. Requiring
    it would suppress the rule tier's confirming evidence against the LLM tier's
    refutation of the very sink it reports, re-opening the deletion above.

    Present means the rule finding must survive suppression and be published
    beside its counterpart. It still does not get paired: the caller keeps the
    two findings separate, because the pairing is what _find_match refuses.

    Args:
        rule_finding: The rule-tier finding at risk of suppression
        llm_findings: All findings from the LLM tier for this file

    Returns:
        bool: True when an LLM finding names the same sink with an opposite
        conclusion
    """

    return any(
        _same_file(rule_finding, llm_finding)
        and _types_agree(rule_finding, llm_finding)
        # Same file and a compatible type only narrow the candidates; the
        # counterpart must report *this* sink. _same_sink_point subsumes the two
        # checks above by construction and is kept explicit here as the identity
        # the exemption rests on.
        and _same_sink_point(rule_finding, llm_finding)
        and verdicts_conflict(rule_finding, llm_finding)
        for llm_finding in llm_findings
    )


def _assessment_rank(status: Any) -> int:
    """
    Rank a verification state so the stronger conclusion can win.

    Args:
        status: A finding's assessment_status, of any type

    Returns:
        int: Rank from 0 (absent/unknown) to 4 (supported)
    """

    if status is None:
        return ASSESSMENT_RANK[None]
    key = str(status).strip().lower()
    return ASSESSMENT_RANK.get(key, ASSESSMENT_RANK[""])


def _finding_status(v: Vulnerability) -> str:
    """
    Read a finding's assessment status without trusting its shape.

    Args:
        v: Candidate finding

    Returns:
        str: Lower-cased status, or "" when the finding carries none
    """

    return str(getattr(v, "assessment_status", None) or "").strip().lower()


def _verdict_rank(verdict: Any) -> str:
    """
    Normalise a verification verdict for comparison.

    Args:
        verdict: A verification record's 'verdict' value, of any type

    Returns:
        str: Lower-cased verdict, or "" when absent
    """

    return str(verdict or "").strip().lower()


def _finding_verdict(v: Vulnerability) -> str:
    """
    Read a finding's verification verdict without trusting its shape.

    Args:
        v: Candidate finding

    Returns:
        str: Lower-cased verdict, or "" when the finding was never verified
    """

    verification = getattr(v, "verification", None)
    if not isinstance(verification, dict):
        return ""
    return _verdict_rank(verification.get("verdict"))


def verdicts_conflict(a: Vulnerability, b: Vulnerability) -> bool:
    """
    Test whether two findings hold mutually exclusive conclusions.

    A conclusion is recorded in two places: the verification record's 'verdict'
    ('confirmed' / 'refuted', written by the verifier) and the finding's
    assessment_status ('supported' / 'refuted' / 'uncertain' / 'unreviewed').
    Neither place is always populated - a rule-tier finding assessed straight to
    'refuted' often carries no verification record at all, and a CONFIRMED
    finding may carry an 'unreviewed' status - so reading only one of them makes
    an opposite conclusion look like no opinion. That is how {'confirmed', ''}
    and {'refuted', 'unreviewed'} both slipped past the earlier verdict-only
    guard and got folded.

    A pair is a conflict when any of these hold:
    - the two verdicts are exactly {'confirmed', 'refuted'};
    - the two statuses are exactly {'supported', 'refuted'};
    - one side's verdict is 'confirmed' and the other's status is 'refuted';
    - one side's verdict is 'refuted' and the other's status is 'supported'.

    Every clause is symmetric and needs exactly the two opposite values, so an
    agreeing pair - both 'supported', both 'unreviewed', both 'uncertain',
    'supported' next to 'uncertain' - still folds. This is the single definition
    shared by analyzer.fusion and analyzer.scanner; do not restate it.

    Args:
        a: First finding
        b: Second finding

    Returns:
        bool: True when folding the pair would merge two exclusive conclusions
    """

    verdict_a = _finding_verdict(a)
    verdict_b = _finding_verdict(b)
    status_a = _finding_status(a)
    status_b = _finding_status(b)

    if {verdict_a, verdict_b} == CONTRADICTORY_VERDICTS:
        return True
    if {status_a, status_b} == CONTRADICTORY_STATUSES:
        return True
    if (verdict_a == "confirmed" and status_b == "refuted") or (
        verdict_b == "confirmed" and status_a == "refuted"
    ):
        return True
    if (verdict_a == "refuted" and status_b == "supported") or (
        verdict_b == "refuted" and status_a == "supported"
    ):
        return True
    return False


def _copy_trace(path: Any) -> List[Dict[str, Any]]:
    """
    Copy a traced flow step by step so two findings never share a dict.

    Args:
        path: A finding's taint_path, of any type

    Returns:
        List[Dict[str, Any]]: Copied steps; non-dict entries are kept as-is
    """

    if not isinstance(path, (list, tuple)):
        return []
    return [
        dict(step) if isinstance(step, dict) else step
        for step in path
    ]


def _path_signature(steps: Any, fallback_file: str = "") -> Optional[Tuple[Tuple[str, str, int], ...]]:
    """
    Reduce a raw list of trace steps to a comparable tuple.

    This is the identity of a flow: the same steps at the same program points,
    in the same order. Two flows with different signatures are different data
    reaching a sink, so neither may be dropped in favour of the other.

    Args:
        steps: A taint path (list of step dicts)
        fallback_file: File attributed to a step that names none

    Returns:
        Optional[tuple]: Normalised (kind, file, line) steps, or None when there
        is no usable step
    """

    if not isinstance(steps, (list, tuple)):
        return None
    usable = [step for step in steps if isinstance(step, dict)]
    if not usable:
        return None
    return tuple(
        (
            str(step.get("kind") or "").strip().lower(),
            normalise_step_path(step.get("file") or fallback_file),
            int(step.get("line") or 0) if isinstance(step.get("line"), int) else 0,
        )
        for step in usable
    )


def merge_taint_paths(
    primary: Any,
    alternates_a: Any = (),
    alternates_b: Any = (),
) -> Tuple[List[Dict[str, Any]], List[List[Dict[str, Any]]]]:
    """
    Union every traced flow of two findings into one primary plus alternates.

    A trace is evidence, and evidence is not overwritten. Two findings can agree
    on a sink while naming different origins, and each finding can itself carry
    several flows: keeping only one survivor's paths deleted the other's flows
    from the report with no field recording them. So every path from both sides
    is collected, deduplicated by flow signature, and only then split into the
    primary (the caller's preferred flow) and the alternates.

    The primary stays primary: it is the flow the caller chose to stand behind
    (the LLM tier's richer trace, or the survivor's, depending on the stage).
    When the primary is empty the first non-empty candidate flow becomes it - a
    finding with no trace of its own takes the only trace there is rather than
    reporting nothing.

    Alternates are sorted by signature so the output is a function of the set
    of flows, not of the order the two findings arrived in. Same inputs in a
    different order therefore serialise identically.

    Shared with `analyzer.scanner`, which calls it from its own
    `_absorb_duplicate`; one implementation, so the cross-tier merge, the
    intra-tier collapse and the post-verification merge cannot drift apart.

    Args:
        primary: The flow that should stay in `taint_path`
        alternates_a: Every path of the first side, primary flow included
        alternates_b: Every path of the second side, primary flow included

    Returns:
        Tuple[List[Dict[str, Any]], List[List[Dict[str, Any]]]]: The primary
        flow and the remaining distinct flows, sorted by signature
    """

    sides = [
        side if isinstance(side, (list, tuple)) else []
        for side in (alternates_a, alternates_b)
    ]
    candidates = [
        path
        for side in sides
        for path in side
        if _path_signature(path) is not None
    ]

    primary_steps = _copy_trace(primary)
    primary_signature = _path_signature(primary_steps)
    if primary_signature is None and candidates:
        # No flow of its own: the first available flow is the only proof there
        # is, and losing it would delete the dataflow entirely.
        primary_steps = _copy_trace(candidates.pop(0))
        primary_signature = _path_signature(primary_steps)

    seen = {primary_signature} if primary_signature is not None else set()
    alternates: List[List[Dict[str, Any]]] = []
    for path in candidates:
        signature = _path_signature(path)
        if signature in seen:
            continue
        seen.add(signature)
        alternates.append(_copy_trace(path))

    alternates.sort(key=_path_signature)
    return primary_steps, alternates


def _absorb_into(anchor: Vulnerability, duplicate: Vulnerability) -> bool:
    """
    Fold a duplicate finding's evidence into the survivor, in place.

    Deliberately local rather than shared with analyzer.scanner._absorb_duplicate:
    scanner imports this module, so calling back into it would close an import
    cycle. Only what a survivor must not lose is carried over - the evidence ids
    that name stored artifacts, corroboration, every traced flow (the survivor's
    own and the duplicate's, unioned), a stronger confidence, a stronger
    verification state, and identifiers the survivor lacks. The survivor's
    location, type and severity stay authoritative.

    The assessment triple - assessment_status, assessment, verification - is a
    single unit and moves as one. Naming a stronger status while keeping the
    weaker side's verification record produced findings that said 'supported'
    next to "verdict": "refuted", and the post-verification deduplication keys
    on assessment_status, so it then acted on a state that was a fiction. When
    the duplicate's status outranks the survivor's, all three fields come from
    the duplicate; verification is only filled in from the duplicate when the
    survivor holds none.

    A pair holding contradicting conclusions is refused outright, not folded,
    and the caller keeps both findings. The test is verdicts_conflict, the same
    predicate _deduplicate_tier and _find_match apply, so no future caller can
    collapse such a pair by accident and no stage can disagree with another
    about whether a pair contradicts.

    Args:
        anchor: The finding being kept, modified in place
        duplicate: The finding being dropped

    Returns:
        bool: True when the duplicate was folded in, False when the caller must
        keep both findings
    """

    if verdicts_conflict(anchor, duplicate):
        logging.warning(
            "Refused to fold contradicting conclusions: %s at L%d "
            "(status=%s, verdict=%s) vs L%d (status=%s, verdict=%s)",
            anchor.type.value, anchor.location.start_line,
            _finding_status(anchor) or "none", _finding_verdict(anchor) or "none",
            duplicate.location.start_line,
            _finding_status(duplicate) or "none", _finding_verdict(duplicate) or "none",
        )
        return False

    if duplicate.corroborated and not anchor.corroborated:
        anchor.corroborated = True

    # Two folds can meet here for the same sink: the one that has a trace and
    # the one that has none, and the one where both traced different origins.
    # Both are handled by unioning every flow, so a fold never chooses one
    # finding's dataflow over the other's.
    anchor.taint_path, anchor.alternate_taint_paths = merge_taint_paths(
        anchor.taint_path,
        anchor.alternate_taint_paths or [],
        [duplicate.taint_path, *(duplicate.alternate_taint_paths or [])],
    )

    for evidence_id in list(duplicate.evidence_ids or []):
        if evidence_id not in anchor.evidence_ids:
            anchor.evidence_ids.append(evidence_id)
    if float(duplicate.confidence or 0.0) > float(anchor.confidence or 0.0):
        anchor.confidence = duplicate.confidence

    # Status and its metadata are one conclusion: whichever side's status wins,
    # its assessment record and verification record move with it.
    if _assessment_rank(duplicate.assessment_status) > _assessment_rank(anchor.assessment_status):
        anchor.assessment_status = duplicate.assessment_status
        anchor.assessment = copy.deepcopy(duplicate.assessment)
        anchor.verification = copy.deepcopy(duplicate.verification)
    elif anchor.verification is None and duplicate.verification is not None:
        # No status change, so the survivor's own status stays authoritative;
        # an unverified survivor may still take the duplicate's verdict.
        anchor.verification = copy.deepcopy(duplicate.verification)
    if anchor.assessment is None and duplicate.assessment is not None:
        anchor.assessment = copy.deepcopy(duplicate.assessment)
    if not anchor.rule_id and duplicate.rule_id:
        anchor.rule_id = duplicate.rule_id
    for rule in list(duplicate.merged_rule_ids or []):
        if rule not in anchor.merged_rule_ids:
            anchor.merged_rule_ids.append(rule)

    return True


def _deduplicate_tier(findings: List[Vulnerability]) -> List[Vulnerability]:
    """
    Collapse findings within one tier that describe the same defect.

    Identity is the same test the post-verification merge applies
    (is_same_sink): same file, compatible types, and the same sink - named by
    the traced sink step, or by an identical reported line when neither report
    traced a flow. A line window is deliberately not used here. Two distinct
    sinks a few lines apart share file and type, so a window merges them and
    deletes a true positive together with its taint path and evidence ids
    before the merge stage ever sees it. The more severe finding wins; ties
    keep the richer description.

    Collapsing is not deleting: the dropped finding's evidence ids,
    corroboration, taint path, verification state and confidence are folded
    into the survivor by _absorb_into (see that function for why it is not
    scanner's helper). Dropping the duplicate outright orphaned evidence a
    reviewer could no longer reach from the report.

    A pair that holds contradicting conclusions about the same sink is not a
    duplicate: 'supported' and 'refuted' cannot both describe one sink, and the
    sort order that picks the survivor carries no evidence for either. The same
    holds when only one side wrote a verification record - one 'confirmed', the
    other 'refuted', or a 'confirmed' verdict against a 'refuted' status. The
    test is verdicts_conflict, applied here before a candidate is chosen so an
    anchor is never picked for such a pair, and again inside _absorb_into. Both
    findings are kept for review rather than one being chosen arbitrarily, and
    the folded status and verification always come from the same side.

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
        anchor = None
        contradicted_by = None
        for existing in kept:
            if not is_same_sink(existing, finding):
                continue
            if verdicts_conflict(existing, finding):
                contradicted_by = existing
                continue
            anchor = existing
            break

        if anchor is None:
            if contradicted_by is not None:
                logging.warning(
                    "Contradicting conclusions on one sink kept as two findings: "
                    "%s L%d (status=%s, verdict=%s) vs L%d (status=%s, verdict=%s)",
                    finding.type.value,
                    contradicted_by.location.start_line,
                    _finding_status(contradicted_by) or "none",
                    _finding_verdict(contradicted_by) or "none",
                    finding.location.start_line,
                    _finding_status(finding) or "none",
                    _finding_verdict(finding) or "none",
                )
            kept.append(finding)
            continue

        logging.debug(
            "Intra-tier duplicate folded: %s at L%d into L%d",
            finding.type.value, finding.location.start_line,
            anchor.location.start_line
        )
        if not _absorb_into(anchor, finding):
            # The pair was refused as two verdicts on one sink. Keeping the
            # duplicate is the whole point of the refusal; dropping it here
            # would delete the finding the refusal exists to preserve.
            kept.append(finding)

    return kept


def _untraced_position_match(a: Vulnerability, b: Vulnerability) -> bool:
    """
    Test whether two findings with no sink evidence at all sit close enough to
    be the same defect reported by two tiers.

    This is the only remaining use of LINE_WINDOW as a match condition, and it
    is gated on the strictest precondition available: neither side's trace
    names a sink point. With a sink point on either side, identity is decided
    by is_same_sink alone and position is irrelevant - that is the case where a
    window silently welded two different sinks, and their evidence ids, into
    one finding.

    A trace that names no sink point is not evidence that there is no trace.
    A path stopping at 'source@app.py:17' says the flow was recorded but was not
    followed to its sink; position cannot settle identity there either, so the
    pair stays two findings. Only when both sides are entirely untraced is
    there nothing to contradict a match: both tiers describe one file and one
    compatible type, and the LLM tier reports approximate lines even when
    prompted with numbered source. Refusing to match there would turn every
    tier agreement into two findings on position noise alone
    (tests/test_core.py pins that behaviour).

    Args:
        a: First finding
        b: Second finding

    Returns:
        bool: True when neither side carries any trace step and the two sit
        inside the cross-tier window
    """

    if sink_point(a) is not None or sink_point(b) is not None:
        return False
    if _has_any_trace(a) or _has_any_trace(b):
        return False
    return _line_distance(a, b) is not None


def _has_any_trace(v: Vulnerability) -> bool:
    """
    Test whether a finding carries a recorded trace at all.

    Distinguishes 'no trace' from 'a trace that stops before the sink'. Both
    yield no sink point, but only the first leaves position free to decide
    identity: a recorded flow is a claim about a specific program point, and
    matching it to a nearby unrelated line is the mistake this guards against.

    Degrades quietly on untrusted shapes the way sink_point does: anything that
    is not a list/tuple, or a list with no dict step, counts as no trace.

    Args:
        v: Candidate finding

    Returns:
        bool: True when taint_path holds at least one step
    """

    raw_path = getattr(v, "taint_path", None)
    if not isinstance(raw_path, (list, tuple)):
        return False
    return any(isinstance(step, dict) for step in raw_path)


def _find_match(
    rule_finding: Vulnerability,
    llm_findings: List[Vulnerability],
    claimed: set
) -> Optional[Vulnerability]:
    """
    Locate the LLM finding that describes the same defect, if any.

    Identity across tiers is the same predicate the intra-tier collapse and the
    post-verification merge use - is_same_sink - so no stage can merge a pair
    the others would keep. A rule sink at line 10 and an LLM sink at line 17 are
    two defects; matching them on distance alone welded them into one finding
    and dropped the rule tier's evidence with it.

    Line distance is only an ordering key. When several candidates prove the
    same sink, the closest one wins; an identity-proof match always outranks a
    position-only one.

    A candidate that holds a conclusion contradicting the rule finding's is not
    a match, however exactly they agree on the sink: _combine copies the LLM
    finding and unions the rule tier's evidence into it, so pairing a
    'refuted' LLM finding with a CONFIRMED rule finding would publish the rule
    tier's proof under the opposite conclusion while deleting the rule finding.
    Such a pair stays two findings, decided by verdicts_conflict - the same
    predicate the intra-tier collapse and _absorb_into apply.

    Args:
        rule_finding: A finding from the rule tier
        llm_findings: All findings from the LLM tier
        claimed: ids of LLM findings already matched to another rule finding

    Returns:
        Optional[Vulnerability]: The best match, or None when no candidate is
        provably the same sink (both findings then survive on their own)
    """

    candidates = []
    for llm_finding in llm_findings:
        if id(llm_finding) in claimed:
            continue
        if not _same_file(rule_finding, llm_finding):
            continue
        if not _types_agree(rule_finding, llm_finding):
            continue
        if verdicts_conflict(rule_finding, llm_finding):
            logging.warning(
                "Refused to pair contradicting conclusions across tiers: %s L%d "
                "(status=%s, verdict=%s) vs L%d (status=%s, verdict=%s)",
                rule_finding.type.value, rule_finding.location.start_line,
                _finding_status(rule_finding) or "none",
                _finding_verdict(rule_finding) or "none",
                llm_finding.location.start_line,
                _finding_status(llm_finding) or "none",
                _finding_verdict(llm_finding) or "none",
            )
            continue

        identical = is_same_sink(rule_finding, llm_finding)
        if not identical and not _untraced_position_match(rule_finding, llm_finding):
            continue

        distance = _line_distance(rule_finding, llm_finding)
        candidates.append((
            0 if identical else 1,
            LINE_WINDOW + 1 if distance is None else distance,
            llm_finding,
        ))

    if not candidates:
        return None

    candidates.sort(key=lambda candidate: (candidate[0], candidate[1]))
    return candidates[0][2]


def normalise_step_path(path: Any) -> str:
    """
    Normalise a taint step's file for identity comparison.

    Identity comparison must be exact: 'a/app.py' and 'b/app.py' are different
    files even though they share a basename, so nothing is stripped beyond the
    separator style and a leading './'.

    Args:
        path: Raw path from a taint step

    Returns:
        str: Lower-cased POSIX form
    """

    normalised = str(path or "").replace("\\", "/").strip()
    while normalised.startswith("./"):
        normalised = normalised[2:]
    return normalised.lower()


def sink_point(v: Vulnerability) -> Optional[Tuple[str, int]]:
    """
    Return the program point (file, line) the finding actually writes to.

    Only a step that declares itself a sink ('sink', 'imported_sink') names a
    sink point. Any other trailing step - a source, a propagation hop - is where
    the recorded path stops, not where the data lands, so treating it as the
    sink welds a finding that reported line 10 with a trace that stops at
    'source@app.py:17' onto a different finding that merely reported line 17.
    A path that carries no sink step is therefore not proof of identity: callers
    fall back to comparing reported lines (see is_same_sink).

    Degrades quietly rather than raising on untrusted shapes: a taint path that
    is None, not a list, empty, or a step missing 'file'/'line', or carrying a
    non-integer line, yields None (sink not established).

    Args:
        v: Candidate finding

    Returns:
        Optional[Tuple[str, int]]: (file, line) of the sink step, or None when
        the finding's taint path does not name a sink point
    """

    raw_path = getattr(v, "taint_path", None)
    if not isinstance(raw_path, (list, tuple)):
        return None
    sinks = [
        step for step in raw_path
        if isinstance(step, dict)
        and str(step.get("kind") or "").strip().lower() in SINK_STEP_KINDS
    ]
    if not sinks:
        return None
    step = sinks[-1]
    line = step.get("line")
    if not isinstance(line, int) or isinstance(line, bool) or line <= 0:
        return None
    path = step.get("file")
    if not str(path or "").strip():
        return None
    return (normalise_step_path(path), line)


def flow_signature(v: Vulnerability) -> Optional[Tuple[Tuple[str, str, int], ...]]:
    """
    Reduce a traced flow to a comparable tuple.

    Two findings that traced different flows described the same sink reached by
    different data, so folding one into the other would delete a real flow.

    Args:
        v: Candidate finding

    Returns:
        Optional[tuple]: Normalised (kind, file, line) steps, or None when the
        finding has no traced flow
    """

    steps = [step for step in (v.taint_path or []) if isinstance(step, dict)]
    if not steps:
        return None
    return tuple(
        (
            str(step.get("kind") or "").strip().lower(),
            normalise_step_path(step.get("file") or v.location.file_path),
            int(step.get("line") or 0) if isinstance(step.get("line"), int) else 0,
        )
        for step in steps
    )


def _point_is_reported_at(point: Tuple[str, int], v: Vulnerability) -> bool:
    """
    Test whether an untraced finding reports the program point of a traced sink.

    When only one side of a pair carries a trace, the traced sink step is the
    only exact location available. The untraced side is the same sink only when
    its reported start line is that step's line - a flow in 'views.py' that
    terminates at 'db.py:17' is not the finding reported at 'views.py:17'.

    Args:
        point: (normalised file, line) of the traced sink step
        v: The finding without a traceable sink point

    Returns:
        bool: True when the untraced report names that exact point
    """

    point_file, point_line = point
    reported_file = normalise_step_path(v.location.file_path)
    if point_file and reported_file and point_file != reported_file:
        return False
    return int(v.location.start_line or 1) == point_line


def _same_sink_point(a: Vulnerability, b: Vulnerability) -> bool:
    """
    Decide whether two findings report the same program point as their sink.

    This is sink identity without flow identity: it answers "is this the same
    sink?", not "is this the same finding?". The two questions are different
    whenever two flows reach one point - a source at line 1 and a source at line
    2 both land on line 10 - and a caller that only needs to know whether the
    other tier had an opinion about this sink must use this predicate. Folding
    two such reports needs is_same_sink, which additionally requires one and the
    same flow, because that fold deletes a trace.

    Same file and a compatible type are necessary but nowhere near sufficient:
    two distinct sinks in one file ten lines apart share both. Identity is
    therefore established in priority order:

    1. Both findings name a sink point (a step whose kind is 'sink' or
       'imported_sink'): those points must be the exact same (file, line).
    2. Exactly one names a sink point: it must be the other's reported start
       line. This is what lets a traced report speak about the same sink as a
       tier that traced nothing.
    3. Neither names a sink point: the reported start lines must be equal. A
       +/- window is deliberately not used - a window is not identity.

    Args:
        a: First finding
        b: Second finding

    Returns:
        bool: True when both reports name one sink point
    """

    if not _same_file(a, b) or not _types_agree(a, b):
        return False

    point_a, point_b = sink_point(a), sink_point(b)
    if point_a is not None and point_b is not None:
        return point_a == point_b
    if point_a is not None:
        return _point_is_reported_at(point_a, b)
    if point_b is not None:
        return _point_is_reported_at(point_b, a)
    return int(a.location.start_line or 1) == int(b.location.start_line or 1)


def is_same_sink(a: Vulnerability, b: Vulnerability) -> bool:
    """
    Decide whether two findings demonstrably report the same sink.

    Same file and a compatible type are necessary but nowhere near sufficient:
    two distinct sinks in one file ten lines apart share both. The merge
    condition is therefore an identity proof, in priority order:

    1. Both findings name a sink point (a step whose kind is 'sink' or
       'imported_sink'): those points must be the exact same (file, line) *and*
       the two flows must be the same flow. Different traced paths are
       different data reaching a point, which is a second finding, not a
       duplicate.
    2. Exactly one names a sink point: it must be the other's reported start
       line. This is what lets a traced report absorb the same sink reported by
       a tier that traced nothing. A path that stops at a source names no sink
       point at all, so it lands here or in 3 rather than inventing one.
    3. Neither names a sink point: the reported start lines must be equal.
       A +/- window is deliberately not used - a window is not identity, and
       using it silently deleted a true positive along with its evidence ids.

    One implementation only: the intra-tier collapse in this module and the
    post-verification merge in `analyzer.scanner` both call this function, so
    the two stages cannot drift apart and delete what the other would keep.

    The point comparison itself lives in _same_sink_point, shared with the
    suppression exemption; this function adds the flow requirement that only a
    fold needs.

    Args:
        a: First finding
        b: Second finding

    Returns:
        bool: True when the two reports describe one sink
    """

    if not _same_sink_point(a, b):
        return False

    point_a, point_b = sink_point(a), sink_point(b)
    if point_a is not None and point_b is not None:
        # Same point, two different traces: two flows reaching one sink. Folding
        # them would delete a flow, so they are two findings.
        return flow_signature(a) == flow_signature(b)
    return True


def _same_file(a: Vulnerability, b: Vulnerability) -> bool:
    """
    Compare file paths, tolerating absolute vs relative forms while preventing
    cross-directory collisions like 'a/app.py' vs 'b/app.py'.
    """

    raw_a = str(a.location.file_path).replace("\\", "/").strip().lstrip("./")
    raw_b = str(b.location.file_path).replace("\\", "/").strip().lstrip("./")
    if not raw_a or not raw_b:
        return True  # single-file scans often omit the path on one side
    if raw_a == raw_b or raw_a.lower() == raw_b.lower():
        return True
    if (raw_a.endswith("/" + raw_b) and "/" in raw_b) or (raw_b.endswith("/" + raw_a) and "/" in raw_a):
        return True
    return False


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

    # If the rule finding landed on an import statement (e.g. 'import xml...') while
    # the LLM finding landed on the actual sink call (e.g. 'ET.parse' or 'parseString'),
    # prefer the sink call location so it aligns with ground-truth sink coordinates.
    rule_loc_ctx = (rule_finding.location.context or "").lower()
    llm_loc_ctx = (llm_finding.location.context or "").lower()
    if ("import " in rule_loc_ctx or "from " in rule_loc_ctx) and not ("import " in llm_loc_ctx or "from " in llm_loc_ctx):
        combined.location = llm_finding.location.model_copy(deep=True)
    else:
        combined.location = rule_finding.location.model_copy(deep=True)

    combined.severity = severity
    combined.source = FindingSource.CONFIRMED
    combined.corroborated = True
    combined.engine_sources = ["SEMGREP", "LLM"]
    combined.confidence = CONFIDENCE[FindingSource.CONFIRMED]
    combined.rule_id = rule_finding.rule_id
    combined.merged_rule_ids = list(rule_finding.merged_rule_ids)

    # Evidence ids are unioned, not taken from one side: each id names a stored
    # artifact that still exists, and dropping the rule tier's ids here would
    # orphan evidence a reviewer can no longer reach from the merged finding.
    for evidence_id in list(rule_finding.evidence_ids or []):
        if evidence_id not in combined.evidence_ids:
            combined.evidence_ids.append(evidence_id)

    # A trace is evidence, not prose, so it does not travel with the explanation.
    # The LLM finding is copied whole for its text, and when it traced nothing
    # the rule tier's path is the only record of the flow reaching this sink -
    # discarding it drops the dataflow proof the two-tier design exists to keep.
    # When both traced different flows, the LLM's path stays primary because it
    # is the richer trace, but the rule tier's path is kept alongside it as an
    # alternate flow: the two tiers agreed on the sink while naming different
    # origins (rule 'source@app.py:1' vs LLM 'source@app.py:5'), and one path
    # field cannot hold both. Keeping only the LLM's left the rule tier's origin
    # out of the report with no field recording it.
    # Copying the LLM finding wholesale also copies its traces, and the rule
    # tier's flows were then either lost (when the LLM traced nothing) or
    # overwritten (when it already held alternates). Both sides' flows are
    # evidence, so they are unioned: the LLM's path stays primary as the richer
    # trace, and the rule tier's distinct flows survive as alternates.
    combined.taint_path, combined.alternate_taint_paths = merge_taint_paths(
        combined.taint_path,
        combined.alternate_taint_paths or [],
        [rule_finding.taint_path, *(rule_finding.alternate_taint_paths or [])],
    )
    if _has_any_trace(rule_finding) and flow_signature(combined) != flow_signature(rule_finding):
        logging.debug(
            "Cross-tier traces differ for %s at L%d: LLM path (%d steps) "
            "stays primary, rule tier's %d flow(s) kept as alternates",
            combined.type.value, combined.location.start_line,
            len(combined.taint_path or []), len(combined.alternate_taint_paths or []),
        )

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
