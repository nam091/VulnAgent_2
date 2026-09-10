from collections import defaultdict
from enum import Enum
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AssessmentStatus(str, Enum):
    UNREVIEWED = "unreviewed"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    UNCERTAIN = "uncertain"
    STALE = "stale"


class FindingAssessment(BaseModel):
    finding_id: str
    snapshot_id: str
    status: AssessmentStatus = AssessmentStatus.UNCERTAIN
    reason: str = ""
    evidence_ids: List[str] = Field(default_factory=list)
    control_evidence_id: Optional[str] = None
    missing_context: List[str] = Field(default_factory=list)
    mitigating_control: Optional[str] = None
    taint_path: List[Dict[str, Any]] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    assessor: str = "agent"  # "host_editor" | "agent" | "user"
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


def evaluate_assessment_policy(
    vuln_id: str,
    vuln_type: Optional[str],
    snapshot_id: str,
    evidence_store: Any,
    verdict: str,
    evidence_ids: List[str],
    reason: str = "",
    mitigating_control: Optional[str] = None,
    control_evidence_id: Optional[str] = None,
    taint_path: Optional[List[Dict[str, Any]]] = None,
    missing_context: Optional[List[str]] = None,
    limitations: Optional[List[str]] = None,
    assessor: str = "agent",
) -> FindingAssessment:
    """
    Shared evaluation policy for both MCP and API verifiers (B02/B03/B12).
    Ensures strict validation across schema, snapshot membership, and evidence integrity.
    """
    norm_verdict = (verdict or "").strip().lower()
    if norm_verdict not in ("supported", "refuted", "uncertain"):
        norm_verdict = "uncertain"

    policy_notes: List[str] = []
    final_status = norm_verdict

    # 1. Snapshot validation
    if not evidence_store or not snapshot_id:
        final_status = "uncertain"
        policy_notes.append("Missing evidence store or snapshot ID")
    else:
        snap = evidence_store.get_snapshot(snapshot_id)
        if not snap:
            final_status = "uncertain"
            policy_notes.append(f"Snapshot '{snapshot_id}' not found in evidence store")

    # 2. Evidence validation
    invalid_eids: Dict[str, str] = {}
    valid_eids: List[str] = []
    if evidence_store and snapshot_id:
        for eid in evidence_ids:
            is_valid, ev_status, msg = evidence_store.validate_evidence(eid, snapshot_id)
            if is_valid:
                valid_eids.append(eid)
            else:
                invalid_eids[eid] = msg

    # 3. Refuted policy
    if norm_verdict == "refuted":
        if not mitigating_control or not mitigating_control.strip():
            final_status = "uncertain"
            policy_notes.append("Refutation rejected: missing non-empty mitigating_control")

        if not evidence_ids:
            final_status = "uncertain"
            policy_notes.append("Refutation rejected: thiếu mã bằng chứng (no evidence_ids cited)")
        elif invalid_eids:
            final_status = "uncertain"
            policy_notes.append(
                "Refutation rejected: bằng chứng không còn hợp lệ trên đĩa hoặc file đã thay đổi: "
                + "; ".join(f"{eid} ({msg})" for eid, msg in invalid_eids.items())
            )
        elif control_evidence_id and control_evidence_id not in valid_eids:
            final_status = "uncertain"
            policy_notes.append(f"Refutation rejected: control_evidence_id '{control_evidence_id}' is not valid")

    # 4. Supported policy
    elif norm_verdict == "supported":
        if not evidence_ids:
            final_status = "uncertain"
            policy_notes.append("Supported verdict rejected: no evidence_ids cited")
        elif invalid_eids:
            final_status = "uncertain"
            policy_notes.append(
                "Supported verdict rejected: cited evidence is invalid or stale: "
                + "; ".join(f"{eid} ({msg})" for eid, msg in invalid_eids.items())
            )

        # Check taint path binding for injection/traversal vulnerability types
        is_taint_cwe = False
        if vuln_type:
            v_lower = str(vuln_type).lower()
            if any(k in v_lower for k in ("sql", "command", "traversal", "xss", "code_injection", "rce")):
                is_taint_cwe = True

        if is_taint_cwe and not taint_path:
            final_status = "uncertain"
            policy_notes.append("Supported verdict requires concrete taint_path steps for taint-based vulnerability")

        if taint_path:
            for step in taint_path:
                step_eid = step.get("evidence_id")
                if step_eid and step_eid in invalid_eids:
                    final_status = "uncertain"
                    policy_notes.append(f"Taint step references invalid evidence '{step_eid}'")

    # Final reason assembly
    combined_reason = reason.strip()
    if policy_notes:
        if combined_reason:
            combined_reason += " | " + "; ".join(policy_notes)
        else:
            combined_reason = "; ".join(policy_notes)

    return FindingAssessment(
        finding_id=vuln_id,
        snapshot_id=snapshot_id,
        status=AssessmentStatus(final_status),
        reason=combined_reason,
        evidence_ids=evidence_ids,
        control_evidence_id=control_evidence_id,
        missing_context=missing_context or [],
        mitigating_control=mitigating_control,
        taint_path=taint_path or [],
        limitations=limitations or [],
        assessor=assessor,
        created_at=time.time(),
        updated_at=time.time(),
    )


def check_assessment_stale(assessment: FindingAssessment, evidence_store: Any) -> bool:
    """
    Check if any cited evidence in the assessment has become stale on disk.
    Updates assessment.status to STALE if modified.
    """
    if not assessment.evidence_ids or not evidence_store:
        return False

    for eid in assessment.evidence_ids:
        is_valid, ev_status, msg = evidence_store.validate_evidence(eid, assessment.snapshot_id)
        if not is_valid:
            assessment.status = AssessmentStatus.STALE
            assessment.reason = f"Assessment is STALE: evidence '{eid}' became invalid ({msg})"
            assessment.updated_at = time.time()
            return True
    return False


class AssessmentStore:
    """
    In-memory or persistent store for finding assessments and their audit history.
    """

    def __init__(self) -> None:
        self._assessments: Dict[str, FindingAssessment] = {}
        self._history: Dict[str, List[FindingAssessment]] = defaultdict(list)

    def save(self, assessment: FindingAssessment) -> None:
        self._assessments[assessment.finding_id] = assessment
        self._history[assessment.finding_id].append(assessment.model_copy(deep=True))

    def get(self, finding_id: str) -> Optional[FindingAssessment]:
        return self._assessments.get(finding_id)

    def list_all(self) -> List[FindingAssessment]:
        return list(self._assessments.values())

    def get_history(self, finding_id: str) -> List[FindingAssessment]:
        return self._history.get(finding_id, [])

    def check_all_stale(self, evidence_store: Any) -> List[str]:
        stale_ids = []
        for fid, a in self._assessments.items():
            if a.status in (AssessmentStatus.SUPPORTED, AssessmentStatus.REFUTED):
                if check_assessment_stale(a, evidence_store):
                    stale_ids.append(fid)
        return stale_ids
