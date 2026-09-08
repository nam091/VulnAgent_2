from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AssessmentStatus(str, Enum):
    UNREVIEWED = "unreviewed"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    UNCERTAIN = "uncertain"


class FindingAssessment(BaseModel):
    finding_id: str
    snapshot_id: str
    status: AssessmentStatus = AssessmentStatus.UNCERTAIN
    reason: str = ""
    evidence_ids: List[str] = Field(default_factory=list)
    missing_context: List[str] = Field(default_factory=list)
    mitigating_control: Optional[str] = None
    taint_path: List[Dict[str, Any]] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    assessor: str = "agent"  # "host_editor" or "agent" or "user"
