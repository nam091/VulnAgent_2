from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EvidenceStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    STALE = "stale"
    MISSING = "missing"


class EvidenceRecord(BaseModel):
    evidence_id: str
    snapshot_id: str
    path: str
    content_hash: str
    start_line: int
    end_line: int
    excerpt_hash: str
    origin: str = "read_lines"
    read_succeeded: bool = True
    content: Optional[str] = None
    status: EvidenceStatus = EvidenceStatus.VALID
    error_message: Optional[str] = None


class SnapshotManifest(BaseModel):
    snapshot_id: str
    root: str
    created_at: str
    git_commit: Optional[str] = None
    is_dirty: bool = False
    files: Dict[str, str] = Field(default_factory=dict)  # relative_path -> sha256
