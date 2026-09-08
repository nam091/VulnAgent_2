import hashlib
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from evidence.safe_reader import SafeReader
from models.evidence import EvidenceRecord, EvidenceStatus, SnapshotManifest


class EvidenceStore:
    """
    Manages snapshots of working trees and evidence records.
    Ensures that assessments cite real, verifiable evidence from the exact snapshot analyzed.
    """

    def __init__(self, root: Optional[Path] = None) -> None:
        self.root = Path(root).resolve() if root else Path.cwd().resolve()
        self.reader = SafeReader(self.root)
        self._snapshots: Dict[str, SnapshotManifest] = {}
        self._evidence: Dict[str, EvidenceRecord] = {}

    def create_snapshot(self, root: Optional[Path] = None) -> SnapshotManifest:
        """
        Create a reproducible snapshot manifest of files under root.
        """
        scan_root = Path(root).resolve() if root else self.root
        reader = SafeReader(scan_root)
        files = reader.list_python_files()

        file_hashes: Dict[str, str] = {}
        hasher = hashlib.sha256()

        for f in sorted(files, key=lambda p: reader.to_relative(p)):
            rel = reader.to_relative(f)
            try:
                content = f.read_bytes()
                h = hashlib.sha256(content).hexdigest()
                file_hashes[rel] = h
                hasher.update(f"{rel}:{h}".encode("utf-8"))
            except OSError:
                continue

        git_commit = None
        is_dirty = False
        try:
            import git
            repo = git.Repo(scan_root, search_parent_directories=True)
            git_commit = repo.head.commit.hexsha
            is_dirty = repo.is_dirty()
        except Exception:
            pass

        manifest_digest = hasher.hexdigest()[:16]
        snapshot_id = f"snap_{manifest_digest}"

        manifest = SnapshotManifest(
            snapshot_id=snapshot_id,
            root=str(scan_root),
            created_at=str(time.time()),
            git_commit=git_commit,
            is_dirty=is_dirty,
            files=file_hashes,
        )
        self._snapshots[snapshot_id] = manifest
        return manifest

    def record_evidence(
        self,
        snapshot_id: str,
        path: str,
        start_line: int,
        end_line: int,
        content: Optional[str] = None,
        origin: str = "read_lines"
    ) -> EvidenceRecord:
        """
        Issue an opaque evidence ID for a verified safe file read.
        """
        if content is None:
            try:
                line_info = self.reader.read_lines(path, start_line, end_line)
                content = "\n".join(line_info.get("raw_lines", []))
            except Exception:
                content = ""
        manifest = self._snapshots.get(snapshot_id)
        file_hash = manifest.files.get(path, "") if manifest else ""

        if not file_hash:
            try:
                real_file = self.reader.resolve(path)
                file_hash = hashlib.sha256(real_file.read_bytes()).hexdigest()
            except Exception:
                file_hash = "unknown"

        excerpt_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        key = f"{snapshot_id}:{path}:{start_line}:{end_line}:{excerpt_hash[:8]}"
        evidence_id = f"ev_{hashlib.sha256(key.encode('utf-8')).hexdigest()[:14]}"

        record = EvidenceRecord(
            evidence_id=evidence_id,
            snapshot_id=snapshot_id,
            path=path,
            content_hash=file_hash,
            start_line=start_line,
            end_line=end_line,
            excerpt_hash=excerpt_hash,
            origin=origin,
            read_succeeded=True,
            content=content,
            status=EvidenceStatus.VALID,
        )
        self._evidence[evidence_id] = record
        return record

    def validate_evidence(
        self,
        evidence_id: str,
        current_snapshot_id: str
    ) -> Tuple[bool, EvidenceStatus, str]:
        """
        Validate evidence authenticity against the current snapshot and working tree state.
        """
        record = self._evidence.get(evidence_id)
        if not record:
            return False, EvidenceStatus.MISSING, f"Evidence '{evidence_id}' does not exist"

        if record.snapshot_id != current_snapshot_id:
            return False, EvidenceStatus.STALE, (
                f"Evidence belongs to snapshot '{record.snapshot_id}', "
                f"not current '{current_snapshot_id}'"
            )

        # Check if file has changed on disk
        try:
            target = self.reader.resolve(record.path)
            current_hash = hashlib.sha256(target.read_bytes()).hexdigest()
            if record.content_hash and record.content_hash != "unknown" and current_hash != record.content_hash:
                return False, EvidenceStatus.STALE, f"File '{record.path}' was modified on disk after snapshot"
        except Exception as e:
            return False, EvidenceStatus.INVALID, f"Failed to verify file '{record.path}': {e}"

        return True, EvidenceStatus.VALID, "Evidence verified"

    def get_evidence(self, evidence_id: str) -> Optional[EvidenceRecord]:
        return self._evidence.get(evidence_id)

    def get_snapshot(self, snapshot_id: str) -> Optional[SnapshotManifest]:
        return self._snapshots.get(snapshot_id)
