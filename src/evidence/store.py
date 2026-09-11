import hashlib
import time
import uuid
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
                content = f.read_text(encoding="utf-8", errors="replace").encode("utf-8")
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
        Strictly verifies line bounds and checks that content matches the actual file on disk.
        """
        manifest = self._snapshots.get(snapshot_id)
        if not manifest:
            return self._create_invalid_record(
                snapshot_id, path, start_line, end_line,
                f"Snapshot '{snapshot_id}' does not exist in evidence store",
                origin
            )

        # Safely resolve target file
        try:
            real_file = self.reader.resolve(path)
            if not real_file.is_file():
                return self._create_invalid_record(
                    snapshot_id, path, start_line, end_line, f"File not found: {path}", origin
                )
            rel_path = self.reader.to_relative(real_file)
            file_bytes = real_file.read_text(encoding="utf-8", errors="replace").encode("utf-8")
            current_file_hash = hashlib.sha256(file_bytes).hexdigest()
            file_text = file_bytes.decode("utf-8")
            lines = file_text.splitlines()
            total_lines = len(lines)
        except Exception as e:
            return self._create_invalid_record(
                snapshot_id, path, start_line, end_line, f"Read error: {e}", origin
            )

        manifest_file_hash = manifest.files.get(rel_path) or manifest.files.get(path)
        if not manifest_file_hash:
            return self._create_invalid_record(
                snapshot_id, path, start_line, end_line,
                f"File '{path}' is not present in snapshot '{snapshot_id}' manifest",
                origin
            )

        if current_file_hash != manifest_file_hash:
            return self._create_invalid_record(
                snapshot_id, path, start_line, end_line,
                f"File '{path}' was modified on disk after snapshot '{snapshot_id}'",
                origin, file_hash=manifest_file_hash
            )

        file_hash = manifest_file_hash

        # Strict line bounds check (B03)
        if start_line < 1 or end_line < start_line or start_line > total_lines or end_line > total_lines:
            return self._create_invalid_record(
                snapshot_id, path, start_line, end_line,
                f"Line range {start_line}-{end_line} is out of bounds (file has {total_lines} lines)",
                origin, file_hash=file_hash
            )

        actual_excerpt_lines = lines[start_line - 1:end_line]
        actual_content = "\n".join(actual_excerpt_lines)

        # Content verification: if caller supplied content, it must strictly match disk content (B03)
        if content is not None:
            norm_supplied = "\n".join(content.splitlines())
            norm_actual = "\n".join(actual_content.splitlines())
            if norm_supplied != norm_actual:
                return self._create_invalid_record(
                    snapshot_id, path, start_line, end_line,
                    "Fabricated content: provided content does not match code on disk",
                    origin, file_hash=file_hash
                )
        else:
            content = actual_content

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

    def _create_invalid_record(
        self,
        snapshot_id: str,
        path: str,
        start_line: int,
        end_line: int,
        reason: str,
        origin: str,
        file_hash: str = "invalid"
    ) -> EvidenceRecord:
        key = f"{snapshot_id}:{path}:{start_line}:{end_line}:invalid:{uuid.uuid4().hex[:6]}"
        evidence_id = f"ev_invalid_{hashlib.sha256(key.encode('utf-8')).hexdigest()[:12]}"
        record = EvidenceRecord(
            evidence_id=evidence_id,
            snapshot_id=snapshot_id,
            path=path,
            content_hash=file_hash,
            start_line=start_line,
            end_line=end_line,
            excerpt_hash="invalid",
            origin=origin,
            read_succeeded=False,
            content="",
            status=EvidenceStatus.INVALID,
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
        Verifies line bounds, file hash, and excerpt hash against current disk content.
        """
        record = self._evidence.get(evidence_id)
        if not record:
            return False, EvidenceStatus.MISSING, f"Evidence '{evidence_id}' does not exist"

        if record.status != EvidenceStatus.VALID or not record.read_succeeded:
            return False, EvidenceStatus.INVALID, f"Evidence '{evidence_id}' is invalid"

        if record.snapshot_id != current_snapshot_id:
            return False, EvidenceStatus.STALE, (
                f"Evidence belongs to snapshot '{record.snapshot_id}', "
                f"not current '{current_snapshot_id}'"
            )

        manifest = self._snapshots.get(current_snapshot_id)
        if not manifest:
            return False, EvidenceStatus.INVALID, f"Snapshot '{current_snapshot_id}' does not exist in store"

        # Check if file has changed on disk or lines are out of bounds
        try:
            target = self.reader.resolve(record.path)
            if not target.is_file():
                return False, EvidenceStatus.STALE, f"File '{record.path}' no longer exists on disk"

            rel_path = self.reader.to_relative(target)
            manifest_file_hash = manifest.files.get(rel_path) or manifest.files.get(record.path)
            if not manifest_file_hash:
                return False, EvidenceStatus.INVALID, f"File '{record.path}' is not in snapshot '{current_snapshot_id}' manifest"

            file_bytes = target.read_text(encoding="utf-8", errors="replace").encode("utf-8")
            current_hash = hashlib.sha256(file_bytes).hexdigest()
            if current_hash != manifest_file_hash or (record.content_hash and record.content_hash != "unknown" and current_hash != record.content_hash):
                return False, EvidenceStatus.STALE, f"File '{record.path}' was modified on disk after snapshot"

            file_text = file_bytes.decode("utf-8")
            lines = file_text.splitlines()
            total_lines = len(lines)
            if record.start_line < 1 or record.end_line < record.start_line or record.start_line > total_lines or record.end_line > total_lines:
                return False, EvidenceStatus.INVALID, f"Line range {record.start_line}-{record.end_line} out of bounds"

            actual_excerpt = "\n".join(lines[record.start_line - 1:record.end_line])
            actual_excerpt_hash = hashlib.sha256(actual_excerpt.encode("utf-8")).hexdigest()
            if actual_excerpt_hash != record.excerpt_hash:
                return False, EvidenceStatus.STALE, "Excerpt content has changed on disk"

        except Exception as e:
            return False, EvidenceStatus.INVALID, f"Failed to verify file '{record.path}': {e}"

        return True, EvidenceStatus.VALID, "Evidence verified"

    def get_evidence(self, evidence_id: str) -> Optional[EvidenceRecord]:
        return self._evidence.get(evidence_id)

    def get_snapshot(self, snapshot_id: str) -> Optional[SnapshotManifest]:
        return self._snapshots.get(snapshot_id)
