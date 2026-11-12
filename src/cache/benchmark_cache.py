"""Disk-backed cache for benchmark evaluation results.

The in-memory `_BENCHMARK_EVAL_CACHE` in `main.py` is thrown away on every
restart, so the first `/api/benchmarks` call after a deploy re-scores every job
from scratch (8 s for 15 jobs, roughly 0.55 s per job). This module persists
those results so a restart costs nothing.

The cache key already includes everything that can change a score: job id,
a hash of the findings, the dataset key, a hash of `labels.json`, the CWE scope,
`exact_cwe` and the scorer version. Reusing a persisted entry is therefore
safe as long as the key matches.

Design notes
------------
* Failures never break the caller: an unreadable, corrupt or unwritable store
  degrades to "no cache" and logs once.
* Writes are atomic (temp file + replace) so a crash cannot leave a truncated
  JSON that poisons the next start.
* The store is capped so a long-lived deployment does not grow without bound;
  the least recently used entries are dropped first.
* Entries are pruned on load when their key references a job that no longer
  exists on disk, which is what happens after retention pruning.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Keep the file small enough to read in milliseconds. 15 jobs produce a few
# hundred kilobytes; 500 entries is generous headroom.
MAX_ENTRIES = 500
# Rewrite the file at most this often during a burst of misses.
SAVE_DEBOUNCE_SECONDS = 2.0


class BenchmarkCacheStore:
    """Persistent key/value store for benchmark evaluation payloads."""

    def __init__(self, path: Path, max_entries: int = MAX_ENTRIES) -> None:
        self.path = Path(path)
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._dirty = False
        self._last_save = 0.0
        self._load()

    # -- loading ----------------------------------------------------------

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("benchmark cache unreadable (%s); starting empty", exc)
            return
        entries = raw.get("entries")
        if not isinstance(entries, dict):
            logger.warning("benchmark cache has no entries map; starting empty")
            return
        now = time.time()
        loaded = 0
        for key, item in entries.items():
            if not isinstance(item, dict):
                continue
            # An entry whose scoring payload is gone is useless; keep only
            # well-formed records so a partial write cannot poison a read.
            if not isinstance(item.get("result"), dict):
                continue
            item.setdefault("touched", now)
            self._entries[key] = item
            loaded += 1
        logger.info("benchmark cache loaded: %d entr%s", loaded,
                    "y" if loaded == 1 else "ies")

    # -- access -----------------------------------------------------------

    def get(self, key: Optional[str]) -> Optional[Dict[str, Any]]:
        if not key:
            return None
        with self._lock:
            item = self._entries.get(key)
            if item is None:
                return None
            item["touched"] = time.time()
            self._dirty = True
            return item.get("result")

    def put(self, key: Optional[str], result: Dict[str, Any], job_id: str = "") -> None:
        if not key or not isinstance(result, dict):
            return
        with self._lock:
            self._entries[key] = {
                "result": result,
                "job_id": job_id,
                "touched": time.time(),
            }
            self._dirty = True
            self._evict_locked()
            should_save = (time.time() - self._last_save) >= SAVE_DEBOUNCE_SECONDS
        if should_save:
            self.save()

    def _evict_locked(self) -> None:
        overflow = len(self._entries) - self.max_entries
        if overflow <= 0:
            return
        # Oldest touched first; the dict is small enough that a full sort on
        # overflow is cheaper than maintaining an LRU list.
        victims = sorted(self._entries.items(), key=lambda kv: kv[1].get("touched", 0))[:overflow]
        for key, _ in victims:
            self._entries.pop(key, None)

    # -- persistence ------------------------------------------------------

    def save(self, force: bool = False) -> None:
        with self._lock:
            if not self._dirty and not force:
                return
            payload = {
                "version": 1,
                "saved_at": time.time(),
                "entries": dict(self._entries),
            }
            self._dirty = False
            self._last_save = time.time()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(
                dir=str(self.path.parent), prefix=self.path.name + ".", suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, ensure_ascii=False)
                os.replace(tmp_name, self.path)
            except Exception:
                # Clean up the temp file; the previous good file stays in place.
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
        except OSError as exc:
            logger.warning("benchmark cache not saved: %s", exc)

    def prune_missing_jobs(self, live_ids: set) -> int:
        """Drop entries whose job file is gone. Returns how many were removed."""
        if not live_ids:
            return 0
        with self._lock:
            doomed = [k for k, v in self._entries.items()
                      if v.get("job_id") and v["job_id"] not in live_ids]
            for key in doomed:
                self._entries.pop(key, None)
            if doomed:
                self._dirty = True
        return len(doomed)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "entries": len(self._entries),
                "path": str(self.path),
                "exists": self.path.is_file(),
            }
