#!/usr/bin/env python3
"""
VulnAgent - Local Scan History Backup Utility.
Saves a complete snapshot of all historical scan jobs, models, and configuration
locally on this computer (outside git tracking) so code can be cleanly deployed to VPS
without losing past research records.
"""

import json
import os
import shutil
import sys
import zipfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXTERNAL_BACKUP_BASE = Path("F:/PERSIONAL/DO_AN/Backup_Lich_Su_Quet_VulnAgent")
LOCAL_BACKUP_BASE = ROOT / ".local_history_backup"


def backup_history():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"[*] Starting VulnAgent scan history backup at {timestamp}...")

    EXTERNAL_BACKUP_BASE.mkdir(parents=True, exist_ok=True)
    LOCAL_BACKUP_BASE.mkdir(parents=True, exist_ok=True)

    # 1. Collect all jobs across .vulnagent-jobs and src/.vulnagent-jobs
    jobs = {}
    sources = [
        ROOT / ".vulnagent-jobs",
        ROOT / "src" / ".vulnagent-jobs",
    ]

    for s in sources:
        if s.is_dir():
            for p in s.glob("*.json"):
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                    jid = data.get("id") or p.stem
                    jobs[jid] = data
                except Exception as e:
                    print(f"[-] Warning: Failed to read job file {p}: {e}")

    print(f"[+] Total unique scan jobs discovered: {len(jobs)}")

    # 2. Write to external backup folder and local backup folder
    backup_folder_name = f"backup_{timestamp}"
    destinations = [
        EXTERNAL_BACKUP_BASE / backup_folder_name,
        LOCAL_BACKUP_BASE / backup_folder_name,
    ]

    for dest in destinations:
        dest.mkdir(parents=True, exist_ok=True)
        jobs_dir = dest / "jobs"
        jobs_dir.mkdir(parents=True, exist_ok=True)

        for jid, d in sorted(jobs.items()):
            (jobs_dir / f"{jid}.json").write_text(
                json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8"
            )

        if (ROOT / ".vulnagent-models.json").is_file():
            shutil.copy2(ROOT / ".vulnagent-models.json", dest / ".vulnagent-models.json")
        if (ROOT / ".env").is_file():
            shutil.copy2(ROOT / ".env", dest / ".env.backup")

        manifest = {
            "backup_timestamp": datetime.now().isoformat(),
            "total_jobs": len(jobs),
            "jobs": [
                {
                    "id": jid,
                    "label": d.get("label"),
                    "status": d.get("status"),
                    "findings_count": len(d.get("result", {}).get("findings", [])) if d.get("result") else 0,
                    "created_at": d.get("created_at"),
                }
                for jid, d in sorted(jobs.items())
            ],
        }
        (dest / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # 3. Create compressed ZIP archive in external thesis backup folder
    zip_path = EXTERNAL_BACKUP_BASE / f"VulnAgent_History_Backup_{timestamp}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        source_dir = EXTERNAL_BACKUP_BASE / backup_folder_name
        for root_p, _, files in os.walk(source_dir):
            for f in files:
                full_path = os.path.join(root_p, f)
                arc_name = os.path.relpath(full_path, source_dir)
                z.write(full_path, arc_name)

    print(f"[✓] Backup completed successfully!")
    print(f"    - External Thesis Folder: {EXTERNAL_BACKUP_BASE / backup_folder_name}")
    print(f"    - Standalone ZIP Archive: {zip_path} ({zip_path.stat().st_size:,} bytes)")
    print(f"    - Local Gitignored Copy:  {LOCAL_BACKUP_BASE / backup_folder_name}")


if __name__ == "__main__":
    backup_history()
