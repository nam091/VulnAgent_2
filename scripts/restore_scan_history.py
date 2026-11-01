#!/usr/bin/env python3
"""
VulnAgent - Scan History Restore Utility.
Restores historical scan jobs from the local backup directory back into .vulnagent-jobs/
with 1 command.
"""

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXTERNAL_BACKUP_BASE = Path("F:/PERSIONAL/DO_AN/Backup_Lich_Su_Quet_VulnAgent")
LOCAL_BACKUP_BASE = ROOT / ".local_history_backup"
TARGET_JOBS_DIR = ROOT / ".vulnagent-jobs"


def restore_history():
    print("[*] Searching for latest VulnAgent scan history backup...")

    # Look for latest backup folder
    backup_dirs = []
    if EXTERNAL_BACKUP_BASE.is_dir():
        backup_dirs.extend([p for p in EXTERNAL_BACKUP_BASE.glob("backup_*") if p.is_dir()])
    if LOCAL_BACKUP_BASE.is_dir():
        backup_dirs.extend([p for p in LOCAL_BACKUP_BASE.glob("backup_*") if p.is_dir()])

    if not backup_dirs:
        print("[-] No backup directories found.")
        sys.exit(1)

    latest_backup = sorted(backup_dirs, key=lambda p: p.stat().st_mtime, reverse=True)[0]
    print(f"[+] Found latest backup at: {latest_backup}")

    jobs_source = latest_backup / "jobs"
    if not jobs_source.is_dir():
        print(f"[-] Missing 'jobs' folder inside {latest_backup}")
        sys.exit(1)

    TARGET_JOBS_DIR.mkdir(parents=True, exist_ok=True)
    restored_count = 0

    for job_file in jobs_source.glob("*.json"):
        shutil.copy2(job_file, TARGET_JOBS_DIR / job_file.name)
        restored_count += 1

    # Restore models file if missing
    models_backup = latest_backup / ".vulnagent-models.json"
    if models_backup.is_file() and not (ROOT / ".vulnagent-models.json").is_file():
        shutil.copy2(models_backup, ROOT / ".vulnagent-models.json")
        print("[+] Restored .vulnagent-models.json")

    print(f"[✓] Restored {restored_count} historical scan jobs into {TARGET_JOBS_DIR} successfully!")


if __name__ == "__main__":
    restore_history()
