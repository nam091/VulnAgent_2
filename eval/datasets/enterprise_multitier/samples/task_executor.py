"""Background maintenance and system automation task executor.

Contains Cross-File OS Command Injection sink (CWE-78).
"""

import subprocess
from typing import Dict
import config


def execute_maintenance_backup(backup_directory: str) -> Dict[str, Any]:
    """Run automated archive compression job via shell utility.

    VULNERABILITY: Cross-File Command Injection (CWE-78).
    The backup_directory parameter originates from HTTP management endpoints
    in controllers.py, forwarded through user_service.py, and interpolated into
    a shell string passed to subprocess.call(..., shell=True).
    The shell executes arbitrary command separators if unsanitized.
    """
    # Execute maintenance backup command with shell=True
    # Form shell command string
    archive_out = f"{config.BACKUP_ARCHIVE_DIR}/backup.tar.gz"
    cmd = f"tar -czf {archive_out} {backup_directory}"
    status_code = subprocess.call(cmd, shell=True)
    return {"status": "ok" if status_code == 0 else "error", "code": status_code}


def run_backup_job_safe(backup_directory: str) -> Dict[str, Any]:
    """Safe counterpart passing argument vector with shell=False."""
    archive_out = str(config.BACKUP_ARCHIVE_DIR / "backup.tar.gz")
    cmd = ["tar", "-czf", archive_out, backup_directory]
    status_code = subprocess.call(cmd, shell=False)
    return {"status": "ok" if status_code == 0 else "error", "code": status_code}
