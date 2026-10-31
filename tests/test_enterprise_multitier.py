"""Test suite for Enterprise Multi-tier benchmark dataset."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERIFY_SCRIPT = ROOT / "eval" / "datasets" / "enterprise_multitier" / "verify_dataset.py"


def test_enterprise_multitier_verification_script():
    """Execute the dataset verification script and assert exit code 0."""
    assert VERIFY_SCRIPT.is_file(), f"Verification script not found at {VERIFY_SCRIPT}"
    result = subprocess.run(
        [sys.executable, str(VERIFY_SCRIPT)],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, f"Verification failed:\n{result.stderr}\n{result.stdout}"
    assert "ALL VERIFICATIONS PASSED" in result.stdout
