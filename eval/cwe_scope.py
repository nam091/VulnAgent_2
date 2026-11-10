"""Compatibility re-export of the CWE scope policy.

The policy belongs to the product (src/), not to the evaluation harness, so
the canonical implementation now lives in models.cwe_scope. This shim keeps
`from eval.cwe_scope import ...` working for existing callers and scripts.
"""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from models.cwe_scope import (  # noqa: E402
    CORE_CWE_SCOPE,
    CORE_CWE_SET,
    CORE_CWE_TITLES,
    EXCLUDED_CWE_TITLES,
    SCOPE_ID,
    SCOPE_LABEL,
    CWE_EQUIVALENCE,
    cwe_matches,
    normalize_cwe,
    eligible,
    in_scope,
    filter_labels,
    filter_clean_files,
    filter_detections,
    scope_coverage,
)

__all__ = [
    "CORE_CWE_SCOPE",
    "CORE_CWE_SET",
    "CORE_CWE_TITLES",
    "EXCLUDED_CWE_TITLES",
    "SCOPE_ID",
    "SCOPE_LABEL",
    "CWE_EQUIVALENCE",
    "cwe_matches",
    "normalize_cwe",
    "eligible",
    "in_scope",
    "filter_labels",
    "filter_clean_files",
    "filter_detections",
    "scope_coverage",
]
