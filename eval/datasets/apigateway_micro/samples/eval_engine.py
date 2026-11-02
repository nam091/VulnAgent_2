"""Dynamic Query and Filter Rule Evaluation Engine.

Microservice handler evaluating dynamic filtering criteria on data records.
Contains Cross-File Code Injection sink (CWE-94).
"""

from typing import Any, Dict


def evaluate_filter(query_expr: str) -> Any:
    """Evaluate dynamic Python filter condition against record fields.

    VULNERABILITY: Cross-File Code Injection (CWE-94).
    The query_expr string originates from HTTP client query parameters in gateway_router.py
    and is passed directly into Python's built-in eval(), enabling arbitrary remote code execution.
    """
    # Line 19: Dynamic code evaluation on untrusted client expression (Sink)
    # Evaluate client query directly
    return eval(query_expr)


def evaluate_filter_safe(field: str, expected_val: Any, record: Dict[str, Any]) -> bool:
    """Safe counterpart evaluating structured equality without dynamic code execution."""
    return record.get(field) == expected_val
