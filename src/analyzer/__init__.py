"""Analyzer package for VulnAgent.

Provides core vulnerability analysis, static rule scanning, AST slicing,
and prompt generation for multi-tier security analysis.
"""

from analyzer.ast_slicer import (
    ASTSlicer,
    ABSTRACT_SINK_CATEGORIES,
    SINK_CALL_SIGNATURES,
    get_sink_category,
    SinkAnchor,
    find_sink_anchors,
    find_call_site_sink_anchors,
)
from analyzer.prompt_manager import CWE_TAINT_RULES, PromptManager

__all__ = [
    "ASTSlicer",
    "ABSTRACT_SINK_CATEGORIES",
    "SINK_CALL_SIGNATURES",
    "get_sink_category",
    "SinkAnchor",
    "find_sink_anchors",
    "find_call_site_sink_anchors",
    "PromptManager",
    "CWE_TAINT_RULES",
]
