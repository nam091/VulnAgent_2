"""Compatibility re-export of ASTSlicer from context.ast_slicer."""

try:
    from context.ast_slicer import (
        ASTSlicer,
        SliceNode,
        SliceResult,
        SinkAnchor,
        ABSTRACT_SINK_CATEGORIES,
        HEURISTIC_SINK_SUFFIXES,
        HEURISTIC_SINK_OBJECT_PREFIXES,
        SINK_CALL_SIGNATURES,
        COMPLETENESS_COMPLETE,
        COMPLETENESS_PARTIAL,
        COMPLETENESS_FAILED,
        get_sink_category,
        find_sink_anchors,
        find_call_site_sink_anchors,
    )
except ImportError:
    from src.context.ast_slicer import (
        ASTSlicer,
        SliceNode,
        SliceResult,
        SinkAnchor,
        ABSTRACT_SINK_CATEGORIES,
        HEURISTIC_SINK_SUFFIXES,
        HEURISTIC_SINK_OBJECT_PREFIXES,
        SINK_CALL_SIGNATURES,
        COMPLETENESS_COMPLETE,
        COMPLETENESS_PARTIAL,
        COMPLETENESS_FAILED,
        get_sink_category,
        find_sink_anchors,
        find_call_site_sink_anchors,
    )

__all__ = [
    "ASTSlicer",
    "SliceNode",
    "SliceResult",
    "SinkAnchor",
    "ABSTRACT_SINK_CATEGORIES",
    "HEURISTIC_SINK_SUFFIXES",
    "HEURISTIC_SINK_OBJECT_PREFIXES",
    "SINK_CALL_SIGNATURES",
    "COMPLETENESS_COMPLETE",
    "COMPLETENESS_PARTIAL",
    "COMPLETENESS_FAILED",
    "get_sink_category",
    "find_sink_anchors",
    "find_call_site_sink_anchors",
]
