"""
Telemetry and token consumption tracker for LLM security analysis runs.
"""
from __future__ import annotations

import threading
from typing import Any, Dict, Optional


class TelemetryTracker:
    _instance: Optional[TelemetryTracker] = None
    _class_lock = threading.Lock()

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.api_requests = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.thinking_tokens = 0
        self.total_tokens = 0

    @classmethod
    def get_instance(cls) -> TelemetryTracker:
        with cls._class_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def reset(self) -> None:
        with self._lock:
            self.api_requests = 0
            self.prompt_tokens = 0
            self.completion_tokens = 0
            self.thinking_tokens = 0
            self.total_tokens = 0

    def record_call(self, usage: Any = None) -> None:
        with self._lock:
            self.api_requests += 1
            if usage is not None:
                # Handle both dict and object usages
                if isinstance(usage, dict):
                    p = int(usage.get("prompt_tokens") or 0)
                    c = int(usage.get("completion_tokens") or 0)
                    t = int(usage.get("total_tokens") or (p + c))
                    details = usage.get("completion_tokens_details") or {}
                    if isinstance(details, dict):
                        r = int(details.get("reasoning_tokens") or details.get("thinking_tokens") or 0)
                    else:
                        r = int(getattr(details, "reasoning_tokens", 0) or getattr(details, "thinking_tokens", 0) or 0)
                    if not r:
                        r = int(usage.get("completion_thinking_tokens") or usage.get("reasoning_tokens") or 0)
                else:
                    p = int(getattr(usage, "prompt_tokens", 0) or 0)
                    c = int(getattr(usage, "completion_tokens", 0) or 0)
                    t = int(getattr(usage, "total_tokens", 0) or (p + c))
                    details = getattr(usage, "completion_tokens_details", None)
                    r = 0
                    if details is not None:
                        if isinstance(details, dict):
                            r = int(details.get("reasoning_tokens") or details.get("thinking_tokens") or 0)
                        else:
                            r = int(getattr(details, "reasoning_tokens", 0) or getattr(details, "thinking_tokens", 0) or 0)
                    if not r:
                        r = int(getattr(usage, "completion_thinking_tokens", 0) or getattr(usage, "reasoning_tokens", 0) or 0)

                self.prompt_tokens += p
                self.completion_tokens += c
                self.thinking_tokens += r
                self.total_tokens += t

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "api_requests": self.api_requests,
                "input_tokens": self.prompt_tokens,
                "output_tokens": self.completion_tokens,
                "thinking_tokens": self.thinking_tokens,
                "reasoning_tokens": self.thinking_tokens,
                "total_tokens": self.total_tokens,
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
            }
