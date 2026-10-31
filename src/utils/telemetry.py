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
            self.total_tokens = 0

    def record_call(self, usage: Any = None) -> None:
        with self._lock:
            self.api_requests += 1
            if usage is not None:
                p = int(getattr(usage, "prompt_tokens", 0) or 0)
                c = int(getattr(usage, "completion_tokens", 0) or 0)
                t = int(getattr(usage, "total_tokens", 0) or (p + c))
                self.prompt_tokens += p
                self.completion_tokens += c
                self.total_tokens += t

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "api_requests": self.api_requests,
                "input_tokens": self.prompt_tokens,
                "output_tokens": self.completion_tokens,
                "total_tokens": self.total_tokens,
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
            }
