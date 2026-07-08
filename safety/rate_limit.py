"""Small request rate limiter shared by security tools."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable


Clock = Callable[[], float]
Sleeper = Callable[[float], None]


@dataclass
class RateLimiter:
    requests_per_minute: int
    clock: Clock = time.monotonic
    sleeper: Sleeper = time.sleep

    def __post_init__(self) -> None:
        if self.requests_per_minute < 1:
            raise ValueError("requests_per_minute must be at least 1")
        self._last_request_at: float | None = None

    @property
    def minimum_interval_seconds(self) -> float:
        return 60.0 / self.requests_per_minute

    def wait(self) -> None:
        now = self.clock()
        if self._last_request_at is not None:
            elapsed = now - self._last_request_at
            remaining = self.minimum_interval_seconds - elapsed
            if remaining > 0:
                self.sleeper(remaining)
                now = self.clock()
        self._last_request_at = now
