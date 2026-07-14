"""Cancellation primitives for multi-request or long-running lab jobs."""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Event
from typing import Any


class JobCancelledError(RuntimeError):
    """Raised by cancellable jobs when cancellation should stop execution."""

    def __init__(self, message: str = "job cancellation requested", result: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.result = result


@dataclass
class CancellationToken:
    """Cancellation signal checked between network requests."""

    _event: Event = field(default_factory=Event)

    def cancel(self) -> None:
        self._event.set()

    def is_cancel_requested(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self.is_cancel_requested():
            raise JobCancelledError("job cancellation requested")
