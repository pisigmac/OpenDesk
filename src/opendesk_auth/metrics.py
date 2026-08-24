"""In-process counters for auth events."""

from __future__ import annotations

from threading import Lock

_lock = Lock()
_counts: dict[str, int] = {}


def inc(name: str, n: int = 1) -> None:
    with _lock:
        _counts[name] = _counts.get(name, 0) + n


def snapshot() -> dict[str, int]:
    with _lock:
        return dict(_counts)
