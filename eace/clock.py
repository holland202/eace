"""Deterministic clock for reproducible experiments."""

from __future__ import annotations

from typing import Optional


class DeterministicClock:
    """
    A monotonic, deterministic logical clock.

    Starts at an optional initial value (default 0) and advances
    by a fixed step on each tick. Used so that replays produce
    identical timestamps and therefore identical ledger hashes
    under identical seeds and protocols.
    """

    def __init__(self, start: int = 0, step: int = 1) -> None:
        if step <= 0:
            raise ValueError("step must be positive")
        self._t = int(start)
        self._step = int(step)
        self._history: list[int] = [self._t]

    @property
    def now(self) -> int:
        return self._t

    def tick(self) -> int:
        """Advance the clock and return the new time."""
        self._t += self._step
        self._history.append(self._t)
        return self._t

    def reset(self, start: Optional[int] = None) -> None:
        """Reset to start (or original start if None)."""
        self._t = int(start) if start is not None else 0
        self._history = [self._t]

    def history(self) -> list[int]:
        return list(self._history)

    def __repr__(self) -> str:
        return f"DeterministicClock(now={self._t}, step={self._step})"
