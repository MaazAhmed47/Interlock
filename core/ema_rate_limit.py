"""Bounded fail-closed per-process limiters for the experimental EMA pilot."""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Hashable


@dataclass
class _Window:
    started_at: float
    count: int


class BoundedWindowLimiter:
    """A bounded fixed-window limiter that denies new keys at capacity."""

    def __init__(
        self,
        *,
        limit: int,
        window_seconds: int,
        max_keys: int,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._monotonic = monotonic
        self._entries: OrderedDict[Hashable, _Window] = OrderedDict()
        self._lock = asyncio.Lock()

    def _purge_expired_locked(self, now: float) -> None:
        expired = [
            key
            for key, entry in self._entries.items()
            if now - entry.started_at >= self.window_seconds
        ]
        for key in expired:
            self._entries.pop(key, None)

    async def allow(self, key: Hashable) -> bool:
        """Consume one request or deny without growing beyond ``max_keys``."""
        now = self._monotonic()
        async with self._lock:
            self._purge_expired_locked(now)
            entry = self._entries.get(key)
            if entry is None:
                if len(self._entries) >= self.max_keys:
                    return False
                self._entries[key] = _Window(started_at=now, count=1)
                return True
            self._entries.move_to_end(key)
            if entry.count >= self.limit:
                return False
            entry.count += 1
            return True

    async def refund(self, key: Hashable) -> None:
        """Remove a successful provisional unauthenticated attempt."""
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return
            entry.count -= 1
            if entry.count <= 0:
                self._entries.pop(key, None)

    def safe_keys(self) -> tuple[Hashable, ...]:
        """Return the already privacy-safe keys for diagnostic tests."""
        return tuple(self._entries)
