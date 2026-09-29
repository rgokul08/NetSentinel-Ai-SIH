"""
Realtime hub: fan-out of pipeline events to WebSocket subscribers.

The simulation engine and the ingestion pipeline publish plain dicts; connected
dashboard clients receive them. Polling clients use /api/traffic/live instead,
so the platform works with or without WebSocket support.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Any, Deque, Dict, Optional, Set

logger = logging.getLogger("cyberforecast.realtime")


class RealtimeHub:
    def __init__(self, history_size: int = 300) -> None:
        self._subscribers: Set[asyncio.Queue] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.recent: Deque[Dict[str, Any]] = deque(maxlen=history_size)
        self.published_total = 0

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def publish(self, event: Dict[str, Any]) -> None:
        """Thread-safe publish (called from the simulation worker thread too)."""
        self.recent.append(event)
        self.published_total += 1
        if not self._subscribers or self._loop is None:
            return
        for queue in list(self._subscribers):
            try:
                self._loop.call_soon_threadsafe(_safe_put, queue, event)
            except RuntimeError:  # loop closed during shutdown
                continue

    def recent_events(self, limit: int = 50) -> list:
        items = list(self.recent)[-limit:]
        return list(reversed(items))


def _safe_put(queue: asyncio.Queue, event: Dict[str, Any]) -> None:
    try:
        queue.put_nowait(event)
    except asyncio.QueueFull:
        try:
            queue.get_nowait()
            queue.put_nowait(event)
        except Exception:  # pragma: no cover
            pass


hub = RealtimeHub()
