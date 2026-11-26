"""极简事件总线：给 SSE 用。只做 fan-out，不做持久化（持久化在 action_log）。"""
from __future__ import annotations

import queue
import threading
from typing import Dict, List, Optional


class Bus:
    def __init__(self, maxsize: int = 256):
        self._subs: List[queue.Queue] = []
        self._lock = threading.Lock()
        self._maxsize = maxsize
        self._seq = 0

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=self._maxsize)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def publish(self, event: Dict) -> Dict:
        with self._lock:
            self._seq += 1
            payload = dict(event)
            payload.setdefault("seq", self._seq)
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(payload)
            except queue.Full:
                pass
        return payload

    @property
    def subscribers(self) -> int:
        with self._lock:
            return len(self._subs)
