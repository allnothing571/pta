"""预算与熔断。

三件事：全局请求数上限、每主机最小间隔、按最近窗口的拦截率熔断。
全部是确定性计数，模型无权修改。
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

from .errors import BudgetExceeded


@dataclass
class HostBucket:
    """每主机最小间隔。锁只保护 last，sleep 在锁外做 —— 否则并发跑多个主机时
    会互相等，把"限速"变成"全局串行"。"""

    min_interval: float
    last: float = 0.0

    def __post_init__(self) -> None:
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delta = now - self.last
            wait_s = self.min_interval - delta
            self.last = now + max(wait_s, 0.0)
        if wait_s > 0:
            time.sleep(wait_s)

    def reserve(self, n: int) -> float:
        """一次预约 n 个时隙，返回"第一发之前要等多久"。

        竞态判定要的是 N 发**同时到达**；逐发 wait() 会把它们按 min_interval
        摊开，测出来的就变成"串行一致性"，结论毫无意义。
        """
        n = max(1, int(n))
        with self._lock:
            now = time.monotonic()
            wait_s = max(self.min_interval - (now - self.last), 0.0)
            self.last = now + wait_s + (n - 1) * self.min_interval
        return wait_s


@dataclass
class CircuitBreaker:
    window: int = 20
    block_ratio: float = 0.5
    cooldown_s: float = 600.0
    _events: Deque[bool] = field(default_factory=lambda: deque(maxlen=20))
    _open_until: float = 0.0

    def record(self, blocked: bool) -> None:
        self._events.append(bool(blocked))
        if len(self._events) >= self.window:
            ratio = sum(1 for e in self._events if e) / float(len(self._events))
            if ratio > self.block_ratio:
                self._open_until = time.monotonic() + self.cooldown_s

    def check(self) -> None:
        if time.monotonic() < self._open_until:
            raise BudgetExceeded("熔断打开，剩余 %.0fs" % (self._open_until - time.monotonic()))

    @property
    def state(self) -> str:
        return "open" if time.monotonic() < self._open_until else "closed"


@dataclass
class Budget:
    max_requests: int
    rate_per_host: float = 5.0
    used: int = 0
    per_host: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    buckets: Dict[str, HostBucket] = field(default_factory=dict)
    breaker: CircuitBreaker = field(default_factory=CircuitBreaker)
    log: List[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._lock = threading.Lock()

    def take(self, host: str) -> None:
        self.breaker.check()
        # 先"占号"再等：并发下如果先 sleep 再计数，N 个工作线程会一起看到
        # used=max-1 然后同时冲过上限。
        with self._lock:
            if self.used >= self.max_requests:
                raise BudgetExceeded("请求预算耗尽：%d/%d" % (self.used, self.max_requests))
            self.used += 1
            self.per_host[host] += 1
            bucket = self.buckets.get(host)
            if bucket is None:
                bucket = HostBucket(min_interval=1.0 / max(self.rate_per_host, 0.1))
                self.buckets[host] = bucket
        bucket.wait()

    def reserve_n(self, n: int, host: str, max_wait_s: float = 3.0) -> float:
        """为"同时发 n 发"一次占号 + 一次限速等待。

        与 take() 的区别：take() 每发都排队，N 发会被摊成 N×min_interval；
        reserve_n() 只等第一发的时隙，把后面 n-1 个时隙预约掉，
        于是调用方可以真的并发发出去，同时账本上仍然记了 n 发。
        """
        self.breaker.check()
        n = max(1, int(n))
        with self._lock:
            if self.used + n > self.max_requests:
                raise BudgetExceeded("请求预算不足：并发 %d 发，剩 %d"
                                     % (n, self.max_requests - self.used))
            self.used += n
            self.per_host[host] += n
            bucket = self.buckets.get(host)
            if bucket is None:
                bucket = HostBucket(min_interval=1.0 / max(self.rate_per_host, 0.1))
                self.buckets[host] = bucket
        wait_s = min(bucket.reserve(n), max_wait_s)
        if wait_s > 0:
            time.sleep(wait_s)
        return wait_s

    def snapshot(self) -> dict:
        with self._lock:
            used, per_host = self.used, dict(self.per_host)
        return {"used": used, "max": self.max_requests,
                "per_host": per_host, "breaker": self.breaker.state}

    def restore(self, used: int, per_host: Optional[Dict[str, int]] = None) -> None:
        """把落库的账接回内存。

        断点续跑时预算不能从 0 起——"上一轮花了多少"是对外的承诺，不是本地状态。
        只增不减：恢复值低于当前值说明内存里已经花了更多，以内存为准。
        """
        with self._lock:
            if int(used) > self.used:
                self.used = int(used)
            for host, n in (per_host or {}).items():
                if int(n) > self.per_host[host]:
                    self.per_host[host] = int(n)
