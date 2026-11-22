"""
AISOP API-key brute-force protection (OWASP API2:2023, API4:2023).

In-memory, per-process, sliding-window failure counter with a lockout that doubles on repeat offences. It is keyed on the
client address (and on the (address, key prefix) pair), never on the key prefix alone, so an attacker who knows or guesses
a prefix cannot lock the legitimate owner out from another address. Only credentials that were actually presented and
rejected count; requests with no credential do not. A successful authentication clears the (address, prefix) counter.

Nothing here stores or logs a secret: keys are never seen by this module, only the non-secret address and prefix strings.
State lives on ``app.state.auth_throttle`` so each application instance (and each test) has its own.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable

MAX_LOCKOUT_SECONDS = 900.0
_MAX_TRACKED_KEYS = 50_000


class AuthFailureThrottle:
    def __init__(
        self,
        *,
        max_failures_per_ip: int = 20,
        max_failures_per_key: int = 5,
        window_seconds: float = 300.0,
        lockout_seconds: float = 60.0,
        time_func: Callable[[], float] | None = None,
    ) -> None:
        self.max_per_ip = max(1, int(max_failures_per_ip))
        self.max_per_key = max(1, int(max_failures_per_key))
        self.window = float(window_seconds)
        self.lockout = float(lockout_seconds)
        self._now = time_func or time.monotonic
        self._failures: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._strikes: dict[str, int] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _keys(ip: str, prefix: str | None) -> list[tuple[str, int | None]]:
        keys: list[tuple[str, int | None]] = [(f"ip:{ip}", None)]
        if prefix:
            keys.append((f"pair:{ip}:{prefix}", -1))
        return keys

    def _limit_for(self, key: str) -> int:
        return self.max_per_key if key.startswith("pair:") else self.max_per_ip

    def retry_after(self, ip: str, prefix: str | None = None) -> int:
        """Seconds the caller must wait, or 0 when it may attempt authentication."""
        now = self._now()
        with self._lock:
            wait = 0.0
            for key, _ in self._keys(ip, prefix):
                until = self._locked_until.get(key)
                if until is not None:
                    if until > now:
                        wait = max(wait, until - now)
                    else:
                        del self._locked_until[key]
            return int(wait) + 1 if wait > 0 else 0

    def record_failure(self, ip: str, prefix: str | None = None) -> None:
        now = self._now()
        with self._lock:
            if len(self._failures) > _MAX_TRACKED_KEYS:
                self._evict(now)
            for key, _ in self._keys(ip, prefix):
                q = self._failures.setdefault(key, deque())
                q.append(now)
                while q and q[0] < now - self.window:
                    q.popleft()
                if len(q) >= self._limit_for(key):
                    strikes = self._strikes.get(key, 0)
                    self._strikes[key] = strikes + 1
                    self._locked_until[key] = now + min(self.lockout * (2**strikes), MAX_LOCKOUT_SECONDS)
                    q.clear()

    def record_success(self, ip: str, prefix: str | None = None) -> None:
        with self._lock:
            if prefix:
                pair = f"pair:{ip}:{prefix}"
                self._failures.pop(pair, None)
                self._strikes.pop(pair, None)

    def _evict(self, now: float) -> None:
        """Drop expired state; if the table is still too large (address-spraying flood) drop the oldest half."""
        for key in [k for k, q in self._failures.items() if not q or q[-1] < now - self.window]:
            self._failures.pop(key, None)
        for key in [k for k, t in self._locked_until.items() if t <= now]:
            self._locked_until.pop(key, None)
            self._strikes.pop(key, None)
        if len(self._failures) > _MAX_TRACKED_KEYS:
            for key in sorted(self._failures, key=lambda k: self._failures[k][-1] if self._failures[k] else 0.0)[: _MAX_TRACKED_KEYS // 2]:
                if key not in self._locked_until:
                    self._failures.pop(key, None)


__all__ = ["AuthFailureThrottle"]
