"""
Token Bucket Rate Limiter for Threat Intelligence Providers.
"""

from __future__ import annotations

import threading
import time
from typing import Callable


class TokenBucketRateLimiter:
    """
    Thread-safe Token Bucket Rate Limiter with configurable capacity and refill rate.

    Guarantees:
    - Immediate atomic acquisition without blocking execution threads.
    - Deterministic testing support via injectable time_func.
    - Thread-safe synchronization via reentrant lock.
    """

    def __init__(
        self,
        capacity: float,
        refill_rate: float,
        time_func: Callable[[], float] | None = None,
    ) -> None:
        """
        Initialize rate limiter.

        Args:
            capacity: Maximum burst capacity in tokens.
            refill_rate: Number of tokens replenished per second.
            time_func: Callable returning epoch timestamp (defaults to time.time).
        """
        if capacity <= 0.0:
            raise ValueError("Token bucket capacity must be positive.")
        if refill_rate < 0.0:
            raise ValueError("Token bucket refill rate cannot be negative.")

        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.tokens = float(capacity)
        self.time_func = time_func or time.time
        self.last_refill = self.time_func()
        self._lock = threading.RLock()

    def _refill(self, now: float) -> None:
        """Update tokens based on elapsed time."""
        elapsed = now - self.last_refill
        if elapsed > 0:
            added = elapsed * self.refill_rate
            self.tokens = min(self.capacity, self.tokens + added)
            self.last_refill = now

    def acquire(self, tokens: float = 1.0) -> bool:
        """
        Attempt to acquire tokens immediately.

        Returns True if tokens were available and consumed, False otherwise.
        """
        with self._lock:
            now = self.time_func()
            self._refill(now)
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def time_until_available(self, tokens: float = 1.0) -> float:
        """
        Estimate seconds until required tokens become available.
        Returns 0.0 if already available.
        """
        with self._lock:
            now = self.time_func()
            self._refill(now)
            if self.tokens >= tokens:
                return 0.0
            if self.refill_rate <= 0:
                return float("inf")
            needed = tokens - self.tokens
            return needed / self.refill_rate

    @property
    def available_tokens(self) -> float:
        """Current number of available tokens."""
        with self._lock:
            self._refill(self.time_func())
            return self.tokens

    def reset(self) -> None:
        """Reset bucket to full capacity."""
        with self._lock:
            self.tokens = self.capacity
            self.last_refill = self.time_func()
