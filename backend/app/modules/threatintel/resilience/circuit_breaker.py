"""
Three-State Circuit Breaker for Threat Intelligence Providers.
"""

from __future__ import annotations

from enum import Enum
import threading
import time
from typing import Callable


class CircuitBreakerState(str, Enum):
    """Mutually exclusive operational state of a circuit breaker."""
    CLOSED = "closed"       # Normal operation: all requests allowed
    OPEN = "open"           # Tripped: all requests fail fast without network calls
    HALF_OPEN = "half_open" # Trial mode: single probe request permitted


class CircuitBreaker:
    """
    Thread-safe three-state circuit breaker pattern for external providers.

    Guarantees:
    - Trips from CLOSED to OPEN after failure_threshold consecutive errors.
    - Remains OPEN for recovery_timeout_seconds before transitioning to HALF_OPEN.
    - In HALF_OPEN, permits 1 trial request. Success resets to CLOSED; failure returns to OPEN.
    - Injected time_func enables deterministic time-travel in tests.
    """

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout_seconds: float = 60.0,
        time_func: Callable[[], float] | None = None,
    ) -> None:
        if failure_threshold <= 0:
            raise ValueError("Failure threshold must be >= 1.")
        if recovery_timeout_seconds < 0.0:
            raise ValueError("Recovery timeout cannot be negative.")

        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self.time_func = time_func or time.time

        self._state = CircuitBreakerState.CLOSED
        self._consecutive_failures = 0
        self._last_failure_time = 0.0
        self._half_open_in_flight = False
        self._lock = threading.RLock()

    @property
    def state(self) -> CircuitBreakerState:
        """Current state of the circuit breaker."""
        with self._lock:
            self._evaluate_state()
            return self._state

    @property
    def consecutive_failures(self) -> int:
        """Number of consecutive failures recorded."""
        with self._lock:
            return self._consecutive_failures

    def _evaluate_state(self) -> None:
        """Internal state transition check based on elapsed time."""
        if self._state == CircuitBreakerState.OPEN:
            now = self.time_func()
            if now - self._last_failure_time >= self.recovery_timeout_seconds:
                self._state = CircuitBreakerState.HALF_OPEN
                self._half_open_in_flight = False

    def allow_request(self) -> bool:
        """
        Check if request is permitted to proceed.

        Returns True if request should proceed, False if circuit is OPEN.
        """
        with self._lock:
            self._evaluate_state()
            if self._state == CircuitBreakerState.CLOSED:
                return True
            if self._state == CircuitBreakerState.HALF_OPEN:
                if not self._half_open_in_flight:
                    self._half_open_in_flight = True
                    return True
                return False
            # OPEN
            return False

    def record_success(self) -> None:
        """Record a successful provider execution."""
        with self._lock:
            self._consecutive_failures = 0
            self._half_open_in_flight = False
            self._state = CircuitBreakerState.CLOSED

    def record_failure(self) -> None:
        """Record a failed or timed-out provider execution."""
        with self._lock:
            now = self.time_func()
            self._last_failure_time = now
            self._consecutive_failures += 1
            if self._state == CircuitBreakerState.HALF_OPEN:
                # Trial failed: re-open circuit
                self._state = CircuitBreakerState.OPEN
                self._half_open_in_flight = False
            elif self._consecutive_failures >= self.failure_threshold:
                # Threshold reached: trip circuit
                self._state = CircuitBreakerState.OPEN

    def reset(self) -> None:
        """Explicitly reset circuit breaker to pristine CLOSED state."""
        with self._lock:
            self._state = CircuitBreakerState.CLOSED
            self._consecutive_failures = 0
            self._last_failure_time = 0.0
            self._half_open_in_flight = False
