"""
Unit tests for provider-neutral threat intelligence resilience primitives:
- TokenBucketRateLimiter
- CircuitBreaker
"""
import concurrent.futures
import pytest
from app.modules.threatintel.resilience import (
    CircuitBreaker,
    CircuitBreakerState,
    TokenBucketRateLimiter,
)


class MockClock:
    """Controllable deterministic clock for zero-sleep testing."""

    def __init__(self, initial_time: float = 1000.0) -> None:
        self.current_time = initial_time

    def time(self) -> float:
        return self.current_time

    def advance(self, seconds: float) -> None:
        self.current_time += seconds


class TestTokenBucketRateLimiter:
    def test_invalid_parameters_raise(self):
        with pytest.raises(ValueError, match="capacity must be positive"):
            TokenBucketRateLimiter(capacity=0, refill_rate=1.0)
        with pytest.raises(ValueError, match="capacity must be positive"):
            TokenBucketRateLimiter(capacity=-5, refill_rate=1.0)
        with pytest.raises(ValueError, match="refill rate cannot be negative"):
            TokenBucketRateLimiter(capacity=10, refill_rate=-1.0)

    def test_initial_tokens_equals_capacity(self):
        clock = MockClock(100.0)
        limiter = TokenBucketRateLimiter(capacity=5.0, refill_rate=1.0, time_func=clock.time)
        assert limiter.available_tokens == 5.0
        assert limiter.time_until_available(1.0) == 0.0

    def test_token_consumption_and_exhaustion(self):
        clock = MockClock(100.0)
        limiter = TokenBucketRateLimiter(capacity=2.0, refill_rate=1.0, time_func=clock.time)
        
        assert limiter.acquire(1.0) is True
        assert limiter.available_tokens == 1.0
        
        assert limiter.acquire(1.0) is True
        assert limiter.available_tokens == 0.0
        
        # Bucket exhausted
        assert limiter.acquire(1.0) is False
        assert limiter.available_tokens == 0.0

    def test_refill_over_time(self):
        clock = MockClock(100.0)
        limiter = TokenBucketRateLimiter(capacity=10.0, refill_rate=2.0, time_func=clock.time)
        
        # Consume all tokens
        assert limiter.acquire(10.0) is True
        assert limiter.available_tokens == 0.0
        
        # Advance 2.5 seconds -> 2.5 * 2.0 = 5.0 tokens refilled
        clock.advance(2.5)
        assert limiter.available_tokens == 5.0
        assert limiter.acquire(3.0) is True
        assert limiter.available_tokens == 2.0
        
        # Advance 10 seconds -> capped at capacity (10.0)
        clock.advance(10.0)
        assert limiter.available_tokens == 10.0

    def test_time_until_available(self):
        clock = MockClock(100.0)
        limiter = TokenBucketRateLimiter(capacity=5.0, refill_rate=2.0, time_func=clock.time)
        limiter.acquire(5.0)
        
        # Need 2 tokens at 2 tokens/sec -> 1.0 second
        assert pytest.approx(limiter.time_until_available(2.0)) == 1.0
        
        # If refill_rate is 0 and exhausted -> infinity
        limiter_zero = TokenBucketRateLimiter(capacity=1.0, refill_rate=0.0, time_func=clock.time)
        limiter_zero.acquire(1.0)
        assert limiter_zero.time_until_available(1.0) == float("inf")

    def test_reset(self):
        clock = MockClock(100.0)
        limiter = TokenBucketRateLimiter(capacity=5.0, refill_rate=1.0, time_func=clock.time)
        limiter.acquire(5.0)
        assert limiter.available_tokens == 0.0
        
        limiter.reset()
        assert limiter.available_tokens == 5.0

    def test_thread_safety(self):
        limiter = TokenBucketRateLimiter(capacity=100.0, refill_rate=0.0)
        consumed = 0

        def worker():
            nonlocal consumed
            for _ in range(10):
                if limiter.acquire(1.0):
                    consumed += 1

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker) for _ in range(10)]
            concurrent.futures.wait(futures)

        assert consumed == 100
        assert limiter.acquire(1.0) is False


class TestCircuitBreaker:
    def test_invalid_parameters_raise(self):
        with pytest.raises(ValueError, match="Failure threshold must be >= 1"):
            CircuitBreaker(failure_threshold=0)
        with pytest.raises(ValueError, match="Recovery timeout cannot be negative"):
            CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=-10)

    def test_initial_state_closed(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=30.0)
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb.consecutive_failures == 0
        assert cb.allow_request() is True

    def test_trip_to_open_after_threshold(self):
        clock = MockClock(100.0)
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=30.0, time_func=clock.time)
        
        cb.record_failure()
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb.consecutive_failures == 1
        assert cb.allow_request() is True
        
        cb.record_failure()
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb.consecutive_failures == 2
        assert cb.allow_request() is True
        
        # 3rd failure trips the circuit
        cb.record_failure()
        assert cb.state == CircuitBreakerState.OPEN
        assert cb.consecutive_failures == 3
        assert cb.allow_request() is False

    def test_success_resets_consecutive_failures(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=30.0)
        cb.record_failure()
        cb.record_failure()
        assert cb.consecutive_failures == 2
        
        cb.record_success()
        assert cb.consecutive_failures == 0
        assert cb.state == CircuitBreakerState.CLOSED

    def test_open_to_half_open_transition(self):
        clock = MockClock(100.0)
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=30.0, time_func=clock.time)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitBreakerState.OPEN
        
        # Before timeout -> still OPEN
        clock.advance(10.0)
        assert cb.state == CircuitBreakerState.OPEN
        assert cb.allow_request() is False
        
        # After timeout -> transitions to HALF_OPEN
        clock.advance(25.0)  # total 35s > 30s
        assert cb.state == CircuitBreakerState.HALF_OPEN
        
        # 1 trial request permitted
        assert cb.allow_request() is True
        # Second in-flight trial rejected
        assert cb.allow_request() is False

    def test_half_open_success_resets_to_closed(self):
        clock = MockClock(100.0)
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=30.0, time_func=clock.time)
        cb.record_failure()
        cb.record_failure()
        clock.advance(35.0)
        assert cb.state == CircuitBreakerState.HALF_OPEN
        
        assert cb.allow_request() is True
        cb.record_success()
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb.consecutive_failures == 0
        assert cb.allow_request() is True

    def test_half_open_failure_reopens_circuit(self):
        clock = MockClock(100.0)
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=30.0, time_func=clock.time)
        cb.record_failure()
        cb.record_failure()
        clock.advance(35.0)
        assert cb.state == CircuitBreakerState.HALF_OPEN
        
        assert cb.allow_request() is True
        cb.record_failure()
        assert cb.state == CircuitBreakerState.OPEN
        assert cb.allow_request() is False

    def test_manual_reset(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=30.0)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitBreakerState.OPEN
        
        cb.reset()
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb.consecutive_failures == 0
        assert cb.allow_request() is True
