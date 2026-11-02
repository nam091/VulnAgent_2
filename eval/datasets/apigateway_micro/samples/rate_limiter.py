"""Token-bucket rate limiter backed by time.monotonic().

Clean control module enforcing rate limits before routing requests to microservices.
"""

import time
from typing import Dict


class TokenBucketRateLimiter:
    """Token bucket rate limiter implementation."""

    def __init__(self, rate: float = 10.0, capacity: float = 60.0):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()

    def acquire(self, tokens: float = 1.0) -> bool:
        """Attempt to acquire tokens from the bucket."""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.last_update = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


class RateLimitRegistry:
    """Per-client rate limiter registry."""

    def __init__(self, default_rate: float = 10.0, default_capacity: float = 20.0):
        self.default_rate = default_rate
        self.default_capacity = default_capacity
        self.limiters: Dict[str, TokenBucketRateLimiter] = {}

    def check_rate_limit(self, client_id: str) -> bool:
        """Check if client has remaining rate limit tokens."""
        if client_id not in self.limiters:
            self.limiters[client_id] = TokenBucketRateLimiter(
                rate=self.default_rate,
                capacity=self.default_capacity
            )
        return self.limiters[client_id].acquire(1.0)
