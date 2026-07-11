import time
from agent.triage.enums import ReviewReason

class CircuitBreakerOpenError(Exception):
    def __init__(self, message="Circuit breaker is open"):
        super().__init__(message)
        self.review_reason = ReviewReason.CIRCUIT_BREAKER_OPEN

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, reset_seconds: int = 60):
        self.failure_threshold = failure_threshold
        self.reset_seconds = reset_seconds
        self.failures = 0
        self.last_failure_time = 0.0
        self.state = "closed"
        
    def record_failure(self):
        self.failures += 1
        self.last_failure_time = time.monotonic()
        if self.failures >= self.failure_threshold:
            self.state = "open"
            
    def record_success(self):
        self.failures = 0
        self.state = "closed"
        
    def check(self):
        if self.state == "open":
            if time.monotonic() - self.last_failure_time > self.reset_seconds:
                self.state = "half_open"
            else:
                raise CircuitBreakerOpenError()
