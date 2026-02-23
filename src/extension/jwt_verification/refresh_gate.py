"""
RefreshGate - anti-refresh DoS protection.
"""

import threading
import time


class RefreshGate:
    """
    Simple, thread-safe refresh limiter.

    Behavior:
    - allow() returns True at most once per min_interval_seconds
    - additional calls within interval return False and increment a counter
    - when enough denials occur, you can log/alert (hook left as a placeholder)
    """

    def __init__(self, min_interval: float = 60.0, alert_threshold: int = 40) -> None:
        self._min_interval = min_interval
        self._alert_threshold = alert_threshold

        self._lock = threading.Lock()
        self._next_allowed_at: float = 0.0
        self._retry_attempts: int = 0

    def allow(self) -> bool:
        now = time.time()
        with self._lock:
            if now < self._next_allowed_at:
                self._retry_attempts += 1
                if self._retry_attempts >= self._alert_threshold:
                    # TODO: log / metrics / alert hook
                    # Example:
                    # logger.warning("JWKS refresh throttled frequently")
                    pass
                return False

            self._next_allowed_at = now + self._min_interval
            self._retry_attempts = 0
            return True
