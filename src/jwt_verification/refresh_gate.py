"""Rate limiting for JWKS refresh operations to prevent DoS attacks.

This module implements RefreshGate, a thread-safe rate limiter that prevents
excessive JWKS endpoint refreshes. This protects against:

1. Accidental DoS from legitimate traffic spikes
2. Malicious DoS attempts using invalid kid values
3. Cascading failures from overzealous retry logic

The gate allows at most one refresh per configured interval, rejecting additional
attempts and tracking denial counts for alerting.
"""

from __future__ import annotations

import threading
import time
from typing import Final

_DEFAULT_INTERVAL: Final[float] = 10
"""Default minimum interval between refreshes in seconds."""

_DEFAULT_ALERT_THRESHOLD: Final[int] = 5
"""Default number of denials before alerting (per interval)."""


class RefreshGate:
    """Thread-safe rate limiter for JWKS refresh operations.

    This gate ensures that forced JWKS refreshes cannot occur more frequently
    than a configured minimum interval. Additional refresh attempts within the
    interval are denied and counted for monitoring.

    Thread Safety:
        All operations are protected by an internal lock, making this class
        thread-safe for use in multi-threaded Flask applications.

    Use Cases:
        - Preventing excessive JWKS endpoint requests
        - Protecting against DoS via invalid kid attacks
        - Rate limiting retry logic after verification failures


    Attributes:
        _min_interval: Minimum seconds between allowed refreshes.
        _alert_threshold: Number of denials before alerting.
        _lock: Thread synchronization lock.
        _next_allowed_at: Unix timestamp when next refresh is allowed.
        _retry_attempts: Count of denied attempts since last allow.
    """

    def __init__(
        self,
        min_interval: float = _DEFAULT_INTERVAL,
        alert_threshold: int = _DEFAULT_ALERT_THRESHOLD,
    ) -> None:
        """Initialize the refresh gate.

        Args:
            min_interval: Minimum seconds between allowed refreshes.
                         Default: 60.0 (1 minute). Typical range: 30-300 seconds.
            alert_threshold: Number of denied attempts before alerting.
                            Default: 40. Tune based on expected traffic patterns.

        Raises:
            ValueError: If min_interval or alert_threshold are invalid.

        Configuration Guidance:
            - min_interval: Balance freshness vs. load. Auth0 keys rotate
              infrequently, so 60-300 seconds is typically safe.
            - alert_threshold: Set based on expected legitimate retries.
              40 denials at ~1 req/sec = ~40 seconds of throttling.
        """
        if min_interval <= 0:
            raise ValueError(f"min_interval must be positive, got {min_interval}")
        if alert_threshold < 1:
            raise ValueError(f"alert_threshold must be at least 1, got {alert_threshold}")

        self._min_interval = min_interval
        self._alert_threshold = alert_threshold

        self._lock = threading.Lock()
        self._next_allowed_at: float = 0.0
        self._retry_attempts: int = 0

    def allow(self) -> bool:
        """Check if a refresh operation is allowed now.

        This method is thread-safe and maintains internal state about when
        the next refresh is allowed.

        Returns:
            True if refresh is allowed (and interval is reset).
            False if refresh is denied (too soon since last refresh).

        Side Effects:
            - On True: Resets next_allowed_at and retry_attempts counter
            - On False: Increments retry_attempts counter
            - If retry_attempts >= alert_threshold: Triggers alert hook (TODO)

        Observability TODO:
            Current implementation has a placeholder for alerting. Production
            deployments should:
            - Log warnings when alert_threshold is reached
            - Emit metrics for denied attempts
            - Integrate with monitoring/alerting systems
        """
        now = time.time()

        with self._lock:
            if now < self._next_allowed_at:
                # Denied - increment retry counter
                self._retry_attempts += 1

                # Alert if threshold reached
                if self._retry_attempts >= self._alert_threshold:
                    # TODO: Integrate with logging/monitoring
                    # Example implementations:
                    # - logger.warning(f"JWKS refresh throttled: {self._retry_attempts} denials")
                    # - metrics.increment("jwks.refresh.throttled")
                    # - alerts.trigger("jwks_refresh_dos")
                    pass

                return False

            # Allowed - reset state and set next allowed time
            self._next_allowed_at = now + self._min_interval
            self._retry_attempts = 0
            return True
