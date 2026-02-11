"""
Nonce store for replay attack protection.

Tracks used nonces with automatic expiration to prevent replay attacks.
Each nonce is stored with a timestamp and automatically expired after
the configured time window.
"""

import threading
import time
from typing import Optional

from include.constants import REPLAY_PROTECTION_TIME_WINDOW_SECONDS

__all__ = ["NonceStore", "nonce_store"]


class NonceStore:
    """
    Thread-safe store for tracking used nonces to prevent replay attacks.

    Nonces are stored with their timestamp and automatically expired
    when they fall outside the configured time window.
    """

    def __init__(self, time_window: float = REPLAY_PROTECTION_TIME_WINDOW_SECONDS):
        self._nonces: dict[str, float] = {}  # nonce -> timestamp
        self._lock = threading.Lock()
        self._time_window = time_window

    def _cleanup_expired(self) -> None:
        """Remove nonces that have expired beyond the time window."""
        now = time.time()
        cutoff_past = now - self._time_window
        cutoff_future = now + self._time_window
        expired = [
            n for n, ts in self._nonces.items()
            if ts < cutoff_past or ts > cutoff_future
        ]
        for n in expired:
            del self._nonces[n]

    def validate_and_store(
        self, nonce: str, timestamp: float
    ) -> Optional[str]:
        """
        Validate a nonce and timestamp, storing it if valid.

        Args:
            nonce: The unique nonce string from the client request.
            timestamp: The timestamp from the client request.

        Returns:
            None if valid, or an error message string if invalid.
        """
        now = time.time()

        # Check timestamp is within acceptable window
        if abs(now - timestamp) > self._time_window:
            return "Request timestamp is outside the acceptable time window"

        with self._lock:
            self._cleanup_expired()

            # Check if nonce has already been used
            if nonce in self._nonces:
                return "Duplicate nonce detected: possible replay attack"

            # Store the nonce
            self._nonces[nonce] = timestamp

        return None


# Global singleton instance
nonce_store = NonceStore()
