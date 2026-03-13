import threading
import time
from datetime import datetime, timedelta
from include.database.handler import Session
from include.database.models.security.login import LoginSecurity
from include.util.log import getCustomLogger

logger = getCustomLogger("login_guard", filepath="./content/logs/login_guard.log")


class LoginGuard:
    """
    A security guard for login attempts, designed to mitigate brute-force
    attacks by tracking failed attempts and temporarily blocking identifiers
    (e.g., IP addresses or usernames) after a threshold is exceeded.
    """

    _mem_cache: dict[str, float] = {}  # { identifier: timestamp }
    _cache_lock = threading.Lock()
    _MAX_CACHE_SIZE: int = 10_000  # upper bound on in-memory cache entries

    @classmethod
    def _prune_cache(cls, now_ts: float) -> None:
        """
        Remove expired entries and enforce the maximum cache size.
        Callers must hold _cache_lock.
        """
        # Remove expired entries first
        expired_keys = [key for key, expiry in cls._mem_cache.items() if expiry <= now_ts]
        for key in expired_keys:
            cls._mem_cache.pop(key, None)

        # Enforce maximum cache size by evicting entries with the earliest expiry
        if len(cls._mem_cache) > cls._MAX_CACHE_SIZE:
            # Sort identifiers by expiry time (oldest first) and evict until size is within bounds
            sorted_items = sorted(cls._mem_cache.items(), key=lambda item: item[1])
            for key, _expiry in sorted_items:
                if len(cls._mem_cache) <= cls._MAX_CACHE_SIZE:
                    break
                cls._mem_cache.pop(key, None)

    @classmethod
    def check_access(cls, identifier: str) -> bool:
        """
        Check if the given identifier is currently blocked.
        Args:
            identifier (str): The identifier to check (e.g., IP or username).
        Returns:
            bool: True if access is allowed, False if blocked.
        """
        now_ts = time.time()
        with cls._cache_lock:
            # Opportunistically prune expired and excess entries
            cls._prune_cache(now_ts)
            expiry = cls._mem_cache.get(identifier)
            if expiry:
                if now_ts < expiry:
                    return False
                else:
                    del cls._mem_cache[identifier]

        with Session() as session:
            record = session.get(LoginSecurity, identifier)
            if record is not None and record.is_locked():
                if record.locked_until is not None:
                    with cls._cache_lock:
                        # Use the database lock expiry; pruning will enforce size bounds
                        cls._mem_cache[identifier] = record.locked_until.timestamp()
                    return False
        return True

    @classmethod
    def report_failure(
        cls, identifier: str, max_attempts: int = 5, lock_minutes: int = 15
    ):
        with Session() as session:
            record = session.get(LoginSecurity, identifier)
            now = datetime.now()

            if not record:
                record = LoginSecurity(identifier=identifier, failed_attempts=1)
                session.add(record)
            else:
                if record.last_attempt < now - timedelta(hours=1):
                    record.failed_attempts = 1
                else:
                    record.failed_attempts += 1
                record.last_attempt = now

            if record.failed_attempts >= max_attempts:
                lock_time = now + timedelta(minutes=lock_minutes)
                record.locked_until = lock_time
                lock_ts = lock_time.timestamp()
                with cls._cache_lock:
                    # Prune before inserting to keep cache bounded
                    cls._prune_cache(time.time())
                    cls._mem_cache[identifier] = lock_ts
                logger.warning(
                    f"Security: identifier '{identifier}' locked until {lock_time}"
                )

            session.commit()

    @classmethod
    def report_success(cls, identifier: str):
        with Session() as session:
            record = session.get(LoginSecurity, identifier)
            if record:
                session.delete(record)
                session.commit()

            with cls._cache_lock:
                cls._mem_cache.pop(identifier, None)
