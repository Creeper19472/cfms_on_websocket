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
                with cls._cache_lock:
                    cls._mem_cache[identifier] = lock_time.timestamp()
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
