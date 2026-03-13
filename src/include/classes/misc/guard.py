import ipaddress
import threading
import time
from datetime import datetime, timedelta
from typing import Optional, Union

from include.database.handler import Session
from include.database.models.security.banned_subnet import BannedSubnet
from include.database.models.security.login import LoginSecurity
from include.util.log import getCustomLogger

logger = getCustomLogger("login_guard", filepath="./content/logs/login_guard.log")


class LoginGuard:
    """
    A security guard for login attempts, designed to mitigate brute-force
    attacks by tracking failed attempts and temporarily blocking identifiers
    (e.g., IP addresses or usernames) after a threshold is exceeded.

    Identifiers use ``|`` as a delimiter to avoid conflicts with IPv6 colons:
        - ``ip_limit|<ip>``
        - ``user_limit|<ip>|<username>``
    """

    _mem_cache: dict[str, float] = {}  # { identifier: locked_until_timestamp }
    _cache_lock = threading.Lock()
    _MAX_CACHE_SIZE: int = 10_000  # upper bound on in-memory cache entries

    # In-memory CIDR network block list
    _banned_networks: list[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
    _networks_loaded: bool = False

    @classmethod
    def reload_networks(cls) -> None:
        """
        Reload the banned subnet list from the database into memory.
        Thread-safe: acquires ``_cache_lock`` while updating ``_banned_networks``.
        """
        networks: list[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        with Session() as session:
            rows = session.query(BannedSubnet).all()
            for row in rows:
                try:
                    # strict=True: reject entries where host bits are set (e.g. '192.168.1.5/24').
                    # Administrators should store the network address ('192.168.1.0/24').
                    networks.append(ipaddress.ip_network(row.subnet, strict=True))
                except ValueError:
                    logger.warning(
                        f"LoginGuard: ignoring invalid subnet in database: {row.subnet!r}"
                    )

        with cls._cache_lock:
            cls._banned_networks = networks
            cls._networks_loaded = True

        logger.info(f"LoginGuard: loaded {len(networks)} banned subnet(s) from database.")

    @classmethod
    def _extract_ip(cls, identifier: str) -> Optional[str]:
        """
        Extract the IP address portion from a ``|``-delimited identifier.

        Supported formats::

            ip_limit|<ip>
            user_limit|<ip>|<username>

        Returns the IP string, or ``None`` if the identifier does not contain
        a recognisable IP field.
        """
        parts = identifier.split("|", 2)
        if len(parts) >= 2:
            return parts[1] or None
        return None

    @classmethod
    def _is_ip_banned_by_subnet(cls, ip_str: str) -> bool:
        """
        Return ``True`` if *ip_str* falls within any banned CIDR range.
        Callers must **not** hold ``_cache_lock`` (this method acquires it internally).
        """
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        with cls._cache_lock:
            networks = list(cls._banned_networks)

        return any(addr in network for network in networks)

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

        Three-layer defence, evaluated in order:

        1. **CIDR check** – if the identifier contains an IP address, check it
           against the in-memory list of administratively banned subnets.
        2. **Memory-cache check** – fast short-circuit for recently seen lockouts.
        3. **Database check** – authoritative lockout records persisted across
           restarts.

        Args:
            identifier (str): The ``|``-delimited identifier to check.
        Returns:
            bool: ``True`` if access is allowed, ``False`` if blocked.
        """
        # Ensure subnet list is loaded at least once.
        if not cls._networks_loaded:
            # Guard initial load with a lock to avoid concurrent reloads.
            with cls._cache_lock:
                if not cls._networks_loaded:
                    cls.reload_networks()

        # Layer 1: CIDR / administratively banned subnet
        ip_str = cls._extract_ip(identifier)
        if ip_str and cls._is_ip_banned_by_subnet(ip_str):
            return False

        # Layer 2: in-memory cache (fast path for recent lockouts)
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

        # Layer 3: database (authoritative, survives restarts)
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
