import collections
import ipaddress
import threading
import time
from datetime import datetime, timedelta
from typing import Union

from loguru import logger as log

from include.database.handler import Session
from include.database.models.security.banned_subnet import BannedSubnet
from include.database.models.security.login import LoginSecurity

logger = log.bind(name="login_guard")


class LoginGuard:
    """
    A security guard for login attempts, designed to mitigate brute-force
    attacks by tracking failed attempts and temporarily blocking identifiers.
    """

    _mem_cache: collections.OrderedDict[tuple[str, str], float] = (
        collections.OrderedDict()
    )  # { (username, ip_address): locked_until_timestamp }
    _cache_lock = threading.Lock()
    _MAX_CACHE_SIZE: int = 10_000

    _banned_networks: list[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
    _networks_loaded: bool = False

    @classmethod
    def reload_networks(cls) -> None:
        """
        Reload the banned subnet list from the database into memory.
        The database query is performed without holding the cache lock; the lock
        is only taken to swap in the new networks list and update state.
        """
        networks: list[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        with Session() as session:
            rows = session.query(BannedSubnet).all()
            for row in rows:
                try:
                    networks.append(ipaddress.ip_network(row.subnet, strict=True))
                except ValueError:
                    logger.warning(
                        f"Ignoring invalid subnet in database: {row.subnet!r}"
                    )
        with cls._cache_lock:
            cls._banned_networks = networks
            cls._networks_loaded = True
            logger.info(f"Loaded {len(networks)} banned subnet(s) from database.")

    @classmethod
    def _is_ip_banned_by_subnet(cls, ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        with cls._cache_lock:
            # Copy reference to local list to minimize lock contention during iteration
            networks = cls._banned_networks

        return any(addr in network for network in networks)

    @classmethod
    def _prune_cache(cls, now_ts: float) -> None:
        """Callers must hold _cache_lock."""
        expired_keys = [
            key for key, expiry in cls._mem_cache.items() if expiry <= now_ts
        ]
        for key in expired_keys:
            cls._mem_cache.pop(key, None)

        while len(cls._mem_cache) > cls._MAX_CACHE_SIZE:
            cls._mem_cache.popitem(last=False)

    @classmethod
    def check_access(cls, username: str, ip_address: str) -> bool:
        """
        Check if the given identifier is currently blocked.
        """

        # Ensure networks are loaded before checking access.
        # reload_networks() is responsible for its own locking, so we avoid
        # taking _cache_lock here to prevent unnecessary complexity or deadlocks.
        if not cls._networks_loaded:
            cls.reload_networks()

        # Layer 1: CIDR / administratively banned subnet
        if ip_address and cls._is_ip_banned_by_subnet(ip_address):
            return False

        # Layer 2: in-memory cache
        key = (username, ip_address)
        now_ts = time.time()
        with cls._cache_lock:
            cls._prune_cache(now_ts)
            expiry = cls._mem_cache.get(key)
            if expiry:
                if now_ts < expiry:
                    cls._mem_cache.move_to_end(key)
                    return False
                else:
                    del cls._mem_cache[key]

        # Layer 3: database
        with Session() as session:
            record = session.get(LoginSecurity, key)
            if record is not None and record.is_locked():
                if record.locked_until is not None:
                    with cls._cache_lock:
                        cls._mem_cache[key] = record.locked_until.timestamp()
                    return False
        return True

    @classmethod
    def report_failure(
        cls,
        username: str,
        ip_address: str,
        max_attempts: int = 5,
        lock_minutes: int = 15,
    ):
        key = (username, ip_address)
        with Session() as session:
            record = session.get(LoginSecurity, key)
            now = datetime.now()

            if not record:
                record = LoginSecurity(
                    username=username, ip_address=ip_address, failed_attempts=1
                )
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
                    cls._prune_cache(time.time())
                    cls._mem_cache[key] = lock_ts
                logger.warning(
                    f"Security: identifier '{username}|{ip_address}' locked until {lock_time}"
                )

            session.commit()

    @classmethod
    def report_success(cls, username: str, ip_address: str):
        key = (username, ip_address)
        with Session() as session:
            record = session.get(LoginSecurity, key)
            if record:
                session.delete(record)
                session.commit()

            with cls._cache_lock:
                cls._mem_cache.pop(key, None)
