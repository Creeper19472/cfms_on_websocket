import collections
import ipaddress
import threading
import time
from datetime import datetime, timedelta
from typing import Optional, Union

from loguru import logger as log

from include.database.handler import Session
from include.database.models.security.banned_subnet import BannedSubnet
from include.database.models.security.login import IPLoginSecurity, LoginSecurity

logger = log.bind(name="login_guard")


class LoginGuard:
    _mem_cache: collections.OrderedDict[tuple, float] = collections.OrderedDict()
    _cache_lock = threading.Lock()
    _MAX_CACHE_SIZE: int = 10_000
    _banned_networks: list[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
    _networks_loaded: bool = False

    @classmethod
    def reload_networks(cls) -> None:
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
            networks = cls._banned_networks
        return any(addr in network for network in networks)

    @classmethod
    def _prune_cache(cls, now_ts: float) -> None:
        expired_keys = [k for k, expiry in cls._mem_cache.items() if expiry <= now_ts]
        for k in expired_keys:
            cls._mem_cache.pop(k, None)
        while len(cls._mem_cache) > cls._MAX_CACHE_SIZE:
            cls._mem_cache.popitem(last=False)

    @classmethod
    def check_access(cls, ip_address: str, username: Optional[str] = None) -> bool:
        if not cls._networks_loaded:
            cls.reload_networks()
        if ip_address and cls._is_ip_banned_by_subnet(ip_address):
            return False

        keys_to_check = []
        if ip_address:
            keys_to_check.append(
                (IPLoginSecurity, IPLoginSecurity.make_cache_key(ip_address))
            )
        if username and ip_address:
            keys_to_check.append(
                (LoginSecurity, LoginSecurity.make_cache_key(username, ip_address))
            )

        now_ts = time.time()
        with cls._cache_lock:
            cls._prune_cache(now_ts)
            for model_cls, key in keys_to_check:
                expiry = cls._mem_cache.get(key)
                if expiry:
                    if now_ts < expiry:
                        cls._mem_cache.move_to_end(key)
                        return False
                    else:
                        del cls._mem_cache[key]

        with Session() as session:
            for model_cls, key in keys_to_check:
                if model_cls == IPLoginSecurity:
                    record = model_cls.get_record(session, ip_address)
                else:
                    record = model_cls.get_record(session, username, ip_address)

                if record is not None and record.is_locked():
                    if record.locked_until is not None:
                        with cls._cache_lock:
                            cls._mem_cache[key] = record.locked_until.timestamp()
                        return False
        return True

    @classmethod
    def report_failure(
        cls,
        ip_address: str,
        username: Optional[str] = None,
        max_attempts: int = 5,
        lock_minutes: int = 15,
        ip_max_attempts: int = 20,
        ip_lock_minutes: int = 15,
    ):
        now = datetime.now()
        with Session() as session:
            # 1. Update IP Security
            if ip_address:
                ip_key = IPLoginSecurity.make_cache_key(ip_address)
                ip_record = IPLoginSecurity.get_record(session, ip_address)
                if not ip_record:
                    ip_record = IPLoginSecurity(
                        ip_address=ip_address, failed_attempts=1
                    )
                    session.add(ip_record)
                else:
                    if ip_record.last_attempt < now - timedelta(hours=1):
                        ip_record.failed_attempts = 1
                    else:
                        ip_record.failed_attempts += 1
                    ip_record.last_attempt = now

                if ip_record.failed_attempts >= ip_max_attempts:
                    lock_time = now + timedelta(minutes=ip_lock_minutes)
                    ip_record.locked_until = lock_time
                    with cls._cache_lock:
                        cls._prune_cache(time.time())
                        cls._mem_cache[ip_key] = lock_time.timestamp()
                    logger.warning(
                        f"Security: IP '{ip_address}' locked until {lock_time}"
                    )

            # 2. Update User+IP Security
            if username and ip_address:
                u_key = LoginSecurity.make_cache_key(username, ip_address)
                u_record = LoginSecurity.get_record(session, username, ip_address)
                if not u_record:
                    u_record = LoginSecurity(
                        username=username, ip_address=ip_address, failed_attempts=1
                    )
                    session.add(u_record)
                else:
                    if u_record.last_attempt < now - timedelta(hours=1):
                        u_record.failed_attempts = 1
                    else:
                        u_record.failed_attempts += 1
                    u_record.last_attempt = now

                if u_record.failed_attempts >= max_attempts:
                    lock_time = now + timedelta(minutes=lock_minutes)
                    u_record.locked_until = lock_time
                    with cls._cache_lock:
                        cls._prune_cache(time.time())
                        cls._mem_cache[u_key] = lock_time.timestamp()
                    logger.warning(
                        f"Security: User '{username}' on IP '{ip_address}' locked until {lock_time}"
                    )

            session.commit()

    @classmethod
    def report_success(cls, ip_address: str, username: Optional[str] = None):
        with Session() as session:
            keys_to_clear = []

            if ip_address:
                ip_key = IPLoginSecurity.make_cache_key(ip_address)
                keys_to_clear.append(ip_key)
                ip_record = IPLoginSecurity.get_record(session, ip_address)
                if ip_record:
                    session.delete(ip_record)

            if username and ip_address:
                u_key = LoginSecurity.make_cache_key(username, ip_address)
                keys_to_clear.append(u_key)
                u_record = LoginSecurity.get_record(session, username, ip_address)
                if u_record:
                    session.delete(u_record)

            session.commit()

            with cls._cache_lock:
                for k in keys_to_clear:
                    cls._mem_cache.pop(k, None)
