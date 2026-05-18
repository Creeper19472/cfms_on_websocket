"""
Shared variables across the program.
"""

__all__ = ["clients", "clients_lock", "lockdown_enabled"]

import threading

from include.classes.multiplexer import MultiplexConnection
from include.providers.manager import ProviderManager

clients: set[MultiplexConnection] = set()
clients_lock = threading.Lock()


class SyncLockdownEvent:
    def __init__(self):
        self._cache = ProviderManager().caching

    def is_set(self) -> bool:
        return self._cache.get("system:lockdown") == True

    def set(self) -> None:
        self._cache.set("system:lockdown", True)

    def clear(self) -> None:
        self._cache.delete("system:lockdown")


lockdown_enabled = SyncLockdownEvent()
