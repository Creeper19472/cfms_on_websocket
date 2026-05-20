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
    def is_set(self) -> bool:
        return ProviderManager().caching.get("system:lockdown") == "1"

    def set(self) -> None:
        ProviderManager().caching.set("system:lockdown", "1")

    def clear(self) -> None:
        ProviderManager().caching.delete("system:lockdown")


lockdown_enabled = SyncLockdownEvent()
