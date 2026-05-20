__all__ = ["MemoryCachingProvider"]

import collections
import threading
import time
from typing import Any, Optional, Union

from include.providers.base import CachingProvider


class MemoryCachingProvider(CachingProvider):
    def __init__(self, max_size: int = 10000):
        self._max_size = max_size
        self._cache: collections.OrderedDict[
            str, tuple[Union[bytes, bytearray, memoryview, str, int, float], float]
        ] = collections.OrderedDict()
        self._lock = threading.Lock()

    def _prune(self):
        now = time.time()
        expired = [k for k, v in self._cache.items() if v[1] > 0 and v[1] < now]
        for k in expired:
            self._cache.pop(k, None)

        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)

    def get(self, key: str) -> Any:
        with self._lock:
            self._prune()
            val = self._cache.get(key)
            if val is None:
                return None
            if val[1] > 0 and val[1] < time.time():
                self._cache.pop(key, None)
                return None
            # LRU behavior
            self._cache.move_to_end(key)
            return val[0]

    def set(
        self,
        key: str,
        value: Union[bytes, bytearray, memoryview, str, int, float],
        ttl: Optional[float] = None,
        nx: bool = False,
    ) -> None:
        with self._lock:
            if nx and self.exists(key):
                return
            expire_at = time.time() + ttl if ttl else 0.0
            self._cache[key] = (value, expire_at)
            self._prune()

    def delete(self, key: str) -> None:
        with self._lock:
            self._cache.pop(key, None)

    def exists(self, key: str) -> bool:
        with self._lock:
            val = self._cache.get(key)
            if val is None:
                return False
            if val[1] > 0 and val[1] < time.time():
                self._cache.pop(key, None)
                return False
            return True
