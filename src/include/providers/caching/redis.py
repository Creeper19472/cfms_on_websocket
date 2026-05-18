__all__ = ["RedisCachingProvider"]

from typing import Any, Optional

import redis

from include.providers.base import CachingProvider


class RedisCachingProvider(CachingProvider):
    def __init__(self, host: str, port: int, password: str = "", db: int = 0):
        self._client = redis.Redis(
            host=host, port=port, password=password, db=db, decode_responses=True
        )

    def get(self, key: str) -> Any:
        return self._client.get(key)

    def set(self, key: str, value: str, ttl: Optional[float] = None) -> None:
        if ttl:
            self._client.setex(key, int(ttl), value)
        else:
            self._client.set(key, value)

    def delete(self, key: str) -> None:
        self._client.delete(key)

    def set_if_not_exists(
        self, key: str, value: str, ttl: Optional[float] = None
    ) -> bool:
        res = self._client.set(key, value, ex=int(ttl) if ttl else None, nx=True)
        return bool(res)

    def exists(self, key: str) -> bool:
        return bool(self._client.exists(key))
