__all__ = ["MemoryCachingProvider", "RedisCachingProvider"]

from .memory import MemoryCachingProvider

try:
    from .redis import RedisCachingProvider
except ImportError:
    RedisCachingProvider = None
