__all__ = ["ProviderManager"]

from typing import cast

from include.providers.base import (
    CachingProvider,
    EventBusProvider,
    Provider,
    StorageProvider,
)


class ProviderManager:
    """
    Manager for providers.

    This class provides a centralized way to access different providers.
    """

    _initialized = False

    def __new__(cls):
        if not hasattr(cls, "_instance"):
            cls._instance = super(ProviderManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._providers: dict[str, Provider] = {}
        self._initialized = True

    def register(self, name: str, provider: Provider) -> None:
        self._providers[name] = provider

    def get(self, name: str, /) -> Provider:
        if name not in self._providers:
            raise KeyError(f"Provider '{name}' is not registered.")
        return self._providers[name]

    @property
    def storage(self) -> StorageProvider:
        return cast(StorageProvider, self.get("storage"))

    @property
    def event_bus(self) -> EventBusProvider:
        return cast(EventBusProvider, self.get("event_bus"))

    @property
    def caching(self) -> CachingProvider:
        return cast(CachingProvider, self.get("caching"))
