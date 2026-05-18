from abc import ABC, abstractmethod
from contextlib import AbstractContextManager
from types import TracebackType
from typing import Any, Callable, Optional


class Provider(ABC):
    """
    Base class for all providers.

    This class defines the interface that all providers must implement.
    """


class FileObject(AbstractContextManager["FileObject"]):
    """
    Abstract base class for file objects that manage read/write operations.
    """

    def __enter__(self) -> "FileObject":
        return self

    @abstractmethod
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        pass

    @abstractmethod
    def read(self, size: int = -1) -> bytes:
        pass

    @abstractmethod
    def write(self, data: bytes) -> int:
        pass

    @abstractmethod
    def close(self) -> None:
        pass

    @abstractmethod
    def seekable(self) -> bool:
        pass

    def seek(self, offset: int, whence: int = 0, /) -> int:
        raise NotImplementedError

    def tell(self) -> int:
        raise NotImplementedError

    def truncate(self, size: Optional[int] = None, /) -> int:
        raise NotImplementedError


class StorageProvider(Provider):
    @abstractmethod
    def fopen(self, uri: str, mode: str = "rb") -> FileObject:
        pass

    @abstractmethod
    def exists(self, uri: str) -> bool:
        pass

    @abstractmethod
    def remove(self, uri: str) -> bool:
        pass

    @abstractmethod
    def mkdir(self, uri: str, mode: int = 0o777) -> None:
        pass

    @abstractmethod
    def makedirs(self, uri: str, mode: int = 0o777, exist_ok: bool = False) -> None:
        pass

    @abstractmethod
    def getsize(self, uri: str, /) -> int:
        pass


class EventBusProvider(Provider):
    @abstractmethod
    def subscribe(self, channel: str, callback: Callable[[str], None]) -> None:
        pass

    @abstractmethod
    def publish(self, channel: str, message: str) -> None:
        pass


class CachingProvider(Provider):
    @abstractmethod
    def get(self, key: str) -> Any:
        pass

    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """
        Set a value with an optional time-to-live in seconds.
        """
        pass

    @abstractmethod
    def delete(self, key: str) -> None:
        pass

    @abstractmethod
    def set_if_not_exists(
        self, key: str, value: str, ttl: Optional[float] = None
    ) -> bool:
        """
        Set a value only if the key does not exist. Returns True if set, False
        if already exists.
        """
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        pass
