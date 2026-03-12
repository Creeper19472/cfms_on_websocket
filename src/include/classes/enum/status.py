from enum import Enum

__all__ = ["EntityStatus"]


class EntityStatus(Enum):
    OK = 0
    DELETED = 1
    LOCKED = 2