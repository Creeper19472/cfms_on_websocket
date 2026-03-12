from enum import Enum

__all__ = ["EntityStatus", "DocumentRevisionStatus"]


class EntityStatus(Enum):
    OK = 0
    DELETED = 1
    LOCKED = 2


class DocumentRevisionStatus(Enum):
    OK = 0
    DELETED = 1
