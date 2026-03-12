from enum import IntEnum

__all__ = ["EntityStatus", "DocumentRevisionStatus"]


class EntityStatus(IntEnum):
    OK = 0
    DELETED = 1
    LOCKED = 2


class DocumentRevisionStatus(IntEnum):
    OK = 0
    DELETED = 1
