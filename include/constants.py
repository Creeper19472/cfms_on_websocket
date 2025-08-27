from include.classes.version import Version

__all__ = ["PROTOCOL_VERSION"]

CORE_VERSION = Version("0.0.1.250828_alpha")
PROTOCOL_VERSION = 3

AVAILABLE_ACCESS_TYPES = ["read", "write", "move", "manage"]