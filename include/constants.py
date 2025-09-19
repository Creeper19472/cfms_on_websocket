from include.classes.version import Version

# __all__ = ["PROTOCOL_VERSION"]

CORE_VERSION = Version("0.1.0.250919_alpha")
PROTOCOL_VERSION = 3

AVAILABLE_ACCESS_TYPES = ["read", "write", "move", "manage"]
AVAILABLE_BLOCK_TYPES: set = {"read", "write", "move"}