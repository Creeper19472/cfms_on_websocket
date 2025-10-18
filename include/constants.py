from include.classes.version import Version

__all__ = [
    "CORE_VERSION",
    "PROTOCOL_VERSION",
    "AVAILABLE_ACCESS_TYPES",
    "AVAILABLE_BLOCK_TYPES",
    "DEFAULT_TOKEN_EXPIRY_SECONDS",
    "FAILED_LOGIN_DELAY_SECONDS",
    "DEFAULT_SSL_CERT_VALIDITY_DAYS",
    "FILE_TRANSFER_CHUNK_SIZE",
    "FILE_TASK_DEFAULT_DURATION_SECONDS",
]

CORE_VERSION = Version("0.1.0.250919_alpha")
PROTOCOL_VERSION = 3

AVAILABLE_ACCESS_TYPES = ["read", "write", "move", "manage"]
AVAILABLE_BLOCK_TYPES: set = {"read", "write", "move"}

# Authentication and Security Constants
DEFAULT_TOKEN_EXPIRY_SECONDS = 3600  # 1 hour
FAILED_LOGIN_DELAY_SECONDS = 3  # Delay after failed login attempt
DEFAULT_SSL_CERT_VALIDITY_DAYS = 365  # 1 year

# File Transfer Constants
FILE_TRANSFER_CHUNK_SIZE = 8192  # 8KB - size threshold for determining end of transfer
FILE_TASK_DEFAULT_DURATION_SECONDS = 3600  # 1 hour