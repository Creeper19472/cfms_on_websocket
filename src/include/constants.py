from include.classes.version import Version

__all__ = [
    "CORE_VERSION",
    "PROTOCOL_VERSION",
    "AVAILABLE_ACCESS_TYPES",
    "AVAILABLE_BLOCK_TYPES",
    "DEFAULT_TOKEN_EXPIRY_SECONDS",
    "FAILED_LOGIN_DELAY_SECONDS",
    "DEFAULT_SSL_CERT_VALIDITY_DAYS",
    "FILE_TRANSFER_MAX_CHUNK_SIZE",
    "FILE_TRANSFER_MIN_CHUNK_SIZE",
    "FILE_TASK_DEFAULT_DURATION_SECONDS",
    "REPLAY_PROTECTION_TIME_WINDOW_SECONDS",
    "NONCE_MIN_LENGTH",
]

CORE_VERSION = Version("0.1.0.260220_alpha")
PROTOCOL_VERSION = 9

AVAILABLE_ACCESS_TYPES = ["read", "write", "move", "manage"]
AVAILABLE_BLOCK_TYPES: set = {"read", "write", "move"}

# Authentication and Security Constants
DEFAULT_TOKEN_EXPIRY_SECONDS = 3600  # 1 hour
FAILED_LOGIN_DELAY_SECONDS = 3  # Delay after failed login attempt
DEFAULT_SSL_CERT_VALIDITY_DAYS = 365  # 1 year

# File Transfer Constants
FILE_TRANSFER_MAX_CHUNK_SIZE = 1024 * 64  # 64KB - size threshold for determining end of transfer
FILE_TRANSFER_MIN_CHUNK_SIZE = 512
FILE_TASK_DEFAULT_DURATION_SECONDS = 3600  # 1 hour

# Replay Attack Protection Constants
REPLAY_PROTECTION_TIME_WINDOW_SECONDS = 15  # Maximum age of a request timestamp
NONCE_MIN_LENGTH = 16  # Minimum length of a nonce string