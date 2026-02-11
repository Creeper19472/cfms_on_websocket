"""
HMAC-SHA256 request signature verification module.

Provides functions to compute and verify request signatures using HMAC-SHA256.
The signature covers the action, normalized data payload, timestamp, and nonce
to ensure request integrity and prevent tampering.
"""

import hashlib
import hmac
import json

__all__ = ["compute_signature", "verify_signature"]


def _normalize_request_payload(action: str, data: dict) -> str:
    """
    Normalize the request payload for signature computation.

    The normalization produces a deterministic string representation of the
    request by sorting JSON keys and using consistent formatting.

    Args:
        action: The request action string.
        data: The request data dictionary.

    Returns:
        A normalized string representation of the request payload.
    """
    normalized_data = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    data_hash = hashlib.sha256(normalized_data.encode("utf-8")).hexdigest()
    return f"{action}:{data_hash}"


def compute_signature(
    secret_key: str,
    action: str,
    data: dict,
    timestamp: float,
    nonce: str,
) -> str:
    """
    Compute an HMAC-SHA256 signature for a request.

    The signature string is composed of: timestamp, nonce, and a hash of
    the normalized request payload (action + data).

    Args:
        secret_key: The HMAC secret key.
        action: The request action string.
        data: The request data dictionary.
        timestamp: The request timestamp.
        nonce: The unique request nonce.

    Returns:
        The hexadecimal HMAC-SHA256 signature string.
    """
    payload_hash = _normalize_request_payload(action, data)
    string_to_sign = f"{timestamp}:{nonce}:{payload_hash}"
    return hmac.new(
        secret_key.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_signature(
    secret_key: str,
    action: str,
    data: dict,
    timestamp: float,
    nonce: str,
    provided_signature: str,
) -> bool:
    """
    Verify an HMAC-SHA256 request signature using constant-time comparison.

    Args:
        secret_key: The HMAC secret key.
        action: The request action string.
        data: The request data dictionary.
        timestamp: The request timestamp.
        nonce: The unique request nonce.
        provided_signature: The signature provided by the client.

    Returns:
        True if the signature is valid, False otherwise.
    """
    expected_signature = compute_signature(secret_key, action, data, timestamp, nonce)
    return hmac.compare_digest(expected_signature, provided_signature)
