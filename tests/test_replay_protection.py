"""
Tests for replay attack protection and HMAC-SHA256 signature verification.

These tests verify that the server correctly:
1. Rejects requests with duplicate nonces (replay attacks)
2. Rejects requests with expired timestamps
3. Rejects requests missing nonce, timestamp, signature, or api_key
4. Rejects requests with invalid signatures
5. Accepts valid signed requests
"""

import json
import secrets
import time

import pytest
from tests.test_client import CFMSTestClient

# Reuse the production-equivalent signature computation from the test client
_compute_signature = CFMSTestClient._compute_signature


class TestReplayProtection:
    """Test replay attack protection mechanisms."""

    @pytest.mark.asyncio
    async def test_normal_authenticated_request_succeeds(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that a normal authenticated request with valid nonce, timestamp, and signature succeeds."""
        response = await authenticated_client.send_request("list_users", {})
        assert response["code"] == 200, (
            f"Normal authenticated request should succeed, got: {response}"
        )

    @pytest.mark.asyncio
    async def test_replay_attack_rejected(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that replaying an identical request (same nonce) is rejected."""
        assert authenticated_client.websocket is not None
        assert authenticated_client.hmac_secret_key is not None
        assert authenticated_client.api_key is not None

        nonce = secrets.token_hex(16)
        ts = time.time()
        data: dict = {}
        action = "list_users"

        signature = _compute_signature(
            authenticated_client.hmac_secret_key, action, data, ts, nonce
        )

        # First request should succeed
        request1 = {
            "action": action,
            "data": data,
            "username": authenticated_client.username,
            "token": authenticated_client.token,
            "nonce": nonce,
            "timestamp": ts,
            "api_key": authenticated_client.api_key,
            "signature": signature,
        }
        await authenticated_client.websocket.send(json.dumps(request1))
        response1 = json.loads(await authenticated_client.websocket.recv())
        assert response1["code"] == 200, (
            f"First request should succeed, got: {response1}"
        )

        # Second request with same nonce should be rejected
        await authenticated_client.websocket.send(json.dumps(request1))
        response2 = json.loads(await authenticated_client.websocket.recv())
        assert response2["code"] == 1001, (
            f"Replayed request should be rejected with 1001, got: {response2}"
        )
        assert "nonce" in response2["message"].lower() or "replay" in response2["message"].lower(), (
            f"Error message should mention nonce or replay: {response2['message']}"
        )

    @pytest.mark.asyncio
    async def test_expired_timestamp_rejected(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that a request with an expired timestamp is rejected."""
        assert authenticated_client.websocket is not None
        assert authenticated_client.hmac_secret_key is not None
        assert authenticated_client.api_key is not None

        nonce = secrets.token_hex(16)
        ts = time.time() - 60  # 60 seconds ago
        data: dict = {}
        action = "list_users"

        signature = _compute_signature(
            authenticated_client.hmac_secret_key, action, data, ts, nonce
        )

        request = {
            "action": action,
            "data": data,
            "username": authenticated_client.username,
            "token": authenticated_client.token,
            "nonce": nonce,
            "timestamp": ts,
            "api_key": authenticated_client.api_key,
            "signature": signature,
        }
        await authenticated_client.websocket.send(json.dumps(request))
        response = json.loads(await authenticated_client.websocket.recv())
        assert response["code"] == 1001, (
            f"Expired timestamp should be rejected with 1001, got: {response}"
        )
        assert "timestamp" in response["message"].lower() or "time" in response["message"].lower(), (
            f"Error message should mention timestamp: {response['message']}"
        )

    @pytest.mark.asyncio
    async def test_future_timestamp_rejected(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that a request with a far-future timestamp is rejected."""
        assert authenticated_client.websocket is not None
        assert authenticated_client.hmac_secret_key is not None
        assert authenticated_client.api_key is not None

        nonce = secrets.token_hex(16)
        ts = time.time() + 60  # 60 seconds in the future
        data: dict = {}
        action = "list_users"

        signature = _compute_signature(
            authenticated_client.hmac_secret_key, action, data, ts, nonce
        )

        request = {
            "action": action,
            "data": data,
            "username": authenticated_client.username,
            "token": authenticated_client.token,
            "nonce": nonce,
            "timestamp": ts,
            "api_key": authenticated_client.api_key,
            "signature": signature,
        }
        await authenticated_client.websocket.send(json.dumps(request))
        response = json.loads(await authenticated_client.websocket.recv())
        assert response["code"] == 1001, (
            f"Future timestamp should be rejected with 1001, got: {response}"
        )

    @pytest.mark.asyncio
    async def test_missing_nonce_rejected(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that an authenticated request without a nonce is rejected."""
        assert authenticated_client.websocket is not None

        request = {
            "action": "list_users",
            "data": {},
            "username": authenticated_client.username,
            "token": authenticated_client.token,
            "timestamp": time.time(),
            "api_key": authenticated_client.api_key,
            "signature": "dummy",
        }
        await authenticated_client.websocket.send(json.dumps(request))
        response = json.loads(await authenticated_client.websocket.recv())
        assert response["code"] == 400, (
            f"Missing nonce should be rejected with 400, got: {response}"
        )

    @pytest.mark.asyncio
    async def test_short_nonce_rejected(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that a nonce that is too short is rejected."""
        assert authenticated_client.websocket is not None

        request = {
            "action": "list_users",
            "data": {},
            "username": authenticated_client.username,
            "token": authenticated_client.token,
            "nonce": "short",  # Less than NONCE_MIN_LENGTH (16)
            "timestamp": time.time(),
            "api_key": authenticated_client.api_key,
            "signature": "dummy",
        }
        await authenticated_client.websocket.send(json.dumps(request))
        response = json.loads(await authenticated_client.websocket.recv())
        assert response["code"] == 400, (
            f"Short nonce should be rejected with 400, got: {response}"
        )

    @pytest.mark.asyncio
    async def test_missing_timestamp_rejected(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that an authenticated request without a timestamp is rejected."""
        assert authenticated_client.websocket is not None

        request = {
            "action": "list_users",
            "data": {},
            "username": authenticated_client.username,
            "token": authenticated_client.token,
            "nonce": secrets.token_hex(16),
            "api_key": authenticated_client.api_key,
            "signature": "dummy",
        }
        await authenticated_client.websocket.send(json.dumps(request))
        response = json.loads(await authenticated_client.websocket.recv())
        assert response["code"] == 400, (
            f"Missing timestamp should be rejected with 400, got: {response}"
        )

    @pytest.mark.asyncio
    async def test_unauthenticated_requests_skip_replay_check(
        self, client: CFMSTestClient
    ):
        """Test that unauthenticated requests (no username/token) are not subject to replay checks."""
        # server_info is an unauthenticated endpoint
        response1 = await client.send_request("server_info", include_auth=False)
        assert response1["code"] == 200

        # Can send same request again without nonce/timestamp
        response2 = await client.send_request("server_info", include_auth=False)
        assert response2["code"] == 200

    @pytest.mark.asyncio
    async def test_unique_nonces_succeed(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that multiple requests with unique nonces all succeed."""
        for _ in range(5):
            response = await authenticated_client.send_request("list_users", {})
            assert response["code"] == 200, (
                f"Request with unique nonce should succeed, got: {response}"
            )


class TestSignatureVerification:
    """Test HMAC-SHA256 signature verification."""

    @pytest.mark.asyncio
    async def test_invalid_signature_rejected(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that a request with an invalid signature is rejected."""
        assert authenticated_client.websocket is not None

        nonce = secrets.token_hex(16)
        ts = time.time()

        request = {
            "action": "list_users",
            "data": {},
            "username": authenticated_client.username,
            "token": authenticated_client.token,
            "nonce": nonce,
            "timestamp": ts,
            "api_key": authenticated_client.api_key,
            "signature": "invalid_signature_value",
        }
        await authenticated_client.websocket.send(json.dumps(request))
        response = json.loads(await authenticated_client.websocket.recv())
        assert response["code"] == 1001, (
            f"Invalid signature should be rejected with 1001, got: {response}"
        )
        assert "signature" in response["message"].lower(), (
            f"Error message should mention signature: {response['message']}"
        )

    @pytest.mark.asyncio
    async def test_missing_signature_rejected(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that a request without a signature is rejected."""
        assert authenticated_client.websocket is not None

        request = {
            "action": "list_users",
            "data": {},
            "username": authenticated_client.username,
            "token": authenticated_client.token,
            "nonce": secrets.token_hex(16),
            "timestamp": time.time(),
            "api_key": authenticated_client.api_key,
            # No signature
        }
        await authenticated_client.websocket.send(json.dumps(request))
        response = json.loads(await authenticated_client.websocket.recv())
        assert response["code"] == 400, (
            f"Missing signature should be rejected with 400, got: {response}"
        )

    @pytest.mark.asyncio
    async def test_missing_api_key_rejected(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that a request without an API key is rejected."""
        assert authenticated_client.websocket is not None

        request = {
            "action": "list_users",
            "data": {},
            "username": authenticated_client.username,
            "token": authenticated_client.token,
            "nonce": secrets.token_hex(16),
            "timestamp": time.time(),
            "signature": "dummy",
            # No api_key
        }
        await authenticated_client.websocket.send(json.dumps(request))
        response = json.loads(await authenticated_client.websocket.recv())
        assert response["code"] == 400, (
            f"Missing API key should be rejected with 400, got: {response}"
        )

    @pytest.mark.asyncio
    async def test_wrong_api_key_rejected(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that a request with a wrong API key is rejected."""
        assert authenticated_client.websocket is not None

        nonce = secrets.token_hex(16)
        ts = time.time()

        request = {
            "action": "list_users",
            "data": {},
            "username": authenticated_client.username,
            "token": authenticated_client.token,
            "nonce": nonce,
            "timestamp": ts,
            "api_key": "wrong_api_key_value",
            "signature": "dummy",
        }
        await authenticated_client.websocket.send(json.dumps(request))
        response = json.loads(await authenticated_client.websocket.recv())
        assert response["code"] == 1001, (
            f"Wrong API key should be rejected with 1001, got: {response}"
        )

    @pytest.mark.asyncio
    async def test_tampered_data_rejected(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that a request with tampered data (signature mismatch) is rejected."""
        assert authenticated_client.websocket is not None
        assert authenticated_client.hmac_secret_key is not None
        assert authenticated_client.api_key is not None

        nonce = secrets.token_hex(16)
        ts = time.time()
        original_data = {"username": "admin"}
        tampered_data = {"username": "someone_else"}
        action = "get_user_info"

        # Compute signature for original data
        signature = _compute_signature(
            authenticated_client.hmac_secret_key, action, original_data, ts, nonce
        )

        # Send with tampered data (different username)
        request = {
            "action": action,
            "data": tampered_data,
            "username": authenticated_client.username,
            "token": authenticated_client.token,
            "nonce": nonce,
            "timestamp": ts,
            "api_key": authenticated_client.api_key,
            "signature": signature,
        }
        await authenticated_client.websocket.send(json.dumps(request))
        response = json.loads(await authenticated_client.websocket.recv())
        assert response["code"] == 1001, (
            f"Tampered data should be rejected with 1001, got: {response}"
        )

    @pytest.mark.asyncio
    async def test_login_returns_api_key_and_secret(
        self, client: CFMSTestClient, admin_credentials: dict
    ):
        """Test that successful login returns api_key and hmac_secret_key."""
        response = await client.login(
            admin_credentials["username"],
            admin_credentials["password"]
        )
        assert response["code"] == 200
        assert "api_key" in response["data"], "Login response should include api_key"
        assert "hmac_secret_key" in response["data"], "Login response should include hmac_secret_key"
        assert client.api_key is not None, "Client api_key should be set after login"
        assert client.hmac_secret_key is not None, "Client hmac_secret_key should be set after login"
