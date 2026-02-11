"""
Tests for replay attack protection.

These tests verify that the server correctly rejects:
1. Requests with duplicate nonces (replay attacks)
2. Requests with expired timestamps
3. Requests missing nonce or timestamp when auth is included
"""

import json
import secrets
import time

import pytest
from tests.test_client import CFMSTestClient


class TestReplayProtection:
    """Test replay attack protection mechanisms."""

    @pytest.mark.asyncio
    async def test_normal_authenticated_request_succeeds(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that a normal authenticated request with valid nonce and timestamp succeeds."""
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

        nonce = secrets.token_hex(16)
        ts = time.time()

        # First request should succeed
        request1 = {
            "action": "list_users",
            "data": {},
            "username": authenticated_client.username,
            "token": authenticated_client.token,
            "nonce": nonce,
            "timestamp": ts,
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

        # Timestamp from 60 seconds ago (outside the 30-second window)
        request = {
            "action": "list_users",
            "data": {},
            "username": authenticated_client.username,
            "token": authenticated_client.token,
            "nonce": secrets.token_hex(16),
            "timestamp": time.time() - 60,
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

        # Timestamp 60 seconds in the future (outside the 30-second window)
        request = {
            "action": "list_users",
            "data": {},
            "username": authenticated_client.username,
            "token": authenticated_client.token,
            "nonce": secrets.token_hex(16),
            "timestamp": time.time() + 60,
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
            # No nonce
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
            # No timestamp
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
