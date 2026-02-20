"""
Tests for keyring operations.
"""

import pytest
from tests.test_client import CFMSTestClient


class TestKeyringOperations:
    """Test keyring CRUD operations for the authenticated user."""

    @pytest.mark.asyncio
    async def test_upload_keyring(self, authenticated_client: CFMSTestClient):
        """Test uploading a new key to the keyring."""
        response = await authenticated_client.upload_keyring(
            key_content="encrypted_dek_value_abc123",
            label="test-key",
        )
        assert response.get("code") == 200, f"Expected 200, got: {response}"
        assert "key_id" in response.get("data", {}), "Response must include key_id"

        # Cleanup
        key_id = response["data"]["key_id"]
        await authenticated_client.delete_keyring(key_id)

    @pytest.mark.asyncio
    async def test_get_keyring(self, authenticated_client: CFMSTestClient):
        """Test retrieving a key by its key_id."""
        upload_resp = await authenticated_client.upload_keyring(
            key_content="get_test_content",
            label="get-test",
        )
        assert upload_resp.get("code") == 200
        key_id = upload_resp["data"]["key_id"]

        get_resp = await authenticated_client.get_keyring(key_id)
        assert get_resp.get("code") == 200, f"Expected 200, got: {get_resp}"
        data = get_resp.get("data", {})
        assert data["key_id"] == key_id
        assert data["key_content"] == "get_test_content"
        assert data["label"] == "get-test"
        assert data["is_primary"] == False

        # Cleanup
        await authenticated_client.delete_keyring(key_id)

    @pytest.mark.asyncio
    async def test_get_nonexistent_keyring(self, authenticated_client: CFMSTestClient):
        """Test that retrieving a non-existent key returns 404."""
        response = await authenticated_client.get_keyring("nonexistent_key_id_xyz")
        assert response.get("code") == 404, f"Expected 404, got: {response}"

    @pytest.mark.asyncio
    async def test_delete_keyring(self, authenticated_client: CFMSTestClient):
        """Test deleting a key from the keyring."""
        upload_resp = await authenticated_client.upload_keyring(
            key_content="delete_test_content",
        )
        assert upload_resp.get("code") == 200
        key_id = upload_resp["data"]["key_id"]

        del_resp = await authenticated_client.delete_keyring(key_id)
        assert del_resp.get("code") == 200, f"Expected 200, got: {del_resp}"

        # Verify deletion
        get_resp = await authenticated_client.get_keyring(key_id)
        assert get_resp.get("code") == 404, "Key should not exist after deletion"

    @pytest.mark.asyncio
    async def test_list_keyrings(self, authenticated_client: CFMSTestClient):
        """Test listing all keys in the keyring."""
        upload_resp = await authenticated_client.upload_keyring(
            key_content="list_test_content",
            label="list-test",
        )
        assert upload_resp.get("code") == 200
        key_id = upload_resp["data"]["key_id"]

        list_resp = await authenticated_client.list_keyrings()
        assert list_resp.get("code") == 200, f"Expected 200, got: {list_resp}"
        keys = list_resp.get("data", {}).get("keys", [])
        assert isinstance(keys, list)
        key_ids = [k["key_id"] for k in keys]
        assert key_id in key_ids, "Uploaded key should appear in listing"

        # key_content must NOT be exposed in listing
        for k in keys:
            assert "key_content" not in k, "key_content must not be in list response"

        # Cleanup
        await authenticated_client.delete_keyring(key_id)

    @pytest.mark.asyncio
    async def test_set_primary_keyring(self, authenticated_client: CFMSTestClient):
        """Test designating a key as primary."""
        upload_resp = await authenticated_client.upload_keyring(
            key_content="primary_test_content",
        )
        assert upload_resp.get("code") == 200
        key_id = upload_resp["data"]["key_id"]

        set_resp = await authenticated_client.set_primary_keyring(key_id)
        assert set_resp.get("code") == 200, f"Expected 200, got: {set_resp}"

        get_resp = await authenticated_client.get_keyring(key_id)
        assert get_resp["data"]["is_primary"] == True

        # Cleanup
        await authenticated_client.delete_keyring(key_id)

    @pytest.mark.asyncio
    async def test_upload_primary_demotes_previous(self, authenticated_client: CFMSTestClient):
        """Uploading a new primary key must demote the previous one."""
        first_resp = await authenticated_client.upload_keyring(
            key_content="first_primary",
            is_primary=True,
        )
        assert first_resp.get("code") == 200
        first_id = first_resp["data"]["key_id"]

        second_resp = await authenticated_client.upload_keyring(
            key_content="second_primary",
            is_primary=True,
        )
        assert second_resp.get("code") == 200
        second_id = second_resp["data"]["key_id"]

        first_info = await authenticated_client.get_keyring(first_id)
        second_info = await authenticated_client.get_keyring(second_id)

        assert first_info["data"]["is_primary"] == False, "Previous primary should be demoted"
        assert second_info["data"]["is_primary"] == True, "New primary should be set"

        # Cleanup
        await authenticated_client.delete_keyring(first_id)
        await authenticated_client.delete_keyring(second_id)

    @pytest.mark.asyncio
    async def test_primary_key_returned_on_login(
        self,
        client: CFMSTestClient,
        admin_credentials: dict,
        authenticated_client: CFMSTestClient,
    ):
        """The primary key should be included in the login response."""
        upload_resp = await authenticated_client.upload_keyring(
            key_content="login_primary_content",
            is_primary=True,
        )
        assert upload_resp.get("code") == 200
        key_id = upload_resp["data"]["key_id"]

        # Login with a fresh client to get the login response data
        login_resp = await client.login(
            admin_credentials["username"],
            admin_credentials["password"],
        )
        assert login_resp.get("code") == 200
        data = login_resp.get("data", {})
        assert "primary_key" in data, "Login response must include primary_key when set"
        assert data["primary_key"]["key_id"] == key_id
        assert data["primary_key"]["key_content"] == "login_primary_content"

        # Cleanup
        await authenticated_client.delete_keyring(key_id)

    @pytest.mark.asyncio
    async def test_no_primary_key_not_in_login(
        self,
        client: CFMSTestClient,
        admin_credentials: dict,
        authenticated_client: CFMSTestClient,
    ):
        """When no primary key is set, login response should not contain primary_key."""
        # Ensure no primary key exists for admin
        list_resp = await authenticated_client.list_keyrings()
        for k in list_resp.get("data", {}).get("keys", []):
            if k["is_primary"]:
                await authenticated_client.delete_keyring(k["key_id"])

        login_resp = await client.login(
            admin_credentials["username"],
            admin_credentials["password"],
        )
        assert login_resp.get("code") == 200
        data = login_resp.get("data", {})
        assert "primary_key" not in data, (
            "Login response must not include primary_key when none is set"
        )


class TestKeyringWithoutAuth:
    """Keyring operations require authentication."""

    @pytest.mark.asyncio
    async def test_upload_keyring_without_auth(self, client: CFMSTestClient):
        response = await client.send_request(
            "upload_keyring",
            {"key_content": "test"},
            include_auth=False,
        )
        assert response.get("code") == 401

    @pytest.mark.asyncio
    async def test_get_keyring_without_auth(self, client: CFMSTestClient):
        response = await client.send_request(
            "get_keyring",
            {"key_id": "someid"},
            include_auth=False,
        )
        assert response.get("code") == 401

    @pytest.mark.asyncio
    async def test_delete_keyring_without_auth(self, client: CFMSTestClient):
        response = await client.send_request(
            "delete_keyring",
            {"key_id": "someid"},
            include_auth=False,
        )
        assert response.get("code") == 401

    @pytest.mark.asyncio
    async def test_list_keyrings_without_auth(self, client: CFMSTestClient):
        response = await client.send_request(
            "list_keyrings",
            {},
            include_auth=False,
        )
        assert response.get("code") == 401
