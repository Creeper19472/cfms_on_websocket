"""
Tests for password protection functionality.
"""

import pytest
from tests.test_client import CFMSTestClient


class TestPasswordProtection:
    """Test password protection on documents and directories."""
    
    @pytest.mark.asyncio
    async def test_enable_password_protection_on_document(
        self, authenticated_client: CFMSTestClient, test_document: dict
    ):
        """Test enabling password protection on a document."""
        document_id = test_document["document_id"]
        password = "test_password_123"
        
        # Enable password protection
        response = await authenticated_client.send_request(
            action="enable_password_protection",
            data={
                "target_type": "document",
                "target_id": document_id,
                "password": password
            }
        )
        
        assert isinstance(response, dict), "Response should be a dictionary"
        assert "code" in response, "Response missing 'code' field"
        assert response["code"] == 200, \
            f"Failed to enable password protection: {response.get('message', '')}"
    
    @pytest.mark.asyncio
    async def test_access_password_protected_document_without_password(
        self, authenticated_client: CFMSTestClient, test_document: dict
    ):
        """Test accessing a password-protected document without providing password."""
        document_id = test_document["document_id"]
        password = "test_password_456"
        
        # Enable password protection
        await authenticated_client.send_request(
            action="enable_password_protection",
            data={
                "target_type": "document",
                "target_id": document_id,
                "password": password
            }
        )
        
        # Try to access without password - should return 202
        response = await authenticated_client.send_request(
            action="get_document_info",
            data={"document_id": document_id}
        )
        
        assert isinstance(response, dict), "Response should be a dictionary"
        assert "code" in response, "Response missing 'code' field"
        assert response["code"] == 202, \
            f"Expected 202 (Password required), got {response.get('code')}: {response.get('message', '')}"
    
    @pytest.mark.asyncio
    async def test_access_password_protected_document_with_wrong_password(
        self, authenticated_client: CFMSTestClient, test_document: dict
    ):
        """Test accessing a password-protected document with incorrect password."""
        document_id = test_document["document_id"]
        correct_password = "correct_password_789"
        wrong_password = "wrong_password"
        
        # Enable password protection
        await authenticated_client.send_request(
            action="enable_password_protection",
            data={
                "target_type": "document",
                "target_id": document_id,
                "password": correct_password
            }
        )
        
        # Try to access with wrong password - should return 403
        response = await authenticated_client.send_request(
            action="get_document_info",
            data={
                "document_id": document_id,
                "password": wrong_password
            }
        )
        
        assert isinstance(response, dict), "Response should be a dictionary"
        assert "code" in response, "Response missing 'code' field"
        assert response["code"] == 403, \
            f"Expected 403 (Incorrect password), got {response.get('code')}: {response.get('message', '')}"
    
    @pytest.mark.asyncio
    async def test_access_password_protected_document_with_correct_password(
        self, authenticated_client: CFMSTestClient, test_document: dict
    ):
        """Test accessing a password-protected document with correct password."""
        document_id = test_document["document_id"]
        password = "correct_password_abc"
        
        # Enable password protection
        await authenticated_client.send_request(
            action="enable_password_protection",
            data={
                "target_type": "document",
                "target_id": document_id,
                "password": password
            }
        )
        
        # Access with correct password - should return 200
        response = await authenticated_client.send_request(
            action="get_document_info",
            data={
                "document_id": document_id,
                "password": password
            }
        )
        
        assert isinstance(response, dict), "Response should be a dictionary"
        assert "code" in response, "Response missing 'code' field"
        assert response["code"] == 200, \
            f"Expected 200 (Success), got {response.get('code')}: {response.get('message', '')}"
        assert "data" in response, "Response missing 'data'"
    
    @pytest.mark.asyncio
    async def test_remove_password_protection_from_document(
        self, authenticated_client: CFMSTestClient, test_document: dict
    ):
        """Test removing password protection from a document."""
        document_id = test_document["document_id"]
        password = "temp_password_xyz"
        
        # Enable password protection
        await authenticated_client.send_request(
            action="enable_password_protection",
            data={
                "target_type": "document",
                "target_id": document_id,
                "password": password
            }
        )
        
        # Remove password protection
        response = await authenticated_client.send_request(
            action="remove_password_protection",
            data={
                "target_type": "document",
                "target_id": document_id
            }
        )
        
        assert isinstance(response, dict), "Response should be a dictionary"
        assert "code" in response, "Response missing 'code' field"
        assert response["code"] == 200, \
            f"Failed to remove password protection: {response.get('message', '')}"
        
        # Now access without password should work (200)
        response = await authenticated_client.send_request(
            action="get_document_info",
            data={"document_id": document_id}
        )
        
        assert response["code"] == 200, \
            f"Expected 200 after removing protection, got {response.get('code')}"
    
    @pytest.mark.asyncio
    async def test_verify_password(
        self, authenticated_client: CFMSTestClient, test_document: dict
    ):
        """Test password verification endpoint."""
        document_id = test_document["document_id"]
        password = "verify_test_password"
        
        # Enable password protection
        await authenticated_client.send_request(
            action="enable_password_protection",
            data={
                "target_type": "document",
                "target_id": document_id,
                "password": password
            }
        )
        
        # Verify correct password
        response = await authenticated_client.send_request(
            action="verify_password",
            data={
                "target_type": "document",
                "target_id": document_id,
                "password": password
            }
        )
        
        assert response["code"] == 200, \
            f"Expected 200 for correct password, got {response.get('code')}"
        assert response.get("data", {}).get("verified") is True, \
            "Expected verified=True for correct password"
        
        # Verify incorrect password
        response = await authenticated_client.send_request(
            action="verify_password",
            data={
                "target_type": "document",
                "target_id": document_id,
                "password": "wrong_password"
            }
        )
        
        assert response["code"] == 403, \
            f"Expected 403 for incorrect password, got {response.get('code')}"
        assert response.get("data", {}).get("verified") is False, \
            "Expected verified=False for incorrect password"
    
    @pytest.mark.asyncio
    async def test_password_protection_on_directory(
        self, authenticated_client: CFMSTestClient
    ):
        """Test password protection on directories."""
        # Create a test directory
        create_response = await authenticated_client.create_directory("Test Protected Dir")
        assert create_response["code"] == 200, "Failed to create test directory"
        directory_id = create_response["data"]["id"]
        
        try:
            password = "dir_password_123"
            
            # Enable password protection
            response = await authenticated_client.send_request(
                action="enable_password_protection",
                data={
                    "target_type": "directory",
                    "target_id": directory_id,
                    "password": password
                }
            )
            assert response["code"] == 200, "Failed to enable password protection on directory"
            
            # Try to access without password - should return 202
            response = await authenticated_client.send_request(
                action="get_directory_info",
                data={"directory_id": directory_id}
            )
            assert response["code"] == 202, \
                f"Expected 202 (Password required), got {response.get('code')}"
            
            # Access with correct password - should return 200
            response = await authenticated_client.send_request(
                action="get_directory_info",
                data={
                    "directory_id": directory_id,
                    "password": password
                }
            )
            assert response["code"] == 200, \
                f"Expected 200 with correct password, got {response.get('code')}"
            
        finally:
            # Cleanup
            try:
                await authenticated_client.delete_directory(directory_id)
            except Exception:
                pass
    
    @pytest.mark.asyncio
    async def test_update_password(
        self, authenticated_client: CFMSTestClient, test_document: dict
    ):
        """Test updating password on a protected document."""
        document_id = test_document["document_id"]
        old_password = "old_password_123"
        new_password = "new_password_456"
        
        # Enable password protection with old password
        await authenticated_client.send_request(
            action="enable_password_protection",
            data={
                "target_type": "document",
                "target_id": document_id,
                "password": old_password
            }
        )
        
        # Update to new password
        response = await authenticated_client.send_request(
            action="enable_password_protection",
            data={
                "target_type": "document",
                "target_id": document_id,
                "password": new_password
            }
        )
        assert response["code"] == 200, "Failed to update password"
        
        # Old password should no longer work
        response = await authenticated_client.send_request(
            action="get_document_info",
            data={
                "document_id": document_id,
                "password": old_password
            }
        )
        assert response["code"] == 403, \
            f"Old password should not work, got {response.get('code')}"
        
        # New password should work
        response = await authenticated_client.send_request(
            action="get_document_info",
            data={
                "document_id": document_id,
                "password": new_password
            }
        )
        assert response["code"] == 200, \
            f"New password should work, got {response.get('code')}"
    
    @pytest.mark.asyncio
    async def test_password_protection_on_get_document(
        self, authenticated_client: CFMSTestClient, test_document: dict
    ):
        """Test password protection on get_document action."""
        document_id = test_document["document_id"]
        password = "get_doc_password"
        
        # Enable password protection
        await authenticated_client.send_request(
            action="enable_password_protection",
            data={
                "target_type": "document",
                "target_id": document_id,
                "password": password
            }
        )
        
        # Try get_document without password - should return 202
        response = await authenticated_client.send_request(
            action="get_document",
            data={"document_id": document_id}
        )
        assert response["code"] == 202, \
            f"Expected 202 for get_document without password, got {response.get('code')}"
        
        # Try with password - should return 200
        response = await authenticated_client.send_request(
            action="get_document",
            data={
                "document_id": document_id,
                "password": password
            }
        )
        assert response["code"] == 200, \
            f"Expected 200 for get_document with password, got {response.get('code')}"
    
    @pytest.mark.asyncio
    async def test_password_protection_on_list_directory(
        self, authenticated_client: CFMSTestClient
    ):
        """Test password protection on list_directory action."""
        # Create a test directory
        create_response = await authenticated_client.create_directory("Test List Protected Dir")
        assert create_response["code"] == 200, "Failed to create test directory"
        directory_id = create_response["data"]["id"]
        
        try:
            password = "list_dir_password"
            
            # Enable password protection
            await authenticated_client.send_request(
                action="enable_password_protection",
                data={
                    "target_type": "directory",
                    "target_id": directory_id,
                    "password": password
                }
            )
            
            # Try list_directory without password - should return 202
            response = await authenticated_client.send_request(
                action="list_directory",
                data={"folder_id": directory_id}
            )
            assert response["code"] == 202, \
                f"Expected 202 for list_directory without password, got {response.get('code')}"
            
            # Try with password - should return 200
            response = await authenticated_client.send_request(
                action="list_directory",
                data={
                    "folder_id": directory_id,
                    "password": password
                }
            )
            assert response["code"] == 200, \
                f"Expected 200 for list_directory with password, got {response.get('code')}"
            
        finally:
            # Cleanup
            try:
                await authenticated_client.delete_directory(directory_id)
            except Exception:
                pass
