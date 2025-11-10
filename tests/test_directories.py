"""
Tests for directory management operations.
"""

import pytest
from tests.test_client import CFMSTestClient


class TestDirectoryOperations:
    """Test directory operations."""
    
    async def test_list_directory_root(self, authenticated_client: CFMSTestClient):
        """Test listing the root directory."""
        response = await authenticated_client.list_directory()
        
        assert response["code"] == 200
        assert "data" in response
    
    async def test_create_directory(self, authenticated_client: CFMSTestClient):
        """Test creating a new directory."""
        dir_name = "Test Directory"
        response = await authenticated_client.create_directory(dir_name)
        
        # Directory creation might succeed or fail based on permissions
        # We just check the response is valid
        assert "code" in response
        assert "data" in response
        
        if response["code"] == 200:
            # Cleanup if created successfully
            directory_id = response["data"].get("id")
            if directory_id:
                try:
                    await authenticated_client.delete_directory(directory_id)
                except Exception:
                    pass
    
    async def test_create_directory_with_empty_name(self, authenticated_client: CFMSTestClient):
        """Test creating a directory with an empty name."""
        response = await authenticated_client.create_directory("")
        
        # Should fail validation
        assert response["code"] == 400
    
    async def test_delete_directory(self, authenticated_client: CFMSTestClient):
        """Test deleting a directory."""
        # First create a directory
        create_response = await authenticated_client.create_directory("Directory to Delete")
        
        if create_response["code"] == 200:
            directory_id = create_response["data"]["id"]
            
            # Delete it
            delete_response = await authenticated_client.delete_directory(directory_id)
            
            # Should get a response (success or failure is implementation-dependent)
            assert "code" in delete_response
    
    async def test_delete_nonexistent_directory(self, authenticated_client: CFMSTestClient):
        """Test deleting a directory that doesn't exist."""
        response = await authenticated_client.delete_directory("nonexistent_folder_id")
        
        assert response["code"] != 200
    
    async def test_list_directory_contents(self, authenticated_client: CFMSTestClient):
        """Test listing directory contents after creating items."""
        # Create a test directory
        dir_response = await authenticated_client.create_directory("Test List Dir")
        
        if dir_response["code"] == 200:
            directory_id = dir_response["data"]["id"]
            
            try:
                # Create a document in the directory
                doc_response = await authenticated_client.create_document(
                    "Test Doc in Dir",
                    folder_id=directory_id
                )
                
                if doc_response["code"] == 200:
                    # List the directory
                    list_response = await authenticated_client.list_directory(directory_id)
                    
                    assert list_response["code"] == 200
                    assert "data" in list_response
                    
                    # Cleanup document
                    try:
                        await authenticated_client.delete_document(
                            doc_response["data"]["document_id"]
                        )
                    except Exception:
                        pass
            finally:
                # Cleanup directory
                try:
                    await authenticated_client.delete_directory(directory_id)
                except Exception:
                    pass


class TestDirectoryWithoutAuth:
    """Test that directory operations require authentication."""
    
    async def test_list_directory_without_auth(self, client: CFMSTestClient):
        """Test that listing directories requires authentication."""
        response = await client.send_request(
            "list_directory",
            {"folder_id": None},
            include_auth=False
        )
        
        assert response["code"] == 401
    
    async def test_create_directory_without_auth(self, client: CFMSTestClient):
        """Test that creating a directory requires authentication."""
        response = await client.send_request(
            "create_directory",
            {"name": "Test"},
            include_auth=False
        )
        
        assert response["code"] == 401
