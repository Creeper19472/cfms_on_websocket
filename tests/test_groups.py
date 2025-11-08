"""
Tests for group management operations.
"""

import pytest
import time
from tests.test_client import CFMSTestClient


class TestGroupOperations:
    """Test group management operations."""
    
    def test_list_groups(self, authenticated_client: CFMSTestClient):
        """Test listing all groups."""
        response = authenticated_client.list_groups()
        
        assert response["code"] == 200
        assert "data" in response
        assert "groups" in response["data"]
        assert isinstance(response["data"]["groups"], list)
        
        # Should have at least the default groups (sysop, user)
        group_names = [group["name"] for group in response["data"]["groups"]]
        assert "sysop" in group_names
        assert "user" in group_names
    
    def test_create_group(self, authenticated_client: CFMSTestClient):
        """Test creating a new group."""
        group_name = f"test_group_{int(time.time())}"
        
        response = authenticated_client.create_group(
            group_name=group_name,
            permissions=[]
        )
        
        assert response["code"] == 200
        
        # Cleanup
        try:
            authenticated_client.send_request("delete_group", {"group_name": group_name})
        except Exception:
            pass
    
    def test_get_group_info(self, authenticated_client: CFMSTestClient, test_group: dict):
        """Test getting group information."""
        response = authenticated_client.get_group_info(test_group["group_name"])
        
        assert response["code"] == 200
        assert "data" in response
        assert response["data"]["name"] == test_group["group_name"]
    
    def test_get_sysop_group_info(self, authenticated_client: CFMSTestClient):
        """Test getting information for the sysop group."""
        response = authenticated_client.get_group_info("sysop")
        
        assert response["code"] == 200
        assert "data" in response
        assert response["data"]["name"] == "sysop"
        assert "permissions" in response["data"]
    
    def test_get_nonexistent_group_info(self, authenticated_client: CFMSTestClient):
        """Test getting info for a group that doesn't exist."""
        response = authenticated_client.get_group_info("nonexistent_group_12345")
        
        assert response["code"] != 200
    
    def test_create_group_with_permissions(self, authenticated_client: CFMSTestClient):
        """Test creating a group with specific permissions."""
        group_name = f"perm_group_{int(time.time())}"
        permissions = [
            {"permission": "create_document", "start_time": 0, "end_time": None}
        ]
        
        response = authenticated_client.create_group(
            group_name=group_name,
            permissions=permissions
        )
        
        assert response["code"] == 200
        
        # Verify the group has the permissions
        info_response = authenticated_client.get_group_info(group_name)
        if info_response["code"] == 200:
            assert "permissions" in info_response["data"]
        
        # Cleanup
        try:
            authenticated_client.send_request("delete_group", {"group_name": group_name})
        except Exception:
            pass
    
    def test_create_group_with_empty_name(self, authenticated_client: CFMSTestClient):
        """Test creating a group with an empty name."""
        response = authenticated_client.create_group("")
        
        # Should fail validation
        assert response["code"] == 400
    
    def test_create_duplicate_group(self, authenticated_client: CFMSTestClient, test_group: dict):
        """Test creating a group with a duplicate name."""
        response = authenticated_client.create_group(test_group["group_name"])
        
        # Should fail due to duplicate name
        assert response["code"] != 200
    
    def test_delete_group(self, authenticated_client: CFMSTestClient):
        """Test deleting a group."""
        # Create a group
        group_name = f"group_to_delete_{int(time.time())}"
        create_response = authenticated_client.create_group(group_name)
        assert create_response["code"] == 200
        
        # Delete it
        delete_response = authenticated_client.send_request(
            "delete_group",
            {"group_name": group_name}
        )
        assert delete_response["code"] == 200
        
        # Verify it's gone
        info_response = authenticated_client.get_group_info(group_name)
        assert info_response["code"] != 200


class TestGroupWithoutAuth:
    """Test that group operations require authentication."""
    
    def test_list_groups_without_auth(self, client: CFMSTestClient):
        """Test that listing groups requires authentication."""
        response = client.send_request(
            "list_groups",
            {},
            include_auth=False
        )
        
        assert response["code"] == 401
    
    def test_create_group_without_auth(self, client: CFMSTestClient):
        """Test that creating a group requires authentication."""
        response = client.send_request(
            "create_group",
            {"group_name": "testgroup"},
            include_auth=False
        )
        
        assert response["code"] == 401
    
    def test_get_group_info_without_auth(self, client: CFMSTestClient):
        """Test that getting group info requires authentication."""
        response = client.send_request(
            "get_group_info",
            {"group_name": "sysop"},
            include_auth=False
        )
        
        assert response["code"] == 401
