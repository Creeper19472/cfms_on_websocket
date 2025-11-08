"""
Tests for user management operations.
"""

import pytest
import time
from tests.test_client import CFMSTestClient


class TestUserOperations:
    """Test user management operations."""
    
    def test_list_users(self, authenticated_client: CFMSTestClient):
        """Test listing all users."""
        response = authenticated_client.list_users()
        
        assert response["code"] == 200
        assert "data" in response
        assert "users" in response["data"]
        assert isinstance(response["data"]["users"], list)
        
        # Should at least have the admin user
        usernames = [user["username"] for user in response["data"]["users"]]
        assert "admin" in usernames
    
    def test_create_user(self, authenticated_client: CFMSTestClient):
        """Test creating a new user."""
        username = f"test_user_{int(time.time())}"
        password = "TestPassword123!"
        
        response = authenticated_client.create_user(
            username=username,
            password=password,
            nickname="Test User"
        )
        
        assert response["code"] == 200
        
        # Cleanup
        try:
            authenticated_client.delete_user(username)
        except Exception:
            pass
    
    def test_get_user_info(self, authenticated_client: CFMSTestClient, test_user: dict):
        """Test getting user information."""
        response = authenticated_client.get_user_info(test_user["username"])
        
        assert response["code"] == 200
        assert "data" in response
        assert response["data"]["username"] == test_user["username"]
    
    def test_get_nonexistent_user_info(self, authenticated_client: CFMSTestClient):
        """Test getting info for a user that doesn't exist."""
        response = authenticated_client.get_user_info("nonexistent_user_12345")
        
        assert response["code"] != 200
    
    def test_delete_user(self, authenticated_client: CFMSTestClient):
        """Test deleting a user."""
        # Create a user
        username = f"user_to_delete_{int(time.time())}"
        create_response = authenticated_client.create_user(
            username=username,
            password="TestPassword123!"
        )
        assert create_response["code"] == 200
        
        # Delete it
        delete_response = authenticated_client.delete_user(username)
        assert delete_response["code"] == 200
        
        # Verify it's gone
        info_response = authenticated_client.get_user_info(username)
        assert info_response["code"] != 200
    
    def test_create_user_with_weak_password(self, authenticated_client: CFMSTestClient):
        """Test creating a user with a weak password."""
        username = f"weak_pwd_user_{int(time.time())}"
        weak_password = "weak"
        
        response = authenticated_client.create_user(
            username=username,
            password=weak_password
        )
        
        # Should fail due to password requirements
        assert response["code"] != 200
    
    def test_create_user_with_duplicate_username(self, authenticated_client: CFMSTestClient, test_user: dict):
        """Test creating a user with a duplicate username."""
        response = authenticated_client.create_user(
            username=test_user["username"],
            password="AnotherPassword123!"
        )
        
        # Should fail due to duplicate username
        assert response["code"] != 200
    
    def test_create_user_with_empty_username(self, authenticated_client: CFMSTestClient):
        """Test creating a user with an empty username."""
        response = authenticated_client.create_user(
            username="",
            password="TestPassword123!"
        )
        
        # Should fail validation
        assert response["code"] == 400
    
    def test_get_admin_user_info(self, authenticated_client: CFMSTestClient):
        """Test getting admin user information."""
        response = authenticated_client.get_user_info("admin")
        
        assert response["code"] == 200
        assert "data" in response
        assert response["data"]["username"] == "admin"


class TestUserWithoutAuth:
    """Test that user operations require authentication."""
    
    def test_list_users_without_auth(self, client: CFMSTestClient):
        """Test that listing users requires authentication."""
        response = client.send_request(
            "list_users",
            {},
            include_auth=False
        )
        
        assert response["code"] == 401
    
    def test_create_user_without_auth(self, client: CFMSTestClient):
        """Test that creating a user requires authentication."""
        response = client.send_request(
            "create_user",
            {
                "username": "testuser",
                "password": "TestPassword123!"
            },
            include_auth=False
        )
        
        assert response["code"] == 401
    
    def test_get_user_info_without_auth(self, client: CFMSTestClient):
        """Test that getting user info requires authentication."""
        response = client.send_request(
            "get_user_info",
            {"username": "admin"},
            include_auth=False
        )
        
        assert response["code"] == 401
