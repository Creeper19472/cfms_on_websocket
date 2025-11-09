"""
Tests for basic server functionality and authentication.
"""

import pytest
from tests.test_client import CFMSTestClient


class TestServerBasics:
    """Test basic server functionality."""
    
    def test_server_connection(self, client: CFMSTestClient):
        """Test that we can connect to the server."""
        assert client.websocket is not None
        assert client.websocket.protocol.state.name == "OPEN"
    
    def test_server_info(self, client: CFMSTestClient):
        """Test getting server information."""
        response = client.server_info()
        
        assert response["code"] == 200
        assert "data" in response
        assert "server_name" in response["data"]
        assert "version" in response["data"]
        assert "protocol_version" in response["data"]
    
    def test_unknown_action(self, client: CFMSTestClient):
        """Test that unknown actions are handled properly."""
        response = client.send_request("nonexistent_action", include_auth=False)
        
        assert response["code"] == 400
        assert "Unknown action" in response["message"]


class TestAuthentication:
    """Test authentication functionality."""
    
    def test_login_success(self, client: CFMSTestClient, admin_credentials: dict):
        """Test successful login."""
        response = client.login(
            admin_credentials["username"],
            admin_credentials["password"]
        )
        
        # For debugging
        if response["code"] != 200:
            print(f"Login response: {response}")
        
        assert response["code"] == 200
        assert "data" in response
        assert "token" in response["data"]
        assert client.token is not None
        assert client.username == admin_credentials["username"]
    
    def test_login_invalid_credentials(self, client: CFMSTestClient):
        """Test login with invalid credentials."""
        response = client.login("invalid_user", "invalid_password")
        
        assert response["code"] == 401
        assert "Invalid credentials" in response["message"]
    
    def test_login_missing_username(self, client: CFMSTestClient):
        """Test login with missing username."""
        response = client.send_request("login", {"password": "test"}, include_auth=False)
        
        assert response["code"] == 400
    
    def test_login_missing_password(self, client: CFMSTestClient):
        """Test login with missing password."""
        response = client.send_request("login", {"username": "test"}, include_auth=False)
        
        assert response["code"] == 400
    
    def test_refresh_token(self, authenticated_client: CFMSTestClient):
        """Test token refresh."""
        old_token = authenticated_client.token
        
        response = authenticated_client.refresh_token()
        
        assert response["code"] == 200
        assert "token" in response["data"]
        assert authenticated_client.token is not None
        assert authenticated_client.token != old_token
    
    def test_authentication_required(self, client: CFMSTestClient):
        """Test that protected endpoints require authentication."""
        response = client.send_request("list_users", include_auth=False)
        
        # Server returns 401 or 403 for missing authentication
        assert response["code"] in [401, 403]
    
    def test_invalid_token(self, client: CFMSTestClient, admin_credentials: dict):
        """Test request with invalid token."""
        # Login first to get a valid session structure
        client.login(admin_credentials["username"], admin_credentials["password"])
        
        # Now use an invalid token
        response = client.send_request(
            "list_users",
            username=admin_credentials["username"],
            token="invalid_token_12345"
        )
        
        assert response["code"] == 403
