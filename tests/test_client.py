"""
Test client for CFMS WebSocket Server.

This module provides a reusable WebSocket client for testing the CFMS server.
"""

import json
import ssl
import time
from typing import Any, Dict, Optional
from websockets.sync.client import connect, ClientConnection


class CFMSTestClient:
    """
    A test client for the CFMS WebSocket server.
    
    This client provides convenient methods for connecting to the server,
    sending requests, and receiving responses. It handles authentication
    and connection management automatically.
    """
    
    def __init__(self, host: str = "localhost", port: int = 5104, use_ssl: bool = True):
        """
        Initialize the test client.
        
        Args:
            host: Server hostname
            port: Server port
            use_ssl: Whether to use SSL/TLS connection
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.websocket: Optional[ClientConnection] = None
        self.username: Optional[str] = None
        self.token: Optional[str] = None
        
    def connect(self) -> None:
        """
        Establish a WebSocket connection to the server.
        """
        if self.websocket is not None:
            return
            
        protocol = "wss" if self.use_ssl else "ws"
        uri = f"{protocol}://{self.host}:{self.port}"
        
        if self.use_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        else:
            ssl_context = None
            
        self.websocket = connect(uri, ssl=ssl_context)
        
    def disconnect(self) -> None:
        """
        Close the WebSocket connection.
        """
        if self.websocket is not None:
            self.websocket.close()
            self.websocket = None
        self.username = None
        self.token = None
    
    def send_request(
        self,
        action: str,
        data: Optional[Dict[str, Any]] = None,
        username: Optional[str] = None,
        token: Optional[str] = None,
        include_auth: bool = True
    ) -> Dict[str, Any]:
        """
        Send a request to the server and receive the response.
        
        Args:
            action: The action to perform
            data: Optional data payload for the request
            username: Optional username (defaults to stored username)
            token: Optional token (defaults to stored token)
            include_auth: Whether to include authentication credentials
            
        Returns:
            The response from the server as a dictionary
        """
        if self.websocket is None:
            raise RuntimeError("Not connected to server. Call connect() first.")
        
        request = {
            "action": action,
            "data": data if data is not None else {}
        }
        
        if include_auth:
            request["username"] = username if username is not None else self.username
            request["token"] = token if token is not None else self.token
        
        self.websocket.send(json.dumps(request, ensure_ascii=False))
        response_text = self.websocket.recv()
        return json.loads(response_text)
    
    def login(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate with the server.
        
        Args:
            username: Username to authenticate with
            password: Password for the user
            
        Returns:
            The login response from the server
        """
        response = self.send_request(
            "login",
            {"username": username, "password": password},
            include_auth=False
        )
        
        if response.get("code") == 200:
            self.username = username
            self.token = response.get("data", {}).get("token")
        
        return response
    
    def server_info(self) -> Dict[str, Any]:
        """
        Get server information.
        
        Returns:
            Server information including version and protocol version
        """
        return self.send_request("server_info", include_auth=False)
    
    def refresh_token(self) -> Dict[str, Any]:
        """
        Refresh the authentication token.
        
        Returns:
            Response with new token
        """
        response = self.send_request("refresh_token")
        
        if response.get("code") == 200:
            self.token = response.get("data", {}).get("token")
        
        return response
    
    def get_document(self, document_id: str) -> Dict[str, Any]:
        """
        Get a document by ID.
        
        Args:
            document_id: The ID of the document to retrieve
            
        Returns:
            The document data
        """
        return self.send_request("get_document", {"document_id": document_id})
    
    def create_document(self, title: str, folder_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a new document.
        
        Args:
            title: Title of the document
            folder_id: Optional folder ID to create the document in
            
        Returns:
            Response with created document information
        """
        data = {"title": title}
        if folder_id is not None:
            data["folder_id"] = folder_id
        return self.send_request("create_document", data)
    
    def delete_document(self, document_id: str) -> Dict[str, Any]:
        """
        Delete a document.
        
        Args:
            document_id: The ID of the document to delete
            
        Returns:
            Response indicating success or failure
        """
        return self.send_request("delete_document", {"document_id": document_id})
    
    def rename_document(self, document_id: str, new_title: str) -> Dict[str, Any]:
        """
        Rename a document.
        
        Args:
            document_id: The ID of the document to rename
            new_title: The new title for the document
            
        Returns:
            Response indicating success or failure
        """
        return self.send_request("rename_document", {
            "document_id": document_id,
            "new_title": new_title
        })
    
    def get_document_info(self, document_id: str) -> Dict[str, Any]:
        """
        Get information about a document.
        
        Args:
            document_id: The ID of the document
            
        Returns:
            Document information
        """
        return self.send_request("get_document_info", {"document_id": document_id})
    
    def list_directory(self, folder_id: Optional[str] = None) -> Dict[str, Any]:
        """
        List contents of a directory.
        
        Args:
            folder_id: The ID of the folder (None for root)
            
        Returns:
            Directory listing
        """
        data = {}
        data["folder_id"] = folder_id

        return self.send_request("list_directory", data)
    
    def create_directory(self, name: str, parent_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a new directory.
        
        Args:
            name: Name of the directory
            parent_id: Optional parent directory ID
            
        Returns:
            Response with created directory information
        """
        data = {"name": name}
        if parent_id is not None:
            data["parent_id"] = parent_id
        return self.send_request("create_directory", data)
    
    def delete_directory(self, folder_id: str) -> Dict[str, Any]:
        """
        Delete a directory.
        
        Args:
            folder_id: The ID of the folder to delete
            
        Returns:
            Response indicating success or failure
        """
        return self.send_request("delete_directory", {"folder_id": folder_id})
    
    def create_user(
        self,
        username: str,
        password: str,
        nickname: Optional[str] = None,
        groups: Optional[list] = None
    ) -> Dict[str, Any]:
        """
        Create a new user.
        
        Args:
            username: Username for the new user
            password: Password for the new user
            nickname: Optional nickname
            groups: Optional list of group assignments
            
        Returns:
            Response with created user information
        """
        data: dict[str, Any] = {
            "username": username,
            "password": password
        }
        if nickname is not None:
            data["nickname"] = nickname
        if groups is not None:
            data["groups"] = groups
        return self.send_request("create_user", data)
    
    def delete_user(self, username: str) -> Dict[str, Any]:
        """
        Delete a user.
        
        Args:
            username: Username of the user to delete
            
        Returns:
            Response indicating success or failure
        """
        return self.send_request("delete_user", {"username": username})
    
    def get_user_info(self, username: str) -> Dict[str, Any]:
        """
        Get information about a user.
        
        Args:
            username: Username of the user
            
        Returns:
            User information
        """
        return self.send_request("get_user_info", {"username": username})
    
    def list_users(self) -> Dict[str, Any]:
        """
        List all users.
        
        Returns:
            List of users
        """
        return self.send_request("list_users", {})
    
    def create_group(self, group_name: str, permissions: Optional[list] = None) -> Dict[str, Any]:
        """
        Create a new user group.
        
        Args:
            group_name: Name of the group
            permissions: Optional list of permissions
            
        Returns:
            Response with created group information
        """
        data: dict[str, Any] = {"group_name": group_name}
        if permissions is not None:
            data["permissions"] = permissions
        return self.send_request("create_group", data)
    
    def list_groups(self) -> Dict[str, Any]:
        """
        List all user groups.
        
        Returns:
            List of groups
        """
        return self.send_request("list_groups", {})
    
    def get_group_info(self, group_name: str) -> Dict[str, Any]:
        """
        Get information about a group.
        
        Args:
            group_name: Name of the group
            
        Returns:
            Group information
        """
        return self.send_request("get_group_info", {"group_name": group_name})
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
