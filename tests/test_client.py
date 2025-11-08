"""
Test client for CFMS WebSocket Server.

This module provides a reusable WebSocket client for testing the CFMS server.
"""

import hashlib
import json
import mmap
import os
import ssl
import time
from typing import Any, Dict, Optional
from websockets.sync.client import connect, ClientConnection


def calculate_sha256(file_path: str) -> str:
    """
    Calculate SHA256 hash of a file using memory-mapped I/O for efficiency.
    
    Uses memory-mapped files for faster hash calculation of large files.
    
    Args:
        file_path: Path to the file to hash
        
    Returns:
        Hexadecimal SHA256 hash string
    """
    with open(file_path, "rb", encoding='utf-8') as f:
        # Use memory-mapped files to map directly to memory
        mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        return hashlib.sha256(mmapped_file).hexdigest()


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
    
    def upload_file_to_server(
        self, task_id: str, file_path: str
    ):
        """
        Upload a file to the server over WebSocket connection.
        
        Args:
            task_id: Server task ID for this upload
            file_path: Local path to the file to upload
            
        Raises:
            ValueError: If server response is invalid
            RuntimeError: If upload is rejected by server
        """

        # Receive file metadata from the server
        response = self.send_request(
            "upload_file",
            {"task_id": task_id},
            include_auth=True
        )

        if response["action"] != "transfer_file":
            raise ValueError

        file_size = os.path.getsize(file_path)
        sha256 = calculate_sha256(file_path) if file_size else None

        task_info = {
            "action": "transfer_file",
            "data": {
                "sha256": sha256,
                "file_size": file_size,
            },
        }

        assert self.websocket
        self.websocket.send(json.dumps(task_info, ensure_ascii=False))
        received_response = str(self.websocket.recv())

        if received_response.startswith("ready"):
            ready = True
        elif received_response == "stop":
            ready = False
        else:
            raise RuntimeError

        if ready:

            try:
                chunk_size = int(received_response.split()[1])
                with open(file_path, "rb", encoding='utf-8') as f:
                    while True:
                        chunk = f.read(chunk_size)
                        self.websocket.send(chunk)

                        if not chunk or len(chunk) < chunk_size:
                            break

                # need to wait for server confirmation
                server_response = json.loads(self.websocket.recv())

            except Exception:
                raise


    # def receive_file_from_server(
    #     self,
    #     task_id: str,
    #     file_path: str,  # filename: str | None = None
    # ):
    #     """
    #     Receives a file from the server over a websocket connection using AES encryption.

    #     Steps:
    #         1. Requests file metadata (SHA-256 hash, file size, chunk info) from the server.
    #         2. Sends readiness acknowledgment to the server.
    #         3. Receives encrypted file chunks, saves them temporarily.
    #         4. Receives AES key and IV, decrypts all chunks, and writes the output file.
    #         5. Deletes temporary chunk files.
    #         6. Verifies the file size and SHA-256 hash.
    #         7. Removes the output file if verification fails.

    #     Args:
    #         client (ClientConnection): The websocket client connection.
    #         task_id (str): The identifier for the file transfer task.
    #         file_path (str): The path to save the received file.

    #     Yields:
    #         Tuple[int, ...]: Progress updates at various stages.

    #     Raises:
    #         ValueError: If the server response is invalid.
    #         FileSizeMismatchError: If the received file size does not match the expected size.
    #         FileHashMismatchError: If the received file hash does not match the expected hash.
    #         Exception: For other errors during transfer or decryption.
    #     """

    #     assert self.websocket

    #     # Send the request for file metadata
    #     self.websocket.send(
    #         json.dumps(
    #             {
    #                 "action": "download_file",
    #                 "data": {"task_id": task_id},
    #             },
    #             ensure_ascii=False,
    #         )
    #     )

    #     # Receive file metadata from the server
    #     response = json.loads(self.websocket.recv())
    #     if response["action"] != "transfer_file":
    #         raise ValueError("Invalid action received for file transfer")

    #     sha256 = response["data"].get("sha256")  # SHA256 of original file
    #     file_size = response["data"].get("file_size")  # Size of original file
    #     chunk_size = response["data"].get("chunk_size", 8192)  # Chunk size
    #     total_chunks = response["data"].get("total_chunks")  # Total chunks

    #     self.websocket.send("ready")

    #     downloading_path = FLET_APP_STORAGE_TEMP + "/downloading/" + task_id
    #     await aiofiles.os.makedirs(downloading_path, exist_ok=True)

    #     if not file_size:
    #         async with aiofiles.open(file_path, "wb") as f:
    #             await f.truncate(0)
    #         return

    #     try:

    #         received_chunks = 0
    #         iv: bytes = b""

    #         while received_chunks + 1 <= total_chunks:
    #             # Receive encrypted data from the server

    #             data = await self.recv()
    #             if not data:
    #                 raise ValueError("Received empty data from server")

    #             data_json: dict = json.loads(data)

    #             index = data_json["data"].get("index")
    #             if index == 0:
    #                 iv = base64.b64decode(data_json["data"].get("iv"))
    #             chunk_hash = data_json["data"].get("hash")  # provided but unused
    #             chunk_data = base64.b64decode(data_json["data"].get("chunk"))
    #             chunk_file_path = os.path.join(downloading_path, str(index))

    #             async with aiofiles.open(chunk_file_path, "wb") as chunk_file:
    #                 await chunk_file.write(chunk_data)

    #             received_chunks += 1

    #             if received_chunks < total_chunks:
    #                 received_file_size = chunk_size * received_chunks
    #             else:
    #                 received_file_size = file_size

    #             yield 0, received_file_size, file_size

    #         # Get decryption information
    #         decrypted_data = await self.recv()
    #         decrypted_data_json: dict = json.loads(decrypted_data)

    #         aes_key = base64.b64decode(decrypted_data_json["data"].get("key"))

    #         # Decrypt chunks
    #         decrypted_chunks = 1
    #         cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)  # Initialize cipher

    #         async with aiofiles.open(file_path, "wb") as out_file:
    #             while decrypted_chunks <= total_chunks:
    #                 yield 1, decrypted_chunks, total_chunks

    #                 chunk_file_path = os.path.join(
    #                     downloading_path, str(decrypted_chunks - 1)
    #                 )

    #                 async with aiofiles.open(chunk_file_path, "rb") as chunk_file:
    #                     encrypted_chunk = await chunk_file.read()
    #                     decrypted_chunk = cipher.decrypt(encrypted_chunk)
    #                     await out_file.write(decrypted_chunk)

    #                 # os.remove(chunk_file_path)
    #                 decrypted_chunks += 1

    #         # Delete temporary folder
    #         yield 2,

    #         await asyncio.get_event_loop().run_in_executor(
    #             None, shutil.rmtree, downloading_path
    #         )

    #     except Exception:
    #         raise

    #     # Verify file

    #     async def _action_verify() -> None:

    #         if file_size != await aiofiles.os.path.getsize(file_path):
    #             raise FileSizeMismatchError(
    #                 file_size, await aiofiles.os.path.getsize(file_path)
    #             )

    #         # Verify SHA256
    #         actual_sha256 = await calculate_sha256(file_path)
    #         if sha256 and actual_sha256 != sha256:
    #             raise FileHashMismatchError(sha256, actual_sha256)

    #     yield 3,

    #     try:
    #         await _action_verify()
    #     except Exception:
    #         await aiofiles.os.remove(file_path)
    #         raise
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
