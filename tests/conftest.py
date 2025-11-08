"""
Pytest configuration and fixtures for CFMS test suite.
"""

import os
import pytest
import subprocess
import time
import signal
from typing import Generator

from tests.test_client import CFMSTestClient


@pytest.fixture(scope="session")
def server_process() -> Generator[subprocess.Popen, None, None]:
    """
    Start the CFMS server for testing and tear it down after tests complete.
    
    This fixture starts the server in a subprocess and waits for it to be ready.
    After all tests complete, it gracefully shuts down the server.
    """
    # Ensure config file exists
    config_file = "config.toml"
    if not os.path.exists(config_file):
        # Copy sample config if config doesn't exist
        import shutil
        shutil.copy("config.sample.toml", config_file)
    
    # Start the server
    process = subprocess.Popen(
        ["python", "main.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for server to be ready (give it time to initialize)
    time.sleep(5)
    
    # Check if process is still running
    if process.poll() is not None:
        stdout, stderr = process.communicate()
        pytest.fail(f"Server failed to start.\nSTDOUT: {stdout}\nSTDERR: {stderr}")
    
    yield process
    
    # Cleanup: terminate the server
    try:
        process.terminate()
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


@pytest.fixture(scope="session")
def admin_credentials() -> dict:
    """
    Get admin credentials from the generated password file.
    
    Returns:
        Dictionary with 'username' and 'password' keys
    """
    # Wait a moment for the password file to be created
    password_file = "admin_password.txt"
    max_retries = 10
    retry_count = 0
    
    while not os.path.exists(password_file) and retry_count < max_retries:
        time.sleep(1)
        retry_count += 1
    
    if not os.path.exists(password_file):
        pytest.fail("Admin password file not found")
    
    with open(password_file, "r", encoding="utf-8") as f:
        password = f.read().strip()
    
    return {
        "username": "admin",
        "password": password
    }


@pytest.fixture
def client(server_process) -> Generator[CFMSTestClient, None, None]:
    """
    Provide a connected test client for each test.
    
    This fixture creates a new client instance and connects to the server.
    After the test completes, it disconnects the client.
    """
    client = CFMSTestClient()
    client.connect()
    yield client
    client.disconnect()


@pytest.fixture
def authenticated_client(client: CFMSTestClient, admin_credentials: dict) -> CFMSTestClient:
    """
    Provide an authenticated test client with admin credentials.
    
    This fixture logs in with admin credentials and provides
    a ready-to-use authenticated client.
    """
    response = client.login(admin_credentials["username"], admin_credentials["password"])
    assert response["code"] == 200, f"Login failed: {response}"
    return client


@pytest.fixture
def test_document(authenticated_client: CFMSTestClient) -> Generator[dict, None, None]:
    """
    Create a test document and clean it up after the test.
    
    Yields:
        Dictionary with document information
    """
    response = authenticated_client.create_document("Test Document")
    assert response["code"] == 200, f"Failed to create test document: {response}"
    
    document_id = response["data"]["document_id"]
    
    yield {
        "document_id": document_id,
        "title": "Test Document"
    }
    
    # Cleanup: delete the document
    try:
        authenticated_client.delete_document(document_id)
    except Exception:
        pass  # Ignore cleanup errors


@pytest.fixture
def test_user(authenticated_client: CFMSTestClient) -> Generator[dict, None, None]:
    """
    Create a test user and clean it up after the test.
    
    Yields:
        Dictionary with user information
    """
    username = f"test_user_{int(time.time())}"
    password = "TestPassword123!"
    
    response = authenticated_client.create_user(
        username=username,
        password=password,
        nickname="Test User"
    )
    assert response["code"] == 200, f"Failed to create test user: {response}"
    
    yield {
        "username": username,
        "password": password,
        "nickname": "Test User"
    }
    
    # Cleanup: delete the user
    try:
        authenticated_client.delete_user(username)
    except Exception:
        pass  # Ignore cleanup errors


@pytest.fixture
def test_group(authenticated_client: CFMSTestClient) -> Generator[dict, None, None]:
    """
    Create a test group and clean it up after the test.
    
    Yields:
        Dictionary with group information
    """
    group_name = f"test_group_{int(time.time())}"
    
    response = authenticated_client.create_group(
        group_name=group_name,
        permissions=[]
    )
    assert response["code"] == 200, f"Failed to create test group: {response}"
    
    yield {
        "group_name": group_name
    }
    
    # Cleanup: delete the group
    try:
        authenticated_client.send_request("delete_group", {"group_name": group_name})
    except Exception:
        pass  # Ignore cleanup errors
