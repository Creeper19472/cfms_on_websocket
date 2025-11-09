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
    # Ensure config file exists in src/ directory (server runs from there)
    src_config_file = "src/config.toml"
    if not os.path.exists(src_config_file):
        # Copy sample config if config doesn't exist
        import shutil
        shutil.copy("src/config.sample.toml", src_config_file)
    
    # Modify config for testing: disable password expiration
    with open(src_config_file, "r", encoding='utf-8') as f:
        config_content = f.read()
    
    # enable debug mode for tests
    config_content = config_content.replace(
        "debug = false",
        "debug = true"
    )
    # Disable password expiration for tests
    config_content = config_content.replace(
        "enable_passwd_force_expiration = true",
        "enable_passwd_force_expiration = false"
    )
    config_content = config_content.replace(
        "require_passwd_enforcement_changes = true",
        "require_passwd_enforcement_changes = false"
    )
    config_content = config_content.replace(
        "dualstack_ipv6 = true",
        "dualstack_ipv6 = false"
    )
    
    with open(src_config_file, "w", encoding='utf-8') as f:
        f.write(config_content)
    
    # Clean up any previous test artifacts (in src/ where server runs)
    for artifact in ["init", "app.db", "admin_password.txt"]:
        src_artifact = os.path.join("src", artifact)
        if os.path.exists(src_artifact):
            os.remove(src_artifact)
    
    # Ensure necessary directories exist in src/ (where server runs from)
    os.makedirs("src/content/ssl", exist_ok=True)
    os.makedirs("src/content/logs", exist_ok=True)
        
    # Start the server (run from src/ directory)
    process = subprocess.Popen(
        ["uv", "run", "python", "main.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=os.path.join(os.getcwd(), "src")
    )
    
    # Wait for server to be ready (give it time to initialize)
    max_wait = 15
    wait_time = 0
    while wait_time < max_wait:
        time.sleep(1)
        wait_time += 1
        
        # Check if process crashed
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(f"Server failed to start.\nSTDOUT: {stdout}\nSTDERR: {stderr}")
        
        # Check if initialization is complete (admin_password.txt is in src/)
        if os.path.exists("src/admin_password.txt"):
            # Give it one more second to fully start
            time.sleep(1)
            break
    
    if not os.path.exists("src/admin_password.txt"):
        process.terminate()
        stdout, stderr = process.communicate()
        pytest.fail(f"Server initialization timed out.\nSTDOUT: {stdout}\nSTDERR: {stderr}")
    
    yield process
    
    # Cleanup: terminate the server
    try:
        process.terminate()
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


@pytest.fixture(scope="session")
def admin_credentials(server_process) -> dict:
    """
    Get admin credentials from the generated password file.
    
    Args:
        server_process: The server process fixture (dependency to ensure server is started)
    
    Returns:
        Dictionary with 'username' and 'password' keys
    """
    # The server_process fixture has already started the server and waited
    # for admin_password.txt to be created in src/, so we can just read it
    password_file = "src/admin_password.txt"
    
    if not os.path.exists(password_file):
        pytest.fail("Admin password file not found after server started")
    
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
    # reconnect if needed
    for _attempt in range(5):
        try:
            client.connect()
            break
        except (ConnectionRefusedError, TimeoutError):
            if _attempt == 4:
                raise
            continue

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
    task_id = response["data"]["task_data"]["task_id"]

    # upload the file
    authenticated_client.upload_file_to_server(
        task_id,
        "./pyproject.toml"
    )
    
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
