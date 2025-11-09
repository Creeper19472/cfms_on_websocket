"""
Pytest configuration and fixtures for CFMS test suite - Rewritten for robustness.
"""

import os
import pytest
import subprocess
import time
from typing import Generator
from tests.test_client import CFMSTestClient


@pytest.fixture(scope="session")
def server_process() -> Generator[subprocess.Popen, None, None]:
    """
    Start the CFMS server for testing and tear it down after tests complete.
    
    This fixture starts the server in a subprocess with improved error handling.
    """
    # Ensure config file exists
    src_config_file = "src/config.toml"
    if not os.path.exists(src_config_file):
        import shutil
        if not os.path.exists("src/config.sample.toml"):
            pytest.fail("Config sample file not found: src/config.sample.toml")
        shutil.copy("src/config.sample.toml", src_config_file)
    
    # Read and modify config for testing
    try:
        with open(src_config_file, "r", encoding='utf-8') as f:
            config_content = f.read()
    except Exception as e:
        pytest.fail(f"Failed to read config file: {e}")
    
    # Apply test-specific config changes
    config_changes = {
        "debug = false": "debug = true",
        "enable_passwd_force_expiration = true": "enable_passwd_force_expiration = false",
        "require_passwd_enforcement_changes = true": "require_passwd_enforcement_changes = false",
        "dualstack_ipv6 = true": "dualstack_ipv6 = false",
    }
    
    for old, new in config_changes.items():
        config_content = config_content.replace(old, new)
    
    try:
        with open(src_config_file, "w", encoding='utf-8') as f:
            f.write(config_content)
    except Exception as e:
        pytest.fail(f"Failed to write config file: {e}")
    
    # Clean up previous test artifacts
    artifacts = ["init", "app.db", "admin_password.txt"]
    for artifact in artifacts:
        artifact_path = os.path.join("src", artifact)
        if os.path.exists(artifact_path):
            try:
                os.remove(artifact_path)
            except Exception as e:
                pytest.fail(f"Failed to remove artifact {artifact}: {e}")
    
    # Ensure necessary directories exist
    directories = ["src/content/ssl", "src/content/logs"]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # Start the server
    try:
        process = subprocess.Popen(
            ["uv", "run", "python", "main.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=os.path.join(os.getcwd(), "src")
        )
    except Exception as e:
        pytest.fail(f"Failed to start server process: {e}")
    
    # Wait for server to be ready
    max_wait = 20  # Increased timeout
    wait_interval = 0.5
    waited = 0
    
    while waited < max_wait:
        time.sleep(wait_interval)
        waited += wait_interval
        
        # Check if process crashed
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                f"Server failed to start (exit code: {process.returncode}).\n"
                f"STDOUT: {stdout}\n"
                f"STDERR: {stderr}"
            )
        
        # Check if initialization is complete
        if os.path.exists("src/admin_password.txt"):
            # Give server additional time to fully start
            time.sleep(2)
            break
    
    # Verify server started successfully
    if not os.path.exists("src/admin_password.txt"):
        try:
            process.terminate()
            stdout, stderr = process.communicate(timeout=5)
        except:
            process.kill()
            stdout, stderr = "", ""
        pytest.fail(
            f"Server initialization timed out after {max_wait} seconds.\n"
            f"STDOUT: {stdout}\n"
            f"STDERR: {stderr}"
        )
    
    yield process
    
    # Cleanup: terminate the server
    try:
        process.terminate()
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=2)
        except:
            pass


@pytest.fixture(scope="session")
def admin_credentials(server_process) -> dict:
    """
    Get admin credentials from the generated password file.
    """
    password_file = "src/admin_password.txt"
    
    if not os.path.exists(password_file):
        pytest.fail("Admin password file not found after server started")
    
    try:
        with open(password_file, "r", encoding="utf-8") as f:
            password = f.read().strip()
    except Exception as e:
        pytest.fail(f"Failed to read admin password: {e}")
    
    if not password:
        pytest.fail("Admin password file is empty")
    
    return {
        "username": "admin",
        "password": password
    }


@pytest.fixture
def client(server_process) -> Generator[CFMSTestClient, None, None]:
    """
    Provide a connected test client for each test.
    """
    test_client = CFMSTestClient()
    
    # Try to connect with retries
    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            test_client.connect()
            break
        except (ConnectionRefusedError, TimeoutError, OSError) as e:
            if attempt == max_attempts - 1:
                pytest.fail(f"Failed to connect to server after {max_attempts} attempts: {e}")
            time.sleep(1)
    
    yield test_client
    
    # Cleanup
    try:
        test_client.disconnect()
    except:
        pass


@pytest.fixture
def authenticated_client(client: CFMSTestClient, admin_credentials: dict) -> CFMSTestClient:
    """
    Provide an authenticated test client with admin credentials.
    """
    try:
        response = client.login(
            admin_credentials["username"],
            admin_credentials["password"]
        )
    except Exception as e:
        pytest.fail(f"Login request failed with exception: {e}")
    
    if response.get("code") != 200:
        pytest.fail(f"Login failed: {response}")
    
    return client


@pytest.fixture
def test_document(authenticated_client: CFMSTestClient) -> Generator[dict, None, None]:
    """
    Create a test document and clean it up after the test.
    """
    try:
        response = authenticated_client.create_document("Test Document")
    except Exception as e:
        pytest.fail(f"Failed to create test document: {e}")
    
    if response.get("code") != 200:
        pytest.fail(f"Failed to create test document: {response}")
    
    document_id = response["data"]["document_id"]
    task_id = response["data"]["task_data"]["task_id"]
    
    # Upload file to activate the document
    try:
        authenticated_client.upload_file_to_server(task_id, "./pyproject.toml")
    except Exception as e:
        # Try to cleanup before failing
        try:
            authenticated_client.delete_document(document_id)
        except:
            pass
        pytest.fail(f"Failed to upload file to document: {e}")
    
    yield {
        "document_id": document_id,
        "title": "Test Document"
    }
    
    # Cleanup
    try:
        authenticated_client.delete_document(document_id)
    except Exception:
        pass  # Ignore cleanup errors


@pytest.fixture
def test_user(authenticated_client: CFMSTestClient) -> Generator[dict, None, None]:
    """
    Create a test user and clean it up after the test.
    """
    username = f"test_user_{int(time.time() * 1000)}"
    password = "TestPassword123!"
    
    try:
        response = authenticated_client.create_user(
            username=username,
            password=password,
            nickname="Test User"
        )
    except Exception as e:
        pytest.fail(f"Failed to create test user: {e}")
    
    if response.get("code") != 200:
        pytest.fail(f"Failed to create test user: {response}")
    
    yield {
        "username": username,
        "password": password,
        "nickname": "Test User"
    }
    
    # Cleanup
    try:
        authenticated_client.delete_user(username)
    except Exception:
        pass


@pytest.fixture
def test_group(authenticated_client: CFMSTestClient) -> Generator[dict, None, None]:
    """
    Create a test group and clean it up after the test.
    """
    group_name = f"test_group_{int(time.time() * 1000)}"
    
    try:
        response = authenticated_client.create_group(
            group_name=group_name,
            permissions=[]
        )
    except Exception as e:
        pytest.fail(f"Failed to create test group: {e}")
    
    if response.get("code") != 200:
        pytest.fail(f"Failed to create test group: {response}")
    
    yield {
        "group_name": group_name
    }
    
    # Cleanup
    try:
        authenticated_client.send_request("delete_group", {"group_name": group_name})
    except Exception:
        pass
