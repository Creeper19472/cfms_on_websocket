#!/usr/bin/env python3
"""
Integration test for the backup generation WebSocket API.

This script tests the backup generation functionality through the WebSocket
API, verifying that it can be requested remotely by a client.
"""

import json
import os
import ssl
import sys
import threading
import time

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from websockets.sync.client import connect

def start_server():
    """Start the CFMS server in a separate thread."""
    import main
    
    # Give the server some time to start
    time.sleep(2)


def test_backup_via_websocket():
    """Test backup generation through the WebSocket API."""
    print("Testing backup generation via WebSocket API...")
    
    # Create SSL context that doesn't verify certificates (for testing)
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    try:
        with connect("wss://localhost:5104", ssl=ssl_context) as websocket:
            # Read admin password
            with open("admin_password.txt", "r", encoding="utf-8") as f:
                password = f.read().strip()
            
            # Login
            print("\n1. Logging in as admin...")
            login_request = {
                "action": "login",
                "data": {
                    "username": "admin",
                    "password": password,
                }
            }
            websocket.send(json.dumps(login_request, ensure_ascii=False))
            login_response = json.loads(websocket.recv())
            
            if login_response.get("code") != 200:
                print(f"Login failed: {login_response}")
                return False
            
            token = login_response.get("data", {}).get("token", "")
            print("✓ Login successful")
            
            # Generate backup
            print("\n2. Requesting backup generation...")
            backup_request = {
                "action": "generate_backup",
                "data": {
                    "backup_name": "api_test_backup"
                },
                "username": "admin",
                "token": token
            }
            websocket.send(json.dumps(backup_request, ensure_ascii=False))
            backup_response = json.loads(websocket.recv())
            
            print(f"\nBackup response: {json.dumps(backup_response, indent=2)}")
            
            if backup_response.get("code") != 200:
                print(f"✗ Backup generation failed: {backup_response}")
                return False
            
            # Verify the response contains expected data
            response_data = backup_response.get("data", {})
            if not all(key in response_data for key in ["archive_path", "key_path", "metadata"]):
                print("✗ Response missing required fields")
                return False
            
            # Verify files were created
            archive_path = response_data["archive_path"]
            key_path = response_data["key_path"]
            
            if not os.path.exists(archive_path):
                print(f"✗ Archive file not found: {archive_path}")
                return False
            
            if not os.path.exists(key_path):
                print(f"✗ Key file not found: {key_path}")
                return False
            
            print(f"✓ Backup generated successfully")
            print(f"  Archive: {archive_path} ({os.path.getsize(archive_path)} bytes)")
            print(f"  Key: {key_path}")
            print(f"  Metadata: {json.dumps(response_data['metadata'], indent=4)}")
            
            return True
            
    except Exception as e:
        print(f"✗ Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main test function."""
    print("="*60)
    print("CFMS Backup Generation API Integration Test")
    print("="*60)
    
    # Check if server is already running by trying to initialize it
    if not os.path.exists("./init"):
        print("\nInitializing server for the first time...")
        # Need to import all models first, then create tables
        from include.database.handler import Base, engine
        from include.database.models.classic import User, UserGroup, UserPermission, UserMembership, AuditEntry, ObjectAccessEntry
        from include.database.models.entity import Document, DocumentRevision, DocumentAccessRule, Folder, FolderAccessRule
        from include.database.models.file import File, FileTask
        from include.database.models.blocking import UserBlockEntry, UserBlockSubEntry
        
        Base.metadata.create_all(engine)
        
        from main import server_init
        server_init()
        print("✓ Server initialized")
    
    # Start server in background thread
    print("\nStarting CFMS server...")
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    time.sleep(3)  # Give server time to start
    
    # Run the test
    try:
        success = test_backup_via_websocket()
        
        print("\n" + "="*60)
        if success:
            print("SUCCESS: Backup generation API test passed!")
        else:
            print("FAILURE: Backup generation API test failed!")
        print("="*60)
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        return 1
    except Exception as e:
        print(f"\nTest failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
