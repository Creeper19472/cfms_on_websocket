#!/usr/bin/env python3
"""
Simple test client for backup generation API.

This test assumes the server is already running and will just test
the backup generation request.
"""

import json
import os
import ssl
import sys

from websockets.sync.client import connect


def test_backup_api():
    """Test the backup generation API with an already running server."""
    print("Testing backup generation API...")
    print("Note: This test assumes the server is already running at wss://localhost:5104")
    print()
    
    # Create SSL context
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    try:
        # Check if admin password file exists
        if not os.path.exists("admin_password.txt"):
            print("Error: admin_password.txt not found. Please start the server first.")
            return False
            
        with open("admin_password.txt", "r", encoding="utf-8") as f:
            password = f.read().strip()
        
        with connect("wss://localhost:5104", ssl=ssl_context) as websocket:
            # Step 1: Login
            print("1. Logging in as admin...")
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
                print(f"   ✗ Login failed: {login_response}")
                return False
            
            token = login_response.get("data", {}).get("token", "")
            print("   ✓ Login successful")
            
            # Step 2: Generate backup
            print("\n2. Requesting backup generation...")
            backup_request = {
                "action": "generate_backup",
                "data": {
                    "backup_name": "client_test_backup"
                },
                "username": "admin",
                "token": token
            }
            websocket.send(json.dumps(backup_request, ensure_ascii=False))
            backup_response = json.loads(websocket.recv())
            
            print(f"\n   Response code: {backup_response.get('code')}")
            print(f"   Response message: {backup_response.get('message')}")
            
            if backup_response.get("code") != 200:
                print(f"   ✗ Backup generation failed")
                print(f"   Full response: {json.dumps(backup_response, indent=2)}")
                return False
            
            # Verify response data
            response_data = backup_response.get("data", {})
            
            if not all(key in response_data for key in ["archive_path", "key_path", "metadata"]):
                print("   ✗ Response missing required fields")
                return False
            
            archive_path = response_data["archive_path"]
            key_path = response_data["key_path"]
            metadata = response_data["metadata"]
            
            print("\n   ✓ Backup generated successfully!")
            print(f"\n   Archive: {archive_path}")
            
            # Verify files exist
            if os.path.exists(archive_path):
                size = os.path.getsize(archive_path)
                print(f"   Archive size: {size:,} bytes")
            else:
                print(f"   ✗ Archive file not found!")
                return False
            
            print(f"\n   Key file: {key_path}")
            if os.path.exists(key_path):
                print(f"   ✓ Key file exists")
                with open(key_path, 'r') as f:
                    key_data = json.load(f)
                    print(f"   Algorithm: {key_data.get('algorithm')}")
            else:
                print(f"   ✗ Key file not found!")
                return False
            
            print(f"\n   Metadata:")
            print(f"   - Version: {metadata.get('version')}")
            print(f"   - Documents: {metadata.get('documents_count')}")
            print(f"   - Folders: {metadata.get('folders_count')}")
            print(f"   - Files: {metadata.get('files_count')}")
            
            return True
            
    except ConnectionRefusedError:
        print("✗ Connection refused. Is the server running?")
        return False
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    print("="*60)
    print("CFMS Backup Generation API Test")
    print("="*60)
    print()
    
    success = test_backup_api()
    
    print()
    print("="*60)
    if success:
        print("SUCCESS: All tests passed!")
    else:
        print("FAILURE: Test failed!")
    print("="*60)
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
