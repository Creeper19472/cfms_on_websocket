#!/usr/bin/env python3
"""
Test script for the backup generation functionality.

This script initializes a test database, creates some test data,
and then generates a backup to verify the functionality works.
"""

import json
import os
import sys
import tempfile

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Initialize directories first
os.makedirs("./content/logs/", exist_ok=True)
os.makedirs("./content/ssl/", exist_ok=True)
os.makedirs("./content/backups/", exist_ok=True)

from include.conf_loader import global_config
from include.database.handler import Base, Session, engine
from include.database.models.classic import User, UserGroup
from include.database.models.entity import Document, DocumentRevision, Folder
from include.database.models.file import File
from include.util.backup import generate_backup
from include.util.group import create_group
from include.util.user import create_user


def setup_test_database():
    """Set up a test database with sample data."""
    print("Setting up test database...")

    # Remove existing database
    if os.path.exists("./app.db"):
        os.remove("./app.db")

    # Create all tables
    Base.metadata.create_all(engine)

    # Create test groups
    create_group(
        group_name="user",
        permissions=[
            {"permission": "set_passwd", "start_time": 0, "end_time": None},
        ],
    )
    
    create_group(
        group_name="sysop",
        permissions=[
            {"permission": "manage_system", "start_time": 0, "end_time": None},
            {"permission": "shutdown", "start_time": 0, "end_time": None},
        ],
    )

    # Create test user
    create_user(
        username="testuser",
        password="testpassword123",
        nickname="Test User",
        permissions=[],
        groups=[
            {"group_name": "sysop", "start_time": 0, "end_time": None},
            {"group_name": "user", "start_time": 0, "end_time": None},
        ],
    )

    # Create test content directory
    os.makedirs("./content/test_files", exist_ok=True)

    # Create test files and documents
    with Session() as session:
        # Create a test folder
        folder = Folder(id="test_folder_1", name="Test Folder")
        session.add(folder)

        # Create a test file
        test_file_path = "./content/test_files/test_document.txt"
        with open(test_file_path, "w") as f:
            f.write("This is a test document for backup functionality.")

        file1 = File(id="test_file_1", path=test_file_path, active=True)
        session.add(file1)

        # Create a test document
        document1 = Document(id="test_doc_1", title="Test Document 1", folder_id=folder.id)
        revision1 = DocumentRevision(file_id=file1.id)
        document1.revisions.append(revision1)
        session.add(document1)
        session.add(revision1)

        # Create another test file
        test_file_path2 = "./content/test_files/test_document2.txt"
        with open(test_file_path2, "w") as f:
            f.write("This is another test document.")

        file2 = File(id="test_file_2", path=test_file_path2, active=True)
        session.add(file2)

        # Create another test document without a folder
        document2 = Document(id="test_doc_2", title="Test Document 2")
        revision2 = DocumentRevision(file_id=file2.id)
        document2.revisions.append(revision2)
        session.add(document2)
        session.add(revision2)

        session.commit()

    print("Test database setup complete.")


def test_backup_generation():
    """Test the backup generation functionality."""
    print("\nTesting backup generation...")

    with Session() as session:
        # Generate backup
        backup_dir = "./content/backups"
        result = generate_backup(session, backup_dir, "test_backup")

        print(f"\nBackup generated successfully!")
        print(f"Archive path: {result['archive_path']}")
        print(f"Key path: {result['key_path']}")
        print(f"Metadata: {json.dumps(result['metadata'], indent=2)}")

        # Verify files exist
        assert os.path.exists(result['archive_path']), "Archive file not created"
        assert os.path.exists(result['key_path']), "Key file not created"

        # Verify archive is not empty
        archive_size = os.path.getsize(result['archive_path'])
        print(f"\nArchive size: {archive_size} bytes")
        assert archive_size > 0, "Archive is empty"

        # Verify key file contains valid JSON
        with open(result['key_path'], 'r') as f:
            key_data = json.load(f)
            assert 'key' in key_data, "Key file missing 'key' field"
            assert 'algorithm' in key_data, "Key file missing 'algorithm' field"
            print(f"\nKey file content: {json.dumps(key_data, indent=2)}")

        print("\n✓ All backup tests passed!")


def main():
    """Main test function."""
    try:
        setup_test_database()
        test_backup_generation()
        print("\n" + "="*50)
        print("SUCCESS: Backup generation functionality works!")
        print("="*50)
    except Exception as e:
        print(f"\n{'='*50}")
        print(f"ERROR: {str(e)}")
        print("="*50)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
