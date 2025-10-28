#!/usr/bin/env python3
"""
Test script for the backup restoration functionality.

This script tests the complete backup and restore cycle.
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
from include.util.backup import generate_backup, restore_backup
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
            {"permission": "export_backup", "start_time": 0, "end_time": None},
            {"permission": "import_backup", "start_time": 0, "end_time": None},
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
            f.write("This is a test document for backup/restore functionality.")

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
            f.write("This is another test document for verification.")

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


def test_backup_restore_cycle():
    """Test the complete backup and restore cycle."""
    print("\nTesting backup and restore cycle...")

    # Step 1: Generate backup
    print("\n1. Generating backup...")
    with Session() as session:
        backup_dir = "./content/backups"
        result = generate_backup(session, backup_dir, "restore_test")

        print(f"   ✓ Backup created: {result['archive_path']}")
        print(f"   ✓ Key file: {result['key_path']}")
        
        archive_path = result['archive_path']
        key_path = result['key_path']
        
        # Load key data
        with open(key_path, 'r') as f:
            key_data = json.load(f)

    # Step 2: Clear database
    print("\n2. Clearing database...")
    with Session() as session:
        # Delete all documents
        session.query(DocumentRevision).delete()
        session.query(Document).delete()
        session.query(Folder).delete()
        # Delete files (keeping File objects but clearing content)
        for file in session.query(File).all():
            if os.path.exists(file.path):
                os.remove(file.path)
        session.query(File).delete()
        session.commit()
    
    # Verify database is empty
    with Session() as session:
        doc_count = session.query(Document).count()
        folder_count = session.query(Folder).count()
        file_count = session.query(File).count()
        print(f"   ✓ Database cleared: {doc_count} docs, {folder_count} folders, {file_count} files")
        assert doc_count == 0, "Documents not cleared"
        assert folder_count == 0, "Folders not cleared"
        assert file_count == 0, "Files not cleared"

    # Step 3: Restore backup
    print("\n3. Restoring backup...")
    
    progress_updates = []
    def progress_callback(progress):
        progress_updates.append({
            "status": progress.status,
            "step": progress.current_step,
            "percent": progress.progress_percent
        })
        print(f"   Progress: {progress.progress_percent}% - {progress.current_step}")
    
    with Session() as session:
        result = restore_backup(
            session,
            archive_path,
            key_data,
            restore_dir="./content/restore_test",
            progress_callback=progress_callback
        )
        
        print(f"\n   Restore result: {result['status']}")
        if result['status'] == 'failed':
            print(f"   Error: {result.get('error')}")
            return False
        
        print(f"   ✓ Documents imported: {result['documents_imported']}")
        print(f"   ✓ Folders imported: {result['folders_imported']}")
        print(f"   ✓ Files imported: {result['files_imported']}")

    # Step 4: Verify restored data
    print("\n4. Verifying restored data...")
    with Session() as session:
        # Check documents
        docs = session.query(Document).all()
        print(f"   ✓ Found {len(docs)} documents")
        assert len(docs) == 2, f"Expected 2 documents, found {len(docs)}"
        
        # Check folders
        folders = session.query(Folder).all()
        print(f"   ✓ Found {len(folders)} folders")
        assert len(folders) == 1, f"Expected 1 folder, found {len(folders)}"
        
        # Check files
        files = session.query(File).all()
        print(f"   ✓ Found {len(files)} files")
        assert len(files) == 2, f"Expected 2 files, found {len(files)}"
        
        # Verify file content
        for file in files:
            assert os.path.exists(file.path), f"File not found: {file.path}"
            size = os.path.getsize(file.path)
            print(f"   ✓ File {file.id} exists ({size} bytes)")
        
        # Check document-folder relationships
        doc_with_folder = session.query(Document).filter_by(id="test_doc_1").first()
        assert doc_with_folder is not None, "Document test_doc_1 not found"
        assert doc_with_folder.folder_id == "test_folder_1", "Document folder relationship broken"
        print(f"   ✓ Document-folder relationship preserved")
        
        # Check document revisions
        for doc in docs:
            assert len(doc.revisions) > 0, f"Document {doc.id} has no revisions"
        print(f"   ✓ All documents have revisions")

    print("\n   ✓ All verification checks passed!")
    print(f"\n   Progress updates received: {len(progress_updates)}")
    return True


def main():
    """Main test function."""
    try:
        setup_test_database()
        success = test_backup_restore_cycle()
        
        print("\n" + "="*60)
        if success:
            print("SUCCESS: Backup/restore cycle completed successfully!")
        else:
            print("FAILURE: Backup/restore test failed!")
        print("="*60)
        
        return 0 if success else 1
    except Exception as e:
        print(f"\n{'='*60}")
        print(f"ERROR: {str(e)}")
        print("="*60)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
