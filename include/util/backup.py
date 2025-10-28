"""
Backup and restore utilities for CFMS.

This module provides functionality to export database entries (documents, folders,
document revisions, access rules) and their associated files into an encrypted
archive. The archive can be used to restore the data on another server.
"""

import json
import os
import secrets
import tarfile
import tempfile
import time
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from sqlalchemy.orm import Session

from include.database.models.entity import (
    Document,
    DocumentRevision,
    DocumentAccessRule,
    Folder,
    FolderAccessRule,
)
from include.database.models.file import File


__all__ = ["generate_backup", "restore_backup", "BackupMetadata", "RestoreProgress"]


class BackupMetadata:
    """Metadata for a backup archive."""

    def __init__(self):
        self.version = "1.0"
        self.created_at = time.time()
        self.documents_count = 0
        self.folders_count = 0
        self.files_count = 0


class RestoreProgress:
    """Track progress of backup restoration."""

    def __init__(self):
        self.status = "pending"  # pending, decrypting, extracting, importing, completed, failed
        self.current_step = ""
        self.progress_percent = 0
        self.documents_imported = 0
        self.folders_imported = 0
        self.files_imported = 0
        self.error_message = None
        self.started_at = time.time()
        self.completed_at = None


def _serialize_access_rule(rule) -> Dict:
    """Serialize an access rule to a dictionary."""
    return {
        "id": rule.id,
        "access_type": rule.access_type,
        "rule_data": rule.rule_data,
    }


def _serialize_document_revision(revision: DocumentRevision) -> Dict:
    """Serialize a document revision to a dictionary."""
    return {
        "id": revision.id,
        "document_id": revision.document_id,
        "file_id": revision.file_id,
        "created_time": revision.created_time,
    }


def _serialize_document(document: Document) -> Dict:
    """Serialize a document to a dictionary."""
    return {
        "id": document.id,
        "title": document.title,
        "created_time": document.created_time,
        "folder_id": document.folder_id,
        "access_rules": [_serialize_access_rule(rule) for rule in document.access_rules],
        "revisions": [_serialize_document_revision(rev) for rev in document.revisions],
    }


def _serialize_folder(folder: Folder) -> Dict:
    """Serialize a folder to a dictionary."""
    return {
        "id": folder.id,
        "name": folder.name,
        "created_time": folder.created_time,
        "parent_id": folder.parent_id,
        "access_rules": [_serialize_access_rule(rule) for rule in folder.access_rules],
    }


def _serialize_file(file: File) -> Dict:
    """Serialize a file metadata to a dictionary."""
    return {
        "id": file.id,
        "sha256": file.sha256,
        "path": file.path,
        "created_time": file.created_time,
        "active": file.active,
    }


def _encrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    """
    Encrypt a file using AES-256-CBC.

    Args:
        input_path: Path to the input file
        output_path: Path to the output encrypted file
        key: 32-byte encryption key
    """
    # Generate a random IV
    iv = secrets.token_bytes(16)

    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Write IV to the beginning of the output file
    with open(output_path, "wb") as out_file:
        out_file.write(iv)

        # Read and encrypt the input file
        with open(input_path, "rb") as in_file:
            # Use padding for block cipher
            padder = padding.PKCS7(128).padder()

            while True:
                chunk = in_file.read(64 * 1024)  # 64KB chunks
                if not chunk:
                    break

                padded_data = padder.update(chunk)
                encrypted_data = encryptor.update(padded_data)
                out_file.write(encrypted_data)

            # Finalize padding and encryption
            padded_data = padder.finalize()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            out_file.write(encrypted_data)


def generate_backup(
    session: Session, output_dir: str, backup_name: Optional[str] = None
) -> Dict[str, str]:
    """
    Generate a backup of the database and files.

    This function exports all documents, folders, document revisions, access rules,
    and associated files into an encrypted archive. The encryption key is saved
    separately.

    Args:
        session: SQLAlchemy database session
        output_dir: Directory where backup files will be saved
        backup_name: Optional name for the backup (defaults to timestamp)

    Returns:
        Dictionary containing:
        - archive_path: Path to the encrypted backup archive
        - key_path: Path to the encryption key file
        - metadata: Backup metadata information
    """
    # Generate backup name if not provided
    if not backup_name:
        backup_name = f"backup_{int(time.time())}"

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Generate encryption key (256-bit for AES-256)
    encryption_key = secrets.token_bytes(32)

    # Create temporary directory for staging backup content
    with tempfile.TemporaryDirectory() as temp_dir:
        # Initialize metadata
        metadata = BackupMetadata()

        # Export documents
        documents = session.query(Document).all()
        documents_data = [_serialize_document(doc) for doc in documents]
        metadata.documents_count = len(documents_data)

        with open(os.path.join(temp_dir, "documents.json"), "w", encoding="utf-8") as f:
            json.dump(documents_data, f, indent=2, ensure_ascii=False)

        # Export folders
        folders = session.query(Folder).all()
        folders_data = [_serialize_folder(folder) for folder in folders]
        metadata.folders_count = len(folders_data)

        with open(os.path.join(temp_dir, "folders.json"), "w", encoding="utf-8") as f:
            json.dump(folders_data, f, indent=2, ensure_ascii=False)

        # Export file metadata and collect file IDs
        file_ids = set()
        for doc in documents:
            for revision in doc.revisions:
                file_ids.add(revision.file_id)

        files = session.query(File).filter(File.id.in_(file_ids)).all() if file_ids else []
        files_data = [_serialize_file(file) for file in files]
        metadata.files_count = len(files_data)

        with open(os.path.join(temp_dir, "files.json"), "w", encoding="utf-8") as f:
            json.dump(files_data, f, indent=2, ensure_ascii=False)

        # Export metadata
        metadata_dict = {
            "version": metadata.version,
            "created_at": metadata.created_at,
            "documents_count": metadata.documents_count,
            "folders_count": metadata.folders_count,
            "files_count": metadata.files_count,
        }

        with open(os.path.join(temp_dir, "metadata.json"), "w", encoding="utf-8") as f:
            json.dump(metadata_dict, f, indent=2, ensure_ascii=False)

        # Copy actual files to the backup
        files_dir = os.path.join(temp_dir, "files")
        os.makedirs(files_dir, exist_ok=True)

        for file in files:
            if os.path.exists(file.path):
                # Copy file with its ID as the filename
                dest_path = os.path.join(files_dir, file.id)
                try:
                    with open(file.path, "rb") as src, open(dest_path, "wb") as dst:
                        dst.write(src.read())
                except (IOError, PermissionError) as e:
                    # Log error but continue with backup
                    print(f"Warning: Could not copy file {file.path}: {e}")

        # Create unencrypted tar archive
        unencrypted_archive = os.path.join(temp_dir, f"{backup_name}.tar")
        with tarfile.open(unencrypted_archive, "w") as tar:
            tar.add(temp_dir, arcname=".", filter=lambda tarinfo: tarinfo if tarinfo.name != unencrypted_archive else None)

        # Encrypt the archive
        encrypted_archive_path = os.path.join(output_dir, f"{backup_name}.cfms.enc")
        _encrypt_file(unencrypted_archive, encrypted_archive_path, encryption_key)

    # Save encryption key to a separate file
    key_path = os.path.join(output_dir, f"{backup_name}.key")
    with open(key_path, "w", encoding="utf-8") as f:
        key_data = {
            "key": encryption_key.hex(),
            "algorithm": "AES-256-CBC",
            "created_at": metadata.created_at,
            "backup_name": backup_name,
        }
        json.dump(key_data, f, indent=2)

    return {
        "archive_path": encrypted_archive_path,
        "key_path": key_path,
        "metadata": metadata_dict,
    }


def _decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    """
    Decrypt a file using AES-256-CBC.

    Args:
        input_path: Path to the encrypted input file
        output_path: Path to the decrypted output file
        key: 32-byte encryption key
    """
    with open(input_path, "rb") as in_file:
        # Read IV from the beginning of the file
        iv = in_file.read(16)

        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt and write the file
        with open(output_path, "wb") as out_file:
            unpadder = padding.PKCS7(128).unpadder()

            while True:
                chunk = in_file.read(64 * 1024)  # 64KB chunks
                if not chunk:
                    break

                decrypted_data = decryptor.update(chunk)
                unpadded_data = unpadder.update(decrypted_data)
                out_file.write(unpadded_data)

            # Finalize decryption and padding
            decrypted_data = decryptor.finalize()
            unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
            out_file.write(unpadded_data)


def restore_backup(
    session: Session,
    archive_path: str,
    key_data: Dict,
    restore_dir: str = "./content/restore",
    progress_callback=None,
) -> Dict:
    """
    Restore a backup from an encrypted archive.

    This function decrypts and extracts a backup archive, then imports all
    documents, folders, document revisions, access rules, and files back
    into the database.

    Args:
        session: SQLAlchemy database session
        archive_path: Path to the encrypted backup archive
        key_data: Dictionary containing the encryption key and metadata
        restore_dir: Directory for temporary restoration files
        progress_callback: Optional callback function to report progress

    Returns:
        Dictionary containing:
        - status: "success" or "failed"
        - documents_imported: Number of documents imported
        - folders_imported: Number of folders imported
        - files_imported: Number of files imported
        - error: Error message if failed

    Raises:
        ValueError: If the backup format is invalid or incompatible
        FileNotFoundError: If the archive or key file is missing
    """
    progress = RestoreProgress()

    def update_progress(status, step, percent):
        progress.status = status
        progress.current_step = step
        progress.progress_percent = percent
        if progress_callback:
            progress_callback(progress)

    try:
        # Validate key data
        if "key" not in key_data or "algorithm" not in key_data:
            raise ValueError("Invalid key file format")

        if key_data["algorithm"] != "AES-256-CBC":
            raise ValueError(f"Unsupported encryption algorithm: {key_data['algorithm']}")

        # Parse encryption key
        encryption_key = bytes.fromhex(key_data["key"])
        if len(encryption_key) != 32:
            raise ValueError("Invalid encryption key length")

        update_progress("decrypting", "Decrypting archive", 10)

        # Create restore directory
        os.makedirs(restore_dir, exist_ok=True)

        # Decrypt archive to temporary location
        with tempfile.TemporaryDirectory() as temp_dir:
            decrypted_archive = os.path.join(temp_dir, "backup.tar")
            _decrypt_file(archive_path, decrypted_archive, encryption_key)

            update_progress("extracting", "Extracting archive", 30)

            # Extract tar archive
            extract_dir = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)

            with tarfile.open(decrypted_archive, "r") as tar:
                tar.extractall(extract_dir)

            update_progress("importing", "Loading metadata", 40)

            # Load metadata
            metadata_path = os.path.join(extract_dir, "metadata.json")
            if not os.path.exists(metadata_path):
                raise ValueError("Backup archive missing metadata.json")

            with open(metadata_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)

            # Validate backup version
            if metadata.get("version") != "1.0":
                raise ValueError(f"Unsupported backup version: {metadata.get('version')}")

            # Load backup data
            with open(os.path.join(extract_dir, "folders.json"), "r", encoding="utf-8") as f:
                folders_data = json.load(f)

            with open(os.path.join(extract_dir, "documents.json"), "r", encoding="utf-8") as f:
                documents_data = json.load(f)

            with open(os.path.join(extract_dir, "files.json"), "r", encoding="utf-8") as f:
                files_data = json.load(f)

            update_progress("importing", "Importing files", 50)

            # Import files first
            files_dir = os.path.join(extract_dir, "files")
            os.makedirs(restore_dir, exist_ok=True)
            restored_files_dir = os.path.join(restore_dir, "files")
            os.makedirs(restored_files_dir, exist_ok=True)

            file_id_map = {}  # Map old file IDs to new File objects
            for file_data in files_data:
                # Create new file entry
                new_file_path = os.path.join(restored_files_dir, file_data["id"])

                # Copy file content if it exists
                source_file = os.path.join(files_dir, file_data["id"])
                if os.path.exists(source_file):
                    with open(source_file, "rb") as src, open(new_file_path, "wb") as dst:
                        dst.write(src.read())

                # Create File object
                file_obj = File(
                    id=file_data["id"],
                    sha256=file_data.get("sha256"),
                    path=new_file_path,
                    created_time=file_data["created_time"],
                    active=file_data.get("active", True),
                )
                session.add(file_obj)
                file_id_map[file_data["id"]] = file_obj
                progress.files_imported += 1

            session.flush()  # Flush to assign IDs

            update_progress("importing", "Importing folders", 60)

            # Import folders (respecting parent-child relationships)
            folder_id_map = {}  # Map old folder IDs to new folder IDs
            folders_by_id = {f["id"]: f for f in folders_data}

            def import_folder(folder_data, parent_id=None):
                """Recursively import folders."""
                # Create Folder object
                folder = Folder(
                    id=folder_data["id"],
                    name=folder_data["name"],
                    created_time=folder_data["created_time"],
                    parent_id=parent_id,
                )
                session.add(folder)
                folder_id_map[folder_data["id"]] = folder

                # Import access rules
                for rule_data in folder_data.get("access_rules", []):
                    rule = FolderAccessRule(
                        access_type=rule_data["access_type"],
                        folder_id=folder.id,
                        rule_data=rule_data["rule_data"],
                    )
                    session.add(rule)

                progress.folders_imported += 1

            # First import root folders (no parent)
            root_folders = [f for f in folders_data if not f.get("parent_id")]
            for folder_data in root_folders:
                import_folder(folder_data)

            # Then import child folders
            for folder_data in folders_data:
                if folder_data.get("parent_id") and folder_data["id"] not in folder_id_map:
                    parent_id = folder_data["parent_id"]
                    import_folder(folder_data, parent_id)

            session.flush()

            update_progress("importing", "Importing documents", 80)

            # Import documents
            for doc_data in documents_data:
                # Create Document object
                document = Document(
                    id=doc_data["id"],
                    title=doc_data["title"],
                    created_time=doc_data["created_time"],
                    folder_id=doc_data.get("folder_id"),
                )
                session.add(document)

                # Import document revisions
                for rev_data in doc_data.get("revisions", []):
                    revision = DocumentRevision(
                        document_id=document.id,
                        file_id=rev_data["file_id"],
                        created_time=rev_data["created_time"],
                    )
                    session.add(revision)

                # Import access rules
                for rule_data in doc_data.get("access_rules", []):
                    rule = DocumentAccessRule(
                        access_type=rule_data["access_type"],
                        document_id=document.id,
                        rule_data=rule_data["rule_data"],
                    )
                    session.add(rule)

                progress.documents_imported += 1

            update_progress("importing", "Finalizing import", 95)

            # Commit all changes
            session.commit()

            update_progress("completed", "Restore completed", 100)
            progress.completed_at = time.time()

            return {
                "status": "success",
                "documents_imported": progress.documents_imported,
                "folders_imported": progress.folders_imported,
                "files_imported": progress.files_imported,
                "metadata": metadata,
            }

    except Exception as e:
        session.rollback()
        progress.status = "failed"
        progress.error_message = str(e)
        progress.completed_at = time.time()

        if progress_callback:
            progress_callback(progress)

        return {
            "status": "failed",
            "error": str(e),
            "documents_imported": progress.documents_imported,
            "folders_imported": progress.folders_imported,
            "files_imported": progress.files_imported,
        }
