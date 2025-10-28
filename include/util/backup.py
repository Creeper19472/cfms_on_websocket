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


__all__ = ["generate_backup", "BackupMetadata"]


class BackupMetadata:
    """Metadata for a backup archive."""

    def __init__(self):
        self.version = "1.0"
        self.created_at = time.time()
        self.documents_count = 0
        self.folders_count = 0
        self.files_count = 0


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
