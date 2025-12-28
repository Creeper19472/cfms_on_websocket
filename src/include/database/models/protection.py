"""
Database models for object protection (passwords, encryption, biometric, etc.)

This module provides a unified protection system that can handle multiple
protection types in a single table.
"""

import hashlib
import json
import secrets
from typing import Optional

from sqlalchemy import VARCHAR, Integer, Text
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from include.database.handler import Base


class ObjectProtection(Base):
    """
    Unified model for all types of protection on documents and directories.
    
    This single table handles all protection types (password, encryption, biometric, etc.)
    distinguished by the protection_type column.
    """
    __tablename__ = "object_protections"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    
    # Target object identification
    target_type: Mapped[str] = mapped_column(
        VARCHAR(64), nullable=False, comment="Type: 'document' or 'directory'"
    )
    target_id: Mapped[str] = mapped_column(
        VARCHAR(255), nullable=False, comment="ID of the protected object"
    )
    
    # Protection type identifier
    protection_type: Mapped[str] = mapped_column(
        VARCHAR(64), nullable=False,
        comment="Protection type: 'password', 'encryption', 'biometric', etc."
    )
    
    # Protection data (type-specific, stored as JSON or text)
    # For password: contains password_hash and salt
    # For other types: contains type-specific data
    protection_data: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="Protection-specific data (JSON format for flexibility)"
    )
    
    # Additional metadata (reserved for future use)
    protection_metadata: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True,
        comment="JSON metadata for future extensions"
    )
    
    def set_password(self, plain_password: str) -> None:
        """
        Set password protection data for this entry.
        
        Uses PBKDF2-HMAC-SHA256 with 600,000 iterations for secure password hashing,
        following OWASP recommendations for password storage.
        
        Args:
            plain_password: The plain text password to hash and store
        """
        self.protection_type = "password"
        
        # Generate salt and hash
        salt = secrets.token_hex(16)
        password_bytes = plain_password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 600000)
        password_hash = key.hex()
        
        # Store as JSON
        self.protection_data = json.dumps({
            "password_hash": password_hash,
            "salt": salt
        })
    
    def verify_password(self, plain_password: str) -> bool:
        """
        Verify a password against the stored hash.
        
        Uses constant-time comparison to prevent timing attacks.
        Only works if protection_type is "password".
        
        Args:
            plain_password: The plain text password to verify
            
        Returns:
            True if the password matches, False otherwise
        """
        if self.protection_type != "password":
            return False
        
        try:
            data = json.loads(self.protection_data)
            password_hash = data["password_hash"]
            salt = data["salt"]
        except (json.JSONDecodeError, KeyError):
            return False
        
        password_bytes = plain_password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 600000)
        computed_hash = key.hex()
        
        # Use constant-time comparison to prevent timing attacks
        return secrets.compare_digest(computed_hash, password_hash)
    
    def __repr__(self) -> str:
        return (
            f"ObjectProtection(id={self.id!r}, "
            f"target_type={self.target_type!r}, target_id={self.target_id!r}, "
            f"protection_type={self.protection_type!r})"
        )
