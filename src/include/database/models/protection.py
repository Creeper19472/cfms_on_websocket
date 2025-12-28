"""
Database models for object protection (passwords, etc.)

This module provides a scalable protection system that can be extended
with additional protection types in the future.
"""

import hashlib
import secrets
from typing import Optional

from sqlalchemy import VARCHAR, Integer, Text
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from include.database.handler import Base


class PasswordProtection(Base):
    """
    Model for password-based protection on documents and directories.
    
    This table is separate from the main entity tables to maintain scalability
    and allow for future protection types (e.g., encryption, biometric, etc.)
    """
    __tablename__ = "password_protections"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    
    # Target object identification
    target_type: Mapped[str] = mapped_column(
        VARCHAR(64), nullable=False, comment="Type: 'document' or 'directory'"
    )
    target_id: Mapped[str] = mapped_column(
        VARCHAR(255), nullable=False, comment="ID of the protected object"
    )
    
    # Password storage (hashed)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    salt: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Reserved for future protection types
    protection_type: Mapped[str] = mapped_column(
        VARCHAR(64), nullable=False, default="password",
        comment="Protection type: 'password' (reserved for future types like 'encryption', 'biometric')"
    )
    
    # Additional metadata (reserved for future use)
    protection_metadata: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True,
        comment="JSON metadata for future extensions"
    )
    
    def set_password(self, plain_password: str) -> None:
        """
        Set a new password for this protection entry.
        
        Uses PBKDF2-HMAC-SHA256 with 600,000 iterations for secure password hashing,
        following OWASP recommendations for password storage.
        
        Args:
            plain_password: The plain text password to hash and store
        """
        self.salt = secrets.token_hex(16)
        # Use PBKDF2-HMAC for secure password hashing (OWASP recommended)
        # 600,000 iterations is the OWASP recommended minimum as of 2023
        password_bytes = plain_password.encode('utf-8')
        salt_bytes = self.salt.encode('utf-8')
        key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 600000)
        self.password_hash = key.hex()
    
    def verify_password(self, plain_password: str) -> bool:
        """
        Verify a password against the stored hash.
        
        Uses constant-time comparison to prevent timing attacks.
        
        Args:
            plain_password: The plain text password to verify
            
        Returns:
            True if the password matches, False otherwise
        """
        password_bytes = plain_password.encode('utf-8')
        salt_bytes = self.salt.encode('utf-8')
        key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 600000)
        computed_hash = key.hex()
        
        # Use constant-time comparison to prevent timing attacks
        return secrets.compare_digest(computed_hash, self.password_hash)
    
    def __repr__(self) -> str:
        return (
            f"PasswordProtection(id={self.id!r}, "
            f"target_type={self.target_type!r}, target_id={self.target_id!r})"
        )
