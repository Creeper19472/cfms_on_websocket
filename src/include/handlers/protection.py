"""
Handlers for password protection management.

This module provides handlers for enabling, removing, and verifying
password protection on documents and directories.
"""

from typing import Optional

from include.classes.connection import ConnectionHandler
from include.classes.request import RequestHandler
from include.constants import TARGET_TYPE_MAPPING
from include.database.handler import Session
from include.database.models.classic import User
from include.database.models.entity import Document, Folder
from include.database.models.protection import ObjectProtection

__all__ = [
    "RequestEnablePasswordProtectionHandler",
    "RequestRemovePasswordProtectionHandler",
    "RequestVerifyPasswordHandler",
    "check_password_protection",
]


def check_password_protection(target, password: Optional[str], session) -> tuple[int, str]:
    """
    Check password protection for a document or directory.
    
    This is a helper function to be used by request handlers to check
    if an object has password protection and verify the password if provided.
    
    Args:
        target: The Document or Folder object to check
        password: The password provided by the user (None if not provided)
        session: The database session
        
    Returns:
        Tuple of (code, message):
            - (0, "success") if access granted (no protection or correct password)
            - (202, "Password required") if protected but no password provided
            - (403, "Incorrect password") if protected and wrong password provided
    """
    target_type = TARGET_TYPE_MAPPING[target.__tablename__]
    
    # Check if object has password protection
    protection = (
        session.query(ObjectProtection)
        .filter(
            ObjectProtection.target_type == target_type,
            ObjectProtection.target_id == target.id,
            ObjectProtection.protection_type == "password"
        )
        .first()
    )
    
    if not protection:
        # No password protection, access granted
        return (0, "success")
    
    if password is None:
        # Password required but not provided
        return (202, "Password required")
    
    # Verify the password
    if protection.verify_password(password):
        return (0, "success")
    else:
        return (403, "Incorrect password")


class RequestEnablePasswordProtectionHandler(RequestHandler):
    """
    Enable password protection on a document or directory.
    """
    
    data_schema = {
        "type": "object",
        "properties": {
            "target_type": {
                "type": "string",
                "enum": ["document", "directory"]
            },
            "target_id": {"type": "string", "minLength": 1},
            "password": {"type": "string", "minLength": 1}
        },
        "required": ["target_type", "target_id", "password"],
        "additionalProperties": False
    }
    
    require_auth = True
    
    def handle(self, handler: ConnectionHandler):
        target_type: str = handler.data["target_type"]
        target_id: str = handler.data["target_id"]
        password: str = handler.data["password"]
        
        with Session() as session:
            user = session.get(User, handler.username)
            assert user is not None
            
            # Get the target object
            if target_type == "document":
                target = session.get(Document, target_id)
                if not target:
                    handler.conclude_request(404, {}, "Document not found")
                    return 404, target_id, handler.username
                
                # Check if user has manage permissions
                if not target.check_access_requirements(user, access_type="manage"):
                    handler.conclude_request(403, {}, "Access denied to manage this document")
                    return 403, target_id, handler.username
                    
            elif target_type == "directory":
                target = session.get(Folder, target_id)
                if not target:
                    handler.conclude_request(404, {}, "Directory not found")
                    return 404, target_id, handler.username
                
                # Check if user has manage permissions
                if not target.check_access_requirements(user, access_type="manage"):
                    handler.conclude_request(403, {}, "Access denied to manage this directory")
                    return 403, target_id, handler.username
            else:
                handler.conclude_request(400, {}, "Invalid target type")
                return 400, target_id, handler.username
            
            # Check if protection already exists
            existing_protection = (
                session.query(ObjectProtection)
                .filter(
                    ObjectProtection.target_type == target_type,
                    ObjectProtection.target_id == target_id,
                    ObjectProtection.protection_type == "password"
                )
                .first()
            )
            
            if existing_protection:
                # Update existing protection
                existing_protection.set_password(password)
                session.commit()
                handler.conclude_request(
                    200, {}, "Password protection updated successfully"
                )
                return 0, target_id, handler.username
            else:
                # Create new protection
                protection = ObjectProtection(
                    target_type=target_type,
                    target_id=target_id
                )
                protection.set_password(password)
                session.add(protection)
                session.commit()
                
                handler.conclude_request(
                    200, {}, "Password protection enabled successfully"
                )
                return 0, target_id, handler.username


class RequestRemovePasswordProtectionHandler(RequestHandler):
    """
    Remove password protection from a document or directory.
    """
    
    data_schema = {
        "type": "object",
        "properties": {
            "target_type": {
                "type": "string",
                "enum": ["document", "directory"]
            },
            "target_id": {"type": "string", "minLength": 1}
        },
        "required": ["target_type", "target_id"],
        "additionalProperties": False
    }
    
    require_auth = True
    
    def handle(self, handler: ConnectionHandler):
        target_type: str = handler.data["target_type"]
        target_id: str = handler.data["target_id"]
        
        with Session() as session:
            user = session.get(User, handler.username)
            assert user is not None
            
            # Get the target object
            if target_type == "document":
                target = session.get(Document, target_id)
                if not target:
                    handler.conclude_request(404, {}, "Document not found")
                    return 404, target_id, handler.username
                
                # Check if user has manage permissions
                if not target.check_access_requirements(user, access_type="manage"):
                    handler.conclude_request(403, {}, "Access denied to manage this document")
                    return 403, target_id, handler.username
                    
            elif target_type == "directory":
                target = session.get(Folder, target_id)
                if not target:
                    handler.conclude_request(404, {}, "Directory not found")
                    return 404, target_id, handler.username
                
                # Check if user has manage permissions
                if not target.check_access_requirements(user, access_type="manage"):
                    handler.conclude_request(403, {}, "Access denied to manage this directory")
                    return 403, target_id, handler.username
            else:
                handler.conclude_request(400, {}, "Invalid target type")
                return 400, target_id, handler.username
            
            # Find and delete the protection
            protection = (
                session.query(ObjectProtection)
                .filter(
                    ObjectProtection.target_type == target_type,
                    ObjectProtection.target_id == target_id,
                    ObjectProtection.protection_type == "password"
                )
                .first()
            )
            
            if not protection:
                handler.conclude_request(
                    404, {}, "Password protection not found for this object"
                )
                return 404, target_id, handler.username
            
            session.delete(protection)
            session.commit()
            
            handler.conclude_request(
                200, {}, "Password protection removed successfully"
            )
            return 0, target_id, handler.username


class RequestVerifyPasswordHandler(RequestHandler):
    """
    Verify a password for a protected document or directory.
    This is useful for client-side validation before attempting access.
    """
    
    data_schema = {
        "type": "object",
        "properties": {
            "target_type": {
                "type": "string",
                "enum": ["document", "directory"]
            },
            "target_id": {"type": "string", "minLength": 1},
            "password": {"type": "string"}
        },
        "required": ["target_type", "target_id", "password"],
        "additionalProperties": False
    }
    
    require_auth = True
    
    def handle(self, handler: ConnectionHandler):
        target_type: str = handler.data["target_type"]
        target_id: str = handler.data["target_id"]
        password: str = handler.data["password"]
        
        with Session() as session:
            user = session.get(User, handler.username)
            assert user is not None
            
            # Get the target object
            if target_type == "document":
                target = session.get(Document, target_id)
                if not target:
                    handler.conclude_request(404, {}, "Document not found")
                    return 404, target_id, handler.username
                    
            elif target_type == "directory":
                target = session.get(Folder, target_id)
                if not target:
                    handler.conclude_request(404, {}, "Directory not found")
                    return 404, target_id, handler.username
            else:
                handler.conclude_request(400, {}, "Invalid target type")
                return 400, target_id, handler.username
            
            # Find the protection
            protection = (
                session.query(ObjectProtection)
                .filter(
                    ObjectProtection.target_type == target_type,
                    ObjectProtection.target_id == target_id,
                    ObjectProtection.protection_type == "password"
                )
                .first()
            )
            
            if not protection:
                handler.conclude_request(
                    404, {}, "Password protection not found for this object"
                )
                return 404, target_id, handler.username
            
            # Verify the password
            if protection.verify_password(password):
                handler.conclude_request(
                    200, {"verified": True}, "Password verified successfully"
                )
                return 0, target_id, handler.username
            else:
                handler.conclude_request(
                    403, {"verified": False}, "Incorrect password"
                )
                return 403, target_id, handler.username
