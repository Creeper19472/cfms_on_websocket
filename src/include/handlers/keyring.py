"""
Keyring handlers for CFMS.

These handlers allow authenticated users to upload, query, and delete their own
encryption keys. A key marked as *primary* is returned in the login response so
that any compliant client can retrieve the configuration-encryption DEK without
needing to know the key identifier in advance.

Security constraints enforced by these handlers:
- A user may only access and manage their own keys.
- Admins with the ``manage_keyrings`` permission may manage any user's keys.
- At most one key per user may be marked *primary*; uploading a new primary
  key automatically demotes the previous one.
"""

import time

from include.classes.connection import ConnectionHandler
from include.classes.request import RequestHandler
from include.database.handler import Session
from include.database.models.classic import Keyring, User

__all__ = [
    "RequestUploadKeyringHandler",
    "RequestGetKeyringHandler",
    "RequestDeleteKeyringHandler",
    "RequestSetPrimaryKeyringHandler",
    "RequestListKeyringsHandler",
]


class RequestUploadKeyringHandler(RequestHandler):
    """
    Upload a new key into the user's keyring.

    The caller must be authenticated. The key is bound to the authenticated user
    unless the caller has ``manage_keyrings`` permission and explicitly passes a
    ``target_username``.

    Request data:
        key_content  (str, required)  – The key material / encrypted DEK.
        label        (str, optional)  – Human-readable label.
        is_primary   (bool, optional) – Mark this key as the primary config key
                                        (default: false).
        target_username (str, opt.)   – Admin-only: operate on another user.

    Response codes:
        200 – Key uploaded successfully; ``key_id`` is returned in data.
        403 – Permission denied.
        404 – Target user not found (admin path only).
    """

    data_schema = {
        "type": "object",
        "properties": {
            "key_content": {"type": "string", "minLength": 1},
            "label": {"type": "string"},
            "is_primary": {"type": "boolean"},
            "target_username": {"type": "string", "minLength": 1},
        },
        "required": ["key_content"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        key_content: str = handler.data["key_content"]
        label: str | None = handler.data.get("label")
        is_primary: bool = handler.data.get("is_primary", False)
        target_username: str | None = handler.data.get("target_username")

        with Session() as session:
            this_user = session.get(User, handler.username)
            assert this_user is not None

            # Determine which user's keyring to write to
            if target_username and target_username != handler.username:
                if "manage_keyrings" not in this_user.all_permissions:
                    handler.conclude_request(403, {}, "Permission denied")
                    return 403, target_username, handler.username
                owner = session.get(User, target_username)
                if not owner:
                    handler.conclude_request(404, {}, "Target user not found")
                    return 404, target_username, handler.username
            else:
                target_username = handler.username
                owner = this_user

            # Demote any existing primary key for this user when uploading a new
            # primary key so the invariant of at most one primary per user holds.
            if is_primary:
                session.query(Keyring).filter(
                    Keyring.username == target_username,
                    Keyring.is_primary == True,  # noqa: E712
                ).update({"is_primary": False})

            key = Keyring(
                username=target_username,
                key_content=key_content,
                label=label,
                is_primary=is_primary,
                created_time=time.time(),
            )
            session.add(key)
            session.commit()

            handler.conclude_request(
                200,
                {"key_id": key.key_id},
                "Key uploaded successfully",
            )
            return 200, target_username, handler.username


class RequestGetKeyringHandler(RequestHandler):
    """
    Retrieve a single key from the keyring by its ``key_id``.

    The authenticated user may retrieve only their own keys unless they hold
    ``manage_keyrings`` permission.

    Request data:
        key_id          (str, required) – The key identifier to retrieve.
        target_username (str, optional) – Admin-only.

    Response codes:
        200 – Key found; key details returned in data.
        403 – Permission denied.
        404 – Key not found.
    """

    data_schema = {
        "type": "object",
        "properties": {
            "key_id": {"type": "string", "minLength": 1},
            "target_username": {"type": "string", "minLength": 1},
        },
        "required": ["key_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        key_id: str = handler.data["key_id"]
        target_username: str | None = handler.data.get("target_username")

        with Session() as session:
            this_user = session.get(User, handler.username)
            assert this_user is not None

            key = session.get(Keyring, key_id)
            if not key:
                handler.conclude_request(404, {}, "Key not found")
                return 404, key_id, handler.username

            # Authorisation: the key must belong to the requesting user, or the
            # user must have admin-level manage_keyrings permission.
            if key.username != handler.username:
                if "manage_keyrings" not in this_user.all_permissions:
                    handler.conclude_request(403, {}, "Permission denied")
                    return 403, key_id, handler.username

            handler.conclude_request(
                200,
                {
                    "key_id": key.key_id,
                    "username": key.username,
                    "label": key.label,
                    "key_content": key.key_content,
                    "is_primary": key.is_primary,
                    "created_time": key.created_time,
                },
                "Key retrieved successfully",
            )
            return 200, key_id, handler.username


class RequestDeleteKeyringHandler(RequestHandler):
    """
    Delete a key from the keyring by its ``key_id``.

    The authenticated user may delete only their own keys unless they hold
    ``manage_keyrings`` permission.

    Request data:
        key_id          (str, required) – The key identifier to delete.
        target_username (str, optional) – Admin-only.

    Response codes:
        200 – Key deleted successfully.
        403 – Permission denied.
        404 – Key not found.
    """

    data_schema = {
        "type": "object",
        "properties": {
            "key_id": {"type": "string", "minLength": 1},
            "target_username": {"type": "string", "minLength": 1},
        },
        "required": ["key_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        key_id: str = handler.data["key_id"]

        with Session() as session:
            this_user = session.get(User, handler.username)
            assert this_user is not None

            key = session.get(Keyring, key_id)
            if not key:
                handler.conclude_request(404, {}, "Key not found")
                return 404, key_id, handler.username

            if key.username != handler.username:
                if "manage_keyrings" not in this_user.all_permissions:
                    handler.conclude_request(403, {}, "Permission denied")
                    return 403, key_id, handler.username

            session.delete(key)
            session.commit()

            handler.conclude_request(200, {}, "Key deleted successfully")
            return 200, key_id, handler.username


class RequestSetPrimaryKeyringHandler(RequestHandler):
    """
    Designate a key as the primary configuration-encryption key for the user.

    The primary key will be returned in the login response so clients can
    retrieve the config DEK transparently. At most one key per user is primary;
    calling this endpoint demotes any previously primary key.

    Request data:
        key_id          (str, required) – The key identifier to mark primary.
        target_username (str, optional) – Admin-only.

    Response codes:
        200 – Primary key updated.
        403 – Permission denied.
        404 – Key not found.
    """

    data_schema = {
        "type": "object",
        "properties": {
            "key_id": {"type": "string", "minLength": 1},
            "target_username": {"type": "string", "minLength": 1},
        },
        "required": ["key_id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        key_id: str = handler.data["key_id"]

        with Session() as session:
            this_user = session.get(User, handler.username)
            assert this_user is not None

            key = session.get(Keyring, key_id)
            if not key:
                handler.conclude_request(404, {}, "Key not found")
                return 404, key_id, handler.username

            if key.username != handler.username:
                if "manage_keyrings" not in this_user.all_permissions:
                    handler.conclude_request(403, {}, "Permission denied")
                    return 403, key_id, handler.username

            # Demote current primary, then promote the requested key.
            session.query(Keyring).filter(
                Keyring.username == key.username,
                Keyring.is_primary == True,  # noqa: E712
            ).update({"is_primary": False})

            key.is_primary = True
            session.add(key)
            session.commit()

            handler.conclude_request(200, {}, "Primary key updated successfully")
            return 200, key_id, handler.username


class RequestListKeyringsHandler(RequestHandler):
    """
    List all keys in the authenticated user's keyring (metadata only, no key_content).

    The authenticated user sees only their own keys unless they hold
    ``manage_keyrings`` permission and pass ``target_username``.

    Request data:
        target_username (str, optional) – Admin-only: list another user's keys.

    Response codes:
        200 – List returned in ``data.keys``.
        403 – Permission denied.
        404 – Target user not found (admin path only).
    """

    data_schema = {
        "type": "object",
        "properties": {
            "target_username": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        target_username: str | None = handler.data.get("target_username")

        with Session() as session:
            this_user = session.get(User, handler.username)
            assert this_user is not None

            if target_username and target_username != handler.username:
                if "manage_keyrings" not in this_user.all_permissions:
                    handler.conclude_request(403, {}, "Permission denied")
                    return 403, target_username, handler.username
                if not session.get(User, target_username):
                    handler.conclude_request(404, {}, "Target user not found")
                    return 404, target_username, handler.username
            else:
                target_username = handler.username

            keys = (
                session.query(Keyring)
                .filter(Keyring.username == target_username)
                .all()
            )

            handler.conclude_request(
                200,
                {
                    "keys": [
                        {
                            "key_id": k.key_id,
                            "label": k.label,
                            "is_primary": k.is_primary,
                            "created_time": k.created_time,
                        }
                        for k in keys
                    ]
                },
                "Keyring listed successfully",
            )
            return 200, target_username, handler.username
