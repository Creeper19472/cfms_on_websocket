"""
Search handlers for documents and directories.

Provides functionality to search for documents and directories by name,
with permission filtering, result limiting, and sorting capabilities.
"""

import time
from typing import List, Dict, Any, Literal

from sqlalchemy import or_

from include.classes.connection import ConnectionHandler
from include.classes.request import RequestHandler
from include.conf_loader import global_config
from include.database.handler import Session
from include.database.models.blocking import UserBlockEntry, UserBlockSubEntry
from include.database.models.classic import ObjectAccessEntry, User
from include.database.models.entity import Document, Folder, NoActiveRevisionsError
from include.constants import AVAILABLE_BLOCK_TYPES

__all__ = ["RequestSearchHandler"]


def _prefetch_user_blocks(
    session,
    user: User,
    access_type: str,
    now: float,
) -> tuple[bool, set[str]]:
    if access_type not in AVAILABLE_BLOCK_TYPES:
        return False, set()

    block_entries = (
        session.query(UserBlockEntry)
        .join(UserBlockSubEntry, UserBlockSubEntry.parent_id == UserBlockEntry.block_id)
        .filter(
            UserBlockEntry.username == user.username,
            UserBlockEntry.not_before <= now,
            (UserBlockEntry.not_after == -1) | (UserBlockEntry.not_after >= now),
            UserBlockSubEntry.block_type == access_type,
        )
        .all()
    )

    is_globally_blocked = any(entry.target_type == "all" for entry in block_entries)
    blocked_ids = {
        entry.target_id
        for entry in block_entries
        if entry.target_type != "all" and entry.target_id
    }

    return is_globally_blocked, blocked_ids


def _batch_prefetch_granted_ids(
    session,
    user: User,
    obj_ids: list[str],
    target_type: Literal["document", "directory"],
    access_type: str,
    now: float,
) -> set[str]:
    """
    Batch prefetch object IDs that the user has been granted access to.
    This function queries the database to retrieve a set of object identifiers
    for which the specified user (directly or through their group memberships)
    has the requested access type at the given time.
    Args:
        session: SQLAlchemy session for database queries.
        user (User): The user object containing username and group memberships.
        obj_ids (list[str]): List of object identifiers to check access for.
        target_type (Literal["document", "directory"]): The type of target object.
        access_type (str): The type of access to check (e.g., "read", "write").
        now (float): The current timestamp used to validate access validity window.
    Returns:
        set[str]: A set of object identifiers that the user has been granted
                  access to based on their direct permissions or group memberships.
                  Returns an empty set if obj_ids is empty or no matching entries found.
    """

    if not obj_ids:
        return set()

    entity_identifiers = [user.username] + [g.group_name for g in user.groups]

    rows = (
        session.query(ObjectAccessEntry.target_identifier)
        .filter(
            ObjectAccessEntry.target_type == target_type,
            ObjectAccessEntry.target_identifier.in_(obj_ids),
            ObjectAccessEntry.entity_identifier.in_(entity_identifiers),
            ObjectAccessEntry.access_type == access_type,
            ObjectAccessEntry.start_time <= now,
            or_(
                ObjectAccessEntry.end_time == None,
                ObjectAccessEntry.end_time >= now,
            ),
        )
        .all()
    )
    return {row[0] for row in rows}


def _check_single_folder_own_access(
    session,
    user: User,
    folder: "Folder",
    access_type: str,
    now: float,
) -> bool:
    """
    Check a single Folder's own access rules without recursing into its parents.
    Used during parent-chain traversal to evaluate each folder in isolation.

    Mirrors the logic of check_access_requirements() but skips:
      - UserBlock check (already handled globally by _prefetch_user_blocks)
      - Recursive parent traversal (handled by the caller: _check_parent_chain)
    """
    entity_identifiers = [user.username] + [g.group_name for g in user.groups]
    row = (
        session.query(ObjectAccessEntry.id)
        .filter(
            ObjectAccessEntry.target_type == "directory",
            ObjectAccessEntry.target_identifier == folder.id,
            ObjectAccessEntry.entity_identifier.in_(entity_identifiers),
            ObjectAccessEntry.access_type == access_type,
            ObjectAccessEntry.start_time <= now,
            or_(
                ObjectAccessEntry.end_time.is_(None),
                ObjectAccessEntry.end_time >= now,
            ),
        )
        .first()
    )
    if row:
        return True

    if not folder.access_rules:
        return True

    # Has access_rules: evaluate them with inheritance temporarily disabled
    # to avoid re-triggering recursive parent traversal inside check_access_requirements.
    original_inherit = folder.inherit
    folder.inherit = False
    try:
        return folder.check_access_requirements(user, access_type=access_type)
    finally:
        folder.inherit = original_inherit


def _check_parent_chain(
    session,
    user: User,
    obj: "Document | Folder",
    access_type: str,
    now: float,
    folder_cache: dict[str, bool],
) -> bool:
    """
    Walk the parent-folder chain of obj, checking access at each level.
    Results are stored in folder_cache so that folders shared by multiple
    search results are only evaluated once per request.
    """
    parent = obj.folder if isinstance(obj, Document) else obj.parent

    visited: set[str] = set()
    while parent is not None:
        if parent.id in visited:
            raise RuntimeError("Cycle detected in folder hierarchy")
        visited.add(parent.id)

        if parent.id in folder_cache:
            if not folder_cache[parent.id]:
                return False
        else:
            result = _check_single_folder_own_access(
                session, user, parent, access_type, now
            )
            folder_cache[parent.id] = result
            if not result:
                return False

        if not parent.inherit:
            break
        parent = parent.parent

    return True


def _check_object_access_with_cache(
    session,
    user: User,
    obj: "Document | Folder",
    access_type: str,
    now: float,
    explicitly_granted_ids: set[str],
    folder_cache: dict[str, bool],
) -> bool:
    """
    Full access check for a single Document or Folder, with parent-folder
    results cached in folder_cache to avoid redundant DB queries across
    multiple objects that share the same ancestors.

    Decision order (mirrors check_access_requirements semantics):
      1. Recursive parent-chain check (if enabled and obj.inherit is True)
      2. ObjectAccessEntry explicit grant  → allow
      3. No access_rules                  → allow
      4. Evaluate access_rules (pure Python, no extra DB queries)
    """
    if global_config["access"]["enable_access_recursive_check"] and obj.inherit:
        if not _check_parent_chain(session, user, obj, access_type, now, folder_cache):
            return False

    if obj.id in explicitly_granted_ids:
        return True

    if not obj.access_rules:
        return True

    # Pure Python rule evaluation; access_rules already loaded via selectinload
    # Temporarily disable inherit to prevent check_access_requirements from
    # re-running the parent chain (we already handled it above).
    original_inherit = obj.inherit
    obj.inherit = False
    try:
        return obj.check_access_requirements(user, access_type=access_type)
    finally:
        obj.inherit = original_inherit


class RequestSearchHandler(RequestHandler):
    """
    Handles the "search" action for finding documents and directories by name.

    Features:
    1. Accepts a search query (name) as the main parameter
    2. Returns matching objects with their ID and parent directory ID
    3. Filters results based on user read permissions
    4. Supports limiting the maximum number of search results
    5. Supports sorting by multiple criteria (time, size, name, etc.)
    """

    data_schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "minLength": 1},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
            "sort_by": {
                "type": "string",
                "enum": ["name", "created_time", "size", "last_modified"],
            },
            "sort_order": {"type": "string", "enum": ["asc", "desc"]},
            "search_documents": {"type": "boolean"},
            "search_directories": {"type": "boolean"},
        },
        "required": ["query"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        """
        Handle the search request.

        Args:
            handler: The connection handler containing request data

        Returns:
            Tuple containing status code, query, and username for audit logging
        """
        query: str = handler.data["query"]
        limit: int = handler.data.get("limit", 100)
        sort_by: str = handler.data.get("sort_by", "name")
        sort_order: str = handler.data.get("sort_order", "asc")
        search_documents: bool = handler.data.get("search_documents", True)
        search_directories: bool = handler.data.get("search_directories", True)

        with Session() as session:
            user = session.get(User, handler.username)
            assert user is not None

            now = time.time()

            results: Dict[str, List[Dict[str, Any]]] = {
                "documents": [],
                "directories": [],
            }

            # ------------------------------------------------------------------ #
            # Preload block entries
            # ------------------------------------------------------------------ #
            is_globally_blocked, blocked_ids = _prefetch_user_blocks(
                session, user, "read", now
            )

            # Shared cache for parent-folder access results across both loops
            folder_access_cache: dict[str, bool] = {}

            # Search documents
            if search_documents and not is_globally_blocked:
                documents = (
                    session.query(Document)
                    .filter(Document.title.ilike(f"%{query}%"))
                    .all()
                )

                # ------------------------------------------------------------------ #
                # Preload explicitly granted document IDs for the user in a single batch query
                # ------------------------------------------------------------------ #
                doc_ids = [doc.id for doc in documents]
                explicitly_granted_doc_ids = _batch_prefetch_granted_ids(
                    session, user, doc_ids, "document", "read", now
                )

                # ------------------------------------------------------------------ #
                # Query loop with in-memory permission checks using preloaded data, avoiding N+1 queries
                # ------------------------------------------------------------------ #
                for document in documents:
                    if not document.active:
                        continue
                    if document.id in blocked_ids:
                        continue
                    if not _check_object_access_with_cache(
                        session, user, document, "read", now,
                        explicitly_granted_doc_ids, folder_access_cache,
                    ):
                        continue

                    try:
                        latest_revision = document.get_latest_revision()
                        size = latest_revision.file.size if latest_revision.file else 0
                        last_modified = latest_revision.created_time
                    except (NoActiveRevisionsError, AttributeError):
                        size = 0
                        last_modified = document.created_time

                    results["documents"].append(
                        {
                            "id": document.id,
                            "name": document.title,
                            "parent_id": document.folder_id,
                            "created_time": document.created_time,
                            "last_modified": last_modified,
                            "size": size,
                            "type": "document",
                        }
                    )

            # Search directories
            if search_directories and not is_globally_blocked:
                directories = (
                    session.query(Folder).filter(Folder.name.ilike(f"%{query}%")).all()
                )

                dir_ids = [d.id for d in directories]
                explicitly_granted_dir_ids = _batch_prefetch_granted_ids(
                    session, user, dir_ids, "directory", "read", now
                )

                for directory in directories:
                    if directory.id in blocked_ids:
                        continue
                    if not _check_object_access_with_cache(
                        session, user, directory, "read", now,
                        explicitly_granted_dir_ids, folder_access_cache,
                    ):
                        continue

                    results["directories"].append(
                        {
                            "id": directory.id,
                            "name": directory.name,
                            "parent_id": directory.parent_id,
                            "created_time": directory.created_time,
                            "type": "directory",
                        }
                    )

            # Sort results
            all_results = results["documents"] + results["directories"]

            # Sort by the specified field
            if sort_by == "name":
                all_results.sort(
                    key=lambda x: x["name"].lower(), reverse=(sort_order == "desc")
                )
            elif sort_by == "created_time":
                all_results.sort(
                    key=lambda x: x["created_time"], reverse=(sort_order == "desc")
                )
            elif sort_by == "size":
                all_results.sort(
                    key=lambda x: x.get("size", 0), reverse=(sort_order == "desc")
                )
            elif sort_by == "last_modified":
                all_results.sort(
                    key=lambda x: x.get("last_modified", x["created_time"]),
                    reverse=(sort_order == "desc"),
                )

            # Apply limit
            all_results = all_results[:limit]

            # Separate back into documents and directories
            final_documents = [r for r in all_results if r["type"] == "document"]
            final_directories = [r for r in all_results if r["type"] == "directory"]

            response_data = {
                "documents": final_documents,
                "directories": final_directories,
                "total_count": len(all_results),
                "query": query,
            }

            handler.conclude_request(
                200,
                response_data,
                f"Search completed successfully. Found {len(all_results)} result(s).",
            )
            return 0, query, handler.username
