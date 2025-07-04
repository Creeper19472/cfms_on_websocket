from include.classes.connection import ConnectionHandler
from include.database.handler import Session
from include.database.models import User, Folder, Document, FolderAccessRule
import time


AVAILABLE_ACCESS_TYPES = [0, 1]


def apply_directory_access_rules(
    folder: Folder, set_access_rules: dict, user: User
) -> bool:
    for access_type in set_access_rules:
        if access_type not in AVAILABLE_ACCESS_TYPES:
            raise ValueError(f"Invalid access type: {access_type}")

        this_rule_data = set_access_rules.get(access_type, None)
        if this_rule_data is None:
            raise ValueError(
                f"Access rule data for access type {access_type} is missing"
            )

        with Session() as session:
            for rule in folder.access_rules:
                if rule.access_type == access_type:
                    folder.access_rules.remove(rule)
            this_new_rule = FolderAccessRule(
                folder_id=folder.id,
                access_type=access_type,
                rule_data=this_rule_data,
            )
            folder.access_rules.append(this_new_rule)

            if folder.check_access_requirements(user, access_type):
                session.commit()
            else:
                session.rollback()
                return False

    return True


def handle_list_directory(handler: ConnectionHandler):
    """
    Handles directory listing requests.
    This function processes a directory listing request by generating a list of files and directories in the specified directory.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200 - Directory listing successful, returns a list of files and directories in the response data.
        400 - Invalid request.
        403 - Invalid user or token.
        404 - Directory not found.
        500 - Internal server error, with the exception message.
    """
    try:
        # Parse the directory listing request
        folder_id = handler.data.get("folder_id")

        with Session() as session:
            this_user = session.get(User, handler.username)
            if not this_user or not this_user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 403, "message": "Invalid user or token", "data": {}}
                )
                return
            if not folder_id:
                parent = None
                children = (
                    session.query(Folder).filter(Folder.parent_id.is_(None)).all()
                )
                documents = (
                    session.query(Document).filter(Document.folder_id.is_(None)).all()
                )
            else:
                folder = session.get(Folder, folder_id)
                if not folder:
                    handler.conclude_request(
                        **{"code": 404, "message": "Directory not found", "data": {}}
                    )
                    return
                if not folder.check_access_requirements(this_user, 0):
                    handler.conclude_request(
                        **{"code": 403, "message": "Access denied", "data": {}}
                    )
                    return
                parent = folder.parent
                children = folder.children
                documents = folder.documents

            active_documents = [document for document in documents if document.active]

            if parent:
                parent_id = parent.id
            elif not folder_id:
                parent_id = None
            else:
                parent_id = "/"

            response = {
                "code": 200,
                "message": "Directory listing successful",
                "data": {
                    "parent_id": parent_id,
                    "documents": [
                        {
                            "id": document.id,
                            "title": document.title,
                            "created_time": document.created_time,
                            "last_modified": (
                                last_revision := document.get_latest_revision()
                            ).created_time,
                            "sha256": last_revision.file.sha256,
                            "size": last_revision.file.size,
                        }
                        for document in active_documents
                    ],
                    "folders": [
                        {
                            "id": child.id,
                            "name": child.name,
                            "created_time": child.created_time,
                        }
                        for child in children
                    ],
                },
            }

        # Send the response back to the client
        handler.conclude_request(**response)
    except Exception as e:
        handler.logger.error(f"Error detected when handling requests.", exc_info=True)
        handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


def handle_get_directory_info(handler: ConnectionHandler):
    """
    Handles directory information requests.
    This function processes a directory information request by retrieving information about the specified directory.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200 - Directory info successful, returns directory info in the response data.
        400 - Invalid request.
        403 - Invalid user or token.
        404 - Directory not found.
        500 - Internal server error, with the exception message.
    """
    try:
        directory_id = handler.data.get("directory_id")

        if not directory_id:
            handler.conclude_request(400, {}, "Directory ID is required")
            return

        if not handler.username:
            handler.conclude_request(
                **{"code": 403, "message": "Authentication is required", "data": {}}
            )
            return

        with Session() as session:
            user = session.get(User, handler.username)
            directory = session.get(Folder, directory_id)

            if user is None or not user.is_token_valid(handler.token):
                handler.conclude_request(403, {}, "Invalid user or token")
                return

            if not directory:
                handler.conclude_request(404, {}, "Directory not found")
                return

            if not directory.check_access_requirements(user, access_type=0):
                handler.conclude_request(403, {}, "Permission denied")
                return

            info_code = 0
            ### generate access_rules text
            access_rules = []
            if "view_access_rules" in user.all_permissions:
                for each_rule in directory.access_rules:
                    access_rules.append(
                        {
                            "rule_id": each_rule.id,
                            "rule_data": each_rule.rule_data,
                            "access_type": each_rule.access_type,
                        }
                    )
            else:
                info_code = 1  # 无权访问目录

            data = {
                "directory_id": directory.id,
                "count_of_child": directory.count_of_child,
                "parent_id": directory.parent_id,
                "name": directory.name,
                "created_time": directory.created_time,
                "access_rules": access_rules,
                "info_code": info_code,
            }

            handler.conclude_request(200, data, "Directory info retrieved successfully")

    except Exception as e:
        handler.logger.error(f"Error detected when handling requests.", exc_info=True)
        handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


def handle_create_directory(handler: ConnectionHandler):
    """
    Handles directory creation requests.
    This function processes a directory creation request by creating a new directory in the specified parent directory.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200 - Directory created successfully, returns the created directory in the response data.
        400 - Invalid request.
        403 - Invalid user or token.
        404 - Parent directory not found.
        500 - Internal server error, with the exception message.
    """
    try:
        # Parse the directory creation request
        parent_id = handler.data.get("parent_id")
        name = handler.data.get("name")
        access_rules_to_apply = handler.data.get("access_rules", {})

        if not name:
            handler.conclude_request(
                **{"code": 400, "message": "Directory name is required", "data": {}}
            )
            return

        with Session() as session:
            this_user = session.get(User, handler.username)
            if not this_user or not this_user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 403, "message": "Invalid user or token", "data": {}}
                )
                return
            if parent_id:
                parent = session.get(Folder, parent_id)
                if not parent:
                    handler.conclude_request(
                        **{
                            "code": 404,
                            "message": "Parent directory not found",
                            "data": {},
                        }
                    )
                    return
                if not parent.check_access_requirements(this_user, 1):
                    handler.conclude_request(
                        **{"code": 403, "message": "Access denied", "data": {}}
                    )
                    return
            else:
                parent = None

            if "create_directory" not in this_user.all_permissions:
                handler.conclude_request(
                    **{
                        "code": 403,
                        "message": "You do have no permissions to create new folders",
                        "data": {},
                    }
                )
                return

            folder = Folder(name=name, parent=parent)

            if apply_directory_access_rules(folder, access_rules_to_apply, this_user):
                session.add(folder)
                session.commit()
                handler.conclude_request(
                    200,
                    {
                        "id": folder.id,
                        "name": folder.name,
                        "last_modified": folder.created_time,
                    },
                    "Directory created successfully",
                )

            else:
                session.rollback()
                handler.conclude_request(
                    403, {}, "Set access rules failed: permission denied"
                )

            session.add(folder)
            session.commit()

    except Exception as e:
        handler.logger.error(f"Error detected when handling requests.", exc_info=True)
        handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


def handle_delete_directory(handler: ConnectionHandler):
    """
    Handles directory deletion requests.
    This function processes a directory deletion request by deleting the specified directory.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200 - Directory deleted successfully.
        400 - Invalid request.
        403 - Invalid user or token.
        404 - Directory not found.
        500 - Internal server error, with the exception message.
    """
    try:
        # Parse the directory deletion request
        folder_id = handler.data.get(
            "folder_id"
        )  # Get the folder ID from the request data

        if not folder_id:
            handler.conclude_request(
                **{"code": 400, "message": "Directory ID is required", "data": {}}
            )
            return

        with Session() as session:
            this_user = session.get(User, handler.username)
            if not this_user or not this_user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 403, "message": "Invalid user or token", "data": {}}
                )
                return
            folder = session.get(Folder, folder_id)
            if not folder:
                handler.conclude_request(
                    **{"code": 404, "message": "Directory not found", "data": {}}
                )
                return
            if (
                "delete_directory" not in this_user.all_permissions
                or not folder.check_access_requirements(this_user, 1)
            ):
                handler.conclude_request(
                    **{"code": 403, "message": "Access denied", "data": {}}
                )
                return

            try:
                folder.delete_all_children()
            except PermissionError:
                handler.conclude_request(
                    500,
                    {},
                    "An error occurred when attempting to delete documents in the directory. Perhaps a download task is still in progress?",
                )
                return
            session.delete(folder)
            session.commit()

            handler.conclude_request(
                **{"code": 200, "message": "Directory deleted successfully", "data": {}}
            )

    except Exception as e:
        handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


def handle_rename_directory(handler: ConnectionHandler):
    """
    Handles directory renaming requests.
    This function processes a directory renaming request by updating the name of the specified directory.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200 - Directory renamed successfully.
        400 - Invalid request.
        403 - Invalid user or token.
        404 - Directory not found.
        500 - Internal server error, with the exception message.
    """
    try:
        # Parse the directory renaming request
        folder_id = handler.data.get("folder_id")
        new_name = handler.data.get("new_name")

        if not folder_id:
            handler.conclude_request(
                **{"code": 400, "message": "Directory ID is required", "data": {}}
            )
            return

        if not new_name:
            handler.conclude_request(
                **{"code": 400, "message": "New name is required", "data": {}}
            )
            return

        with Session() as session:
            this_user = session.get(User, handler.username)
            if not this_user or not this_user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 403, "message": "Invalid user or token", "data": {}}
                )
                return
            folder = session.get(Folder, folder_id)
            if not folder:
                handler.conclude_request(
                    **{"code": 404, "message": "Directory not found", "data": {}}
                )
                return
            if (
                "rename_directory" not in this_user.all_permissions
                or not folder.check_access_requirements(this_user, 1)
            ):
                handler.conclude_request(
                    **{"code": 403, "message": "Access denied", "data": {}}
                )
                return

            if folder.name == new_name:
                handler.conclude_request(
                    **{
                        "code": 400,
                        "message": "New name is the same as the current name",
                        "data": {},
                    }
                )
                return
            else:
                folder.name = new_name

            session.commit()

            handler.conclude_request(
                **{"code": 200, "message": "Directory renamed successfully", "data": {}}
            )

    except Exception as e:
        handler.logger.error(f"Error detected when handling requests.", exc_info=True)
        handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})
