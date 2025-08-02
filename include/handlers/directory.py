from include.classes.connection import ConnectionHandler
from include.classes.request import RequestHandler
from include.conf_loader import global_config
from include.database.handler import Session
from include.database.models.general import User, Folder, Document, FolderAccessRule
from include.function.audit import log_audit
import include.system.messages as smsg
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


class RequestListDirectoryHandler(RequestHandler):
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

    data_schema = {
        "type": "object",
        "properties": {"folder_id": {"anyOf": [{"type": "string"}, {"type": "null"}]}},
    }

    def handle(self, handler: ConnectionHandler):

        try:
            # Parse the directory listing request
            folder_id: str = handler.data.get("folder_id", "")

            with Session() as session:
                this_user = session.get(User, handler.username)
                if not this_user or not this_user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 401, "message": "Invalid user or token", "data": {}}
                    )
                    return 401, folder_id
                if not folder_id:
                    parent = None
                    children = (
                        session.query(Folder).filter(Folder.parent_id.is_(None)).all()
                    )
                    documents = (
                        session.query(Document)
                        .filter(Document.folder_id.is_(None))
                        .all()
                    )
                else:
                    folder = session.get(Folder, folder_id)
                    if not folder:
                        handler.conclude_request(
                            **{
                                "code": 404,
                                "message": "Directory not found",
                                "data": {},
                            }
                        )
                        return 404, folder_id, handler.username
                    if (
                        not "super_list_directory" in this_user.all_permissions
                        and not folder.check_access_requirements(this_user, 0)
                    ):
                        handler.conclude_request(
                            **{"code": 403, "message": "Access denied", "data": {}}
                        )
                        return 403, folder_id, handler.username
                    parent = folder.parent
                    children = folder.children
                    documents = folder.documents

                active_documents = [
                    document for document in documents if document.active
                ]

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
            return 0, folder_id, handler.username

        except Exception as e:
            handler.logger.error(
                f"Error detected when handling requests.", exc_info=True
            )
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestGetDirectoryInfoHandler(RequestHandler):
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

    data_schema = {
        "type": "object",
        "properties": {"directory_id": {"type": "string", "minLength": 1}},
        "required": ["directory_id"],
    }

    def handle(self, handler: ConnectionHandler):

        try:
            directory_id: str = handler.data["directory_id"]

            if not directory_id:
                handler.conclude_request(400, {}, "Directory ID is required")
                return

            if not handler.username:
                handler.conclude_request(
                    **{"code": 401, "message": "Authentication is required", "data": {}}
                )
                return 401, directory_id

            with Session() as session:
                user = session.get(User, handler.username)
                directory = session.get(Folder, directory_id)

                if user is None or not user.is_token_valid(handler.token):
                    handler.conclude_request(403, {}, "Invalid user or token")
                    return 401, directory_id

                if not directory:
                    handler.conclude_request(404, {}, "Directory not found")
                    return 404, directory_id, handler.username

                if not directory.check_access_requirements(user, access_type=0):
                    handler.conclude_request(403, {}, "Permission denied")
                    return 403, directory_id, handler.username

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

                handler.conclude_request(
                    200, data, "Directory info retrieved successfully"
                )
                return 0, directory_id, handler.username

        except Exception as e:
            handler.logger.error(
                f"Error detected when handling requests.", exc_info=True
            )
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestCreateDirectoryHandler(RequestHandler):
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

    data_schema = {
        "type": "object",
        "properties": {
            "parent_id": {"type": "string"},
            "name": {"type": "string", "minLength": 1},
            "access_rules": {"type": "object"},
        },
        "required": ["name"],
    }

    def handle(self, handler: ConnectionHandler):

        try:
            # Parse the directory creation request
            parent_id: str = handler.data.get("parent_id", "")
            name: str = handler.data["name"]
            access_rules_to_apply: dict = handler.data.get("access_rules", {})
            exists_ok = handler.data.get("exists_ok", False)

            with Session() as session:
                this_user = session.get(User, handler.username)
                if not this_user or not this_user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 403, "message": "Invalid user or token", "data": {}}
                    )
                    return 401, parent_id, handler.username
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
                        return 404, parent_id, handler.username
                    if not parent.check_access_requirements(this_user, 1):
                        handler.conclude_request(
                            **{"code": 403, "message": "Access denied", "data": {}}
                        )
                        return 403, parent_id, handler.username

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
                    return 403, parent_id, handler.username

                # Check for duplicate folder or document name under the same parent
                if not global_config["document"]["allow_name_duplicate"]:
                    existing_folder = (
                        session.query(Folder)
                        .filter(Folder.parent_id == parent_id, Folder.name == name)
                        .first()
                    )
                    existing_document = (
                        session.query(Document)
                        .filter(Document.folder_id == parent_id, Document.title == name)
                        .first()
                    )

                    if existing_document:
                        # 如果存在同名文档，无论是否有 exists_ok 都不能忽略重名
                        # 提醒删除该重名的文档
                        handler.conclude_request(
                            400,
                            {"type": "document", "id": existing_document.id},
                            smsg.DOCUMENT_NAME_DUPLICATE,
                        )
                        return

                    elif (
                        existing_folder
                    ):  # 第二步判断有无同名文件夹，如有检查 exists_ok

                        if exists_ok:
                            handler.conclude_request(
                                200,
                                {
                                    "id": existing_folder.id,
                                    "name": existing_folder.name,
                                    "last_modified": existing_folder.created_time,
                                },
                                "Directory already exists",
                            )
                            return 0, parent_id, handler.username
                        else:
                            handler.conclude_request(
                                400,
                                {},
                                smsg.DIRECTORY_NAME_DUPLICATE,  # 第一步判断已经知道没有同名文档，则一定是同名文件夹
                            )
                            return

                folder = Folder(name=name, parent=parent)

                if apply_directory_access_rules(
                    folder, access_rules_to_apply, this_user
                ):
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
                    log_audit(
                        "create_directory",
                        username=handler.username,
                        target=parent_id,
                        result=0,
                        remote_address=handler.remote_address,
                    )

                else:
                    session.rollback()
                    handler.conclude_request(
                        403, {}, "Set access rules failed: permission denied"
                    )
                    log_audit(
                        "create_directory",
                        username=handler.username,
                        target=parent_id,
                        result=403,
                        remote_address=handler.remote_address,
                    )

                session.add(folder)
                session.commit()

        except Exception as e:
            handler.logger.error(
                f"Error detected when handling requests.", exc_info=True
            )
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestDeleteDirectoryHandler(RequestHandler):
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

    data_schema = {
        "type": "object",
        "properties": {
            "folder_id": {"type": "string", "minLength": 1},
        },
        "required": ["folder_id"],
    }

    def handle(self, handler: ConnectionHandler):

        try:
            # Parse the directory deletion request
            folder_id = handler.data[
                "folder_id"
            ]  # Get the folder ID from the request data

            with Session() as session:
                this_user = session.get(User, handler.username)
                if not this_user or not this_user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 403, "message": "Invalid user or token", "data": {}}
                    )
                    return 401, folder_id
                folder = session.get(Folder, folder_id)
                if not folder:
                    handler.conclude_request(
                        **{"code": 404, "message": "Directory not found", "data": {}}
                    )
                    return 404, folder_id, handler.username
                if (
                    "delete_directory" not in this_user.all_permissions
                    or not folder.check_access_requirements(this_user, 1)
                ):
                    handler.conclude_request(
                        **{"code": 403, "message": "Access denied", "data": {}}
                    )
                    return 403, folder_id, handler.username

                try:
                    folder.delete_all_children()
                except PermissionError:
                    handler.conclude_request(
                        500,
                        {},
                        "An error occurred when attempting to delete documents in the directory. Perhaps a download task is still in progress?",
                    )
                    return 500, folder_id, handler.username
                session.delete(folder)
                session.commit()

                handler.conclude_request(
                    **{
                        "code": 200,
                        "message": "Directory deleted successfully",
                        "data": {},
                    }
                )
                return 0, folder_id, handler.username

        except Exception as e:
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestRenameDirectoryHandler(RequestHandler):
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

    data_schema = {
        "type": "object",
        "properties": {
            "folder_id": {"type": "string", "minLength": 1},
            "new_name": {"type": "string", "minLength": 1},
        },
        "required": ["folder_id", "new_name"],
    }

    def handle(self, handler: ConnectionHandler):

        try:
            # Parse the directory renaming request
            folder_id = handler.data["folder_id"]
            new_name = handler.data["new_name"]

            with Session() as session:
                this_user = session.get(User, handler.username)
                if not this_user or not this_user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 403, "message": "Invalid user or token", "data": {}}
                    )
                    return 401, folder_id
                folder = session.get(Folder, folder_id)
                if not folder:
                    handler.conclude_request(
                        **{"code": 404, "message": "Directory not found", "data": {}}
                    )
                    return 404, folder_id, handler.username
                if (
                    "rename_directory" not in this_user.all_permissions
                    or not folder.check_access_requirements(this_user, 1)
                ):
                    handler.conclude_request(
                        **{"code": 403, "message": "Access denied", "data": {}}
                    )
                    return 403, folder_id, handler.username

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
                    **{
                        "code": 200,
                        "message": "Directory renamed successfully",
                        "data": {},
                    }
                )
                return 0, folder_id, handler.username

        except Exception as e:
            handler.logger.error(
                f"Error detected when handling requests.", exc_info=True
            )
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestMoveDirectoryHandler(RequestHandler):

    data_schema = {
        "type": "object",
        "properties": {
            "folder_id": {"type": "string", "minLength": 1},
            "target_folder_id": {"type": "string", "minLength": 1},
        },
        "required": ["folder_id", "target_folder_id"],
    }

    def handle(self, handler: ConnectionHandler):

        folder_id: str = handler.data["folder_id"]
        target_folder_id: str = handler.data["target_folder_id"]

        if not folder_id:
            handler.conclude_request(
                **{
                    "code": 400,
                    "message": "folder_id is required",
                    "data": {},
                }
            )
            return

        with Session() as session:
            user = session.get(User, handler.username)
            if not user or not user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 403, "message": smsg.INVALID_USER_OR_TOKEN, "data": {}}
                )
                return 401, folder_id

            if "move" not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_MOVE_DIRECTORY)
                return 403, folder_id, handler.username

            folder = session.get(Folder, folder_id)

            if not folder:
                handler.conclude_request(
                    **{
                        "code": 404,
                        "message": smsg.SUBJECT_DIRECTORY_NOT_FOUND,
                        "data": {},
                    }
                )
                return 404, folder_id, handler.username

            if not folder.check_access_requirements(user, 2):
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_MOVE_DIRECTORY)
                return 403, folder_id, handler.username

            if target_folder_id:
                target_folder = session.get(Folder, target_folder_id)
                if not target_folder:
                    handler.conclude_request(
                        **{
                            "code": 404,
                            "message": smsg.TARGET_DIRECTORY_NOT_FOUND,
                            "data": {},
                        }
                    )
                    return 404, folder_id, handler.username

                if not target_folder.check_access_requirements(
                    user, 1
                ):  # 对于目标文件夹，移动可视为一种写操作
                    handler.conclude_request(
                        403, {}, smsg.ACCESS_DENIED_WRITE_DIRECTORY
                    )
                    return 403, folder_id, handler.username

                folder.parent = target_folder
            else:
                # 未来添加有关根目录写入的规则
                folder.parent = None

            session.commit()

        handler.conclude_request(200, {}, smsg.SUCCESS)
        return 0, folder_id, handler.username
