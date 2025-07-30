import datetime
import secrets
from include.classes.connection import ConnectionHandler
from include.database.handler import Session
from include.database.models import (
    DocumentAccessRule,
    DocumentRevision,
    User,
    Document,
    File,
    Folder,
    FileTask,
    NoActiveRevisionsError,
)
from include.conf_loader import global_config
import include.system.messages as smsg
import time

__all__ = [
    "handle_create_document",
    "handle_get_document",
    "handle_download_file",
    "handle_upload_file",
    "handle_upload_document",
    "handle_get_document_info",
    "handle_delete_document",
    "handle_rename_document",
    "handle_set_document_rules",
]


# def create_file_task(file_id: str, transfer_mode=0):
def create_file_task(file: File, transfer_mode=0):
    """
    Creates a new file processing task for the specified file.
    Args:
        file (File): The file object for which the task is to be generated.
    Returns:
        dict or None: A dictionary containing the task details:
            - task_id (int): The unique identifier of the created task.
            - created_at (float): The timestamp when the task was created.
            - start_time (float): The start time of the task.
            - end_time (float): The end time of the task (1 hour after start).
        Returns None if the file with the given file_id does not exist.
    """

    with Session() as session:
        # file = session.get(File, file_id)
        if not file:
            return None

        now = time.time()
        task = FileTask(
            file_id=file.id,
            status=0,
            mode=transfer_mode,
            start_time=now,
            end_time=now + 3600,
        )
        session.add(task)
        session.commit()

        return {
            "task_id": task.id,
            "start_time": task.start_time,
            "end_time": task.end_time,
        }


def handle_get_document_info(handler: ConnectionHandler):
    """
    Handles the "get_document_info" action.
    Args:
        handler (ConnectionHandler): The connection handler object.
    Returns:
        None
    """

    document_id = handler.data.get("document_id")

    if not document_id:
        handler.conclude_request(400, {}, "Document ID is required")
        return

    if not handler.username:
        handler.conclude_request(
            **{"code": 403, "message": "Authentication is required", "data": {}}
        )
        return

    with Session() as session:
        user = session.get(User, handler.username)
        document = session.get(Document, document_id)

        if user is None or not user.is_token_valid(handler.token):
            handler.conclude_request(403, {}, "Invalid user or token")
            return

        if not document:
            handler.conclude_request(404, {}, "Document not found")
            return

        if not document.check_access_requirements(user, access_type=0):
            handler.conclude_request(403, {}, "Permission denied")
            return

        info_code = 0
        ### generate access_rules text
        access_rules = []
        if "view_access_rules" in user.all_permissions:
            for each_rule in document.access_rules:
                access_rules.append(
                    {
                        "rule_id": each_rule.id,
                        "rule_data": each_rule.rule_data,
                        "access_type": each_rule.access_type,
                    }
                )
        else:
            info_code = 1  # 无权访问文档的权限

        data = {
            "document_id": document.id,
            "parent_id": document.folder_id,
            "title": document.title,
            "size": document.get_latest_revision().file.size,
            "created_time": document.created_time,
            "last_modified": document.get_latest_revision().created_time,
            "access_rules": access_rules,
            "info_code": info_code,
        }

        handler.conclude_request(200, data, "Document info retrieved successfully")


def handle_get_document(handler: ConnectionHandler):
    document_id = handler.data.get("document_id")

    if not document_id:
        handler.conclude_request(400, {}, "Document ID is required")
        return

    with Session() as session:
        user = session.get(User, handler.username)
        document = session.get(Document, document_id)

        if user is None or not user.is_token_valid(handler.token):
            handler.conclude_request(403, {}, "Invalid user or token")
            return

        if not document:
            handler.conclude_request(404, {}, "Document not found")
            return

        if not document.check_access_requirements(user):
            handler.conclude_request(403, {}, "Access denied to the document")
            return

        try:
            latest_revision = document.get_latest_revision()
        except NoActiveRevisionsError:
            handler.conclude_request(
                404, {}, "No active revisions found for this document"
            )
            return

        data = {
            "document_id": document.id,
            "title": document.title,
            "task_data": create_file_task(latest_revision.file),
        }

        handler.conclude_request(200, data, "Document successfully fetched")


AVAILABLE_ACCESS_TYPES = [0, 1]


def apply_document_access_rules(
    document_id: str, set_access_rules: dict, user: User
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
            document = session.get(Document, document_id)
            if not document:
                raise ValueError(f"Document not found: {document_id}")
            for rule in document.access_rules:
                if rule.access_type == access_type:
                    document.access_rules.remove(rule)
            this_new_rule = DocumentAccessRule(
                document_id=document_id,
                access_type=access_type,
                rule_data=this_rule_data,
            )
            document.access_rules.append(this_new_rule)

            if document.check_access_requirements(user, access_type):
                session.commit()
            else:
                session.rollback()
                return False

    return True


def handle_create_document(handler: ConnectionHandler):
    """
    Handles the document creation request from the client.
    """
    folder_id = handler.data.get("folder_id")
    document_title = handler.data.get("title")
    access_rules_to_apply: dict = handler.data.get("access_rules", {})

    if not access_rules_to_apply:  # fix
        access_rules_to_apply = {}

    with Session() as session:
        user = session.get(User, handler.username)

        if not user or not user.is_token_valid(handler.token):
            handler.conclude_request(403, {}, "Invalid user or token")
            return

        if not document_title:
            handler.conclude_request(400, {}, "Document title is required")

        if folder_id:
            folder = session.get(Folder, folder_id)
            if not folder:
                handler.conclude_request(404, {}, "Folder not found")
                return
            if (
                not folder.check_access_requirements(user, access_type=1)
                and not "super_create_document" in user.all_permissions
            ):  # 创建文件肯定是写权限
                handler.conclude_request(403, {}, "Access denied to the folder")
                return
            
            # 检查同一 folder_id 下是否有同名文件
            existing_doc = (
                session.query(Document)
                .filter_by(folder_id=folder_id, title=document_title)
                .first()
            )
            # 检查同一 folder_id 下是否有同名文件夹
            existing_folder = (
                session.query(Folder)
                .filter_by(parent_id=folder_id, name=document_title)
                .first()
            )
            if (
                (existing_doc or existing_folder)
                and global_config["document"]["allow_name_duplicate"] is False
            ):
                handler.conclude_request(400, {}, smsg.DOCUMENT_OR_DIRECTORY_NAME_DUPLICATE)
                return

        if not "create_document" in user.all_permissions:
            handler.conclude_request(403, {}, "Permission denied")
            return

        today = datetime.date.today()
        new_real_filename = secrets.token_hex(32)

        new_file = File(
            path=f"./content/files/{today.year}/{today.month}/{new_real_filename}",
            id=secrets.token_hex(32),
        )
        new_document = Document(
            id=secrets.token_hex(32),
            title=document_title,
            folder_id=folder_id if folder_id else None,
        )
        new_document_revision = DocumentRevision(file_id=new_file.id)
        new_document.revisions.append(new_document_revision)

        if apply_document_access_rules(new_document.id, access_rules_to_apply, user):
            session.add(new_file)
            session.add(new_document)
            session.add(new_document_revision)
            session.commit()
            task_data = create_file_task(new_document_revision.file, transfer_mode=1)
            handler.conclude_request(
                200, {"task_data": task_data}, "Task successfully created"
            )
        else:
            session.rollback()
            handler.conclude_request(
                403, {}, "Set access rules failed: permission denied"
            )


def handle_upload_document(handler: ConnectionHandler):
    """
    Handles the document upload request from the client.

    Args:
        handler (ConnectionHandler): The connection handler instance.
    """
    document_id = handler.data.get("document_id")
    if not document_id:
        handler.conclude_request(400, {}, "Document ID is required")
        return

    with Session() as session:
        document = session.get(Document, document_id)
        this_user = session.get(User, handler.username)
        if not this_user or not this_user.is_token_valid(handler.token):
            handler.conclude_request(403, {}, "Invalid user or token")
            return

        if document:
            if not document.check_access_requirements(this_user, access_type=1):
                handler.conclude_request(403, {}, "Access denied to the document")
                return

            today = datetime.date.today()

            file_id = secrets.token_hex(32)
            real_filename = secrets.token_hex(32)

            new_file = File(
                id=file_id,
                path=f"./content/files/{today.year}/{today.month}/{real_filename}",
            )

            new_revision = DocumentRevision(document_id=document_id, file_id=file_id)
            document.revisions.append(new_revision)

            session.add(new_file)
            session.add(new_revision)
            session.commit()

        else:
            handler.conclude_request(404, {}, "Document not found")
            return

        task_data = create_file_task(new_file, 1)

    handler.conclude_request(200, {"task_data": task_data}, "Task successfully created")


def handle_delete_document(handler: ConnectionHandler):
    """
    Handles the document deletion request from the client.
    """
    document_id = handler.data.get("document_id")

    if not document_id:
        handler.conclude_request(400, {}, "Document ID is required")
        return

    with Session() as session:
        user = session.get(User, handler.username)
        document = session.get(Document, document_id)

        if not user or not user.is_token_valid(handler.token):
            handler.conclude_request(403, {}, "Invalid user or token")
            return

        if not document:
            handler.conclude_request(404, {}, "Document not found")
            return

        if (
            "delete_document" not in user.all_permissions
            or not document.check_access_requirements(user, access_type=1)
        ):
            handler.conclude_request(403, {}, "Access denied to the document")
            return

        try:
            document.delete_all_revisions()
        except PermissionError:
            handler.conclude_request(
                500,
                {},
                "Failed to delete revisions. Perhaps a download task is still in progress?",
            )
            return
        session.delete(document)
        session.commit()

    handler.conclude_request(200, {}, "Document successfully deleted")


def handle_rename_document(handler: ConnectionHandler):
    """
    Handles the document renaming request from the client.
    """
    try:
        # Parse the directory renaming request
        document_id = handler.data.get("document_id")
        new_title = handler.data.get("new_title")

        if not document_id:
            handler.conclude_request(
                **{"code": 400, "message": "Directory ID is required", "data": {}}
            )
            return

        if not new_title:
            handler.conclude_request(
                **{"code": 400, "message": "New document title is required", "data": {}}
            )
            return

        with Session() as session:
            this_user = session.get(User, handler.username)
            if not this_user or not this_user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 403, "message": "Invalid user or token", "data": {}}
                )
                return
            document = session.get(Document, document_id)
            if not document:
                handler.conclude_request(
                    **{"code": 404, "message": "Document not found", "data": {}}
                )
                return
            if (
                "rename_document" not in this_user.all_permissions
                or not document.check_access_requirements(this_user, 1)
            ):
                handler.conclude_request(
                    **{"code": 403, "message": "Access denied", "data": {}}
                )
                return

            if document.title == new_title:
                handler.conclude_request(
                    **{
                        "code": 400,
                        "message": "New name is the same as the current name",
                        "data": {},
                    }
                )
                return
            else:
                document.title = new_title

            session.commit()

            handler.conclude_request(
                **{"code": 200, "message": "Document renamed successfully", "data": {}}
            )

    except Exception as e:
        handler.logger.error(f"Error detected when handling requests.", exc_info=True)
        handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


def handle_download_file(handler: ConnectionHandler):
    task_id = handler.data.get("task_id")

    if not task_id:
        handler.conclude_request(400, {}, "Task ID is required")
        return

    with Session() as session:
        task = session.get(FileTask, task_id)
        if not task:
            handler.conclude_request(404, {}, "Task not found")
            return

        if task.status != 0 or task.mode != 0:
            handler.conclude_request(
                400, {}, "Task is not in a valid state for download"
            )
            return

        if task.start_time > time.time() or (
            task.end_time and task.end_time < time.time()
        ):
            handler.conclude_request(
                400, {}, "Task is either not started yet or has already ended"
            )
            return

    ### 服务器还需要发送一次响应
    handler.send_file(task_id)


def handle_upload_file(handler: ConnectionHandler):
    """
    Handles the file upload request from the client.

    Args:
        handler (ConnectionHandler): The connection handler instance.
    """
    task_id = handler.data.get("task_id")
    if not task_id:
        handler.conclude_request(400, {}, "Task ID is required")
        return

    with Session() as session:
        task = session.get(FileTask, task_id)
        if not task:
            handler.conclude_request(404, {}, "Task not found")
            return

        if task.status != 0 or task.mode != 1:
            handler.conclude_request(400, {}, "Task is not in a valid state for upload")
            return

        if task.start_time > time.time() or (
            task.end_time and task.end_time < time.time()
        ):
            handler.conclude_request(
                400, {}, "Task is either not started yet or has already ended"
            )
            return

    ### 服务器需要发送一次响应
    handler.receive_file(task_id)


def handle_set_document_rules(handler: ConnectionHandler):
    """
    Handles the document access rules setting request from the client.
    """
    document_id = handler.data.get("document_id")
    access_rules_to_apply = handler.data.get("access_rules")

    if not handler.username:
        handler.conclude_request(
            **{"code": 403, "message": "Authentication is required", "data": {}}
        )
        return

    if not document_id or not access_rules_to_apply:
        handler.conclude_request(
            **{
                "code": 400,
                "message": "Document_id and access_rules are required",
                "data": {},
            }
        )
        return

    with Session() as session:
        user = session.get(User, handler.username)
        if not user or not user.is_token_valid(handler.token):
            handler.conclude_request(
                **{"code": 403, "message": "Invalid user or token", "data": {}}
            )
            return

        document = session.get(Document, document_id)

        if not document:
            handler.conclude_request(404, {}, "Document not found")
            return

        if not "set_access_rules" in user.all_permissions:
            handler.conclude_request(403, {}, "Access denied to set access rules")
            return

        if not document.check_access_requirements(user, access_type=3):
            handler.conclude_request(403, {}, "Access denied to the document")
            return

        if apply_document_access_rules(document.id, access_rules_to_apply, user):
            handler.conclude_request(200, {}, "Set access rules successfully")
        else:
            session.rollback()
            handler.conclude_request(
                403, {}, "Set access rules failed: permission denied"
            )


def handle_move_document(handler: ConnectionHandler):
    document_id = handler.data.get("document_id")
    target_folder_id = handler.data.get("target_folder_id")

    if not document_id:
        handler.conclude_request(
            **{
                "code": 400,
                "message": "Document_id is required",
                "data": {},
            }
        )
        return
    
    if not handler.username or not handler.token:
        handler.conclude_request(
            **{"code": 403, "message": smsg.MISSING_USERNAME_OR_TOKEN, "data": {}}
        )
        return

    with Session() as session:
        user = session.get(User, handler.username)
        if not user or not user.is_token_valid(handler.token):
            handler.conclude_request(
                **{"code": 403, "message": smsg.INVALID_USER_OR_TOKEN, "data": {}}
            )
            return

        if "move" not in user.all_permissions:
            handler.conclude_request(403, {}, smsg.ACCESS_DENIED_MOVE_DOCUMENT)
            return

        document = session.get(Document, document_id)
        if not document:
            handler.conclude_request(
                **{
                    "code": 404,
                    "message": smsg.TARGET_DOCUMENT_NOT_FOUND,
                    "data": {},
                }
            )
            return

        if not document.check_access_requirements(user, 2):
            handler.conclude_request(403, {}, smsg.ACCESS_DENIED_MOVE_DOCUMENT)
            return

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
                return

            if not target_folder.check_access_requirements(
                user, 1
            ):  # 对于目标文件夹，移动可视为一种写操作
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_WRITE_DIRECTORY)
                return

            document.folder = target_folder
        else:
            document.folder = None

        session.commit()

    handler.conclude_request(200, {}, smsg.SUCCESS)
