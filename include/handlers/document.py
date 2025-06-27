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
    NoActiveRevisionsError
)
import time

__all__ = ["handle_create_document", "handle_get_document", "handle_download_file", "handle_upload_file", "handle_upload_document"]


# def create_file_task(file_id: str, transfer_mode=0):
def create_file_task(file: File, transfer_mode=0):
    """
    Creates a new file processing task for the specified file.
    Args:
        file_id (str): The unique identifier of the file for which the task is to be generated.
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
            handler.conclude_request(404, {}, "No active revisions found for this document")
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

    if not access_rules_to_apply: # fix
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
            
        if not "create_document" in user.all_permissions:
            handler.conclude_request(403, {}, "Permission denied")
            return

        today = datetime.date.today()
        new_real_filename = secrets.token_hex(32)

        new_file = File(
            path=f"./content/files/{today.year}/{today.month}/{new_real_filename}",
            id = secrets.token_hex(32),
        )
        new_document = Document(
            id=secrets.token_hex(32), title=document_title, folder_id=folder_id if folder_id else None
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

        if "delete_document" not in user.all_permissions or not document.check_access_requirements(user, access_type=1):
            handler.conclude_request(403, {}, "Access denied to the document")
            return

        document.delete_all_revisions()
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
            if "rename_document" not in this_user.all_permissions or not document.check_access_requirements(this_user, 1):
                handler.conclude_request(
                    **{"code": 403, "message": "Access denied", "data": {}}
                )
                return
            
            if document.title == new_title:
                handler.conclude_request(
                    **{"code": 400, "message": "New name is the same as the current name", "data": {}}
                )
                return
            else:
                document.title = new_title
            
            session.commit()
            
            handler.conclude_request(**{"code": 200, "message": "Document renamed successfully", "data": {}})
            
    except Exception as e:
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
        
        if task.start_time > time.time() or (task.end_time and task.end_time < time.time()):
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
        
        if task.start_time > time.time() or (task.end_time and task.end_time < time.time()):
            handler.conclude_request(
            400, {}, "Task is either not started yet or has already ended"
            )
            return

    ### 服务器需要发送一次响应
    handler.receive_file(task_id)
