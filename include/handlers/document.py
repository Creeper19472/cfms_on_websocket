from include.classes.connection import ConnectionHandler
from include.database.handler import Session
from include.database.models import User, Document, File, FileTask
import time


def generate_file_task(file_id: str):
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
        file = session.get(File, file_id)
        if not file:
            return None

        now = time.time()
        task = FileTask(
            file_id=file.id, status=0, mode=0, start_time=now, end_time=now + 3600
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
        
        latest_revision = document.get_latest_revision()
        if not latest_revision:
            handler.conclude_request(404, {}, "No revisions found for this document")
            return

        data = {
            "document_id": document.id,
            "title": document.title,
            "task_data": generate_file_task(latest_revision.file_id),
        }

        handler.conclude_request(200, data, "Document retrieved successfully")


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
        
    handler.receive_file(document_id)

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

        if task.status != 0:
            handler.conclude_request(400, {}, "Task is not in a valid state for download")
            return

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

        if task.status != 1:
            handler.conclude_request(400, {}, "Task is not in a valid state for upload")
            return
        
    handler.receive_file(task_id)