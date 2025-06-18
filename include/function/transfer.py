from include.database.handler import Session
from include.database.models import User, Document, File, FileTask


def get_file_id_by_task_id(task_id: str):
    with Session() as session:
        # Query the FileTask table to get the file_id associated with the task_id
        file_task = session.get(FileTask, task_id)
        if not file_task:
            return None
        # Return the file_id from the found FileTask
        file_id = file_task.file_id
    return file_id

def get_file_path_by_file_id(file_id):
    with Session() as session:
        # Query the File table to get the file path associated with the file_id
        file = session.get(File, file_id)
        if not file:
            return None
        # Return the file path from the found File
        return file.path