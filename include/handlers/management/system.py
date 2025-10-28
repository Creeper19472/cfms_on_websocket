import json
import time
from typing import Optional

from sqlalchemy import desc, update, func, true
from include.classes.connection import ConnectionHandler
from include.classes.request import RequestHandler
from include.database.handler import Session
from include.database.models.file import FileTask, File, BackupTask
from include.database.models.classic import User, AuditEntry
from include.shared import lockdown_enabled
import include.system.messages as smsg


class RequestLockdownHandler(RequestHandler):
    data_schema = {
        "type": "object",
        "properties": {"status": {"type": "boolean"}},
        "required": ["status"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        status_to_change: bool = handler.data["status"]

        if not handler.username or not handler.token:
            handler.conclude_request(
                **{"code": 401, "message": smsg.MISSING_USERNAME_OR_TOKEN, "data": {}}
            )
            return 401

        with Session() as session:
            user = session.get(User, handler.username)
            if not user or not user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 401, "message": smsg.INVALID_USER_OR_TOKEN, "data": {}}
                )
                return 401

            if "apply_lockdown" not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return 403, None, handler.username

            if status_to_change:
                lockdown_enabled.set()
            else:
                lockdown_enabled.clear()

            # 接下来将数据库 tasks 表中的所有 end_time >= 当前时间的条目的 end_time 修改为当前时间
            # 令所有任务失效
            now = time.time()
            stmt = update(FileTask).where(FileTask.end_time >= now).values(end_time=now)
            session.execute(stmt)
            session.commit()

        handler.conclude_request(200, {}, smsg.SUCCESS)
        handler.broadcast(
            json.dumps({"action": "lockdown", "status": lockdown_enabled.is_set()})
        )
        return 0, None, handler.username


class RequestViewAuditLogsHandler(RequestHandler):
    data_schema = {
        "type": "object",
        "properties": {
            "offset": {"type": "integer", "minimum": 0},
            "count": {"type": "integer", "minimum": 0, "maximum": 100},
            "filters": {"type": "array", "items": {"type": "string"}},
        },
        "required": [],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        offset: int = handler.data.get("offset", 0)
        entries_count: int = handler.data.get("count", 50)
        filtered_actions: list[str] = handler.data.get("filters", [])

        with Session() as session:
            user = session.get(User, handler.username)
            if not user or not user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 401, "message": smsg.INVALID_USER_OR_TOKEN, "data": {}}
                )
                return 401

            if "view_audit_logs" not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return 403, None, handler.username

            queried_entries = (
                session.query(AuditEntry)
                .order_by(desc(AuditEntry.logged_time))
                .filter(
                    AuditEntry.action.in_(filtered_actions)
                    if filtered_actions
                    else true()
                )
                .offset(offset)
                .limit(entries_count)
                .all()
            )
            total_count: int = (
                session.query(func.count(AuditEntry.id))
                .filter(
                    AuditEntry.action.in_(filtered_actions)
                    if filtered_actions
                    else true()
                )
                .scalar()
            )

            result = [
                {
                    "id": entry.id,
                    "action": entry.action,
                    "username": entry.username,
                    "target": entry.target,
                    "data": entry.data,
                    "result": entry.result,
                    "remote_address": entry.remote_address,
                    "logged_time": entry.logged_time,
                }
                for entry in queried_entries
            ]

        handler.conclude_request(
            200, {"total": total_count, "entries": result}, smsg.SUCCESS
        )
        return (
            0,
            None,
            {"offset": offset, "entries_count": entries_count},
            handler.username,
        )


class RequestGenerateBackupHandler(RequestHandler):
    """
    Handler for generating an encrypted backup of documents, folders, and files.

    This handler exports all documents, folders, document revisions, access rules,
    and their associated files into an encrypted archive. The encryption key is
    saved in a separate file.
    """

    data_schema = {
        "type": "object",
        "properties": {
            "backup_name": {"type": "string", "minLength": 1, "maxLength": 255},
        },
        "required": [],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        from include.util.backup import generate_backup

        backup_name = handler.data.get("backup_name", None)

        with Session() as session:
            user = session.get(User, handler.username)
            if not user or not user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 401, "message": smsg.INVALID_USER_OR_TOKEN, "data": {}}
                )
                return 401

            if "export_backup" not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return 403, None, handler.username

            try:
                # Generate backup in the content/backups directory
                backup_dir = "./content/backups"
                result = generate_backup(session, backup_dir, backup_name)

                handler.conclude_request(
                    200,
                    {
                        "archive_path": result["archive_path"],
                        "key_path": result["key_path"],
                        "metadata": result["metadata"],
                    },
                    smsg.SUCCESS,
                )
                return (
                    0,
                    None,
                    {"backup_name": backup_name or "auto"},
                    handler.username,
                )
            except Exception as e:
                handler.conclude_request(
                    500, {"error": str(e)}, "Failed to generate backup"
                )
                return 500, None, handler.username


class RequestInitiateBackupImportHandler(RequestHandler):
    """
    Handler for initiating backup import process.
    
    Creates file upload tasks for the backup archive and key file, then
    returns task IDs that the client can use to upload the files.
    """

    data_schema = {
        "type": "object",
        "properties": {
            "timeout_seconds": {"type": "integer", "minimum": 60, "maximum": 3600},
        },
        "required": [],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        from include.constants import FILE_TASK_DEFAULT_DURATION_SECONDS
        
        timeout_seconds = handler.data.get("timeout_seconds", FILE_TASK_DEFAULT_DURATION_SECONDS)

        with Session() as session:
            user = session.get(User, handler.username)
            if not user or not user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 401, "message": smsg.INVALID_USER_OR_TOKEN, "data": {}}
                )
                return 401

            if "import_backup" not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return 403, None, handler.username

            try:
                import secrets
                import os
                
                # Create temporary files for archive and key
                temp_dir = "./content/backups/import"
                os.makedirs(temp_dir, exist_ok=True)
                
                archive_id = secrets.token_hex(32)
                key_id = secrets.token_hex(32)
                
                archive_path = os.path.join(temp_dir, f"{archive_id}.cfms.enc")
                key_path = os.path.join(temp_dir, f"{key_id}.key")
                
                # Create File objects
                archive_file = File(id=archive_id, path=archive_path, active=False)
                key_file = File(id=key_id, path=key_path, active=False)
                session.add(archive_file)
                session.add(key_file)
                session.flush()
                
                # Create upload tasks
                now = time.time()
                archive_task = FileTask(
                    file_id=archive_file.id,
                    status=0,
                    mode=1,  # Upload mode
                    start_time=now,
                    end_time=now + timeout_seconds,
                )
                key_task = FileTask(
                    file_id=key_file.id,
                    status=0,
                    mode=1,  # Upload mode
                    start_time=now,
                    end_time=now + timeout_seconds,
                )
                session.add(archive_task)
                session.add(key_task)
                session.flush()
                
                # Create BackupTask to track the import
                backup_task = BackupTask(
                    username=handler.username,
                    operation="import",
                    status="pending",
                    current_step="Waiting for file uploads",
                    archive_file_id=archive_file.id,
                    key_file_id=key_file.id,
                    timeout_time=now + timeout_seconds,
                )
                session.add(backup_task)
                session.commit()

                handler.conclude_request(
                    200,
                    {
                        "backup_task_id": backup_task.id,
                        "archive_task_id": archive_task.id,
                        "key_task_id": key_task.id,
                        "timeout": timeout_seconds,
                    },
                    smsg.SUCCESS,
                )
                return (
                    0,
                    None,
                    {"backup_task_id": backup_task.id},
                    handler.username,
                )
            except Exception as e:
                session.rollback()
                handler.conclude_request(
                    500, {"error": str(e)}, "Failed to initiate backup import"
                )
                return 500, None, handler.username


class RequestStartBackupImportHandler(RequestHandler):
    """
    Handler for starting the backup import process after files are uploaded.
    
    This should be called after the archive and key files have been uploaded
    via the upload_file action.
    """

    data_schema = {
        "type": "object",
        "properties": {
            "backup_task_id": {"type": "string", "minLength": 1},
        },
        "required": ["backup_task_id"],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        import threading
        from include.util.backup import restore_backup
        
        backup_task_id = handler.data["backup_task_id"]

        with Session() as session:
            user = session.get(User, handler.username)
            if not user or not user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 401, "message": smsg.INVALID_USER_OR_TOKEN, "data": {}}
                )
                return 401

            if "import_backup" not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return 403, None, handler.username

            backup_task = session.get(BackupTask, backup_task_id)
            if not backup_task:
                handler.conclude_request(404, {}, "Backup task not found")
                return 404, None, handler.username

            if backup_task.username != handler.username:
                handler.conclude_request(403, {}, "Not your backup task")
                return 403, None, handler.username

            if backup_task.status != "pending":
                handler.conclude_request(
                    400, {}, f"Backup task already in {backup_task.status} state"
                )
                return 400, None, handler.username

            # Check if files have been uploaded
            archive_file = session.get(File, backup_task.archive_file_id)
            key_file = session.get(File, backup_task.key_file_id)
            
            if not archive_file or not key_file:
                handler.conclude_request(500, {}, "File references missing")
                return 500, None, handler.username

            # Check if files exist
            import os
            if not os.path.exists(archive_file.path):
                handler.conclude_request(400, {}, "Archive file not uploaded")
                return 400, None, handler.username

            if not os.path.exists(key_file.path):
                handler.conclude_request(400, {}, "Key file not uploaded")
                return 400, None, handler.username

            # Check timeout
            if backup_task.timeout_time and time.time() > backup_task.timeout_time:
                backup_task.status = "timeout"
                backup_task.completed_time = time.time()
                session.commit()
                handler.conclude_request(408, {}, "Backup import timed out")
                return 408, None, handler.username

            # Load key file
            try:
                import json
                with open(key_file.path, "r", encoding="utf-8") as f:
                    key_data = json.load(f)
            except Exception as e:
                backup_task.status = "failed"
                backup_task.error_message = f"Invalid key file: {str(e)}"
                backup_task.completed_time = time.time()
                session.commit()
                handler.conclude_request(400, {}, f"Invalid key file: {str(e)}")
                return 400, None, handler.username

            # Update status to processing
            backup_task.status = "processing"
            backup_task.started_time = time.time()
            backup_task.current_step = "Starting import"
            session.commit()

            # Return immediately and process in background
            handler.conclude_request(
                200,
                {
                    "backup_task_id": backup_task.id,
                    "status": "processing",
                    "message": "Import started. Use get_backup_import_status to check progress."
                },
                smsg.SUCCESS,
            )

            # Start import in background thread
            def background_import():
                import_session = Session()
                try:
                    task = import_session.get(BackupTask, backup_task_id)
                    
                    def progress_callback(progress):
                        """Update task progress in database."""
                        task.status = progress.status
                        task.current_step = progress.current_step
                        task.progress_percent = progress.progress_percent
                        task.documents_count = progress.documents_imported
                        task.folders_count = progress.folders_imported
                        task.files_count = progress.files_imported
                        if progress.error_message:
                            task.error_message = progress.error_message
                        if progress.completed_at:
                            task.completed_time = progress.completed_at
                        import_session.commit()

                    # Perform the restore
                    result = restore_backup(
                        import_session,
                        archive_file.path,
                        key_data,
                        progress_callback=progress_callback,
                    )

                    # Update final status
                    task.status = result["status"]
                    task.documents_count = result.get("documents_imported", 0)
                    task.folders_count = result.get("folders_imported", 0)
                    task.files_count = result.get("files_imported", 0)
                    if result["status"] == "failed":
                        task.error_message = result.get("error")
                    task.completed_time = time.time()
                    import_session.commit()

                    # Broadcast completion to connected clients
                    notification = json.dumps({
                        "action": "backup_import_completed",
                        "data": {
                            "backup_task_id": backup_task_id,
                            "status": result["status"],
                            "documents_imported": result.get("documents_imported", 0),
                            "folders_imported": result.get("folders_imported", 0),
                            "files_imported": result.get("files_imported", 0),
                            "error": result.get("error"),
                        }
                    })
                    handler.broadcast(notification)

                except Exception as e:
                    task.status = "failed"
                    task.error_message = str(e)
                    task.completed_time = time.time()
                    import_session.commit()
                finally:
                    import_session.close()

            thread = threading.Thread(target=background_import, daemon=True)
            thread.start()

            return (
                0,
                None,
                {"backup_task_id": backup_task_id},
                handler.username,
            )


class RequestGetBackupImportStatusHandler(RequestHandler):
    """
    Handler for checking the status of a backup import task.
    """

    data_schema = {
        "type": "object",
        "properties": {
            "backup_task_id": {"type": "string", "minLength": 1},
        },
        "required": ["backup_task_id"],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        backup_task_id = handler.data["backup_task_id"]

        with Session() as session:
            user = session.get(User, handler.username)
            if not user or not user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 401, "message": smsg.INVALID_USER_OR_TOKEN, "data": {}}
                )
                return 401

            backup_task = session.get(BackupTask, backup_task_id)
            if not backup_task:
                handler.conclude_request(404, {}, "Backup task not found")
                return 404, None, handler.username

            if backup_task.username != handler.username:
                # Allow users with import_backup permission to view any task
                if "import_backup" not in user.all_permissions:
                    handler.conclude_request(403, {}, "Access denied")
                    return 403, None, handler.username

            handler.conclude_request(
                200,
                {
                    "backup_task_id": backup_task.id,
                    "status": backup_task.status,
                    "current_step": backup_task.current_step,
                    "progress_percent": backup_task.progress_percent,
                    "documents_count": backup_task.documents_count,
                    "folders_count": backup_task.folders_count,
                    "files_count": backup_task.files_count,
                    "created_time": backup_task.created_time,
                    "started_time": backup_task.started_time,
                    "completed_time": backup_task.completed_time,
                    "error_message": backup_task.error_message,
                },
                smsg.SUCCESS,
            )
            return (
                0,
                None,
                {"backup_task_id": backup_task_id, "status": backup_task.status},
                handler.username,
            )
