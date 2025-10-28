# Backup Import/Restore Feature

## Overview

This document describes the backup import and restoration functionality that allows administrators to restore backups on any CFMS server instance.

## Import Process

The import process is divided into three main steps to handle large file transfers efficiently:

### Step 1: Initiate Import

**Action:** `initiate_backup_import`

**Permission Required:** `import_backup`

Creates file upload tasks for the backup archive and key file, returning task IDs that the client uses to upload the files.

**Request:**
```json
{
  "action": "initiate_backup_import",
  "data": {
    "timeout_seconds": 1800  // Optional, default: 3600
  },
  "username": "admin",
  "token": "<auth_token>"
}
```

**Response:**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "backup_task_id": "abc123...",
    "archive_task_id": "def456...",
    "key_task_id": "ghi789...",
    "timeout": 1800
  }
}
```

### Step 2: Upload Files

Use the existing `upload_file` action with the task IDs from step 1.

**Upload Archive:**
```json
{
  "action": "upload_file",
  "data": {
    "task_id": "<archive_task_id>"
  },
  "username": "admin",
  "token": "<auth_token>"
}
```

Then send the encrypted `.cfms.enc` file using the standard file transfer protocol.

**Upload Key:**
```json
{
  "action": "upload_file",
  "data": {
    "task_id": "<key_task_id>"
  },
  "username": "admin",
  "token": "<auth_token>"
}
```

Then send the `.key` JSON file.

**Note:** The file upload process uses the existing AES-encrypted chunked transfer mechanism. See file transfer documentation for details.

### Step 3: Start Import

**Action:** `start_backup_import`

After both files are uploaded successfully, start the actual import process.

**Request:**
```json
{
  "action": "start_backup_import",
  "data": {
    "backup_task_id": "<backup_task_id>"
  },
  "username": "admin",
  "token": "<auth_token>"
}
```

**Response:**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "backup_task_id": "abc123...",
    "status": "processing",
    "message": "Import started. Use get_backup_import_status to check progress."
  }
}
```

**Important:** This request returns immediately. The import process runs in the background.

## Progress Tracking

### Polling for Status

**Action:** `get_backup_import_status`

Query the current status of an import operation at any time.

**Request:**
```json
{
  "action": "get_backup_import_status",
  "data": {
    "backup_task_id": "<backup_task_id>"
  },
  "username": "admin",
  "token": "<auth_token>"
}
```

**Response:**
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "backup_task_id": "abc123...",
    "status": "processing",
    "current_step": "Importing documents",
    "progress_percent": 75,
    "documents_count": 120,
    "folders_count": 15,
    "files_count": 180,
    "created_time": 1234567890.123,
    "started_time": 1234567895.456,
    "completed_time": null,
    "error_message": null
  }
}
```

### Status Values

- **`pending`**: Waiting for files to be uploaded
- **`uploading`**: Files are being uploaded (not used currently, reserved for future)
- **`processing`**: Import is in progress
- **`completed`**: Successfully completed
- **`failed`**: Failed with error (see `error_message`)
- **`timeout`**: Timed out waiting for file uploads

### Current Step Examples

During processing, `current_step` provides detailed progress information:
- "Decrypting archive"
- "Extracting archive"
- "Loading metadata"
- "Importing files"
- "Importing folders"
- "Importing documents"
- "Finalizing import"
- "Restore completed"

## Completion Notification

### Broadcast Event

When import completes (successfully or with failure), the server broadcasts a notification to all connected clients:

**Event:** `backup_import_completed`

```json
{
  "action": "backup_import_completed",
  "data": {
    "backup_task_id": "abc123...",
    "status": "completed",
    "documents_imported": 150,
    "folders_imported": 25,
    "files_imported": 200,
    "error": null
  }
}
```

This allows clients to:
1. **Active monitoring**: Poll `get_backup_import_status` periodically
2. **Passive monitoring**: Listen for the broadcast event

## Complete Client Flow Example

```python
import json
import ssl
import time
from websockets.sync.client import connect

ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

with connect("wss://localhost:5104", ssl=ssl_context) as websocket:
    # Step 1: Login
    websocket.send(json.dumps({
        "action": "login",
        "data": {"username": "admin", "password": "..."}
    }))
    response = json.loads(websocket.recv())
    token = response["data"]["token"]
    
    # Step 2: Initiate import
    websocket.send(json.dumps({
        "action": "initiate_backup_import",
        "data": {"timeout_seconds": 1800},
        "username": "admin",
        "token": token
    }))
    response = json.loads(websocket.recv())
    backup_task_id = response["data"]["backup_task_id"]
    archive_task_id = response["data"]["archive_task_id"]
    key_task_id = response["data"]["key_task_id"]
    
    # Step 3: Upload archive file
    websocket.send(json.dumps({
        "action": "upload_file",
        "data": {"task_id": archive_task_id},
        "username": "admin",
        "token": token
    }))
    # ... send encrypted file chunks ...
    
    # Step 4: Upload key file
    websocket.send(json.dumps({
        "action": "upload_file",
        "data": {"task_id": key_task_id},
        "username": "admin",
        "token": token
    }))
    # ... send key file ...
    
    # Step 5: Start import
    websocket.send(json.dumps({
        "action": "start_backup_import",
        "data": {"backup_task_id": backup_task_id},
        "username": "admin",
        "token": token
    }))
    response = json.loads(websocket.recv())
    
    # Step 6: Poll for progress
    while True:
        websocket.send(json.dumps({
            "action": "get_backup_import_status",
            "data": {"backup_task_id": backup_task_id},
            "username": "admin",
            "token": token
        }))
        response = json.loads(websocket.recv())
        status = response["data"]["status"]
        progress = response["data"]["progress_percent"]
        
        print(f"Status: {status}, Progress: {progress}%")
        
        if status in ["completed", "failed", "timeout"]:
            break
        
        time.sleep(2)  # Poll every 2 seconds
    
    # Or wait for broadcast notification instead of polling
```

## Restore Process Details

The `restore_backup()` function performs the following operations:

1. **Decryption** (10%): Decrypts the archive using AES-256-CBC
2. **Extraction** (30%): Extracts the TAR archive
3. **Metadata Loading** (40%): Loads and validates backup metadata
4. **File Import** (50%): Copies files and creates File objects
5. **Folder Import** (60%): Imports folders respecting parent-child hierarchy
6. **Document Import** (80%): Imports documents with revisions and access rules
7. **Finalization** (95%): Commits database transaction
8. **Completion** (100%): Updates final status

### Data Integrity

The restore process ensures:
- ✅ All file contents are preserved
- ✅ Document-folder relationships are maintained
- ✅ Document revision history is restored
- ✅ Access rules are reapplied
- ✅ Parent-child folder hierarchy is preserved
- ✅ File metadata (SHA256, timestamps) is preserved

### Error Handling

If any error occurs during import:
- Database transaction is rolled back
- Status is set to "failed"
- Error message is stored in `error_message`
- No partial data remains in the database

## Timeouts

File uploads have a configurable timeout (default: 3600 seconds).

If files are not uploaded within the timeout period:
- The BackupTask status becomes "timeout"
- The import cannot proceed
- Client must initiate a new import

## Permissions

Two separate permissions control backup operations:

### `export_backup`
- Required for: `generate_backup`
- Allows: Creating encrypted backup archives

### `import_backup`
- Required for: `initiate_backup_import`, `start_backup_import`, `get_backup_import_status`
- Allows: Importing and restoring backups

**Recommendation:** Grant these permissions only to trusted administrators.

## Database Model

### BackupTask Table

Tracks backup import operations:

| Field | Type | Description |
|-------|------|-------------|
| id | string | Task ID |
| username | string | User who initiated |
| operation | string | "export" or "import" |
| status | string | pending, processing, completed, failed, timeout |
| current_step | string | Current operation description |
| progress_percent | int | 0-100 |
| archive_file_id | string | Reference to archive File |
| key_file_id | string | Reference to key File |
| documents_count | int | Documents imported |
| folders_count | int | Folders imported |
| files_count | int | Files imported |
| created_time | float | Task creation timestamp |
| started_time | float | Import start timestamp |
| completed_time | float | Completion timestamp |
| timeout_time | float | Timeout deadline |
| error_message | string | Error details if failed |

## File Storage

Imported backup files are stored in:
- Archive: `./content/backups/import/<archive_id>.cfms.enc`
- Key: `./content/backups/import/<key_id>.key`
- Restored files: `./content/restore/files/<file_id>`

## Security Considerations

1. **Authentication Required**: All operations require valid auth token
2. **Permission Checks**: Enforced at every step
3. **File Validation**: Key file format validated before import
4. **Encryption**: Archives remain encrypted until import
5. **Timeout Protection**: Prevents resource exhaustion from abandoned uploads
6. **Transaction Safety**: Rollback on any error prevents partial imports

## Limitations

- Import runs in a background thread (one at a time per task)
- Large backups may take significant time to import
- No incremental import (all-or-nothing)
- No conflict resolution for duplicate IDs (import fails if IDs exist)

## Testing

See `test_restore.py` for a complete test of the backup/restore cycle:

```bash
python3 test_restore.py
```

Expected output:
```
Setting up test database...
Test database setup complete.

Testing backup and restore cycle...

1. Generating backup...
   ✓ Backup created: ./content/backups/restore_test.cfms.enc
   ✓ Key file: ./content/backups/restore_test.key

2. Clearing database...
   ✓ Database cleared: 0 docs, 0 folders, 0 files

3. Restoring backup...
   Progress: 10% - Decrypting archive
   ...
   Progress: 100% - Restore completed

4. Verifying restored data...
   ✓ All verification checks passed!

============================================================
SUCCESS: Backup/restore cycle completed successfully!
============================================================
```

## Troubleshooting

### Import stuck at "pending"
- Check that both archive and key files were uploaded successfully
- Verify upload tasks completed (status = 1)
- Check for timeout expiration

### Import fails immediately
- Verify key file is valid JSON with correct structure
- Check that archive file is the correct encrypted format
- Ensure sufficient disk space for extraction

### Import fails during processing
- Check `error_message` in task status for details
- Common causes:
  - Incompatible backup version
  - Corrupted archive
  - Database constraint violations (duplicate IDs)
  - Insufficient disk space

### Progress stuck at one step
- Import process may be working on large files
- Check server logs for details
- Poll status more frequently for updates

## Future Enhancements

Potential improvements for the import system:

1. **Conflict Resolution**: Handle duplicate IDs during import
2. **Incremental Import**: Import only new/changed data
3. **Selective Import**: Choose which documents/folders to import
4. **Import Validation**: Pre-import checks without committing
5. **Multiple Simultaneous Imports**: Support parallel import tasks
6. **Import Cancellation**: Cancel in-progress imports
7. **Bandwidth Throttling**: Control file upload speed
8. **Compression**: Compress before encryption for smaller archives
