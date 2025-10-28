# Backup Generation Feature

## Overview

This implementation adds a backup generation function to CFMS that exports database entries and files into an encrypted archive for disaster recovery and server migration purposes.

## Features

### 1. Backup Utility Module (`include/util/backup.py`)

The `generate_backup()` function exports:
- **Documents**: All document entries with their metadata and access rules
- **Folders**: Directory structure with access rules
- **Document Revisions**: Version history of documents
- **Files**: Actual file content referenced by document revisions
- **Access Rules**: Both document and folder access rules

### 2. Encryption

- **Algorithm**: AES-256-CBC encryption
- **Key Generation**: 256-bit random encryption key
- **Key Storage**: Separate `.key` file in JSON format containing:
  - Encryption key (hex-encoded)
  - Algorithm name
  - Backup creation timestamp
  - Backup name

### 3. Archive Format

- **Format**: Encrypted TAR archive (`.cfms.enc`)
- **Structure**:
  ```
  backup_name.cfms.enc
  ├── metadata.json          # Backup metadata (version, counts, timestamp)
  ├── documents.json         # All documents with revisions and access rules
  ├── folders.json           # All folders with access rules  
  ├── files.json             # File metadata (id, path, sha256, timestamps)
  └── files/                 # Directory containing actual files
      ├── <file_id_1>
      ├── <file_id_2>
      └── ...
  ```

### 4. WebSocket API Request Handler

**Action**: `generate_backup`

**Permission Required**: `manage_system`

**Request Format**:
```json
{
  "action": "generate_backup",
  "data": {
    "backup_name": "optional_custom_name"  // Optional
  },
  "username": "admin",
  "token": "<auth_token>"
}
```

**Response Format** (Success):
```json
{
  "code": 200,
  "message": "success",
  "data": {
    "archive_path": "./content/backups/backup_name.cfms.enc",
    "key_path": "./content/backups/backup_name.key",
    "metadata": {
      "version": "1.0",
      "created_at": 1234567890.123,
      "documents_count": 10,
      "folders_count": 5,
      "files_count": 8
    }
  }
}
```

**Response Format** (Error):
```json
{
  "code": 500,
  "message": "Failed to generate backup",
  "data": {
    "error": "<error_message>"
  }
}
```

## File Locations

- **Backup Archives**: `./content/backups/`
- **Handler Implementation**: `include/handlers/management/system.py`
- **Utility Module**: `include/util/backup.py`
- **Handler Registration**: `include/connection_handler.py`

## Security Considerations

1. **Authentication Required**: Only authenticated users with `manage_system` permission can generate backups
2. **Encryption**: All backup archives are encrypted with AES-256-CBC
3. **Key Storage**: Encryption keys are stored separately from archives
4. **Sensitive Data**: Backups contain all documents, access rules, and files - treat as highly sensitive

## Usage Example

### Via WebSocket Client

```python
import json
import ssl
from websockets.sync.client import connect

ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

with connect("wss://localhost:5104", ssl=ssl_context) as websocket:
    # Login first
    login_request = {
        "action": "login",
        "data": {
            "username": "admin",
            "password": "your_password"
        }
    }
    websocket.send(json.dumps(login_request))
    login_response = json.loads(websocket.recv())
    token = login_response["data"]["token"]
    
    # Generate backup
    backup_request = {
        "action": "generate_backup",
        "data": {
            "backup_name": "my_backup"
        },
        "username": "admin",
        "token": token
    }
    websocket.send(json.dumps(backup_request))
    backup_response = json.loads(websocket.recv())
    
    print(f"Backup created at: {backup_response['data']['archive_path']}")
```

### Programmatic Usage

```python
from include.database.handler import Session
from include.util.backup import generate_backup

with Session() as session:
    result = generate_backup(
        session=session,
        output_dir="./content/backups",
        backup_name="manual_backup"
    )
    
    print(f"Archive: {result['archive_path']}")
    print(f"Key: {result['key_path']}")
    print(f"Metadata: {result['metadata']}")
```

## Testing

### Standalone Test

Run the standalone test that verifies backup generation:

```bash
python3 test_backup.py
```

This test:
1. Creates a test database with sample documents and folders
2. Generates a backup
3. Verifies the backup archive and key file are created
4. Validates the backup contains expected metadata

### Expected Output

```
Setting up test database...
Test database setup complete.

Testing backup generation...

Backup generated successfully!
Archive path: ./content/backups/test_backup.cfms.enc
Key path: ./content/backups/test_backup.key
Metadata: {
  "version": "1.0",
  "created_at": 1234567890.123,
  "documents_count": 2,
  "folders_count": 1,
  "files_count": 2
}

Archive size: 20,512 bytes

✓ All backup tests passed!

==================================================
SUCCESS: Backup generation functionality works!
==================================================
```

## Future Enhancements

The backup format is designed to support future restoration functionality:

1. **Automatic Restoration**: Import backup archives on another server
2. **Incremental Backups**: Only backup changed files since last backup
3. **Backup Scheduling**: Automated periodic backups
4. **Compression**: Add compression before encryption
5. **Remote Storage**: Support for S3/cloud storage destinations
6. **Backup Verification**: Validate backup integrity before completing

## Implementation Details

### Dependencies

- **cryptography**: AES encryption (already in requirements.txt)
- **tarfile**: Archive creation (Python standard library)
- **json**: Metadata serialization (Python standard library)
- **secrets**: Secure random key generation (Python standard library)

### Error Handling

The backup function handles various error conditions:
- Missing or inaccessible files (logs warning, continues backup)
- Database session errors (raises exception)
- File I/O errors (raises exception)
- Permission errors (raises exception)

### Performance Considerations

- Files are read and written in 64KB chunks to minimize memory usage
- Large file support through streaming encryption
- Database queries use SQLAlchemy ORM for optimal performance
