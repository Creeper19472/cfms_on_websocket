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

            active_documents = [
                document
                for document in documents
                if document.active
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
                            "last_modified": document.get_latest_revision().created_time,
                        }
                        for document in active_documents
                    ],
                    "folders": [
                        {
                            "id": child.id,
                            "name": child.name,
                            "last_modified": child.last_modified,
                        }
                        for child in children
                    ],
                },
            }

        # Send the response back to the client
        handler.conclude_request(**response)
    except Exception as e:
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
                        "last_modified": folder.last_modified,
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
        handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})
