from include.classes.connection import ConnectionHandler
from include.database.handler import Session
from include.database.models import User, Folder, Document, FolderAccessRule


def handle_list_users(handler: ConnectionHandler):
    try:
        with Session() as session:
            this_user = session.get(User, handler.username)

            if not this_user or not this_user.is_token_valid(handler.token):
                handler.conclude_request(
                    **{"code": 403, "message": "Invalid user or token", "data": {}}
                )
                return

            if "manage_system" not in this_user.all_permissions:
                handler.conclude_request(**{"code": 403, "message": "You do not have permission to list users", "data": {}})
                return
            
            users = session.query(User).all()
            response = {
                "code": 200,
                "message": "List of users",
                "data": [
                    {
                        "username": user.username,
                        "created_time": user.created_time,
                        "last_login": user.last_login,
                        "permissions": list(user.all_permissions),
                        "groups": list(user.all_groups),
                    }
                    for user in users
                ],
            }
            
            handler.conclude_request(**response)

    except Exception as e:
        handler.logger.error(f"Error detected when handling requests.", exc_info=True)
        handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})