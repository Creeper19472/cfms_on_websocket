from include.classes.connection import ConnectionHandler
from include.classes.request import RequestHandler
from include.database.handler import Session
from include.database.models.classic import (
    User,
)

__all__ = ["RequestGrantAccessHandler"]


class RequestGrantAccessHandler(RequestHandler):

    data_schema = {
        "type": "object",
        "properties": {
            "username": {"type": "string"},
            "access_types": {"type": "array", "items": {"type": "string"}},
            "start_time": {
                "type": "number",
                "minimum": 0,
            },
            "end_time": {"type": "number", "minimum": 0},
        },
        "required": ["username", "access_types", "start_time"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):

        with Session() as session:
            username = handler.data["username"]
            operator = session.get(User, handler.username)

            if not operator or not operator.is_token_valid(handler.token):
                handler.conclude_request(403, {}, "Invalid user or token")
                return

            if "manage_access" not in operator.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to manage user access",
                    data={},
                )
                return 403, handler.username

            user = session.get(User, username)
            if not user:
                handler.conclude_request(404, {}, "user not found")
                return 404, username, handler.username

            # ...TBD