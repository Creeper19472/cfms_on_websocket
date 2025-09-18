from include.classes.connection import ConnectionHandler
from include.classes.request import RequestHandler
from include.database.handler import Session
from include.database.models.classic import (
    Document,
    Folder,
    ObjectAccessEntry,
    User,
    UserGroup,
)

__all__ = ["RequestGrantAccessHandler"]


class RequestGrantAccessHandler(RequestHandler):

    data_schema = {
        "type": "object",
        "properties": {
            "entity_type": {
                "type": "string",
                "minLength": 1,
                "pattern": "^(user|group)$",
            },
            "entity_identifier": {"type": "string", "minLength": 1},
            "target_type": {
                "type": "string",
                "minLength": 1,
                "pattern": "^(document|directory)$",
            },
            "target_identifier": {"type": "string", "minLength": 1},
            "access_types": {"type": "array", "items": {"type": "string"}},
            "start_time": {
                "type": "number",
                "minimum": 0,
            },
            "end_time": {"type": "number", "minimum": 0},
        },
        "required": [
            "entity_type",
            "entity_identifier",
            "target_type",
            "target_identifier",
            "access_types",
            "start_time",
        ],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):

        ENTITY_TYPE_MAPPING = {"user": User, "group": UserGroup}
        TARGET_TYPE_MAPPING = {"document": Document, "directory": Folder}

        with Session() as session:

            entity_type: str = handler.data["entity_type"]
            entity_identifier: str = handler.data["entity_identifier"]

            target_type: str = handler.data["target_type"]
            target_identifier: str = handler.data["target_identifier"]

            access_types: list[str] = handler.data["access_types"]
            start_time: float = handler.data["start_time"]
            end_time: float | None = handler.data.get("end_time")

            if end_time and not start_time <= end_time:
                handler.conclude_request(
                    400, {}, "The start time should be before the end time"
                )
                return 400, None, handler.data, handler.username

            operator = session.get(User, handler.username)

            if not operator or not operator.is_token_valid(handler.token):
                handler.conclude_request(403, {}, "Invalid user or token")
                return

            if "manage_access" not in operator.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to manage object access",
                    data={},
                )
                return 403, handler.username

            entity: User | UserGroup | None = session.get(
                ENTITY_TYPE_MAPPING[entity_type], entity_identifier
            )
            if not entity:
                handler.conclude_request(404, {}, "entity not found")
                return (
                    404,
                    None,
                    handler.data,
                    handler.username,
                )

            target: Document | Folder | None = session.get(
                TARGET_TYPE_MAPPING[target_type], target_identifier
            )
            if not target:
                handler.conclude_request(404, {}, "target not found")
                return (
                    404,
                    None,
                    handler.data,
                    handler.username,
                )

            for access_type in access_types:

                if not target.check_access_requirements(operator, access_type):
                    handler.conclude_request(403, {}, "access denied")
                    return (
                        403,
                        None,
                        handler.data,
                        handler.username,
                    )

                new = ObjectAccessEntry(
                    entity_type=entity_type,
                    entity_identifier=entity_identifier,
                    target_type=target_type,
                    target_identifier=target_identifier,
                    access_type=access_type,
                    start_time=start_time,
                    end_time=end_time,
                )
                session.add(new)

            session.commit()

        handler.conclude_request(200, {}, "success")
        return 200, None, handler.data, handler.username


class RequestViewAccessEntriesHandler(RequestHandler):

    data_schema = {
        "type": "object",
        "properties": {
            "entity_type": {
                "type": "string",
                "minLength": 1,
                "pattern": "^(user|group)$",
            },
            "entity_identifier": {"type": "string", "minLength": 1},
        },
        "required": [
            "entity_type",
            "entity_identifier",
        ],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        pass