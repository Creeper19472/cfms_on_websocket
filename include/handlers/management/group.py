from typing import Optional
from include.classes.connection import ConnectionHandler
from include.classes.request import RequestHandler
from include.database.handler import Session
from include.database.models.general import (
    User,
    UserGroup,
    UserGroupPermission,
    UserMembership,
)
from include.function.group import create_group


__all__ = [
    "RequestListGroupsHandler",
    # ...
]


class RequestListGroupsHandler(RequestHandler):
    data_schema = {"type": "object", "additionalProperties": False}

    def handle(self, handler: ConnectionHandler):

        try:
            with Session() as session:
                user = session.get(User, handler.username)  # 执行操作的用户

                if not user or not user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 403, "message": "Invalid user or token", "data": {}}
                    )
                    return

                if "list_groups" not in user.all_permissions:
                    handler.conclude_request(
                        **{
                            "code": 403,
                            "message": "You do not have permission to list groups",
                            "data": {},
                        }
                    )
                    return

                groups = session.query(UserGroup).all()
                response = {
                    "code": 200,
                    "message": "List of groups",
                    "data": {
                        "groups": [
                            {
                                "name": group.group_name,
                                "display_name": group.group_display_name,
                                "permissions": list(group.all_permissions),
                                "members": list(group.members),
                            }
                            for group in groups
                        ]
                    },
                }

                handler.conclude_request(**response)

        except Exception as e:
            handler.logger.error(
                f"Error detected when handling requests.", exc_info=True
            )
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestCreateGroupHandler(RequestHandler):
    data_schema = {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "minLength": 1},
            "display_name": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "permissions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "permission": {"type": "string"},
                        "start_time": {"type": "number"},
                        "end_time": {"type": "number"},
                    },
                    "required": ["permission", "start_time"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["group_name"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):

        try:
            with Session() as session:
                user = session.get(User, handler.username)

                if not user or not user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 403, "message": "Invalid user or token", "data": {}}
                    )
                    return

                # currently handle_create_group() will not judge whether the requesting
                # user is eligible to apply the given permissions for the new group.
                #
                # "create_group" is a dangerous privilege that should only be held by administrators.

                if "create_group" not in user.all_permissions:
                    handler.conclude_request(
                        **{
                            "code": 403,
                            "message": "You do not have permission to create groups",
                            "data": {},
                        }
                    )
                    return

                new_group_name: str = handler.data["group_name"]

                existing_group = session.get(UserGroup, new_group_name)
                if existing_group:
                    handler.conclude_request(
                        **{"code": 400, "message": "Group already exists", "data": {}}
                    )
                    return
                del existing_group

                new_display_name: Optional[str] = handler.data.get("display_name", None)
                new_group_permissions: list[dict] = handler.data.get("permissions", [])

                for right in new_group_permissions:
                    if (
                        not isinstance(right, dict)
                        or not right.get("permission")
                        or "start_time" not in right
                        or not isinstance(right["start_time"], float)
                        or (
                            right.get("end_time")
                            and not isinstance(right["end_time"], float)
                        )
                    ):
                        handler.conclude_request(
                            **{
                                "code": 400,
                                "message": "Invalid permissions format",
                                "data": {},
                            }
                        )
                        return

                create_group(
                    group_name=new_group_name,
                    display_name=new_display_name,
                    permissions=new_group_permissions,
                )

            response = {
                "code": 200,
                "message": "Group created successfully",
                "data": {},
            }

            handler.conclude_request(**response)

        except Exception as e:
            handler.logger.error(
                f"Error detected when handling requests.", exc_info=True
            )
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestDeleteGroupHandler(RequestHandler):
    data_schema = {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "minLength": 1},
        },
        "required": ["group_name"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):

        try:
            with Session() as session:
                this_user = session.get(User, handler.username)

                if not this_user or not this_user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 403, "message": "Invalid user or token", "data": {}}
                    )
                    return

                if "delete_group" not in this_user.all_permissions:
                    handler.conclude_request(
                        **{
                            "code": 403,
                            "message": "You do not have permission to delete groups",
                            "data": {},
                        }
                    )
                    return

                group_to_delete_name: str = handler.data["group_name"]
                group_to_delete = session.get(UserGroup, group_to_delete_name)

                if not group_to_delete:
                    handler.conclude_request(
                        **{"code": 404, "message": "Group does not exist", "data": {}}
                    )
                    return

                # Retrieve all memberships associated with the group
                memberships_to_delete = (
                    session.query(UserMembership)
                    .filter_by(group_name=group_to_delete_name)
                    .all()
                )
                for membership in memberships_to_delete:
                    session.delete(membership)

                # Retrieve all permissions associated with the group
                permissions_to_delete = (
                    session.query(UserGroupPermission)
                    .filter_by(group_name=group_to_delete_name)
                    .all()
                )
                for permission in permissions_to_delete:
                    session.delete(permission)

                session.delete(group_to_delete)
                session.commit()

            response = {
                "code": 200,
                "message": "Group deleted successfully",
                "data": {},
            }

            handler.conclude_request(**response)

        except Exception as e:
            handler.logger.error(
                f"Error detected when handling requests.", exc_info=True
            )
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestRenameGroupHandler(RequestHandler):
    data_schema = {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "minLength": 1},
            "display_name": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        },
        "required": ["group_name", "display_name"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):

        target_group_name: str = handler.data["group_name"]

        try:
            with Session() as session:
                this_user = session.get(User, handler.username)

                if not this_user or not this_user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 403, "message": "Invalid user or token", "data": {}}
                    )
                    return

                if "rename_group" not in this_user.all_permissions:
                    handler.conclude_request(
                        **{
                            "code": 403,
                            "message": "You do not have permission to rename groups",
                            "data": {},
                        }
                    )
                    return

                new_display_name: str | None = handler.data.get("display_name", None)
                if type(new_display_name) not in (str, None):
                    handler.conclude_request(
                        **{
                            "code": 400,
                            "message": "display_name must be null or a string",
                            "data": {},
                        }
                    )
                    return

                group_to_rename = session.get(UserGroup, target_group_name)
                if not group_to_rename:
                    handler.conclude_request(
                        **{"code": 400, "message": "Group does not exist", "data": {}}
                    )
                    return

                group_to_rename.group_display_name = new_display_name
                session.commit()

            response = {
                "code": 200,
                "message": "Group renamed successfully",
                "data": {},
            }

            handler.conclude_request(**response)

        except Exception as e:
            handler.logger.error(
                f"Error detected when handling requests.", exc_info=True
            )
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestGetGroupInfoHandler(RequestHandler):
    data_schema = {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "minLength": 1},
        },
        "required": ["group_name"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):

        try:
            with Session() as session:
                user = session.get(User, handler.username)  # 执行操作的用户

                if not user or not user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 403, "message": "Invalid user or token", "data": {}}
                    )
                    return

                if not handler.data["group_name"]:
                    handler.conclude_request(
                        **{"code": 400, "message": "Group name is required", "data": {}}
                    )
                    return

                if "get_group_info" not in user.all_permissions:
                    handler.conclude_request(
                        **{
                            "code": 403,
                            "message": "You do not have permission to view group info",
                            "data": {},
                        }
                    )
                    return

                group = session.get(UserGroup, handler.data["group_name"])
                if not group:
                    handler.conclude_request(
                        **{"code": 404, "message": "Group does not exist", "data": {}}
                    )
                    return

                response = {
                    "code": 200,
                    "message": "Group info retrieved successfully",
                    "data": {
                        "name": group.group_name,
                        "display_name": group.group_display_name,
                        "permissions": list(group.all_permissions),
                        "members": list(group.members),
                    },
                }

                handler.conclude_request(**response)

        except Exception as e:
            handler.logger.error(
                f"Error detected when handling requests.", exc_info=True
            )
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestChangeGroupPermissionsHandler(RequestHandler):
    data_schema = {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "minLength": 1},
            "permissions": {
                "type": "array",
                "items": {
                    "type": "string",
                    "additionalProperties": False,
                },
            },
        },
        "required": ["group_name", "permissions"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):

        try:
            with Session() as session:
                user = session.get(User, handler.username)

                if not user or not user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 403, "message": "Invalid user or token", "data": {}}
                    )
                    return

                if not handler.data["group_name"]:
                    handler.conclude_request(
                        **{"code": 400, "message": "Group name is required", "data": {}}
                    )
                    return

                if "set_group_permissions" not in user.all_permissions:
                    handler.conclude_request(
                        **{
                            "code": 403,
                            "message": "You do not have permission to set group permissions",
                            "data": {},
                        }
                    )
                    return

                group = session.get(UserGroup, handler.data["group_name"])
                if not group:
                    handler.conclude_request(
                        **{"code": 404, "message": "Group does not exist", "data": {}}
                    )
                    return

                new_permissions = handler.data.get("permissions", [])

                # Check if all elements in new_permissions are of type str
                if not all(
                    isinstance(permission, str) for permission in new_permissions
                ):
                    handler.conclude_request(
                        **{
                            "code": 400,
                            "message": "All permissions must be of type str",
                            "data": {},
                        }
                    )
                    return

                if (
                    set(new_permissions) != group.all_permissions
                ):  # 预判断，减少数据库开销
                    group.all_permissions = new_permissions
                    session.commit()

            response = {
                "code": 200,
                "message": "Group permissions set successfully",
                "data": {},
            }

            handler.conclude_request(**response)

        except Exception as e:
            handler.logger.error(
                f"Error detected when handling requests.", exc_info=True
            )
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})
