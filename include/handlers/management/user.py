from include.classes.connection import ConnectionHandler
from include.classes.request import RequestHandler
from include.database.handler import Session
from include.database.models.general import User, UserGroup
from include.function.user import create_user


class RequestListUsersHandler(RequestHandler):

    data_schema = {"type": "object"}

    def handle(self, handler: ConnectionHandler):

        try:
            with Session() as session:
                this_user = session.get(User, handler.username)

                if not this_user or not this_user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 403, "message": "Invalid user or token", "data": {}}
                    )
                    return

                if "list_users" not in this_user.all_permissions:
                    handler.conclude_request(
                        **{
                            "code": 403,
                            "message": "You do not have permission to list users",
                            "data": {},
                        }
                    )
                    return

                users = session.query(User).all()
                response = {
                    "code": 200,
                    "message": "List of users",
                    "data": {
                        "users": [
                            {
                                "username": user.username,
                                "nickname": user.nickname,
                                "created_time": user.created_time,
                                "last_login": user.last_login,
                                "permissions": list(user.all_permissions),
                                "groups": list(user.all_groups),
                            }
                            for user in users
                        ]
                    },
                }

                handler.conclude_request(**response)

        except Exception as e:
            handler.logger.error(
                f"Error detected when handling requests.", exc_info=True
            )
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestCreateUserHandler(RequestHandler):

    data_schema = {
        "type": "object",
        "properties": {
            "username": {"type": "string", "minLength": 1},
            "password": {"type": "string"},
            "nickname": {"type": "string"},
            "permissions": {"type": "array", "items": {"type": "object"}},
            "groups": {"type": "array", "items": {"type": "object"}},
        },
        "required": ["username", "password"],
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

                # currently handle_create_user() will not judge whether the requesting
                # user is eligible to apply the given permissions for the new user.
                #
                # "create_user" is a dangerous privilege that should only be held by administrators.

                if "create_user" not in this_user.all_permissions:
                    handler.conclude_request(
                        **{
                            "code": 403,
                            "message": "You do not have permission to create users",
                            "data": {},
                        }
                    )
                    return

                new_username = handler.data.get("username")
                new_password = handler.data.get("password")

                if not new_username or not new_password:
                    handler.conclude_request(
                        **{
                            "code": 400,
                            "message": "Username and password are required",
                            "data": {},
                        }
                    )
                    return

                existing_user = session.get(User, new_username)
                if existing_user:
                    handler.conclude_request(
                        **{
                            "code": 400,
                            "message": "Username already exists",
                            "data": {},
                        }
                    )
                    return
                del existing_user

                new_nickname = handler.data.get("nickname", None)
                new_user_rights: list[dict] = handler.data.get("permissions", [])
                new_user_groups: list[dict] = handler.data.get("groups", [])

                for right in new_user_rights:
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

                for group in new_user_groups:
                    if (
                        not isinstance(group, dict)
                        or not group.get("group_name")
                        or "start_time" not in group
                        or not isinstance(group["start_time"], float)
                        or (
                            group.get("end_time")
                            and not isinstance(group["end_time"], float)
                        )
                    ):
                        handler.conclude_request(
                            **{
                                "code": 400,
                                "message": "Invalid groups format",
                                "data": {},
                            }
                        )
                        return

                    existing_group = session.get(UserGroup, group["group_name"])
                    if not existing_group:
                        handler.conclude_request(
                            **{
                                "code": 400,
                                "message": f"Group '{group['group_name']}' does not exist",
                                "data": {},
                            }
                        )
                        return

                create_user(
                    username=new_username,
                    password=new_password,
                    nickname=new_nickname,
                    permissions=new_user_rights,
                    groups=new_user_groups,
                )

            response = {
                "code": 200,
                "message": "User created successfully",
                "data": {},
            }

            handler.conclude_request(**response)

        except Exception as e:
            handler.logger.error(
                f"Error detected when handling requests.", exc_info=True
            )
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestDeleteUserHandler(RequestHandler):
    data_schema = {}

    def handle(self, handler: ConnectionHandler):
        try:
            with Session() as session:
                this_user = session.get(User, handler.username)

                if not this_user or not this_user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 403, "message": "Invalid user or token", "data": {}}
                    )
                    return

                if "delete_user" not in this_user.all_permissions:
                    handler.conclude_request(
                        **{
                            "code": 403,
                            "message": "You do not have permission to delete users",
                            "data": {},
                        }
                    )
                    return

                user_to_delete_username = handler.data["username"]
                if not user_to_delete_username:
                    handler.conclude_request(
                        **{"code": 400, "message": "Username is required", "data": {}}
                    )
                    return

                user_to_delete = session.get(User, user_to_delete_username)
                if not user_to_delete:
                    handler.conclude_request(
                        **{"code": 404, "message": "User does not exist", "data": {}}
                    )
                    return

                if user_to_delete.username == this_user.username:
                    handler.conclude_request(
                        **{"code": 400, "message": "Cannot delete yourself", "data": {}}
                    )
                    return

                # if "create_user" not in this_user.all_permissions:
                #     users_with_create_permission = session.query(User).filter(
                #         User.all_permissions.contains("create_user")
                #     ).all()

                #     if len(users_with_create_permission) <= 1:
                #         handler.conclude_request(
                #             **{
                #                 "code": 400,
                #                 "message": "There must be at least one user with 'create_user' permission",
                #                 "data": {},
                #             }
                #         )
                #         return

                for membership in user_to_delete.groups:
                    session.delete(membership)

                session.delete(user_to_delete)
                session.commit()

            response = {
                "code": 200,
                "message": "User deleted successfully",
                "data": {},
            }

            handler.conclude_request(**response)

        except Exception as e:
            handler.logger.error(f"Error detected when handling requests.", exc_info=True)
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestRenameUserHandler(RequestHandler):
    data_schema = {}

    def handle(self, handler: ConnectionHandler):

        target_username = handler.data["username"]
        if not target_username:
            handler.conclude_request(
                **{"code": 400, "message": "Target username is required", "data": {}}
            )
            return

        try:
            with Session() as session:
                this_user = session.get(User, handler.username)

                if not this_user or not this_user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 403, "message": "Invalid user or token", "data": {}}
                    )
                    return

                if (
                    "rename_user" not in this_user.all_permissions
                    and target_username != this_user.username
                ):
                    handler.conclude_request(
                        **{
                            "code": 403,
                            "message": "You do not have permission to rename users",
                            "data": {},
                        }
                    )
                    return

                new_nickname = handler.data.get("nickname", None)

                user_to_rename = session.get(User, target_username)
                if not user_to_rename:
                    handler.conclude_request(
                        **{"code": 400, "message": "User does not exist", "data": {}}
                    )
                    return

                user_to_rename.nickname = new_nickname
                session.commit()

            response = {
                "code": 200,
                "message": "User renamed successfully",
                "data": {},
            }

            handler.conclude_request(**response)

        except Exception as e:
            handler.logger.error(f"Error detected when handling requests.", exc_info=True)
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestGetUserInfoHandler(RequestHandler):
    data_schema = {}

    def handle(self, handler: ConnectionHandler):
        user_to_get_username = handler.data["username"]
        if not user_to_get_username:
            handler.conclude_request(
                **{"code": 400, "message": "Username is required", "data": {}}
            )
            return

        try:
            with Session() as session:
                this_user = session.get(User, handler.username)
                if not this_user or not this_user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 403, "message": "Invalid user or token", "data": {}}
                    )
                    return

                user_to_get = session.get(User, user_to_get_username)
                if not user_to_get:
                    handler.conclude_request(
                        **{"code": 404, "message": "User does not exist", "data": {}}
                    )
                    return

                if (
                    user_to_get_username != this_user.username
                    and "get_user_info" not in this_user.all_permissions
                ):
                    handler.conclude_request(
                        **{
                            "code": 403,
                            "message": "You do not have permission to get user information",
                            "data": {},
                        }
                    )
                    return

                user_info = {
                    "nickname": user_to_get.nickname,
                    "username": user_to_get.username,
                    "permissions": list(user_to_get.all_permissions),
                    "groups": list(user_to_get.all_groups),
                    "last_login": user_to_get.last_login,
                    "created_time": user_to_get.created_time,
                }

                handler.conclude_request(
                    **{"code": 200, "message": "OK", "data": user_info}
                )

        except Exception as e:
            handler.logger.error(f"Error detected when handling requests.", exc_info=True)
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestChangeUserGroupsHandler(RequestHandler):
    data_schema = {}

    def handle(self, handler: ConnectionHandler):

        try:
            with Session() as session:
                this_user = session.get(User, handler.username)
                if not this_user or not this_user.is_token_valid(handler.token):
                    handler.conclude_request(
                        **{"code": 403, "message": "Invalid user or token", "data": {}}
                    )
                    return

                if "change_user_groups" not in this_user.all_permissions:
                    handler.conclude_request(
                        **{
                            "code": 403,
                            "message": "You do not have permission to change user groups",
                            "data": {},
                        }
                    )
                    return

                user_to_change_username = handler.data["username"]
                if not user_to_change_username:
                    handler.conclude_request(
                        **{"code": 400, "message": "Username is required", "data": {}}
                    )
                    return

                user_to_change = session.get(User, user_to_change_username)
                if not user_to_change:
                    handler.conclude_request(
                        **{"code": 404, "message": "User does not exist", "data": {}}
                    )
                    return

                new_user_groups: list[str] = handler.data.get("groups", [])

                if set(new_user_groups) != user_to_change.all_groups:
                    user_to_change.all_groups = new_user_groups
                    session.commit()

            response = {
                "code": 200,
                "message": "User groups changed successfully",
                "data": {},
            }

            handler.conclude_request(**response)

        except Exception as e:
            handler.logger.error(f"Error detected when handling requests.", exc_info=True)
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


class RequestSetPasswdHandler(RequestHandler):
    data_schema = {}

    def handle(self, handler: ConnectionHandler):

        try:
            with Session() as session:
                operator_username = handler.username
                token = handler.data.get("token", None)

                target_username = handler.data.get("username", None)
                old_passwd = handler.data.get("old_passwd", None)
                new_passwd = handler.data.get("new_passwd", None)

                if not target_username:
                    handler.conclude_request(
                        **{"code": 400, "message": "Username is required", "data": {}}
                    )
                    return
                if not new_passwd:
                    handler.conclude_request(
                        **{"code": 400, "message": "New password is required", "data": {}}
                    )
                    return

                user = session.get(User, target_username)
                if not user:
                    handler.conclude_request(
                        **{"code": 401, "message": "Invalid credentials", "data": {}}
                    )
                    return

                # 初始化操作员用户，如果没有指定 operator, 则以目标用户充任
                if operator_username:
                    if not token:
                        handler.conclude_request(
                            **{
                                "code": 400,
                                "message": "Given an operator, token is required",
                                "data": {},
                            }
                        )
                        return

                    operator_user = session.get(User, operator_username)
                    if not operator_user or not operator_user.is_token_valid(token):
                        handler.conclude_request(
                            **{"code": 401, "message": "Invalid user or token", "data": {}}
                        )
                        return
                else:  # 这条路径下的 operator_user 应该永远也不会被调用。
                    operator_user = None

                if old_passwd:  # 如果指定了旧密码，说明是用户更改自己的密码
                    if not user.authenticate_and_create_token(old_passwd):
                        handler.conclude_request(
                            **{
                                "code": 401,
                                "message": "Invalid credentials",
                                "data": {},
                            }
                        )
                        return
                    if not ({"set_passwd", "super_set_passwd"} & user.all_permissions):
                        handler.conclude_request(
                            **{
                                "code": 403,
                                "message": "You do not have permission to change your own password",
                                "data": {},
                            }
                        )
                        return
                else:  # 用户更改其他用户的密码
                    if not operator_user:
                        handler.conclude_request(
                            **{
                                "code": 400,
                                "message": "Operator is required when setting other user password",
                                "data": {},
                            }
                        )
                        return
                    if not "super_set_passwd" in operator_user.all_permissions:
                        handler.conclude_request(
                            **{
                                "code": 403,
                                "message": "You do not have permission to set user password",
                                "data": {},
                            }
                        )
                        return

                user.set_password(new_passwd)
                # session.commit()

            response = {
                "code": 200,
                "message": "Password set successfully",
                "data": {},
            }

            handler.conclude_request(**response)

        except Exception as e:
            handler.logger.error(f"Error detected when handling requests.", exc_info=True)
            handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})
