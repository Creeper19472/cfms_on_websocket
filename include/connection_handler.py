import os
import threading
from types import FunctionType
from typing import Optional, Union
import jsonschema
import websockets
import websockets.sync.server
from websockets.typing import Data
from include.classes.request import RequestHandler
from include.conf_loader import global_config
from include.classes.connection import ConnectionHandler
from include.database.handler import Session
from include.database.models.classic import User
from include.function.audit import log_audit
from include.handlers.auth import RequestLoginHandler, RequestRefreshTokenHandler
from include.handlers.document import (
    RequestCreateDocumentHandler,
    RequestDeleteDocumentHandler,
    RequestDownloadFileHandler,
    RequestGetDocumentHandler,
    RequestGetDocumentInfoHandler,
    RequestGetDocumentAccessRulesHandler,
    RequestMoveDocumentHandler,
    RequestRenameDocumentHandler,
    RequestSetDocumentRulesHandler,
    RequestUploadDocumentHandler,
    RequestUploadFileHandler,
)
from include.handlers.directory import (
    RequestListDirectoryHandler,
    RequestCreateDirectoryHandler,
    RequestDeleteDirectoryHandler,
    RequestGetDirectoryInfoHandler,
    RequestMoveDirectoryHandler,
    RequestRenameDirectoryHandler,
    RequestSetDirectoryRulesHandler,
)
from include.handlers.management.user import (
    RequestChangeUserGroupsHandler,
    RequestCreateUserHandler,
    RequestDeleteUserHandler,
    RequestListUsersHandler,
    RequestGetUserInfoHandler,
    RequestRenameUserHandler,
    RequestSetPasswdHandler,
)
from include.handlers.management.group import (
    RequestChangeGroupPermissionsHandler,
    RequestCreateGroupHandler,
    RequestDeleteGroupHandler,
    RequestGetGroupInfoHandler,
    RequestListGroupsHandler,
    RequestRenameGroupHandler,
)
from include.handlers.management.system import (
    RequestLockdownHandler,
    RequestViewAuditLogsHandler,
)
from include.constants import CORE_VERSION, PROTOCOL_VERSION
from include.shared import connected_listeners, lockdown_enabled
import include.system.messages as smsg

from include.function.log import getCustomLogger

logger = getCustomLogger(
    "connection_handler", filepath="./content/logs/connection_handler.log"
)

connected_listeners: set[websockets.sync.server.ServerConnection]


def handle_connection(websocket: websockets.sync.server.ServerConnection):
    """
    Handle incoming WebSocket connections.

    Args:
        websocket: The WebSocket connection object.
    """

    logger.info(f"Incoming connection: {websocket.remote_address[0]}")

    try:
        while True:
            message = websocket.recv()
            logger.debug(f"Received message: {message}")
            if message is None:
                break  # Connection closed
            handle_request(websocket, message)
    except (websockets.ConnectionClosed, websockets.exceptions.ConnectionClosedOK):
        logger.info("WebSocket connection closed")
    except Exception as e:
        logger.error(f"Error handling WebSocket connection: {e}", exc_info=True)
    finally:
        websocket.close()
        try:
            connected_listeners.remove(websocket)
        except KeyError:
            ...


def handle_request(websocket: websockets.sync.server.ServerConnection, message: Data):
    """
    Handle a specific request/message received over the WebSocket connection.

    Args:
        websocket: The WebSocket connection object.
        message: The data/message received from the client.
    """
    this_handler = ConnectionHandler(websocket, message)
    action = this_handler.action

    if action is None:
        this_handler.conclude_request(400, {}, "No action specified in request")
        return

    available_functions: dict[str, type[RequestHandler]] = {
        "server_info": RequestServerInfoHandler,
        "register_listener": RequestRegisterListenerHandler,
        # 认证类
        "login": RequestLoginHandler,
        "refresh_token": RequestRefreshTokenHandler,
        # 文档类
        "get_document": RequestGetDocumentHandler,
        "create_document": RequestCreateDocumentHandler,
        "upload_document": RequestUploadDocumentHandler,
        "delete_document": RequestDeleteDocumentHandler,
        "rename_document": RequestRenameDocumentHandler,
        "move_document": RequestMoveDocumentHandler,
        "get_document_info": RequestGetDocumentInfoHandler,
        "get_document_access_rules": RequestGetDocumentAccessRulesHandler,
        "set_document_rules": RequestSetDocumentRulesHandler,
        # 文件类
        "download_file": RequestDownloadFileHandler,
        "upload_file": RequestUploadFileHandler,
        # 目录类
        "list_directory": RequestListDirectoryHandler,
        "get_directory_info": RequestGetDirectoryInfoHandler,
        "set_directory_rules": RequestSetDirectoryRulesHandler,
        "create_directory": RequestCreateDirectoryHandler,
        "delete_directory": RequestDeleteDirectoryHandler,
        "rename_directory": RequestRenameDirectoryHandler,
        "move_directory": RequestMoveDirectoryHandler,
        # 用户类
        "list_users": RequestListUsersHandler,
        "create_user": RequestCreateUserHandler,
        "delete_user": RequestDeleteUserHandler,
        "rename_user": RequestRenameUserHandler,
        "get_user_info": RequestGetUserInfoHandler,
        "change_user_groups": RequestChangeUserGroupsHandler,
        "set_passwd": RequestSetPasswdHandler,
        # 用户组类
        "list_groups": RequestListGroupsHandler,
        "create_group": RequestCreateGroupHandler,
        "delete_group": RequestDeleteGroupHandler,
        "rename_group": RequestRenameGroupHandler,
        "get_group_info": RequestGetGroupInfoHandler,
        "change_group_permissions": RequestChangeGroupPermissionsHandler,
        # 系统类
        "lockdown": RequestLockdownHandler,
        "view_audit_logs": RequestViewAuditLogsHandler,
    }

    # 定义白名单内的请求。这些请求即使在防范禁闭时也对所有用户可用。
    whitelisted_functions = [
        "echo",
        "server_info",
        "register_listener",
        "login",
        "refresh_token",
        "upload_file",
        "download_file",
    ]

    if lockdown_enabled.is_set():
        if action not in whitelisted_functions:
            can_bypass_lockdown = False
            if this_handler.username:
                with Session() as session:
                    user = session.get(User, this_handler.username)
                    if user and ("bypass_lockdown" in user.all_permissions):
                        can_bypass_lockdown = True

            if not can_bypass_lockdown:
                this_handler.conclude_request(999, {}, "lockdown")
                return

    if action == "echo":
        # Echo the message back to the client
        this_handler.conclude_request(
            200, {"message": this_handler.data.get("message", "")}, "Echo response"
        )
    elif action == "shutdown":
        with Session() as session:
            this_user = session.get(User, this_handler.username)
            if not this_user or not this_user.is_token_valid(this_handler.token):
                this_handler.conclude_request(403, {}, "Invalid user or token")
                return

            if "shutdown" not in this_user.all_permissions:
                this_handler.conclude_request(403, {}, "Permission denied")
                return

        # Shutdown the server
        this_handler.conclude_request(200, {}, "Server is shutting down")
        logger.info("Server is shutting down")
        threading.Thread(target=os._exit(0), daemon=True).start()
    elif action in available_functions:

        _request_handler: RequestHandler = available_functions[action]()

        try:
            jsonschema.validate(this_handler.data, _request_handler.data_schema)
        except jsonschema.ValidationError as error:
            this_handler.conclude_request(
                400,
                {
                    "validator": error.validator,
                    "validator_value": error.validator_value,
                },
                error.message,
            )
            return

        if _request_handler.require_auth:
            if not this_handler.username or not this_handler.token:
                this_handler.conclude_request(401, {}, "Authentication required")
                return

        callback: Union[
            int,
            tuple[int, Optional[str]],
            tuple[int, Optional[str], dict],
            tuple[int, Optional[str], str],
            tuple[int, Optional[str], dict, str],
            None,
        ] = _request_handler.handle(this_handler)

        if type(callback) is tuple:
            match callback:
                case (result, target) if len(callback) == 2:
                    # 不判断各元素类型是否正确。第二个元素是目标对象
                    log_audit(
                        action,
                        result,
                        target=target,
                        remote_address=this_handler.remote_address,
                    )
                case (result, target, data) if (
                    isinstance(data, dict) and len(callback) == 3
                ):
                    log_audit(
                        action,
                        result,
                        target=target,
                        data=data,
                        remote_address=this_handler.remote_address,
                    )
                case (result, target, username) if (
                    isinstance(username, str) and len(callback) == 3
                ):
                    log_audit(
                        action,
                        result,
                        target=target,
                        username=username,
                        remote_address=this_handler.remote_address,
                    )
                case (result, target, data, username) if len(callback) == 4:
                    log_audit(
                        action,
                        result,
                        target=target,
                        data=data,
                        username=username,
                        remote_address=this_handler.remote_address,
                    )
                case _:
                    raise TypeError
        elif type(callback) is int:
            log_audit(action, callback)
        elif callback is None:
            # 这个设计为两种情况所预留：
            # 1. 为旧版本代码的向下兼容考量；
            # 2. 为不适合采用 return 提交审计信息的逻辑预留。
            return
        else:
            raise TypeError("Invaild returned value")
    else:
        # Handle unknown actions
        this_handler.conclude_request(400, {}, f"Unknown action: {this_handler.action}")

    return


class RequestServerInfoHandler(RequestHandler):
    """
    Handle the 'server_info' action to return server information.

    Args:
        this_handler: The ConnectionHandler instance handling the request.
    """

    data_schema = {"type": "object", "properties": {}, "additionalProperties": False}

    def handle(self, handler: ConnectionHandler):

        server_info = {
            "server_name": global_config["server"]["name"],
            "version": CORE_VERSION.original,
            "protocol_version": PROTOCOL_VERSION,
            "lockdown": lockdown_enabled.is_set(),
        }
        handler.conclude_request(
            200, server_info, "Server information retrieved successfully"
        )
        return


class RequestRegisterListenerHandler(RequestHandler):
    """
    Register a connection as a listener.

    Usually, a listener connection should not send messages to the server, in order
    to prevent potential issues.
    """

    data_schema = {"type": "object", "additionalProperties": False}

    def handle(self, handler: ConnectionHandler) -> None:
        connected_listeners.add(handler.websocket)
        handler.conclude_request(200, {}, "registered as a listener")
        return
