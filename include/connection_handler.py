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
from include.database.models.general import User
from include.function.audit import log_audit
from include.handlers.auth import RequestLoginHandler, RequestRefreshTokenHandler
from include.handlers.document import (
    RequestCreateDocumentHandler,
    RequestDeleteDocumentHandler,
    RequestDownloadFileHandler,
    RequestGetDocumentHandler,
    RequestGetDocumentInfoHandler,
    RequestMoveDocumentHandler,
    RequestRenameDocumentHandler,
    RequestSetDocumentRulesHandler,
    RequestUploadDocumentHandler,
    RequestUploadFileHandler,
)
from include.handlers.directory import (
    RequestListDirectoryHandler,
    RequestCreateDirectoryInfoHandler,
    RequestDeleteDirectoryInfoHandler,
    RequestGetDirectoryInfoHandler,
    RequestMoveDirectoryInfoHandler,
    RequestRenameDirectoryInfoHandler,
)
from include.handlers.management.user import (
    RequestChangeUserGroupsHandler,
    RequestCreateUserHandler,
    RequestDeleteUserHandler,
    RequestListUsersHandler,
    RequestGetUserInfoHandler,
    RequestRenameUserHandler,
    RequestSetPasswdHandler
)
from include.handlers.management.group import (
    RequestChangeGroupPermissionsHandler,
    RequestCreateGroupHandler,
    RequestDeleteGroupHandler,
    RequestGetGroupInfoHandler,
    RequestListGroupsHandler,
    RequestRenameGroupHandler
)
from include.constants import CORE_VERSION, PROTOCOL_VERSION

from include.function.log import getCustomLogger

logger = getCustomLogger(
    "connection_handler", filepath="./content/logs/connection_handler.log"
)


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
        "set_document_rules": RequestSetDocumentRulesHandler,
        # 文件类
        "download_file": RequestDownloadFileHandler,
        "upload_file": RequestUploadFileHandler,
        # 目录类
        "list_directory": RequestListDirectoryHandler,
        "get_directory_info": RequestGetDirectoryInfoHandler,
        "create_directory": RequestCreateDirectoryInfoHandler,
        "delete_directory": RequestDeleteDirectoryInfoHandler,
        "rename_directory": RequestRenameDocumentHandler,
        "move_directory": RequestMoveDirectoryInfoHandler,
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
    }

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
        except jsonschema.ValidationError:
            this_handler.conclude_request(400, {}, "Bad request")
            return

        callback: Union[
            int,
            tuple[int, str],
            tuple[int, str, dict],
            tuple[int, str, dict, str],
            tuple[int, str, str],
            None,
        ] = _request_handler.handle(this_handler)
        """
        callback 的格式：
        - result, Optional[target], Optional[data], Optional[username]
        有以下几种情况：
        1. -> None
            该结果将被忽略。
        2. -> int
            只有 result
        3. -> tuple[int, str]
            这种情况下 int 为 result, 第二个元素必定为 target。
        4. -> tuple[int, str, dict]
            这种情况下 int 为 result, 第二个元素必定为 target, 第三个元素为 data。
        5. -> tuple[int, str, str]
            这种情况下 int 为 result, 第二个元素必定为 target, 第三个元素为 username。
        6. -> tuple[int, str, dict, str]
            这种情况下 int 为 result, 第二个元素必定为 target, 第三个元素为 data, 第四个元素为 username。

        """
        if type(callback) is tuple:
            match callback:
                case (result, target) if len(callback) == 2:
                    # 不判断各元素类型是否正确。第二个元素是目标对象
                    log_audit(action, result, target=target)
                case (result, target, data) if (
                    isinstance(data, dict) and len(callback) == 3
                ):
                    log_audit(action, result, target=target, data=data)
                case (result, target, username) if (
                    isinstance(username, str) and len(callback) == 3
                ):
                    log_audit(action, result, target=target, username=username)
                case (result, target, data, username) if len(callback) == 4:
                    log_audit(
                        action, result, target=target, data=data, username=username
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

    data_schema = {"type": "object"}

    def handle(self, handler: ConnectionHandler):

        server_info = {
            "server_name": global_config["server"]["name"],
            "version": CORE_VERSION.original,
            "protocol_version": PROTOCOL_VERSION,
        }
        handler.conclude_request(
            200, server_info, "Server information retrieved successfully"
        )
        return
