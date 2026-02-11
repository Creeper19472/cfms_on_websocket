import json
import os
import threading
import time
import copy
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
from include.util.audit import log_audit
from include.handlers.auth import RequestLoginHandler, RequestRefreshTokenHandler
from include.handlers.two_factor import (
    RequestCancel2FASetupHandler,
    RequestSetup2FAHandler,
    RequestValidate2FAHandler,
    RequestDisable2FAHandler,
    RequestGet2FAStatusHandler,
)
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
    RequestGetDirectoryAccessRulesHandler,
    RequestMoveDirectoryHandler,
    RequestRenameDirectoryHandler,
    RequestSetDirectoryRulesHandler,
)
from include.handlers.revision import (
    RequestDeleteRevisionHandler,
    RequestListRevisionsHandler,
    RequestGetRevisionHandler,
    RequestSetDocumentRevisionHandler,
)
from include.handlers.management.user import (
    RequestChangeUserGroupsHandler,
    RequestCreateUserHandler,
    RequestDeleteUserHandler,
    RequestBlockUserHandler,
    RequestGetUserAvatarHandler,
    RequestSetUserAvatarHandler,
    RequestUnblockUserHandler,
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
from include.handlers.management.access import (
    RequestGrantAccessHandler,
    RequestRevokeAccessHandler,
    RequestViewAccessEntriesHandler,
)
from include.handlers.management.system import (
    RequestLockdownHandler,
    RequestViewAuditLogsHandler,
)
from include.handlers.debugging.throw import RequestThrowExceptionHandler
from include.handlers.search import RequestSearchHandler

from include.constants import CORE_VERSION, NONCE_MIN_LENGTH, PROTOCOL_VERSION
from include.nonce_store import nonce_store
from include.shared import connected_listeners, lockdown_enabled

from include.util.log import getCustomLogger

logger = getCustomLogger(
    "connection_handler", filepath="./content/logs/connection_handler.log"
)

connected_listeners: set[websockets.sync.server.ServerConnection]


def _validate_replay_protection(
    handler: ConnectionHandler,
) -> Optional[str]:
    """
    Validate nonce and timestamp for an authenticated request.

    Returns None on success, or an error string after sending a rejection
    response via handler.conclude_request.
    """
    nonce = handler.nonce
    request_timestamp = handler.request_timestamp

    if not nonce or len(nonce) < NONCE_MIN_LENGTH:
        handler.conclude_request(
            400, {}, "Missing or invalid nonce for replay protection"
        )
        return "nonce"

    if not request_timestamp:
        handler.conclude_request(
            400, {}, "Missing or invalid timestamp for replay protection"
        )
        return "timestamp"

    replay_error = nonce_store.validate_and_store(nonce, float(request_timestamp))
    if replay_error is not None:
        handler.conclude_request(1001, {}, replay_error)
        return "replay"

    return None


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
    try:
        this_handler = ConnectionHandler(websocket, message)
    except jsonschema.ValidationError as error:
        # Request envelope failed schema validation — send error and bail out
        response = {
            "code": 400,
            "data": {},
            "message": f"Invalid request format: {error.message}",
            "timestamp": time.time(),
        }
        websocket.send(json.dumps(response, ensure_ascii=False))
        return

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
        # 两步验证类
        "setup_2fa": RequestSetup2FAHandler,
        "cancel_2fa_setup": RequestCancel2FASetupHandler,  # especially for cancelling setup
        "validate_2fa": RequestValidate2FAHandler,
        "disable_2fa": RequestDisable2FAHandler,
        "get_2fa_status": RequestGet2FAStatusHandler,
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
        # 修订版本类
        "list_revisions": RequestListRevisionsHandler,
        "get_revision": RequestGetRevisionHandler,
        "set_current_revision": RequestSetDocumentRevisionHandler,
        "delete_revision": RequestDeleteRevisionHandler,
        # 文件类
        "download_file": RequestDownloadFileHandler,
        "upload_file": RequestUploadFileHandler,
        # 目录类
        "list_directory": RequestListDirectoryHandler,
        "get_directory_info": RequestGetDirectoryInfoHandler,
        "get_directory_access_rules": RequestGetDirectoryAccessRulesHandler,
        "set_directory_rules": RequestSetDirectoryRulesHandler,
        "create_directory": RequestCreateDirectoryHandler,
        "delete_directory": RequestDeleteDirectoryHandler,
        "rename_directory": RequestRenameDirectoryHandler,
        "move_directory": RequestMoveDirectoryHandler,
        # Search
        "search": RequestSearchHandler,
        # Users
        "block_user": RequestBlockUserHandler,
        "unblock_user": RequestUnblockUserHandler,
        "list_users": RequestListUsersHandler,
        "create_user": RequestCreateUserHandler,
        "delete_user": RequestDeleteUserHandler,
        "rename_user": RequestRenameUserHandler,
        "get_user_info": RequestGetUserInfoHandler,
        "get_user_avatar": RequestGetUserAvatarHandler,
        "set_user_avatar": RequestSetUserAvatarHandler,
        "change_user_groups": RequestChangeUserGroupsHandler,
        "set_passwd": RequestSetPasswdHandler,
        # 用户组类
        "list_groups": RequestListGroupsHandler,
        "create_group": RequestCreateGroupHandler,
        "delete_group": RequestDeleteGroupHandler,
        "rename_group": RequestRenameGroupHandler,
        "get_group_info": RequestGetGroupInfoHandler,
        "change_group_permissions": RequestChangeGroupPermissionsHandler,
        # 访问类
        "grant_access": RequestGrantAccessHandler,
        "revoke_access": RequestRevokeAccessHandler,
        "view_access_entries": RequestViewAccessEntriesHandler,
        # 系统类
        "lockdown": RequestLockdownHandler,
        "view_audit_logs": RequestViewAuditLogsHandler,
    }

    # Debugging
    if global_config["debug"]:
        available_functions["throw_exception"] = RequestThrowExceptionHandler

    # 定义白名单内的请求。这些请求即使在防范禁闭时也对所有用户可用。
    whitelisted_functions = [
        # "echo",
        "server_info",
        "register_listener",
        "login",
        "refresh_token",
        "validate_2fa",
        "upload_file",
        "download_file",
    ]

    user_permissions: set[str] = set()
    authenticated = False
    if this_handler.username and this_handler.token:
        with Session() as session:
            user = session.get(User, this_handler.username)
            if user and user.is_token_valid(this_handler.token):
                authenticated = True
                user_permissions = copy.deepcopy(user.all_permissions)
            else:
                this_handler.conclude_request(401, {}, "Invalid user or token")
                return

    if lockdown_enabled.is_set():
        if action not in whitelisted_functions:
            can_bypass_lockdown = False
            if authenticated and "bypass_lockdown" in user_permissions:
                can_bypass_lockdown = True

            if not can_bypass_lockdown:
                this_handler.conclude_request(999, {}, "lockdown")
                return

    # Replay attack protection: validate nonce and timestamp.
    # Only applied to authenticated requests to prevent unauthenticated
    # traffic from polluting the nonce store (DoS vector).
    if authenticated and _validate_replay_protection(this_handler) is not None:
        return

    if action == "shutdown":
        if not authenticated or "shutdown" not in user_permissions:
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

        if _request_handler.require_auth and not authenticated:
            this_handler.conclude_request(401, {}, "Authentication required")
            log_audit(
                action,
                401,
                data=this_handler.data,
                remote_address=this_handler.remote_address,
            )
            return

        try:
            callback: Union[
                int,
                tuple[int, Optional[str]],
                tuple[int, Optional[str], dict],
                tuple[int, Optional[str], str],
                tuple[int, Optional[str], dict, str],
                None,
            ] = _request_handler.handle(this_handler)
        except (
            websockets.exceptions.ConnectionClosedOK,
            websockets.exceptions.ConnectionClosedError,
        ):
            raise
        except Exception as e:
            this_handler.logger.error(
                f"Error detected when handling requests.", exc_info=True
            )
            this_handler.conclude_request(500, {}, str(e))
            return

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
