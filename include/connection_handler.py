import os
import threading
import websockets
import websockets.sync.server
from websockets.typing import Data
from include.conf_loader import global_config
from include.classes.connection import ConnectionHandler
from include.database.handler import Session
from include.database.models import User
from include.handlers.auth import handle_login, handle_refresh_token
from include.handlers.document import (
    handle_create_document,
    handle_get_document_info,
    handle_get_document,
    handle_download_file,
    handle_upload_document,
    handle_delete_document,
    handle_rename_document,
    handle_upload_file,
    handle_set_document_rules,
    handle_move_document,
)
from include.handlers.directory import (
    handle_list_directory,
    handle_get_directory_info,
    handle_create_directory,
    handle_delete_directory,
    handle_rename_directory,
    handle_move_directory,
)
from include.handlers.management.user import (
    handle_list_users,
    handle_create_user,
    handle_delete_user,
    handle_rename_user,
    handle_get_user_info,
    handle_change_user_groups,
    handle_set_passwd,
)
from include.handlers.management.group import (
    handle_list_groups,
    handle_create_group,
    handle_delete_group,
    handle_rename_group,
    handle_get_group_info,
    handle_change_group_permissions,
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

    available_functions = {
        "server_info": handle_server_info,
        # 认证类
        "login": handle_login,
        "refresh_token": handle_refresh_token,
        # 文档类
        "get_document": handle_get_document,
        "create_document": handle_create_document,
        "upload_document": handle_upload_document,
        "delete_document": handle_delete_document,
        "rename_document": handle_rename_document,
        "move_document": handle_move_document,
        "get_document_info": handle_get_document_info,
        "set_document_rules": handle_set_document_rules,
        # 文件类
        "download_file": handle_download_file,
        "upload_file": handle_upload_file,
        # 目录类
        "list_directory": handle_list_directory,
        "get_directory_info": handle_get_directory_info,
        "create_directory": handle_create_directory,
        "delete_directory": handle_delete_directory,
        "rename_directory": handle_rename_directory,
        "move_directory": handle_move_directory,
        # 用户类
        "list_users": handle_list_users,
        "create_user": handle_create_user,
        "delete_user": handle_delete_user,
        "rename_user": handle_rename_user,
        "get_user_info": handle_get_user_info,
        "change_user_groups": handle_change_user_groups,
        "set_passwd": handle_set_passwd,
        # 用户组类
        "list_groups": handle_list_groups,
        "create_group": handle_create_group,
        "delete_group": handle_delete_group,
        "rename_group": handle_rename_group,
        "get_group_info": handle_get_group_info,
        "change_group_permissions": handle_change_group_permissions,
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
        available_functions[action](this_handler)
    else:
        # Handle unknown actions
        this_handler.conclude_request(400, {}, f"Unknown action: {this_handler.action}")

    return


def handle_server_info(this_handler: ConnectionHandler):
    """
    Handle the 'server_info' action to return server information.

    Args:
        this_handler: The ConnectionHandler instance handling the request.
    """
    server_info = {
        "server_name": global_config["server"]["name"],
        "version": CORE_VERSION.original,
        "protocol_version": PROTOCOL_VERSION,
    }
    this_handler.conclude_request(
        200, server_info, "Server information retrieved successfully"
    )
