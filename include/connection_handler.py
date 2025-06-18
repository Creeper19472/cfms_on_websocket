import websockets
import websockets.sync.server
from websockets.typing import Data
from include.conf_loader import global_config
from include.classes.connection import ConnectionHandler
from include.handlers.auth import handle_login, handle_refresh_token
from include.handlers.document import handle_get_document
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

    logger.info(f"incoming connection: {websocket.remote_address[0]}")

    try:
        while True:
            message = websocket.recv()
            logger.debug(f"Received message: {message}")
            if message is None:
                break  # Connection closed
            handle_request(websocket, message)
    except websockets.ConnectionClosed:
        logger.info("WebSocket connection closed")
    except Exception as e:
        logger.error(f"Error handling WebSocket connection: {e}")
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

    if this_handler.action is None:
        this_handler.conclude_request(400, {}, "No action specified in request")
        return

    if this_handler.action == "echo":
        # Echo the message back to the client
        this_handler.conclude_request(
            200, {"message": this_handler.data.get("message", "")}, "Echo response"
        )
    elif this_handler.action == "login":
        handle_login(this_handler)
    elif this_handler.action == "refresh_token":
        handle_refresh_token(this_handler)
    elif this_handler.action == "get_document":
        handle_get_document(this_handler)
    else:
        # Handle unknown actions
        this_handler.conclude_request(400, {}, f"Unknown action: {this_handler.action}")

    return
