import websockets
import websockets.sync.server
from websockets.typing import Data


class ConnectionHandler:
    def __init__(self, websocket) -> None:
        self.websocket = websocket

    def conclude_request(self, message: Data):
        """
        Conclude the request by sending a response back to the client.

        Args:
            message: The data/message received from the client.
        """
        self.websocket.send(f"Response: {message}")


def handle_connection(websocket: websockets.sync.server.ServerConnection):
    """
    Handle incoming WebSocket connections.

    Args:
        websocket: The WebSocket connection object.
    """

    try:
        while True:
            message = websocket.recv()
            if message is None:
                break  # Connection closed
            print(f"Received message: {message}")
            websocket.send(f"Echo: {message}")
    except Exception as e:
        print(f"Error handling WebSocket connection: {e}")
    finally:
        websocket.close()


def handle_request(websocket: websockets.sync.server.ServerConnection, message: Data):
    """
    Handle a specific request/message received over the WebSocket connection.

    Args:
        websocket: The WebSocket connection object.
        message: The data/message received from the client.
    """
    this_handler = ConnectionHandler(websocket)
    this_handler.conclude_request(message)
    return
