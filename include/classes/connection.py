import json
import time
from websockets.sync.server import ServerConnection
from websockets.typing import Data
from include.conf_loader import global_config
from include.function.log import getCustomLogger

logger = getCustomLogger(
    "connection",
    filepath="./content/logs/connection.log",
)


class ConnectionHandler:
    def __init__(self, websocket, message: Data) -> None:
        self.websocket = websocket
        self.request = json.loads(message)
        self.logger = logger

        self.action = self.request.get("action", None)
        self.data: dict = self.request.get("data", {})

        self.username: str = self.request.get("username", "")
        self.token: str = self.request.get("token", "")

    def conclude_request(self, code: int, data: dict = {}, message: str = "") -> None:
        """
        Conclude the request by sending a response back to the client.

        Args:
            message: The data/message received from the client.
        """
        response = {
            "code": code,
            "data": data,
            "message": message,
            "timestamp": time.time(),
        }

        response_json = json.dumps(response, ensure_ascii=False)
        self.logger.debug(f"Sending response: {response_json}")

        self.websocket.send(response_json)
