import base64
import hashlib
import json
import mmap
import os
import sys
import time
import traceback
from typing import Iterable
from typing import Optional

import jsonschema
import websockets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from websockets.asyncio.server import broadcast
from websockets.sync.server import ServerConnection
from websockets.typing import Data

from include.conf_loader import global_config
from include.constants import FILE_TRANSFER_CHUNK_SIZE
from include.database.handler import Session
from include.database.models.classic import User
from include.database.models.file import File, FileTask
from include.shared import connected_listeners
from include.util.log import getCustomLogger

logger = getCustomLogger(
    "connection",
    filepath="./content/logs/connection.log",
)


def calculate_sha256(file_path):
    # 使用更快的 hashlib 工具和内存映射文件
    with open(file_path, "rb") as f:
        # 使用内存映射文件直接映射到内存
        mmapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        return hashlib.sha256(mmapped_file).hexdigest()


class ConnectionHandler:
    def __init__(self, websocket: ServerConnection, message: Data) -> None:
        self.websocket = websocket
        self.remote_address = websocket.remote_address[0]

        self.request = json.loads(message)
        self.logger = logger

        self.action = self.request.get("action", None)
        self.data: dict = self.request.get("data", {})

        self.username: str = self.request.get("username", "")
        self.token: str = self.request.get("token", "")

    def conclude_request(
        self, code: int, data: Optional[dict] = None, message: str = ""
    ) -> None:
        """
        Conclude the request by sending a response back to the client.

        Args:
            code: HTTP status code for the response.
            data: Data dictionary to include in the response.
            message: Message string to include in the response.
        """
        response = {
            "code": code,
            "data": data if data is not None else {},
            "message": message,
            "timestamp": time.time(),
        }

        response_json = json.dumps(response, ensure_ascii=False)
        self.logger.debug(f"Sending response: {response_json}")

        self.websocket.send(response_json)

    # def authenticate_user(self, user: User|None) -> bool:
    #     """
    #     Authenticates the user by checking the user authentication status.
    #     Returns:
    #         bool: True if the user is authenticated, False otherwise. If the user is not authenticated,
    #               it concludes the request with a 403 status code and an error message indicating
    #               an invalid user or token.
    #     """

    #     if not user or not user.is_token_valid(self.token):
    #         self.conclude_request(
    #             **{"code": 403, "message": "Invalid user or token", "data": {}}
    #         )
    #         return False

    #     return True

    def send_file(self, task_id: str) -> None:
        """
        Sends a file associated with the given task ID to the client over a websocket connection using AES encryption.
        The method performs the following steps:
        1. Retrieves the file ID and file path based on the provided task ID.
        2. Calculates the SHA-256 hash and size of the file.
        3. Notifies the client of the impending file transfer, including the hash and size.
        4. Waits for the client to acknowledge readiness to receive the file.
        5. Encrypts the file using AES-256 in CFB mode with a randomly generated key and IV.
        6. Sends the IV with the first encrypted chunk, then sends the remaining encrypted chunks.
        7. After the file is sent, transmits the AES key and IV to the client (base64 encoded).
        8. Handles errors and logs relevant information.
        Args:
            task_id (str): The identifier for the task whose associated file is to be sent.
        Raises:
            ValueError: If the file ID or file path cannot be found for the given task ID.
            Exception: If an error occurs during file encryption or transmission.
        Returns:
            None
        """

        with Session() as session:
            # Query the FileTask table to get the file_id associated with the task_id
            file_task = session.get(FileTask, task_id)
            if not file_task:
                raise ValueError(f"File transfer task not found for task_id: {task_id}")
            if file_task.mode != 0:
                raise ValueError(f"Not a read-mode task: {task_id}")
            if file_task.status != 0:
                raise ValueError(
                    f"File transfer task already completed or cancelled: {task_id}"
                )
            # Query the File table to get the file path associated with the file_id
            file = session.get(File, file_task.file_id)
            if not file:
                raise ValueError(f"File not found for file_id: {file_task.file_id}")

            self.logger.info(
                f"Task {file_task.id}: preparing to send file (id: {file_task.file_id})."
            )

            file_size = os.path.getsize(file.path)
            sha256 = calculate_sha256(file.path) if file_size else None

            self.logger.info(
                f"Calculation complete. SHA256: {sha256}, File size: {file_size}"
            )

            file_path = file.path  # 防止 Session 关闭后可能出现的异常

            ### 发送方首先发出文件信息
            chunk_size = global_config["server"]["file_chunk_size"]  # 文件分块大小
            total_chunks = (file_size + chunk_size - 1) // chunk_size

            self.websocket.send(
                json.dumps(
                    {
                        "action": "transfer_file",
                        "data": {
                            "sha256": sha256,  # 原始文件的 SHA256 哈希值
                            "file_size": file_size,  # 原始文件的大小
                            "chunk_size": chunk_size,  # 分块大小
                            "total_chunks": total_chunks,  # 文件总分块数
                        },
                    },
                    ensure_ascii=False,
                )
            )

            received_response = (
                self.websocket.recv()
            )  # Wait for client acknowledgment before sending the file
            if received_response != "ready":
                self.logger.error(
                    f"Client did not acknowledge readiness for file transfer: {received_response}"
                )
                self.conclude_request(400, {}, "Client not ready for file transfer")
                return

            if file_size != 0:
                self.logger.info("File transmission begin.")
                try:
                    aes_key = get_random_bytes(32)  # AES-256
                    iv = get_random_bytes(16)
                    cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)

                    with open(file_path, "rb") as file:
                        chunk_index = 0
                        while True:
                            chunk = file.read(chunk_size)
                            if not chunk:
                                break
                            chunk_hash = hashlib.sha256(chunk).hexdigest()
                            encrypted_chunk = cipher.encrypt(chunk)
                            payload = {
                                "action": "file_chunk",
                                "data": {
                                    "index": chunk_index,
                                    "hash": chunk_hash,
                                    "iv": (
                                        base64.b64encode(iv).decode()
                                        if chunk_index == 0
                                        else ""
                                    ),
                                    "chunk": base64.b64encode(encrypted_chunk).decode(),
                                },
                            }
                            self.websocket.send(json.dumps(payload, ensure_ascii=False))
                            chunk_index += 1

                    # 发送密钥和IV
                    self.websocket.send(
                        json.dumps(
                            {
                                "action": "aes_key",
                                "data": {
                                    "key": base64.b64encode(aes_key).decode(),
                                    # "iv": base64.b64encode(iv).decode(),
                                },
                            },
                            ensure_ascii=False,
                        )
                    )
                    file_task.status = 1
                    session.commit()

                except Exception as e:
                    self.logger.error(f"Error sending file {file_path}: {e}")
                    self.conclude_request(500, {}, f"Error sending file: {str(e)}")

            else:
                self.logger.info("Empty file, no need to send")

        self.logger.info(f"File {file_path} sent successfully.")

    def receive_file(self, task_id: str) -> None:
        """
        Receives a file from the client over a websocket connection using AES encryption.
        The method performs the following steps:
        1. Waits for the client to send the file transfer request, including the SHA-256 hash and file size.
        2. Acknowledges readiness to receive the file.
        3. Receives the encrypted file data in chunks, decrypting each chunk using AES-256 in CFB mode.
        4. Writes the decrypted data to a file on disk.
        5. Handles errors and logs relevant information.
        Returns:
            None
        """

        handshake_msg = {
            "action": "transfer_file",
            "data": {},
            "message": "waiting for file transfer",
        }

        self.websocket.send(json.dumps(handshake_msg, ensure_ascii=False))
        self.logger.info("Receiving file: handshake sent")

        task_info = json.loads(self.websocket.recv())

        try:
            jsonschema.validate(
                task_info,
                {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "pattern": "^transfer_file$"},
                        "data": {
                            "type": "object",
                            "properties": {
                                "sha256": {
                                    "anyOf": [{"type": "string"}, {"type": "null"}]
                                },
                                "file_size": {"type": "integer"},
                            },
                            "required": ["file_size"],
                            "additionalProperties": False,
                        },
                    },
                    "required": ["data"],
                    "additionalProperties": False,
                },
            )
        except jsonschema.ValidationError:
            self.conclude_request(400, {}, "Invalid request for file transfer")
            return

        sha256: str = task_info["data"].get("sha256")
        file_size: int = task_info["data"].get("file_size")

        ### 获取任务与文件基本信息
        with Session() as session:
            # Query the FileTask table to get the file_id associated with the task_id
            file_task = session.get(FileTask, task_id)
            if not file_task:
                raise ValueError(f"File transfer task not found for task_id: {task_id}")
            if file_task.mode != 1:
                raise ValueError(f"Not a write-mode task: {task_id}")
            if file_task.status != 0:
                raise ValueError(
                    f"File transfer task already completed or cancelled: {task_id}"
                )
            # Query the File table to get the file path associated with the file_id
            file = session.get(File, file_task.file_id)
            if not file:
                raise ValueError(f"File not found for file_id: {file_task.file_id}")

            if file_size == 0:  # 空文件
                self.websocket.send("stop")
                with open(file.path, "wb") as f:
                    f.truncate(0)
                file.active = True
                session.commit()
                return

            self.websocket.send("ready")
            try:
                # 生成保存文件的路径
                if not file.id:
                    raise ValueError(f"File path not found for file_id: {file.id}")

                logger.info("Receiving file: transfer started")
                os.makedirs(os.path.dirname(file.path), exist_ok=True)
                with open(file.path, "wb") as f:
                    try:
                        while True:
                            # Receive encrypted data from the server
                            data = self.websocket.recv()
                            f.write(data)  # type: ignore

                            if not data or len(data) < FILE_TRANSFER_CHUNK_SIZE:
                                break
                    except (
                        websockets.ConnectionClosed,
                        websockets.exceptions.ConnectionClosedOK,
                    ) as exc:
                        pass

                # 校验文件大小
                actual_size = os.path.getsize(file.path)
                if file_size and actual_size != file_size:
                    self.logger.error(
                        f"File size mismatch: expected {file_size}, got {actual_size}"
                    )
                    os.remove(file.path)

                    self.conclude_request(
                        400,
                        {},
                        f"File size mismatch: expected {file_size}, got {actual_size}",
                    )
                    return

                # 校验sha256
                if sha256:
                    actual_sha256 = calculate_sha256(file.path)
                    if actual_sha256 != sha256:
                        self.logger.error(
                            f"SHA256 mismatch: expected {sha256}, got {actual_sha256}"
                        )
                        os.remove(file.path)

                        self.conclude_request(
                            400,
                            {},
                            f"SHA256 mismatch: expected {sha256}, got {actual_sha256}",
                        )
                        return

                file_task.status = 1
                file.sha256 = sha256
                file.active = True
                session.commit()

                self.logger.info(
                    f"File received and saved to {file.path}, total size: {actual_size}"
                )

                self.conclude_request(200, {}, "File received successfully")

            except (
                websockets.ConnectionClosed,
                websockets.exceptions.ConnectionClosedError,
                websockets.exceptions.ConnectionClosedOK,
            ):
                raise

            except Exception as e:
                self.logger.error(f"Error receiving file: {e}", exc_info=True)
                self.conclude_request(500, {}, f"Error receiving file: {str(e)}")

    def broadcast(
        self,
        message: Data,
        raise_exceptions: bool = False,
    ):
        """
        Adopted from websockets.asyncio.server.broadcast().
        """
        connections: Iterable[ServerConnection] = connected_listeners

        if isinstance(message, str):
            send_method = "send_text"
            message = message.encode()
        elif isinstance(message, (bytes, bytearray, memoryview)):
            send_method = "send_binary"
        else:
            raise TypeError("data must be str or bytes")

        if raise_exceptions:
            if sys.version_info[:2] < (3, 11):  # pragma: no cover
                raise ValueError("raise_exceptions requires at least Python 3.11")

        exceptions: list[Exception] = []

        for connection in connections:
            exception: Exception

            if connection.protocol.state is not websockets.protocol.OPEN:
                continue

            try:
                # Call connection.protocol.send_text or send_binary.
                # Either way, message is already converted to bytes.
                # getattr(connection.protocol, send_method)(message)
                connection.send(message)
            except Exception as write_exception:
                if raise_exceptions:
                    exception = RuntimeError("failed to write message")
                    exception.__cause__ = write_exception
                    exceptions.append(exception)
                else:
                    connection.logger.warning(
                        "skipped broadcast: failed to write message: %s",
                        traceback.format_exception_only(
                            # Remove first argument when dropping Python 3.9.
                            type(write_exception),
                            write_exception,
                        )[0].strip(),
                    )

        if raise_exceptions and exceptions:
            raise ExceptionGroup("skipped broadcast", exceptions)
