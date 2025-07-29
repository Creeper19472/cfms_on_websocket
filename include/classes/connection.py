import json
import time
import os
import base64
import hashlib

import websockets
from websockets.sync.server import ServerConnection
from websockets.typing import Data

from include.conf_loader import global_config
from include.database.handler import Session
from include.database.models import File, FileTask, User
from include.function.log import getCustomLogger

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import mmap

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
        # self.websocket.remote_address
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

            sha256 = calculate_sha256(file.path)
            file_size = os.path.getsize(file.path)

            self.logger.info(
                f"Calculation complete. SHA256: {sha256}, File size: {file_size}"
            )

            file_path = file.path  # 防止 Session 关闭后可能出现的异常

            ### 发送方首先发出文件信息
            chunk_size = global_config["server"]["file_chunk_size"] # 文件分块大小
            total_chunks = (file_size + chunk_size - 1) // chunk_size

            self.websocket.send(
                json.dumps(
                    {
                        "action": "transfer_file",
                        "data": {
                            "sha256": sha256, # 原始文件的 SHA256 哈希值
                            "file_size": file_size, # 原始文件的大小
                            "chunk_size": chunk_size, # 分块大小
                            "total_chunks": total_chunks, # 文件总分块数
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
                                "iv": base64.b64encode(iv).decode() if chunk_index == 0 else "",
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
        # self.logger.info(task_info)
        if task_info.get("action") != "transfer_file":
            self.logger.error("Invalid flag received for file transfer.")
            self.conclude_request(400, {}, "Invalid flag for file transfer")
            return
        sha256 = task_info["data"].get("sha256")
        file_size = task_info["data"].get("file_size")

        if not file_size:
            self.websocket.send("stop")
            return

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

                            if not data or len(data) < 8192:
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
