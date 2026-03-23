import json
import queue
import struct
import threading
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Optional
from websockets.sync.server import ServerConnection

HEADER_FORMAT = "!IB"  # 4 bytes for frame_id, 1 byte for frame_type
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


class FrameType(IntEnum):
    PROCESS = 0
    CONCLUSION = 1


@dataclass
class Frame:
    frame_id: int
    frame_type: FrameType
    data: Any


class Stream:
    """代表一个独立的通信流（相当于一个虚拟的连接）"""

    def __init__(self, connection: "MultiplexConnection", frame_id: int):
        self.connection = connection
        self.frame_id = frame_id
        self._queue: queue.Queue = queue.Queue()

    def send(self, data: Any, frame_type: FrameType = FrameType.PROCESS):
        """在这个流上发送数据"""
        self.connection._send_frame(self.frame_id, frame_type, data)

    def recv(self, timeout: Optional[float] = None) -> Frame:
        """接收属于这个流的数据，阻塞直到拿到为止"""
        frame = self._queue.get(timeout=timeout)
        if frame is None:
            raise ConnectionError("MultiplexConnection has been closed")
        return frame

    def _put_incoming_frame(self, frame: Optional[Frame]):
        """由 Dispatcher 调用，将属于该流的数据塞入队列"""
        self._queue.put(frame)


class MultiplexConnection:
    def __init__(self, websocket: Any):
        """
        :param websocket: ServerConnection
        """
        self._ws = websocket

        self._next_frame_id = 2
        self._id_lock = threading.Lock()

        self._streams: dict[int, Stream] = {}
        self._streams_lock = threading.Lock()
        self._send_lock = threading.Lock()

        self._new_streams: queue.Queue[Optional[Stream]] = queue.Queue()

        self._is_running = True
        self._dispatcher = threading.Thread(target=self._recv_loop, daemon=True)
        self._dispatcher.start()

    def create_stream(self) -> Stream:
        """主动发起一个新的数据流"""
        with self._id_lock:
            frame_id = self._next_frame_id
            self._next_frame_id += 2  # 保持奇偶性

        new_stream = Stream(self, frame_id)
        with self._streams_lock:
            self._streams[frame_id] = new_stream
            
        return new_stream

    def accept_stream(self) -> Optional[Stream]:
        """阻塞等待并获取对方创建的新的工作流"""
        return self._new_streams.get()

    def _recv_loop(self):
        try:
            while self._is_running:
                raw_payload = self._ws.recv()

                if isinstance(raw_payload, str):
                    raw_payload = raw_payload.encode("utf-8")
                elif not isinstance(raw_payload, bytes):
                    raw_payload = bytes(raw_payload)

                if len(raw_payload) < HEADER_SIZE:
                    continue

                header = raw_payload[:HEADER_SIZE]
                data_bytes = raw_payload[HEADER_SIZE:]
                frame_id, frame_type_val = struct.unpack(HEADER_FORMAT, header)

                try:
                    frame_type = FrameType(frame_type_val)
                except ValueError:
                    continue

                try:
                    data = json.loads(data_bytes.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    data = data_bytes

                frame = Frame(frame_id=frame_id, frame_type=frame_type, data=data)

                with self._streams_lock:
                    if frame.frame_id not in self._streams:
                        # 对方发起的新流，通知本地主线程
                        new_stream = Stream(self, frame.frame_id)
                        self._streams[frame.frame_id] = new_stream
                        self._new_streams.put(new_stream)

                    target_stream = self._streams[frame.frame_id]

                target_stream._put_incoming_frame(frame)

                # 如果对方发来了结束帧，回收路由表内存
                if frame.frame_type == FrameType.CONCLUSION:
                    with self._streams_lock:
                        self._streams.pop(frame.frame_id, None)

        except Exception as e:
            # logger.debug(f"[Dispatcher] Connection closed or error: {e}")
            pass
        finally:
            self._is_running = False
            self._new_streams.put(None)  # 唤醒在 accept_stream 阻塞的线程
            
            # 唤醒所有正在 Stream.recv() 阻塞的线程，防止死锁
            with self._streams_lock:
                for stream in self._streams.values():
                    stream._put_incoming_frame(None)

    def _send_frame(self, frame_id: int, frame_type: FrameType, data: Any):
        header = struct.pack(HEADER_FORMAT, frame_id, frame_type.value)
        if isinstance(data, (dict, list)):
            data_bytes = json.dumps(data).encode("utf-8")
        elif isinstance(data, str):
            data_bytes = data.encode("utf-8")
        elif isinstance(data, bytes):
            data_bytes = data
        else:
            data_bytes = str(data).encode("utf-8")

        payload = header + data_bytes
        with self._send_lock:
            self._ws.send(payload)

        # 本地主动结束时，同样清理内存
        if frame_type == FrameType.CONCLUSION:
            with self._streams_lock:
                self._streams.pop(frame_id, None)

    def close(self):
        self._is_running = False
        try:
            self._ws.close()
        except Exception:
            pass