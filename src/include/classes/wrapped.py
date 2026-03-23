from typing import Callable, TypeVar, ParamSpec, Any
from websockets.sync.server import ServerConnection

P = ParamSpec("P")
R = TypeVar("R")


class ManagedConnection:
    def __init__(self, websocket: ServerConnection) -> None:
        self.frame_id: int = 1
        self._ws = websocket

    def _wrap(self, func: Callable[P, R]) -> Callable[P, R]:
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            self.frame_id += 2
            # print(f"Frame ID: {self.frame_id}") # 统一的逻辑点
            return func(*args, **kwargs)

        return wrapper

    @property
    def send(self):
        return self._wrap(self._ws.send)

    @property
    def recv(self):
        return self._wrap(self._ws.recv)
