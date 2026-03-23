import websockets.sync.server
import threading


__all__ = ["connected_listeners", "lockdown_enabled"]


# FIXME: use new implementation
connected_listeners: set[websockets.sync.server.ServerConnection] = set()
lockdown_enabled = threading.Event()
