from websockets.sync.server import ServerConnection


def get_client_ip(websocket: ServerConnection) -> str:
    assert websocket.request is not None

    forwarded_for = websocket.request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = websocket.request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    return websocket.remote_address[0]
