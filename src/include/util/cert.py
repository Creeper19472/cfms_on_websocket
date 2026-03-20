import websockets.sync.server

__all__ = ["get_client_cert_subject"]


def get_client_cert_subject(
    websocket: websockets.sync.server.ServerConnection,
) -> str | None:
    """
    Extract the subject common name (CN) from the client's TLS certificate,
    if one was presented during the handshake.

    Returns the CN string, or None when no client certificate is available.
    """
    try:
        transport = websocket.socket
        # SSLSocket exposes getpeercert(); plain sockets do not.
        peercert = getattr(transport, "getpeercert", lambda: None)()
        if peercert:
            for rdn in peercert.get("subject", ()):
                for attr_name, attr_value in rdn:
                    if attr_name == "commonName":
                        return attr_value
    except Exception:
        pass
    return None
