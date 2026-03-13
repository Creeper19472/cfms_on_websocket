from http import HTTPStatus
from websockets import Headers, Request, Response
from websockets.sync.server import ServerConnection
from include.classes.misc.guard import LoginGuard


def global_process_request(
    connection: ServerConnection, request: Request
) -> Response | None:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ip = forwarded_for.split(",")[0].strip()
    else:
        ip = connection.remote_address[0]

    if not LoginGuard.check_access(f"ip_limit:{ip}"):
        response_headers = Headers()
        response_headers["Content-Type"] = "text/plain"
        return Response(
            status_code=HTTPStatus.FORBIDDEN,
            reason_phrase="Forbidden",
            headers=response_headers,
            body=b"IP temporarily blocked. Too many failed attempts.",
        )

    return None
