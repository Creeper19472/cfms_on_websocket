from include.classes.connection import ConnectionHandler
from include.database.handler import Session
from include.database.models.general import User
from include.function.audit import log_audit
import time


def handle_login(handler: ConnectionHandler):
    """
    Handles user login requests.
    This function processes a login request by extracting the username and password from the handler's data,
    validates the credentials against the database, and generates an authentication token if successful.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200   - Login successful, returns a token in the response data.
        400 - Missing username or password in the request.
        401 - Invalid credentials.
        500 - Internal server error, with the exception message.
    """

    try:
        # Parse the login request
        username = handler.data.get("username")
        password = handler.data.get("password")

        with Session() as session:
            user = session.get(User, username)

            response_invalid = {
                "code": 401,
                "message": "Invalid credentials",
                "data": {},
            }

            if not username or not password:
                response = {
                    "code": 400,
                    "message": "missing username or password",
                    "data": {},
                }
            elif user:
                if token := user.authenticate_and_create_token(password):
                    response = {
                        "code": 200,
                        "message": "Login successful",
                        "data": {
                            "token": token.raw,
                            "exp": token.exp,
                            "nickname": user.nickname,
                            "permissions": list(user.all_permissions),
                            "groups": list(user.all_groups),
                        },
                    }
                else:
                    response = response_invalid
            else:
                response = response_invalid

        if response == response_invalid:
            time.sleep(3)

        # Send the response back to the client
        handler.conclude_request(**response)
        return response["code"], username

    except Exception as e:
        handler.logger.error(f"Error detected when handling requests.", exc_info=True)
        handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})


def handle_refresh_token(handler: ConnectionHandler):
    """
    Handles token refresh requests.
    This function processes a token refresh request by validating the existing token and generating a new one if valid.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200   - Token refreshed successfully, returns a new token in the response data.
        400 - Missing or invalid token in the request.
        500 - Internal server error, with the exception message.
    """

    try:
        # Parse the refresh token request
        old_token = handler.token

        # Validate the token
        if not old_token or not isinstance(old_token, str):
            response = {"code": 400, "message": "missing or invalid token", "data": {}}
        else:
            with Session() as session:
                user = session.get(User, handler.username)

                if user and user.is_token_valid(old_token):
                    new_token = user.renew_token()
                    response = {
                        "code": 200,
                        "message": "Token refreshed successfully",
                        "data": {"token": new_token.raw, "exp": new_token.exp},
                    }
                    log_audit(
                        "refresh_token",
                        target=handler.username,
                        result=0,
                        remote_address=handler.remote_address,
                    )
                else:
                    response = {
                        "code": 400,
                        "message": "Invalid or expired token",
                        "data": {},
                    }
                    log_audit(
                        "refresh_token",
                        target=handler.username,
                        result=1,
                        remote_address=handler.remote_address,
                    )

        # Send the response back to the client
        handler.conclude_request(**response)

    except Exception as e:
        handler.logger.error(f"Error detected when handling requests.", exc_info=True)
        handler.conclude_request(**{"code": 500, "message": str(e), "data": {}})
