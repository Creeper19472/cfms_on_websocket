import time

from include.classes.connection import ConnectionHandler
from include.classes.request import RequestHandler
from include.conf_loader import global_config
from include.constants import FAILED_LOGIN_DELAY_SECONDS
from include.database.handler import Session
from include.database.models.keyring import UserKey
from include.database.models.classic import User
from include.util.audit import log_audit
from include.util.pwd import check_passwd_requirements


class RequestLoginHandler(RequestHandler):
    """
    Handles user login requests.
    This util processes a login request by extracting the username and password from the handler's data,
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

    data_schema = {
        "type": "object",
        "properties": {
            "username": {"type": "string", "minLength": 1},
            "password": {"type": "string", "minLength": 1},
            "2fa_token": {"type": "string", "minLength": 1},
        },
        "required": ["username", "password"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        username: str = handler.data["username"]
        password: str = handler.data["password"]
        two_factor_auth_token: str = handler.data.get("2fa_token", "")

        cfg = global_config["security"]
        response_invalid = {"code": 401, "message": "Invalid credentials", "data": {}}
        should_delay = False

        with Session() as session:
            user = session.get(User, username)

            if not user:
                response = response_invalid
                should_delay = True
            else:
                token = user.authenticate_and_create_token(password)
                if not token:
                    response = response_invalid
                    should_delay = True
                else:
                    # enforce password policy (force change)
                    try:
                        check_passwd_requirements(
                            password,
                            cfg["passwd_min_length"],
                            cfg["passwd_max_length"],
                            cfg["passwd_must_contain"],
                        )
                    except ValueError:
                        handler.conclude_request(
                            403, {}, "Password must be changed before you can log in"
                        )
                        return 403, username

                    # enforce password expiration
                    if (
                        cfg["enable_passwd_force_expiration"]
                        and time.time() - user.passwd_last_modified
                        > 3600 * 24 * cfg["passwd_expire_after_days"]
                    ):
                        handler.conclude_request(
                            403, {}, "Password should be changed because it's expired"
                        )
                        return 403, username

                    success_data = {
                        "token": token.raw,
                        "exp": token.exp,
                        "nickname": user.nickname,
                        "avatar_id": user.avatar_id,
                        "permissions": list(user.all_permissions),
                        "groups": list(user.all_groups),
                    }

                    # Return the preference keyring key if one is set, so clients
                    # can transparently retrieve the config-encryption DEK.
                    preference_dek = (
                        session.get(UserKey, user.preference_dek_id)
                        if user.preference_dek_id
                        else None
                    )
                    if preference_dek:
                        success_data["preference_dek"] = {
                            "key_id": preference_dek.id,
                            "key_content": preference_dek.content,
                            "label": preference_dek.label,
                        }

                    if user.totp_enabled:
                        if not two_factor_auth_token:
                            response = {
                                "code": 202,
                                "message": "Two-factor authentication required",
                                "data": {"method": "totp"},
                            }
                        elif not user.verify_totp(two_factor_auth_token):
                            response = {
                                "code": 401,
                                "message": "Invalid two-factor authentication token",
                                "data": {},
                            }
                            should_delay = True
                        else:
                            response = {
                                "code": 200,
                                "message": "Login successful",
                                "data": success_data,
                            }
                    else:
                        response = {
                            "code": 200,
                            "message": "Login successful",
                            "data": success_data,
                        }

        if should_delay:
            time.sleep(FAILED_LOGIN_DELAY_SECONDS)

        handler.conclude_request(**response)
        return response["code"], username


class RequestRefreshTokenHandler(RequestHandler):
    """
    Handles token refresh requests.
    This util processes a token refresh request by validating the existing token and generating a new one if valid.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200   - Token refreshed successfully, returns a new token in the response data.
        400 - Missing or invalid token in the request.
        500 - Internal server error, with the exception message.
    """

    data_schema = {"type": "object", "properties": {}, "additionalProperties": False}

    def handle(self, handler: ConnectionHandler):

        # Parse the refresh token request
        old_token = handler.token

        # Validate the token
        if not old_token or not isinstance(old_token, str):
            response = {
                "code": 400,
                "message": "missing or invalid token",
                "data": {},
            }
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
