"""
Two-Factor Authentication (TOTP) handlers for CFMS.

This module provides handlers for setting up, validating, and canceling
two-factor authentication using Time-based One-Time Passwords (TOTP).
"""

import json
import time

from include.classes.auth import Token
from include.classes.connection import ConnectionHandler
from include.classes.request import RequestHandler
from include.conf_loader import global_config
from include.constants import DEFAULT_TOKEN_EXPIRY_SECONDS
from include.database.handler import Session
from include.database.models.classic import User
from include.util.audit import log_audit


class RequestSetup2FAHandler(RequestHandler):
    """
    Handler for setting up two-factor authentication.

    This handler generates a TOTP secret and backup codes for the user.
    The TOTP secret is returned as a provisioning URI that can be used
    to generate a QR code for scanning with authenticator apps.

    Response Data:
        - secret: The TOTP secret (for manual entry)
        - provisioning_uri: URI for QR code generation
        - backup_codes: List of backup codes for account recovery
    """

    data_schema = {
        "type": "object",
        "properties": {"method": {"type": "string", "enum": ["totp"]}},
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        with Session() as session:
            user = session.get(User, handler.username)

            if not user:
                handler.conclude_request(
                    code=404,
                    message="User not found",
                    data={},
                )
                log_audit(
                    "setup_2fa",
                    target=handler.username,
                    result=1,
                    remote_address=handler.remote_address,
                )
                return

            # Check if user already has 2FA enabled
            if user.totp_enabled:
                handler.conclude_request(
                    code=400,
                    message="Two-factor authentication is already enabled. Please cancel it first.",
                    data={
                        "method": "totp"
                    },  # will be extended if other methods are added
                )
                return

            # Setup TOTP
            secret, backup_codes = user.setup_totp()

            handler.conclude_request(
                code=200,
                message="Two-factor authentication setup initiated. Please verify with your authenticator app.",
                data={
                    "secret": secret,
                    "provisioning_uri": user.totp_provisioning_uri,
                    "backup_codes": backup_codes,
                },
            )
            log_audit(
                "setup_2fa",
                target=handler.username,
                result=0,
                remote_address=handler.remote_address,
            )


class RequestValidate2FAHandler(RequestHandler):
    """
    Handler for validating and enabling two-factor authentication.

    After setup, the user must validate their TOTP configuration by
    providing a valid code from their authenticator app. This enables 2FA.
    """

    data_schema = {
        "type": "object",
        "properties": {
            "token": {"type": "string", "minLength": 1},
        },
        "required": ["token"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        token = handler.data["token"]

        with Session() as session:
            user = session.get(User, handler.username)

            if not user:
                handler.conclude_request(
                    code=404,
                    message="User not found",
                    data={},
                )
                log_audit(
                    "validate_2fa",
                    target=handler.username,
                    result=1,
                    remote_address=handler.remote_address,
                )
                return

            # Check if TOTP secret exists but not enabled yet
            if not user.totp_secret:
                handler.conclude_request(
                    code=400,
                    message="Two-factor authentication has not been set up. Please set it up first.",
                    data={},
                )
                return

            if user.totp_enabled:
                handler.conclude_request(
                    code=400,
                    message="Two-factor authentication is already enabled.",
                    data={"method": "totp"},
                )
                return

            # Verify the token
            if user.verify_totp(token):
                user.enable_totp()
                handler.conclude_request(
                    code=200,
                    message="Two-factor authentication enabled successfully",
                    data={"method": "totp"},
                )
                log_audit(
                    "validate_2fa",
                    target=handler.username,
                    result=0,
                    remote_address=handler.remote_address,
                )
            else:
                handler.conclude_request(
                    code=401,
                    message="Invalid verification code",
                    data={},
                )
                log_audit(
                    "validate_2fa",
                    target=handler.username,
                    result=1,
                    remote_address=handler.remote_address,
                )


class RequestDisable2FAHandler(RequestHandler):
    """
    Handler for canceling two-factor authentication.

    This handler disables and removes TOTP configuration for the user.
    The user must provide their password for verification.
    """

    data_schema = {
        "type": "object",
        "properties": {
            "password": {"type": "string", "minLength": 1},
        },
        "required": ["password"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        password = handler.data["password"]

        with Session() as session:
            user = session.get(User, handler.username)

            if not user:
                handler.conclude_request(
                    code=404,
                    message="User not found",
                    data={},
                )
                log_audit(
                    "cancel_2fa",
                    target=handler.username,
                    result=1,
                    remote_address=handler.remote_address,
                )
                return

            # Verify password
            if not user.authenticate_and_create_token(password):
                handler.conclude_request(
                    code=401,
                    message="Invalid password",
                    data={},
                )
                log_audit(
                    "cancel_2fa",
                    target=handler.username,
                    result=1,
                    remote_address=handler.remote_address,
                )
                return

            # Check if 2FA is enabled
            if not user.totp_enabled:
                handler.conclude_request(
                    code=400,
                    message="Two-factor authentication is not enabled",
                    data={"totp_enabled": False},
                )
                return

            # Disable TOTP
            user.disable_totp()

            handler.conclude_request(
                code=200,
                message="Two-factor authentication disabled successfully",
                data={"totp_enabled": False},
            )
            log_audit(
                "cancel_2fa",
                target=handler.username,
                result=0,
                remote_address=handler.remote_address,
            )


class RequestCancel2FASetupHandler(RequestHandler):
    """
    Handler for canceling two-factor authentication setup.

    This handler removes the TOTP configuration that was set up
    but not yet validated/enabled.
    """

    data_schema = {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        with Session() as session:
            user = session.get(User, handler.username)

            if not user:
                handler.conclude_request(
                    code=404,
                    message="User not found",
                    data={},
                )
                return

            # Check if TOTP setup exists but not enabled yet
            if not user.totp_secret or user.totp_enabled:
                handler.conclude_request(
                    code=400,
                    message="No pending two-factor authentication setup to cancel.",
                    data={},
                )
                return

            # Cancel TOTP setup
            user.totp_secret = None
            user.totp_backup_codes = None

            session.add(user)
            session.commit()

            handler.conclude_request(
                code=200,
                message="Two-factor authentication setup canceled successfully",
                data={},
            )


class RequestGet2FAStatusHandler(RequestHandler):
    """
    Handler for getting two-factor authentication status.

    Returns whether 2FA is enabled for the authenticated user.
    """

    data_schema = {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        with Session() as session:
            user = session.get(User, handler.username)

            if not user:
                handler.conclude_request(
                    code=404,
                    message="User not found",
                    data={},
                )
                return

            handler.conclude_request(
                code=200,
                message="Two-factor authentication status",
                data={
                    "enabled": user.totp_enabled,
                    "method": "totp" if user.totp_enabled else None,
                    "backup_codes_count": (
                        len(json.loads(user.totp_backup_codes))
                        if user.totp_backup_codes
                        else 0
                    ),
                },
            )


class RequestVerify2FAHandler(RequestHandler):
    """
    Handler for verifying a 2FA token during login.

    This is used as a second step during the login process when 2FA is enabled.
    It validates the TOTP token and returns a full authentication token if successful.
    """

    data_schema = {
        "type": "object",
        "properties": {
            "username": {"type": "string", "minLength": 1},
            "token": {"type": "string", "minLength": 1},
        },
        "required": ["username", "token"],
        "additionalProperties": False,
    }

    require_auth = False

    def handle(self, handler: ConnectionHandler):
        username = handler.data["username"]
        token = handler.data["token"]

        with Session() as session:
            user = session.get(User, username)

            if not user:
                handler.conclude_request(
                    code=401,
                    message="Invalid credentials",
                    data={},
                )
                log_audit(
                    "verify_2fa_login",
                    target=username,
                    result=1,
                    remote_address=handler.remote_address,
                )
                return

            # Verify the 2FA token
            if not user.verify_totp(token):
                handler.conclude_request(
                    code=401,
                    message="Invalid verification code",
                    data={},
                )
                log_audit(
                    "verify_2fa_login",
                    target=username,
                    result=1,
                    remote_address=handler.remote_address,
                )
                return

            # Generate authentication token
            secret = (
                global_config["server"]["secret_key"]
                if not user.secret_key
                else user.secret_key
            )
            auth_token = Token(secret, user.username)
            auth_token.new(DEFAULT_TOKEN_EXPIRY_SECONDS)

            # Update last login
            user.last_login = time.time()
            session.add(user)
            session.commit()

            handler.conclude_request(
                code=200,
                message="Two-factor authentication successful",
                data={
                    "token": auth_token.raw,
                    "exp": auth_token.exp,
                    "nickname": user.nickname,
                    "avatar_id": user.avatar_id,
                    "permissions": list(user.all_permissions),
                    "groups": list(user.all_groups),
                },
            )
            log_audit(
                "verify_2fa_login",
                target=username,
                result=0,
                remote_address=handler.remote_address,
            )
