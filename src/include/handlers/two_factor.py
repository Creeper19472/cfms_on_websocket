"""
Two-Factor Authentication (TOTP) handlers for CFMS.

This module provides handlers for setting up, validating, and canceling
two-factor authentication using Time-based One-Time Passwords (TOTP).
"""

import json
import time

from include.classes.connection import ConnectionHandler
from include.classes.request import RequestHandler
from include.constants import FAILED_LOGIN_DELAY_SECONDS
from include.database.handler import Session
from include.database.models.classic import User


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
                return 404, handler.username

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
            return 200, handler.username


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
                return 404, handler.username

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
                return 200, handler.username
            else:
                handler.conclude_request(
                    code=401,
                    message="Invalid verification code",
                    data={},
                )
                return 401, handler.username


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
                return 404, handler.username

            # Check if 2FA is enabled
            if not user.totp_enabled:
                handler.conclude_request(
                    code=400,
                    message="Two-factor authentication is not enabled",
                )
                return
            
            # Verify password
            if not user.authenticate_and_create_token(password):
                time.sleep(FAILED_LOGIN_DELAY_SECONDS)  # Mitigate brute-force attacks

                handler.conclude_request(
                    code=401,
                    message="Invalid password",
                    data={},
                )
                return 401, handler.username

            # Disable TOTP
            user.disable_totp()

            handler.conclude_request(
                code=200,
                message="Two-factor authentication disabled successfully",
            )
            return 200, handler.username


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
        "properties": {
            "target": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):

        target_username = handler.data.get("target") or handler.username

        with Session() as session:
            user = session.get(User, handler.username)
            target = session.get(User, target_username)

            if not target:
                handler.conclude_request(
                    code=404,
                    message="Target user not found",
                    data={},
                )
                return
            
            assert user is not None

            if (
                target_username != handler.username
                and "manage_2fa" not in user.all_permissions
            ):
                handler.conclude_request(
                    code=403,
                    message="Forbidden: Cannot access another user's two-factor authentication status",
                    data={},
                )
                return 403, target_username, handler.username

            handler.conclude_request(
                code=200,
                message="Two-factor authentication status",
                data={
                    "enabled": target.totp_enabled,
                    "method": "totp" if target.totp_enabled else None,
                    "backup_codes_count": (
                        len(json.loads(target.totp_backup_codes))
                        if target.totp_backup_codes
                        else 0
                    ),
                },
            )
