import os
import threading
from typing import Optional, Union

from include.classes.enum.permissions import Permissions
from include.classes.request import RequestHandler
from include.conf_loader import global_config
from include.classes.handler import ConnectionHandler
from include.constants import CORE_VERSION, PROTOCOL_VERSION
from include.database.handler import Session
from include.database.models.classic import User
from include.shared import lockdown_enabled
from include.system.plugin_manager import hookimpl
from include.util.log import getCustomLogger

logger = getCustomLogger("BuiltinExtension", filepath="./content/logs/connection.log")


class RequestServerInfoHandler(RequestHandler):
    """
    Handle the 'server_info' action to return server information.

    Args:
        this_handler: The ConnectionHandler instance handling the request.
    """

    data_schema = {"type": "object", "properties": {}, "additionalProperties": False}

    def handle(self, handler: ConnectionHandler):

        server_info = {
            "server_name": global_config["server"]["name"],
            "version": CORE_VERSION.original,
            "protocol_version": PROTOCOL_VERSION,
            "lockdown": lockdown_enabled.is_set(),
        }
        handler.conclude_request(
            200, server_info, "Server information retrieved successfully"
        )
        return


class RequestShutdownHandler(RequestHandler):
    """
    Handle the 'shutdown' action to gracefully shut down the server.

    Args:
        this_handler: The ConnectionHandler instance handling the request.
    """

    data_schema = {"type": "object", "properties": {}, "additionalProperties": False}
    require_auth = True

    def handle(self, handler: ConnectionHandler):

        with Session() as session:
            user = session.get(User, handler.username)
            assert user is not None

            if Permissions.SHUTDOWN not in user.all_permissions:
                handler.conclude_request(403, {}, "Permission denied")
                return

        # Shutdown the server
        handler.conclude_request(200, {}, "Server is shutting down")
        logger.info("Server is shutting down")
        threading.Thread(target=os._exit(0), daemon=True).start()


@hookimpl
def ext_register_handlers():
    return {"server_info": RequestServerInfoHandler, "shutdown": RequestShutdownHandler}


@hookimpl
def ext_post_request(
    action: str,
    handler: ConnectionHandler,
    callback: Union[
        int,
        tuple[int, Optional[str]],
        tuple[int, Optional[str], dict],
        tuple[int, Optional[str], str],
        tuple[int, Optional[str], dict, str],
        None,
    ],
    time_cost: float,
) -> None:
    logger.debug(f"Handled action '{action}' in {time_cost:.3f} seconds")
