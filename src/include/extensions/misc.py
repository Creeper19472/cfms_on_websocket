from include.classes.request import RequestHandler
from include.conf_loader import global_config
from include.classes.handler import ConnectionHandler
from include.constants import CORE_VERSION, PROTOCOL_VERSION
from include.shared import lockdown_enabled
from include.system.plugin_manager import hookimpl


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


@hookimpl
def ext_register_handlers():
    return {"server_info": RequestServerInfoHandler}
