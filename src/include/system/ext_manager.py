__all__ = ["pm", "load_extensions_from_directory"]

from typing import Dict, Type, Optional, Set, Union, TYPE_CHECKING
import os
import importlib.util
from venv import logger
import pluggy
import websockets.sync.server
from include.util.log import getCustomLogger

if TYPE_CHECKING:
    from include.classes.request import RequestHandler
    from include.classes.handler import ConnectionHandler

hookspec = pluggy.HookspecMarker("cfms")
hookimpl = pluggy.HookimplMarker("cfms")

logger = getCustomLogger(
    "ExtensionManager", filepath="./content/logs/extension_manager.log"
)


# ext = extension
class ServerHookSpecs:
    """Hook specifications for server extensions."""

    @hookspec
    def ext_register_handlers(self) -> Dict[str, Type["RequestHandler"]]:
        """
        Register handlers for specific actions.

        Should return a dictionary mapping action names to their
        corresponding RequestHandler classes.
        """
        ...

    @hookspec
    def ext_unregister_handlers(self) -> Set[str]:
        """
        Unregister handlers for specific actions.

        Should return a set of action names whose handlers should
        be unregistered.
        """
        ...

    @hookspec
    def ext_register_whitelisted_actions(self) -> Set[str]:
        """
        Register actions that should be whitelisted (allowed even
        during lockdown).

        Should return a set of action names.
        """
        ...

    @hookspec
    def ext_on_connect(self, websocket: websockets.sync.server.ServerConnection):
        """
        Triggered when a new client connects, providing the websocket
        connection object.
        """

    @hookspec
    def ext_post_disconnect(self):
        """
        Triggered after a client disconnects, regardless of
        the reason.
        """

    @hookspec(firstresult=True)
    def ext_pre_request(
        self, request_handler: "RequestHandler", connection_handler: "ConnectionHandler"
    ) -> Optional[bool]:
        """
        Triggered before processing a request.

        If any extension returns False, the request will be rejected
        immediately.
        """

    @hookspec
    def ext_post_request(
        self,
        action: str,
        handler: "ConnectionHandler",
        callback: Union[
            int,
            tuple[int, Optional[str]],
            tuple[int, Optional[str], dict],
            tuple[int, Optional[str], str],
            tuple[int, Optional[str], dict, str],
            None,
        ],
        time_cost: float,
    ) -> None: ...

    @hookspec
    def ext_on_file_uploaded(self, path: str):
        """
        Triggered when a file is uploaded to the server,
        providing the filename.
        """


def load_extensions_from_directory(extension_dir: str):

    if not os.path.exists(extension_dir):
        logger.warning(
            f"Extension directory '{extension_dir}' does not exist. Skipping."
        )
        return

    for filename in os.listdir(extension_dir):
        if filename.endswith(".py") and not filename.startswith(("_", ".")):
            ext_name = filename[:-3]  # remove .py extension
            ext_path = os.path.join(extension_dir, filename)

            try:
                spec = importlib.util.spec_from_file_location(ext_name, ext_path)
                if spec is None or spec.loader is None:
                    logger.error(f"Failed to load spec for extension: {ext_name}")
                    continue

                module = importlib.util.module_from_spec(spec)

                spec.loader.exec_module(module)
                pm.register(module, name=ext_name)

                logger.info(f"Loaded extension: {ext_name}")

            except Exception as e:
                logger.error(
                    f"Failed to load extension '{ext_name}': {e}", exc_info=True
                )


pm = pluggy.PluginManager("cfms")
pm.add_hookspecs(ServerHookSpecs)
