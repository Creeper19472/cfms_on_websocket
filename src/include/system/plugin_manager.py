__all__ = ["pm"]

from typing import Dict, Type, Optional, Set, Union
import os
import importlib.util
from venv import logger
import pluggy
import websockets.sync.server
from include.classes.handler import ConnectionHandler
from include.classes.request import RequestHandler
from include.classes.enum.permissions import Permissions
from include.util.log import getCustomLogger

hookspec = pluggy.HookspecMarker("cfms")
hookimpl = pluggy.HookimplMarker("cfms")

logger = getCustomLogger("PluginManager", filepath="./content/logs/plugin_manager.log")


# ext = extension
class ServerHookSpecs:
    """Hook specifications for the CFMS WebSocket server plugins."""

    @hookspec
    def ext_register_handlers(self) -> Dict[str, Type[RequestHandler]]:
        """
        注册自定义的 Request Handlers。
        返回字典: {"action_name": RequestHandlerClass}
        """
        ...

    @hookspec
    def ext_register_whitelisted_actions(self) -> Set[str]:
        """
        Register actions that should be whitelisted (allowed even during lockdown).
        Should return a set of action names.
        """
        ...

    @hookspec
    def ext_on_connect(self, websocket: websockets.sync.server.ServerConnection):
        """当客户端建立连接时触发"""

    @hookspec
    def ext_on_disconnect(self, websocket: websockets.sync.server.ServerConnection):
        """当客户端断开连接时触发"""

    @hookspec(firstresult=True)
    def ext_pre_request(self, handler: ConnectionHandler) -> Optional[bool]:
        """
        在请求被处理前触发。
        如果返回 True，则表示插件已接管或拒绝了该请求（已调用 conclude_request），核心逻辑应中止。
        """

    @hookspec(firstresult=True)
    def ext_authenticate(self, username: str, token: str) -> Optional[Set[Permissions]]:
        """
        自定义鉴权钩子。由于设置了 firstresult=True，
        第一个成功返回权限集合的插件将终止其他鉴权插件的调用。
        如果验证失败，应返回 None。
        """

    @hookspec
    def ext_post_request(
        self,
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
        ...


def load_plugins_from_directory(plugin_dir: str):

    if not os.path.exists(plugin_dir):
        logger.warning(f"Plugin directory '{plugin_dir}' does not exist. Skipping.")
        return

    for filename in os.listdir(plugin_dir):
        if filename.endswith(".py") and not filename.startswith(("_", ".")):
            plugin_name = filename[:-3]  # remove .py extension
            plugin_path = os.path.join(plugin_dir, filename)

            try:
                spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
                if spec is None or spec.loader is None:
                    logger.error(f"Failed to load spec for plugin: {plugin_name}")
                    continue

                module = importlib.util.module_from_spec(spec)

                spec.loader.exec_module(module)
                pm.register(module, name=plugin_name)

                logger.info(f"Successfully loaded CFMS plugin: {plugin_name}")

            except Exception as e:
                logger.error(
                    f"Failed to load plugin '{plugin_name}': {e}", exc_info=True
                )


pm = pluggy.PluginManager("cfms")
pm.add_hookspecs(ServerHookSpecs)
