__all__ = ["pm", "load_plugins_from_dir"]

import importlib.util
import pathlib

import pluggy
from typing import Dict, Type, Optional, Set
from include.classes.handler import ConnectionHandler
from include.classes.request import RequestHandler
from include.classes.enum.permissions import Permissions
import websockets.sync.server

hookspec = pluggy.HookspecMarker("cfms")
hookimpl = pluggy.HookimplMarker("cfms")


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
        self, action: str, handler: ConnectionHandler, result: tuple, time_cost: float
    ):
        """在请求处理完毕，准备写入审计日志时触发。可用于 Prometheus 监控打点等操作"""


def load_plugins_from_dir(pm: pluggy.PluginManager, plugin_dir: str):
    path = pathlib.Path(plugin_dir)

    for file_path in path.glob("*.py"):
        if file_path.name == "__init__.py":
            continue

        module_name = f"extensions.{file_path.stem}"

        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            pm.register(module)
            print(f"成功导入并注册插件: {file_path.name}")


pm = pluggy.PluginManager("cfms")
pm.add_hookspecs(ServerHookSpecs)

# (可选) 你可以在这里加载你自己的内置插件或第三方插件
# pm.register(MyCorePlugin())
