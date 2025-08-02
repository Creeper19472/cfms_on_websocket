__all__ = ["RequestHandler"]

from typing import Union
from abc import ABC, abstractmethod

from include.classes.connection import ConnectionHandler


class RequestHandler(ABC):
    """
    Abstract base class for handling requests.
    Attributes:
        data_schema (dict): A dictionary defining the expected schema for request data.
    Methods:
        handle():
            Abstract method to process a request. Must be implemented by subclasses.
            Returns:
                int: Status code.
                tuple[int, str]: Status code and message.
                tuple[int, str, dict]: Status code, message, and additional data.
                tuple[int, str, dict, str]: Status code, message, data, and an extra string.
                tuple[int, str, str]: Status code, message, and an extra string.
                None: (TBD)
    """

    # This property defines the json structure of the request data.
    data_schema: dict = {}

    @abstractmethod
    def handle(self, handler: ConnectionHandler) -> Union[
        int,
        tuple[int, str],
        tuple[int, str, dict],
        tuple[int, str, str],
        tuple[int, str, dict, str],
        None,
    ]:
        pass
