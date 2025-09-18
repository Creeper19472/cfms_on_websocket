import logging
from logging.handlers import RotatingFileHandler

"""
Provides a utility util to create and configure a custom logger with both file and console handlers.
Functions:
    getCustomLogger(logname, level=(logging.DEBUG, logging.INFO), filepath="default.log"):
        Creates and returns a logger with the specified name, log levels, and file path.
        The logger writes logs to both a rotating file and the console, each with its own format and log level.
        Args:
            logname (str): The name of the logger.
            level (tuple): A tuple of two logging levels. The first is for the file handler, the second for the console handler.
                Defaults to (logging.DEBUG, logging.INFO).
            filepath (str): The path to the log file for the file handler. Defaults to "default.log".
        Returns:
            logging.Logger: The configured logger instance.
"""


def getCustomLogger(
    logname: str, level: tuple=(logging.DEBUG, logging.INFO), filepath="default.log"
):
    logger = logging.getLogger(logname)
    logger.setLevel(level=logging.DEBUG)  # This level must be 'logging.DEBUG'.
    logger.propagate = False
    lfhandler = RotatingFileHandler(filename=filepath, maxBytes=10485760, backupCount=1)
    cshandler = logging.StreamHandler()
    formatter1 = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    formatter2 = logging.Formatter("[%(asctime)s %(levelname)s] %(message)s")
    lfhandler.setLevel(level[0])
    cshandler.setLevel(level[1])
    lfhandler.setFormatter(formatter1)
    cshandler.setFormatter(formatter2)
    logger.addHandler(lfhandler)
    logger.addHandler(cshandler)

    return logger
