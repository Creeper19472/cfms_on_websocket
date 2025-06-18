#!/usr/bin/env python

"""Client using the threading API."""

from websockets.sync.client import connect
import ssl


def hello():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    with connect("wss://localhost:5104", ssl=ssl_context) as websocket:
        websocket.send("Hello world!")
        message = websocket.recv()
        print(message)


if __name__ == "__main__":
    hello()