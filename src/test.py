#!/usr/bin/env python

"""Client using the threading API."""

import json
import ssl

from websockets.sync.client import connect

print("Hello world! Client")

def hello():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    with connect("wss://localhost:5104", ssl=ssl_context) as websocket:
        # echo
        request = {
            "action": "echo",
            "data": {
                "message": "Hello world!"
            }
        }
        websocket.send(json.dumps(request, ensure_ascii=False))
        message = websocket.recv()
        print(message)

        with open("admin_password.txt", "r", encoding="utf-8") as f:
            password = f.read().strip()

        # login
        request = {
            "action": "login",
            "data": {
                "username": "admin",
                "password": password,
            }
        }
        websocket.send(json.dumps(request, ensure_ascii=False))
        message = websocket.recv()
        data = json.loads(message).get("data", {})

        # get_document
        request = {
            "action": "get_document",
            "data": {
                "document_id": "hello"
            },
            "username": "admin",
            "token": data.get("token", "")
        }
        websocket.send(json.dumps(request, ensure_ascii=False))
        message = websocket.recv()
        print(message)

        # create_document
        request = {
            "action": "create_document",
            "data": {
                "title": "Hello World"
            },
            "username": "admin",
            "token": data.get("token", "")
        }
        websocket.send(json.dumps(request, ensure_ascii=False))
        message = websocket.recv()
        print(message)

        # shutdown
        request = {
            "action": "shutdown",
            "username": "admin",
            "token": data.get("token", "")
        }
        websocket.send(json.dumps(request, ensure_ascii=False))
        message = websocket.recv()
        print(message)


if __name__ == "__main__":
    hello()