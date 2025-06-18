#!/usr/bin/env python

"""Client using the threading API."""

from websockets.sync.client import connect
import ssl, json

print("Hello world! Client")

def hello():
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    with connect("wss://localhost:5104", ssl=ssl_context) as websocket:
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