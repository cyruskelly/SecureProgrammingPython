import websockets
import json
import os
import dotenv
import asyncio
from websockets.asyncio.server import serve


class Server:
    def __init__(self, server_url):
        self.server_url = server_url

    async def start(self):
        self.server = await serve(self.handler, self.server_url, 8000)
        await self.server.wait_closed()

    async def handler(self, websocket):
        print("Connection established with", websocket.remote_address)
        try:
            async for message in websocket:
                print("Received message:", message)
                data = json.loads(message)
                if data["type"] == "signed_data":
                    if data["data"]["type"] == "hello":
                        print("Received hello message from", websocket.remote_address)
                        await self.server_hello(websocket, data)
                else:
                    print("Received unknown message type from", websocket.remote_address)
        except websockets.exceptions.ConnectionClosedError:
            print("Connection closed by", websocket.remote_address)
        except json.JSONDecodeError:
            print("Received invalid JSON from", websocket.remote_address)
        except Exception as e:
            print("An unexpected error occurred:", e)

    async def server_hello(self, websocket, data):
        print("Sending hello message to", websocket.remote_address)
        hello_msg = {
            "type": "hello",
            "public_key": data
        }

        await websocket.send(json.dumps(hello_msg))

async def main():
    server = Server(os.getenv("SERVER_URL"))
    await server.start()

dotenv.load_dotenv()
asyncio.run(main())