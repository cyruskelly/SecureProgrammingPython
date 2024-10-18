import websockets
import json
import os
import dotenv
import asyncio
from websockets import serve

class Server:
    def __init__(self, server_url, port=8000):
        self.server_url = server_url
        self.port = port
        self.clients = []
        self.other_servers = []

        with open("./data/server_list.txt", "r") as f:
            for line in f:
                self.other_servers.append(line.strip())

    async def start(self):
        self.server = await serve(self.handler, self.server_url, self.port)
        print("Server started at", self.server_url + ":" + str(self.port))
        await self.server.wait_closed()

    async def handler(self, websocket, path):
        print("Connection established with", websocket.remote_address)
        self.clients.append(websocket)
        try:
            async for message in websocket:
                print("Received message:", message)
                data = json.loads(message)
                if data["type"] == "signed_data":
                    # Decode the nested JSON string in the "data" field
                    if data["data"] is dict:
                        nested_data = json.loads(data["data"])
                    else:
                            nested_data = data["data"]
                    if nested_data["type"] == "hello":
                        print("Received hello message from", websocket.remote_address)
                        await self.server_hello(websocket, nested_data)
                    elif nested_data["type"] == "chat":
                        print("Received chat message from", websocket.remote_address)
                        await self.server_chat(websocket, data)
                else:
                    print("Received unknown message type from", websocket.remote_address)
        except websockets.exceptions.ConnectionClosedError:
            print("Connection closed by", websocket.remote_address)
        except json.JSONDecodeError:
            print("Received invalid JSON from", websocket.remote_address)
        except Exception as e:
            print("An unexpected error occurred:", e)
        finally:
            self.clients.remove(websocket)

    async def server_hello(self, websocket, data):
        print("Sending hello message to", websocket.remote_address)
        hello_msg = {
            "type": "hello",
            "public_key": data["public_key"]
        }
        # await websocket.send(json.dumps(hello_msg))

    async def server_chat(self, websocket, data):

        nested_data = json.loads(data["data"])
        if self.server_url + ":" + str(self.port) in nested_data["destination_servers"]:
            print("Relaying message to all clients")
            for client in self.clients:
                await client.send(json.dumps(data))
        
        other_servers = False
        for server in nested_data["destination_servers"]:
            if server != self.server_url + ":" + str(self.port):
                other_servers = True
                break
        
        if other_servers:
            print("Relaying message to other servers")
            for server in self.other_servers:
                async with websockets.connect(server) as other_server:
                    await other_server.send(json.dumps(data))

async def main():
    dotenv.load_dotenv()
    server_url = os.getenv("SERVER_URL")
    port = int(os.getenv("PORT", 8000))
    if not server_url:
        raise ValueError("SERVER_URL environment variable is not set")
    server = Server(server_url, port)
    await server.start()

asyncio.run(main())
"""
    def verify_signature(self, data, signature):
        data = data.encode('utf-8')
        counter = str(12345).encode('utf-8')  # Use the correct counter value
        try:
            self.public_key.verify(
                base64.b64decode(signature),
                data + counter,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False"""