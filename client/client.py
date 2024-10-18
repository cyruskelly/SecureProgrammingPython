import os
import dotenv
import asyncio
import json
import websockets
import base64
from websockets.sync.client import connect
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES

class Client:
    def __init__(self, server_url):
        self.server_url = server_url
        try:
            with open("./data/private_key.pem", "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(key_file.read(), password=None)
            with open("./data/public_key.pem", "rb") as key_file:
                self.public_key = serialization.load_pem_public_key(key_file.read())
            with open("./data/private_key.priv", "rb") as key_file:
                self.priv = key_file.read()
            with open("./data/public_key.pub", "rb") as key_file:
                self.pub = key_file.read()
        except FileNotFoundError:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open("./data/private_key.pem", "wb") as key_file:
                key_file.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            pem_public_key = self.private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            self.pub = ""

            for line in pem_public_key.decode('utf-8').split("\n"):
                if "BEGIN" in line:
                    self.pub = self.pub + line + "\n"
                elif "END" in line:
                    self.pub = self.pub + "\n" + line
                else:
                    self.pub = self.pub + line

            with open("./data/public_key.pem", "wb") as key_file:
                key_file.write(pem_public_key)

            with open("./data/public_key.pub", "w") as key_file:
                key_file.write(self.pub)

            pem_priv_key = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
            
            self.priv = ""

            for line in pem_priv_key.split("\n"):
                if "BEGIN" in line:
                    self.priv = self.priv + line + "\n"
                elif "END" in line:
                    self.priv = self.priv + "\n" + line
                else:
                    self.priv = self.priv + line


            with open("./data/private_key.priv", "w") as key_file:
                key_file.write(self.priv)

            self.public_key = self.private_key.public_key()
            self.pub = pem_public_key

    async def connect(self):
        while True:
            try:
                async with websockets.connect(self.server_url) as websocket:
                    self.websocket = websocket
                    await self.server_hello()
                    await self.handle_messages()
            except websockets.exceptions.InvalidURI:
                print("You haven't configured the server URL correctly in the .env file!")
                break
            except ConnectionRefusedError:
                print("The server refused your connection! Are you sure the server is running?")
                await asyncio.sleep(5)  # Retry after 5 seconds
            except websockets.exceptions.ConnectionClosedError as e:
                print(f"Connection closed with error: {e}")
                await asyncio.sleep(5)  # Retry after 5 seconds

    async def handle_messages(self):
        while True:
            try:
                message = await self.websocket.recv()
                try:
                    json_message = json.loads(message)
                except json.JSONDecodeError:
                    print("Received invalid JSON")
                    continue
                if json_message["type"] == "signed_data":
                    # Example signed_data message:
                    # {
                    #     "type": "signed_data",
                    #     "data": {
                    #         "type": "chat",
                    #         "destination_servers": [
                    #             "<Address of each recipient's destination server>",
                    #         ],
                    #         "iv": "<Base64 encoded (AES initialisation vector)>",
                    #         "symm_keys": [
                    #             "<Base64 encoded (AES key encrypted with recipient's public RSA key)>",
                    #         ],
                    #         "chat": "<Base64 encoded (AES ciphertext segment)>"
                    #     }
                    #     "counter": 12345,
                    #     "signature": "<Base64 encoded (signature of (data JSON concatenated with counter))>"
                    # }
                    #




                    data = json_message["data"]
                    counter = json_message["counter"]
                    signature = json_message["signature"]
                    if int(counter) != 12345:
                        print("Received invalid counter")
                        continue
                    if data["type"] == "chat":
                        await self.decode_chat(json_message)

            except websockets.exceptions.ConnectionClosedError as e:
                print(f"Connection closed with error: {e}")
                break

            message = input("What would you like to do (help for options)? ").strip().lower()
            if message == "exit" or message == "e":
                break
            elif message == "chat" or message == "c":
                user_rsa = input("Who would you like to chat with (enter their public RSA key)? ").strip()
                user_rsa = "-----BEGIN PUBLIC KEY-----\n" + user_rsa + "\n-----END PUBLIC KEY-----"
                server = input("What is the server's address? ").strip().lower()
                message = input("What would you like to say? ")
                await self.chat([user_rsa], [server], message)
            elif message == "broadcast" or message == "b":
                message = input("What would you like to broadcast? ")
                await self.broadcast(message)

    async def parse_signed_data(self, data):
        hello_msg = {
            "type": "signed_data",
            "data": data,
            "counter": 12345,
            "signature": base64.b64encode(self.get_signature(json.dumps(data, separators=(',', ':')))).decode('utf-8')
        }

        await self.websocket.send(json.dumps(hello_msg))

    async def server_hello(self):
        data = {
            "type": "hello",
            "public_key": self.get_pub()
        }

        await self.parse_signed_data(data)
    
    async def chat(self, user_rsas, servers, message):
        aes = os.urandom(32)
        iv = os.urandom(16)
        iv64 = base64.b64encode(iv).decode('utf-8')
    
        user_rsas_obj = []
    
        # Convert string to RSA object
        for user_rsa in user_rsas:
            user_rsas_obj.append(load_pem_public_key(user_rsa.encode('utf-8')))
    
        chat = {
            "participants": [self.pub.decode('utf-8')] + user_rsas,
            "message": message
        }

        chat = json.dumps(chat)

        encryptor = Cipher(
            algorithms.AES(aes),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        cipher = encryptor.update(chat.encode('utf-8')) + encryptor.finalize()

        aes_encrypted_message = base64.b64encode(cipher + encryptor.tag).decode('utf-8')
        
        # symm_key is "<Base64 encoded (AES key encrypted with recipient's public RSA key)>",
        symm_keys = []
        for user_rsa in user_rsas_obj:
            symm_key = user_rsa.encrypt(aes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            symm_keys.append(base64.b64encode(symm_key).decode('utf-8'))
    
        data = {
            "type": "chat",
            "destination_servers": servers,
            "iv": iv64,
            "symm_keys": symm_keys,
            "chat": aes_encrypted_message
        }
    
        await self.parse_signed_data(data)

    async def decode_chat(self, json_message):
        # Example signed_data message:
        # {
        #     "type": "signed_data",
        #     "data": {
        #         "type": "chat",
        #         "destination_servers": [
        #             "<Address of each recipient's destination server>",
        #         ],
        #         "iv": "<Base64 encoded (AES initialisation vector)>",
        #         "symm_keys": [
        #             "<Base64 encoded (AES key encrypted with recipient's public RSA key)>",
        #         ],
        #         "chat": "<Base64 encoded (AES ciphertext segment)>"
        #     }
        #     "counter": 12345,
        #     "signature": "<Base64 encoded (signature of (data JSON concatenated with counter))>"
        # }
        #
        # We need to decrypt the AES ciphertext segment using the AES key encrypted with our public RSA key
        # and the AES initialisation vector

        data = json_message["data"]
        iv = base64.b64decode(data["iv"])
        ciphertag = base64.b64decode(data["chat"])
        symm_keys64 = data.get('symm_keys', [])
        cipher = ciphertag[:-16]
        tag = ciphertag[-16:]

        for symm_key in symm_keys64:
            try:
                symm_key = base64.b64decode(symm_key.encode('utf-8'))
                decrypted_symm_key = self.private_key.decrypt(
                    symm_key,
                    padding.OAEP (
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                decryption = Cipher(
                    algorithms.AES(decrypted_symm_key),
                    modes.GCM(iv, tag),
                    backend=default_backend()
                ).decryptor()
                chat_message = decryption.update(cipher) + decryption.finalize()
                chat = json.loads(chat_message.decode('utf-8'))
                print("\nChat message from:", chat["participants"][0])
                print("Message:\n", chat["message"])
                print()
                break
            except ConnectionAbortedError:
                print("Could not decrypt message")
                continue





    def get_signature(self, data):
        data = data.encode('utf-8')
        counter = self.get_counter().encode('utf-8')
        signature = base64.b64encode(
            self.private_key.sign(
                data + counter,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        )
        return signature

    def get_fingerprint(self):
        return self.private_key.public_key().fingerprint(hashes.SHA256()).hex()

    def get_pub(self):
        return self.pub.decode('utf-8')
    
    def get_priv(self):
        return self.priv.decode('utf-8')
    
    def get_public_key(self):
        return self.public_key
    
    def get_counter(self, add=True):
        with open("./data/counter.txt", "r") as f:
            counter = f.read().strip()
        int_counter = int(counter)
        if not add:
            counter = str(int_counter + 1)
            with open("./data/counter.txt", "w") as f:
                f.write(counter)
        return counter
    

dotenv.load_dotenv()
server_url = os.getenv('SERVER_URL')
if not server_url:
    raise ValueError("SERVER_URL environment variable is not set")
client = Client(server_url)
asyncio.run(client.connect())

