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

class Client:
    def __init__(self, server_url):
        self.server_url = server_url
        try:
            
            with open("./data/private_key.pem", "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(key_file.read(), password=None)
            f = open("./data/public_key.pem", "rb")
            self.pub = f.read()
            f.close()
            with open("./data/public_key.pub", "rb") as key_file:
                self.public_key = serialization.load_pem_public_key(key_file.read())
        except FileNotFoundError:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            f = open("./data/private_key.pem", "w")
            f.close()
            f = open("./data/private_key.pem", "wb")
            f.write(self.private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
            f.close()
            


            pem_public_key = self.private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            
            f = open("./data/public_key.pem", "w")
            f.close()
            f = open("./data/public_key.pem", "wb")

            f.write(pem_public_key)

            f.close()

            f = open("./data/public_key.pub", "w")

            for line in str(pem_public_key).split("\\n"):
                if line[0] == "b" and line[1] == "'":
                    f.write("-----BEGIN PUBLIC KEY-----\n")
                elif line[-1] == "-":
                    f.write("\n-----END PUBLIC KEY-----")
                elif line[-1] == "'":
                    pass
                else:
                    f.write(line)
            
            self.public_key = pem_public_key

            f.close()

            # Read the public key again but formatted correctly
            f = open("./data/public_key.pem", "rb")
            self.pub = f.read()
            f.close()

        try:
            self.websocket = connect(self.server_url)
        except websockets.exceptions.InvalidURI:
            print("You haven't configured the server URL correctly in the .env file!")
            return
        except ConnectionRefusedError:
            print("The server refused your connection! Are you sure the server is running?")
            return
        
        self.server_hello()
        
        while True:
            message = input("What would you like to do? (help for options)").strip().lower()
            if message == "exit" or message == "e":
                break
            elif message == "chat" or message == "c":
                user_rsa = input("Who would you like to chat with (enter their public RSA key)? ").strip()
                user_rsa = "-----BEGIN PUBLIC KEY-----\n" + user_rsa + "\n-----END PUBLIC KEY-----"
                server = input("What is the server's IP? ")
                message = input("What would you like to say? ")
                ## This is where you'd ask for more users to chat with
                self.chat([user_rsa], [server], message)
            elif message == "broadcast" or message == "b":
                message = input("What would you like to broadcast? ")
                self.broadcast(message)

    def parse_signed_data(self, data):
        hello_msg = {
            "type": "signed_data",
            "data": data,
            "counter": 12345,
            "signature:": self.get_signature(json.dumps(data, separators=(',', ':')))
        }

        self.websocket.send(json.dumps(hello_msg))

    def server_hello(self):
        data = {
            "type": "hello",
            "public_key": self.get_pub()
        }

        self.parse_signed_data(data)

    def chat(self, user_rsas, servers, message):
        iv = os.urandom(16)

        user_rsas_obj = []

        # convert string to RSA object
        for user_rsa in user_rsas:
            user_rsas_obj.append(load_pem_public_key(bytes(user_rsa.encode('utf-8'))))

        aes_encrypted_message = base64.b64encode(
            self.get_public_key().encrypt(
                message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        ).decode('utf-8')

        # symm_key is "<Base64 encoded (AES key encrypted with recipient's public RSA key)>",
        symm_keys = []
        for user_rsa in user_rsas_obj:
            symm_key = user_rsa.encrypt(iv, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            symm_keys.append(base64.b64encode(symm_key).decode('utf-8'))
        data = {
            "type": "chat",
            "destination_servers": servers,
            "iv": base64.b64encode(iv).decode('utf-8'),
            "symm_keys": symm_keys,
            "chat": aes_encrypted_message
        }

        self.parse_signed_data(data)

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
        return signature.decode('utf-8')

    def get_pub(self):
        return str(self.pub)
    
    def get_public_key(self):
        return self.public_key
    
    def get_counter(self):
        f = open("./data/counter.txt", "r")
        counter = f.read()
        f.close()
        return counter


dotenv.load_dotenv()
print(os.getenv('SERVER_URL'))
c = Client(os.getenv('SERVER_URL'))

