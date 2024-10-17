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


class Client:
    def __init__(self, server_url):
        self.server_url = server_url
        try:
            
            with open("path/to/key.pem", "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(key_file.read(), password=None)
            f = open("./data/public_key.pem", "rb")
            self.public_key = f.read()
            f.close()
        except FileNotFoundError:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            f = open("./data/private_key.pem", "w")
            f.write(str(self.private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())))
            f.close()


            pem_public_key = self.private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
            
            f = open("./data/public_key.pem", "w")

            for line in str(pem_public_key).split("\\n"):
                if line[0] == "b" and line[1] == "'":
                    f.write("-----BEGIN PUBLIC KEY-----\n")
                elif line[-1] == "-":
                    f.write("\n-----END PUBLIC KEY-----")
                elif line[-1] == "'":
                    pass
                else:
                    f.write(line)
            
            f.close()

            # Read the public key again but formatted correctly
            f = open("./data/public_key.pem", "rb")
            self.public_key = f.read()
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
        

    def parse_json(self, json):
        pass

    def server_hello(self):
        data = {
            "type": "hello",
            "public_key": self.get_public_key()
        }

        hello_msg = {
            "type": "signed_data",
            "data": data,
            "counter": 12345,
            "signature:": self.get_signature(json.dumps(data, separators=(',', ':')))
        }

        self.websocket.send(json.dumps(hello_msg))


    def get_signature(self, data):
        data = data.encode('utf-8')
        counter = self.get_counter().encode('utf-8')
        signature = base64.b64encode(self.private_key.sign(data + counter, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()))
        return signature.decode('utf-8')

    def get_public_key(self):
        return str(self.public_key)
    
    def get_counter(self):
        f = open("./data/counter.txt", "r")
        counter = f.read()
        f.close()
        return counter


dotenv.load_dotenv()
print(os.getenv('SERVER_URL'))
c = Client(os.getenv('SERVER_URL'))

