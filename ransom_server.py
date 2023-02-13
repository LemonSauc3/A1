# Cryptography imports for encrypting the keys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# Importing socketserver to create the server aspect for TCP/IP
import socketserver

# Using Fetnet to generate a token for the key
symmetricKey = Fernet.generate_key()
FernetInstance = Fernet(symmetricKey)


class ClientHandler(socketserver.BaseRequestHandler):

    def handle(self):
        encrypted_key = self.request.recv(1024).strip()
        print(f"Implement decryption of data {encrypted_key}\n")

        # -----------------------------
        # Decryption Code Here

        # Opening the private_key to load into memory
        with open("./keys/pub_priv_pair.key", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        # Decrypting the symmetric key
        decryptedSymmetricKey = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # -----------------------------
        # Send the decrypted symmetric key back to the client
        self.request.sendall(decryptedSymmetricKey)


if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 8000

    tcpServer = socketserver.TCPServer((HOST, PORT), ClientHandler)
    try:
        tcpServer.serve_forever()
    except:
        print("There was an error")
        tcpServer.shutdown()
