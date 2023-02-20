## Assignment 1 for Advanced Computer Security


This assignment is to learn the basics of cryptography with Python3. Using a couple of keys and a client server methodology. This allows the client encrypt a text files contents then to send the encryption key to the server for decryption, for the server to decrypt it and send it back to use to decrypt the text file into a different location with the decrypted contents to view.


## Creating Keys needed to use this assignment
- This generates the public private pair key needed:
```
openssl genrsa -out pub_priv_pair.key 1024
```

- This generates the public key needed:
```
openssl rsa -in pub_priv_pair.key  -pubout -out public_key.key
```

- Both of the files need to be stored inside of a ./keys directory for the program to work correctly as there is no autmated directory search to find the key files.

## Running the Application

- Run the Server in a terminal
- Inside of the SecretTextFile.txt put the contents of what you want encrypted.
- Run the Client inside of another terminal for the contents to then be encrypted and in another file the contents to be decryoted.
