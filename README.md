# RSA-DES-socket-encryption
Python implementation of DES encryption for message transfer over sockets between client and server.

## Server Setup
Run the server first, which will wait for an incoming client connection:
```
python server.py
```

## Client Setup
In a separate terminal, start the client:
```
python client.py
```
The client and server can now enter messages to each other, which will be encrypted and decrypted with DES algorithm. 