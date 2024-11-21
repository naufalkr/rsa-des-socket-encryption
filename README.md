# RSA-DES-socket-encryption
Python implementation of RSA and DES encryption for message transfer over sockets between client and server.

## PKA Server Setup
Run the PKA server first, which will wait for an incoming key request from server and client:
```
python pka_server.py
```

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