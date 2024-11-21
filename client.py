import socket
from des_code import generate_key, generate_round_keys, encrypt, decrypt, bin2hex, hex2bin, bin2ascii
import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from rsa_utils import rsa_encrypt, rsa_decrypt

pka_host = 'localhost'
pka_port = 5001

def client_program():
    # Generate RSA keys and register directly with PKA
    key = RSA.generate(2048)
    public_key = key.publickey().export_key().decode('utf-8')
    private_key = key.export_key().decode('utf-8')

    with open('client_private.pem', 'w') as f:
        f.write(private_key)

    pka_socket = socket.socket()
    pka_socket.connect((pka_host, pka_port))

    register_request = {
        'action': 'register',
        'public_key': public_key
    }

    pka_socket.send(json.dumps(register_request).encode('utf-8'))
    response = json.loads(pka_socket.recv(4096).decode('utf-8'))
    pka_socket.close()

    print("Registered with PKA successfully")

    # Begin communication with server
    host = socket.gethostname()
    port = 5000
    client_socket = socket.socket()
    client_socket.connect((host, port))
    print("Connected to server")

    # Receive and decrypt DES key from server
    encrypted_des_key = client_socket.recv(256)
    print("\nReceived DES key: ", encrypted_des_key, "\n")

    with open('client_private.pem', 'r') as f:
        private_key_data = f.read()

    private_key = RSA.import_key(private_key_data)

    des_key = rsa_decrypt(encrypted_des_key, key)
    print("DES key received and decrypted successfully: ", des_key, "\n")

    binary_key = hex2bin(des_key)
    round_keys = generate_round_keys(binary_key)

    while True:
        message = input("Enter message to send: ")

        # Encrypt and send message
        encrypted_message = encrypt(message, round_keys)
        encrypted_hex = bin2hex(encrypted_message)
        print("Encrypted message from client:", encrypted_hex)
        client_socket.send(encrypted_hex.encode())

        # Receive and decrypt server response
        encrypted_response = client_socket.recv(1024).decode()
        print("Encrypted message from server:", encrypted_response)
        decrypted_response_bin = decrypt(hex2bin(encrypted_response), round_keys[::-1])
        decrypted_response = bin2ascii(decrypted_response_bin)

        print("Decrypted response from server:", decrypted_response)

if __name__ == '__main__':
    client_program()