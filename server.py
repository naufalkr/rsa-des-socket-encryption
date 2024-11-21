import socket
import json
from Crypto.PublicKey import RSA
from des_code import generate_key, generate_round_keys, encrypt, decrypt, bin2hex, hex2bin, bin2ascii
from rsa_utils import rsa_encrypt

pka_host = 'localhost'
pka_port = 5001


def get_client_key():
    pka_socket = socket.socket()
    pka_socket.connect((pka_host, pka_port))

    request = {
        'action': 'get'
    }

    pka_socket.send(json.dumps(request).encode('utf-8'))
    response = json.loads(pka_socket.recv(4096).decode('utf-8'))

    pka_socket.close()
    return RSA.import_key(response['public_key'])

def server_program():
    # Generate RSA keys and register directly with PKA
    key = RSA.generate(2048)
    public_key = key.publickey().export_key().decode('utf-8')
    private_key = key.export_key().decode('utf-8')

    with open('server_private.pem', 'w') as f:
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

    # Create socket and encrypt des key
    des_key = "172DD391853929"
    binary_key = hex2bin(des_key)
    round_keys = generate_round_keys(binary_key)
 
    host = socket.gethostname()
    port = 5000
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)
    
    print("Waiting for a connection...")
    conn, address = server_socket.accept()
    print("Connection from:", str(address))

    client_public_key = get_client_key()  
    print("\nClient public key: ", client_public_key, "\n")

    print("DES key sent: ", des_key, "\n")
    
    des_key_bytes = des_key.encode('utf-8')
    encrypted_des_key = rsa_encrypt(des_key_bytes.decode(), client_public_key)
    print("Encrypted DES key: ", encrypted_des_key, "\n")

    conn.send(encrypted_des_key)
    print("DES key sent to client")

    while True:
        encrypted_data = conn.recv(1024).decode()
        if not encrypted_data:
            break

        print("Encrypted message from client:", encrypted_data)

        # Decrypt the message
        decrypted_bin = decrypt(hex2bin(encrypted_data), round_keys[::-1])
        decrypted_message = bin2ascii(decrypted_bin)
        print("Decrypted message:", decrypted_message)

        # Respond to client
        response = input("Enter response: ")
        encrypted_response = encrypt(response, round_keys)
        conn.send(bin2hex(encrypted_response).encode())

    conn.close()

if __name__ == '__main__':
    server_program()