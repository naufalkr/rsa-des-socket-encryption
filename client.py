import socket
from des_code import generate_key, generate_round_keys, encrypt, decrypt, bin2hex, hex2bin, bin2ascii

def client_program():
    shared_key = "172DD391853929"
    binary_key = hex2bin(shared_key)
    # round_keys = generate_round_keys(binary_key)
    # key = generate_key()
    round_keys = generate_round_keys(binary_key)

    host = socket.gethostname()
    port = 5000
    client_socket = socket.socket()
    client_socket.connect((host, port))

    while True:
        message = input("Enter message to send: ")

        encrypted_message = encrypt(message, round_keys)
        encrypted_hex = bin2hex(encrypted_message)
        print("Encrypted message from client:", encrypted_hex)
        client_socket.send(encrypted_hex.encode())

        encrypted_response = client_socket.recv(1024).decode()
        print("Encrypted message from server:", encrypted_response)
        decrypted_response_bin = decrypt(hex2bin(encrypted_response), round_keys[::-1])  
        decrypted_response = bin2ascii(decrypted_response_bin)
        
        print("Decrypted response from server:", decrypted_response)

if __name__ == '__main__':
    client_program()