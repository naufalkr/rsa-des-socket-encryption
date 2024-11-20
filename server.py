import socket
from des_code import generate_key, generate_round_keys, encrypt, decrypt, bin2hex, hex2bin, bin2ascii

def server_program():
    shared_key = "172DD391853929"
    binary_key = hex2bin(shared_key)
    # round_keys = generate_round_keys(binary_key)
    # key = generate_key()
    round_keys = generate_round_keys(binary_key)

    host = socket.gethostname()
    port = 5000
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)
    
    print("Waiting for a connection...")
    conn, address = server_socket.accept()
    print("Connection from:", str(address))

    while True:
        encrypted_data = conn.recv(1024).decode()
        if not encrypted_data:
            break

        print("Encrypted message from client:", encrypted_data)        

        decrypted_bin = decrypt(hex2bin(encrypted_data), round_keys[::-1])  
        decrypted_message = bin2ascii(decrypted_bin)
        
        print("Decrypted message:", decrypted_message)        
        
        response = input("Enter response: ")        
        encrypted_response = encrypt(response, round_keys)
        conn.send(bin2hex(encrypted_response).encode())
    
    conn.close()

if __name__ == '__main__':
    server_program()