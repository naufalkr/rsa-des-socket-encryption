import socket
import threading
from Crypto.PublicKey import RSA
from datetime import datetime
import json

keys_repository = {}  # {key_id: {'key': key_str, 'timestamp': datetime}}
authority_host = 'localhost'
authority_port = 5001

def pka_program():
    # Create socket server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((authority_host, authority_port))
    server_socket.listen(5)
    print(f"Public Key Authority started")

    while True:
        # Accept connection from client
        client_socket, client_address = server_socket.accept()
        # print(f"Connection from {client_address}")

        # Receive and process request from client
        request_data = client_socket.recv(4096).decode('utf-8')
        parsed_request = json.loads(request_data)

        if parsed_request['action'] == 'register':
            key_identifier = str(len(keys_repository) + 1)
            RSA.import_key(parsed_request['public_key'])

            # Store the public key in the repository
            keys_repository[key_identifier] = {
                'key': parsed_request['public_key'],
                'timestamp': datetime.now().isoformat()
            }
            response = {
                'status': 'success',
                'key_id': key_identifier,
            }
        elif parsed_request['action'] == 'get':
            if keys_repository:
                latest_key_data = list(keys_repository.values())[-1]
                response = {
                    'status': 'success',
                    'public_key': latest_key_data['key'],
                    'timestamp': latest_key_data['timestamp']
                }
            else:
                response = {'status': 'error', 'message': 'No keys found'}
        else:
            response = {'status': 'error', 'message': 'Invalid action'}

        # Send the response back to client
        client_socket.send(json.dumps(response).encode('utf-8'))
        client_socket.close()

if __name__ == '__main__':
    pka_program()
