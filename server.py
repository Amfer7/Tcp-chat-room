import socket
import threading
import ssl
import os

HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 12345
clients = {}  # {socket: username}

# Certificate paths
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'

def broadcast(message, sender_sock=None):
    """Send message to all clients except sender"""
    for client_sock in list(clients.keys()):
        if client_sock != sender_sock:
            try:
                client_sock.sendall(message.encode())
            except:
                client_sock.close()
                if client_sock in clients:
                    del clients[client_sock]

def handle_client(client_sock, addr):
    """Handle communication with a single client"""
    try:
        username = client_sock.recv(1024).decode().strip()
        clients[client_sock] = username
        print(f"{username} connected from {addr}")
        broadcast(f"*** {username} has joined the chat ***", client_sock)
        
        while True:
            data = client_sock.recv(1024)
            if not data:
                break
                
            message = data.decode().strip()
            if message.lower() == "exit":
                break
                
            print(f"{username}: {message}")
            broadcast(f"{username}: {message}", client_sock)
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if client_sock in clients:
            print(f"{clients[client_sock]} disconnected.")
            broadcast(f"*** {clients[client_sock]} has left the chat ***", client_sock)
            del clients[client_sock]
        client_sock.close()

def generate_self_signed_cert():
    """Generate a self-signed certificate if one doesn't exist"""
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        print("Generating self-signed certificate...")
        os.system(f'openssl req -x509 -newkey rsa:4096 -nodes -out {CERT_FILE} -keyout {KEY_FILE} '
                  f'-days 365 -subj "/CN=localhost"')
        print(f"Self-signed certificate generated: {CERT_FILE}, {KEY_FILE}")

def start_server():
    """Start the secure chat server"""
    # Ensure we have certificates
    generate_self_signed_cert()
    
    # Create raw socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    
    # Create SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    
    print(f"Secure chat server listening on {HOST}:{PORT}")
    
    try:
        while True:
            client_conn, client_addr = server_socket.accept()
            print(f"New connection from {client_addr}")
            
            # Wrap the socket with SSL
            ssl_client = context.wrap_socket(client_conn, server_side=True)
            
            # Start a new thread to handle this client
            threading.Thread(target=handle_client, args=(ssl_client, client_addr), daemon=True).start()
            
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        for sock in clients:
            sock.close()
        server_socket.close()

if __name__ == "__main__":
    start_server()