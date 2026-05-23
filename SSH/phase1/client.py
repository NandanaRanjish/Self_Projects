import socket

# 1. Create the client TCP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# 2. Connect to the server's IP and port
client_socket.connect(('127.0.0.1', 9999))

# 3. Send a plaintext string, encoded into raw bytes
client_socket.sendall(b"Hello from Phase 1! Dr. Ganguly can read this.")

# 4. Close the socket
client_socket.close()