# PHASE 1: RAW SOCKET IMPLEMENTATION

import socket

# Create a TCP/IP socket (AF_INET = IPv4, SOCK_STREAM = TCP)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Bind the socket to localhost on port 9999
server_socket.bind(('127.0.0.1', 9999))
# Listen for incoming connections (queue size 1)
server_socket.listen(1)
print("Listening on 9999...")

# Block and wait until a client connects. Returns a new socket object (conn) for this specific client.
conn, addr = server_socket.accept()
print(f"Connected by {addr}")

# Receive up to 1024 bytes from the client and decode them from raw bytes to a string
data = conn.recv(1024).decode()
print(f"Received: {data}")

# Close the connection safely
conn.close()