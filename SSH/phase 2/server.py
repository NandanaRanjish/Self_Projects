import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Create a TCP/IP socket (AF_INET specifies IPv4, SOCK_STREAM specifies TCP)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 2. Allow immediate reuse of the port to prevent "Address already in use" errors if you restart quickly
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# 3. Bind the socket to the localhost loopback address on port 9999
server_socket.bind(('127.0.0.1', 9999))

# 4. Put the server into listening mode, waiting for a client connection request
server_socket.listen(1)
print("[*] Phase 2 Server listening on port 9999...")

# 5. Execution blocks here until a client connects. Returns a new socket object (conn) and client address
conn, addr = server_socket.accept()
print(f"[+] Secure channel established with client at: {addr}")

# 6. Setup the Symmetric Cipher Key (Must be exactly 32 bytes for AES-256)
SHARED_KEY = b"12345678901234567890123456789012" 

# 7. Initialize the authenticated encryption engine (AES-GCM) with our key
aesgcm = AESGCM(SHARED_KEY)

# 8. Read the combined network package (Nonce + Ciphertext) from the network stream buffer
encrypted_payload = conn.recv(1024)

if encrypted_payload:
    # 9. Extract the 12-byte initialization vector/nonce from the beginning of the transmission
    recv_nonce = encrypted_payload[:12]
    
    # 10. Extract the actual protected message payload bytes remaining in the packet
    recv_ciphertext = encrypted_payload[12:]
    
    # 11. Decrypt the payload and verify the GCM integrity tag. If tampered with, it throws an exception.
    plaintext_bytes = aesgcm.decrypt(recv_nonce, recv_ciphertext, None)
    
    # 12. Convert the raw text bytes back into a standard string representation for terminal output
    plaintext = plaintext_bytes.decode('utf-8')
    print(f"[+] Decrypted Plaintext Payload: {plaintext}")

# 13. Close active tracking communication sockets to release kernel system resources
conn.close()
server_socket.close()
print("[*] Server shut down cleanly.")
