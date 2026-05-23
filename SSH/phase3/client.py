import socket
import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Establish connection to the persistent server node
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 9999))
print("[*] Connected to Phase 3 Server.")

# 2. Receive the public key bytes exported by the server host
server_pub_bytes = client_socket.recv(4096)

# 3. Load the raw PEM bytes back into an asymmetric Public Key object
server_pub_key = serialization.load_pem_public_key(server_pub_bytes)

# 4. Generate a cryptographically secure random 32-byte AES key
session_key = os.urandom(32)
aesgcm = AESGCM(session_key)

# 5. Encrypt the secret AES session key using the server's public key via RSA-OAEP
encrypted_aes_key = server_pub_key.encrypt(
    session_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# 6. Transmit the 256 bytes of RSA ciphertext directly to the server
client_socket.sendall(encrypted_aes_key)
print("[*] Secure symmetric key handshake complete.")

# 7. Create an encrypted data transaction frame
nonce = os.urandom(12)
plaintext_message = b"Secret Phase 3 Message: Dynamic Key Exchange Complete!"
ciphertext = aesgcm.encrypt(nonce, plaintext_message, None)

# 8. Send the combined nonce + ciphertext over the secure pipe
client_socket.sendall(nonce + ciphertext)
print("[*] Encrypted data frame sent successfully.")

# 9. Clean up and close the socket session cleanly
client_socket.close()
print("[*] Client closed.")
