import socket
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Initialize the client-side TCP streaming socket interface
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 2. Connect directly across the local network loopback directly to the server's listening port
client_socket.connect(('127.0.0.1', 9999))
print("[*] Successfully connected to remote server endpoint.")

# 3. Define the matching symmetric security key (Must match server key byte-for-byte)
SHARED_KEY = b"12345678901234567890123456789012" 

# 4. Spin up the localized instances of our encryption cipher module
aesgcm = AESGCM(SHARED_KEY)

# 5. Generate a fresh, completely random 12-byte initialization vector (nonce)
nonce = os.urandom(12)

# 6. Define our confidential string message and encode it down to basic byte arrays
plaintext_message = b"Secret Phase 2 Message"

# 7. Process data through the cipher. GCM appends a 16-byte authentication tag automatically.
ciphertext = aesgcm.encrypt(nonce, plaintext_message, None)

# 8. Concatenate the plain nonce to the cipher block and fire the packed string over the stream
client_socket.sendall(nonce + ciphertext)
print("[*] Packaged cryptographic frame transmitted successfully.")

# 9. Formally disconnect socket interface to notify host the interaction pipeline is complete
client_socket.close()
print("[*] Client operations completed.")

