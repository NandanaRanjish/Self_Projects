import socket
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Initialize the main listening TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('127.0.0.1', 9999))
server_socket.listen(5) # Allow a small queue for incoming connections
print("[*] Phase 3 Server listening continuously on port 9999...")

# Infinite loop keeps the server instance alive indefinitely
while True:
    print("\n[*] Waiting for an incoming client connection...")
    try:
        # 2. Block until a client connects. 
        conn, addr = server_socket.accept()
        print(f"[+] Connection established with client at: {addr}")

        print("[*] Generating ephemeral RSA-2048 keypair...")
        # 3. Generate a unique RSA keypair for this specific session
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # 4. Serialize public key to PEM format bytes
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # 5. Send public key to the connected client
        conn.sendall(pub_bytes)
        print("[*] Server public key sent.")

        # 6. Receive the 256-byte RSA-encrypted AES key from the client
        encrypted_aes_key = conn.recv(256)
        
        # 7. Decrypt the AES session key using the private key
        session_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("[+] Symmetric AES session key successfully decrypted!")

        # 8. Initialize the AES-GCM engine with the dynamically negotiated key
        aesgcm = AESGCM(session_key)

        # 9. Receive the encrypted message payload from the client
        encrypted_payload = conn.recv(1024)

        if encrypted_payload:
            # Extract 12-byte nonce and the remaining ciphertext block
            recv_nonce = encrypted_payload[:12]
            recv_ciphertext = encrypted_payload[12:]
            
            # Decrypt and verify the integrity of the data
            plaintext = aesgcm.decrypt(recv_nonce, recv_ciphertext, None).decode('utf-8')
            print(f"[+] Decrypted Plaintext: {plaintext}")

    except Exception as e:
        print(f"[-] An error occurred during this session: {e}")
    
    finally:
        # 10. CRITICAL: Close the connection to THIS client, freeing them up.
        # The main server_socket stays open at the top of the loop!
        if 'conn' in locals():
            conn.close()
            print("[*] Client connection closed safely. Looping back...")