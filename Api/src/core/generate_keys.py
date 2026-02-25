from cryptography.hazmat.primitives import serialization
import os
from cryptography.hazmat.primitives.asymmetric import rsa

SERVER_KEY_PATH = "server_private_key.pem"
SERVER_PUBLIC_KEY_PATH = "server_public_key.pem"

def load_or_generate_server_keys():
    """
    Loads existing server keys if they exist, otherwise generates a new RSA key pair.
    """
    if os.path.exists(SERVER_KEY_PATH) and os.path.exists(SERVER_PUBLIC_KEY_PATH):
        with open(SERVER_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(SERVER_PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        print("✅ Loaded existing server keys")
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        public_key = private_key.public_key()
        # Save private key
        with open(SERVER_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        # Save public key
        with open(SERVER_PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("Generated new server keys")
    
    return private_key, public_key