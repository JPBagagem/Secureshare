import os
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from src.core.generate_keys import load_or_generate_server_keys

# PRIVATE_KEY, _ = load_or_generate_server_keys()


def hash_password(password: str) -> tuple[str, str]:
    """
    Hashes a password using Argon2id.
    Returns (hex_hash, hex_salt).
    """
    salt = os.urandom(16)
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=2,
        lanes=4,
        memory_cost=65536
    )
    key = kdf.derive(password.encode())
    return key.hex(), salt.hex()

def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    """
    Verifies a password against a stored hash and salt.
    """
    salt = bytes.fromhex(salt_hex)
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=2,
        lanes=4,
        memory_cost=65536
    )
    try:
        kdf.verify(password.encode(), bytes.fromhex(hash_hex))
        return True
    except Exception:
        return False

from src.core.settings import settings

ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

import jwt
from datetime import datetime, timedelta, timezone

import uuid

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "jti": str(uuid.uuid4())})
        
    return jwt.encode(to_encode, settings.PRIVATE_KEY.encode(), algorithm=ALGORITHM)


from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

def verify_signature(public_key_pem: str, signature_b64: str, data: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

