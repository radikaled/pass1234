import os
from hashlib import pbkdf2_hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# 32 bytes - 256 bits
def generate_master_key(
        salt: bytes, 
        iterations: int=600000,
        length: int=32
        ) -> bytes:
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,  # bytes
        salt=salt,
        iterations=iterations
        )

generate_master_key(b'nealerickim@gmail.com')

# Salts should be randomly generated

# salt = os.urandom(16)
salt = b'nealerickim@gmail.com'

dk = pbkdf2_hmac('sha256', b'password', salt, 600_000)

# derive
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=600000,
)
key = kdf.derive(b"my great password")

# verify
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=600000,
)

try:
    kdf.verify(b"my great password", key)
    print(f"key matches")
except:
    print(f"key doesn't match")