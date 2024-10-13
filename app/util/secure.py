import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey

class KeyController:
    def __init__(self, email: str, password: str):
        self.iterations = 600000
        self.length = 32  # 256 bits = 32 bytes
        self._email = email
        self._password = password
        self.master_key = self._generate_master_key()
        self.stretched_master_key = self._generate_stretched_master_key()
        self.master_password_hash = self._generate_master_password_hash()

    def _generate_master_key(self) -> bytes:
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.length,  # 256 bits = 32 bytes
            salt=self._email.encode(),
            iterations=self.iterations
            )
        
        master_key = kdf.derive(self._password.encode())

        return master_key

    def _generate_stretched_master_key(self) -> bytes:

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 512 bits = 64 bytes
            salt=None,
            info=None
            )
        
        stretched_master_key = hkdf.derive(self.master_key)

        return stretched_master_key

    def _generate_master_password_hash(self) -> bytes:
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.length,
            salt=self._password.encode(),
            iterations=self.iterations
            )
        
        master_password_hash = kdf.derive(self.master_key)

        return master_password_hash

    def valid_master_password_hash(self, hash: str) -> bool:
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.length,
            salt=self._password.encode(),
            iterations=self.iterations
            )
        
        try:
            kdf.verify(self.master_key, bytes.fromhex(hash))
            return True
        except InvalidKey:
            return False