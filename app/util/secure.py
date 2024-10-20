import os
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidKey

class KeyController:
    def __init__(self, email: str, password: str):
        self.iterations = 600000
        self.length = 32  # 256-bits
        self._email = email
        self._password = password
        self.master_key = self._generate_master_key()
        self.stretched_master_key = self._generate_stretched_master_key()
        self.master_password_hash = self._generate_master_password_hash()

    # Generate the master key
    # Use the email address for salt
    def _generate_master_key(self) -> bytes:
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.length,
            salt=self._email.encode(),
            iterations=self.iterations
        )
        
        master_key = kdf.derive(self._password.encode())

        return master_key

    # Stretches the master key to 512-bits
    # The main reason for stretching is to increase entropy
    # We could also generate and store the salt but it is technically
    # unnecessary
    def _generate_stretched_master_key(self) -> bytes:

        hkdf = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=64,  # 512-bits
            info=b'encryption_key'  #  Additional context about the key
        )
        
        stretched_master_key = hkdf.derive(self.master_key)

        return stretched_master_key

    # Generate the master password hash
    # Use the password itself as the salt
    def _generate_master_password_hash(self) -> bytes:
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.length,
            salt=self._password.encode(),
            iterations=self.iterations
        )
        
        master_password_hash = kdf.derive(self.master_key)

        return master_password_hash

    def verify_master_password_hash(self, hash: bytes) -> bool:
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.length,
            salt=self._password.encode(),
            iterations=self.iterations
        )
        
        try:
            kdf.verify(self.master_key, hash)
            return True
        except InvalidKey:
            return False
        
    def generate_encrypted_symmetric_key(self) -> tuple[str, str]:
        encryption_key = self.master_key[:32] # Use first 256-bits
        
        # In the real world one would use a 
        # Cryptographically Secure Pseudorandom Number Generator (CSPRNG)
        # but os.urandom() is the next best thing.
        # https://cryptography.io/en/latest/random-numbers/
        symmetric_key = os.urandom(64) # 512-bits
        iv = os.urandom(16) # 128-bits
        
        # AES-256-CBC (Cipher Block Chaining)
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        protected_key = encryptor.update(symmetric_key) + encryptor.finalize()
        
        # Encode the protected key and iv with base64
        b64_protected_key = base64.b64encode(protected_key).decode('utf-8')
        b64_iv = base64.b64encode(iv).decode('utf-8')
        
        return b64_protected_key, b64_iv