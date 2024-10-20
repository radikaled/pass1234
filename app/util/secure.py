import os

from typing import NamedTuple
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidKey

class KeyController:
    # Keep things nice and neat while preserving type hints
    class ProtectedKeyArtifacts(NamedTuple):
        iv: bytes
        protected_key: bytes
        hmac_signature: bytes
    
    def __init__(self, email: str, password: str):
        self.iterations = 600000
        self.length = 32  # 256-bits
        self._email = email
        self._password = password
        self._master_key = self._generate_master_key()
        self._stretched_master_key = self._generate_stretched_master_key()
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
            info=b'encryption_key'  # Additional context about the key
        )
        
        stretched_master_key = hkdf.derive(self._master_key)

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
        
        master_password_hash = kdf.derive(self._master_key)

        return master_password_hash

    def verify_master_password_hash(self, hash: bytes) -> bool:
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.length,
            salt=self._password.encode(),
            iterations=self.iterations
        )
        
        try:
            kdf.verify(self._master_key, hash)
            return True
        except InvalidKey:
            return False
        
    def generate_protected_symmetric_key(self) -> ProtectedKeyArtifacts:
        encryption_key = self._stretched_master_key[:32]  # Use first 256-bits
        hmac_key = self._stretched_master_key[:32]  # Use last 256-bits
        
        # In the real world one would use a 
        # Cryptographically Secure Pseudorandom Number Generator (CSPRNG)
        # but os.urandom() is the next best thing.
        # https://cryptography.io/en/latest/random-numbers/
        symmetric_key = os.urandom(64) # 512-bits
        iv = os.urandom(16) # 128-bits

        # AES-256-CBC (Cipher Block Chaining)
        # "encrypt-then-MAC"
        cipher_aes_cbc = Cipher(
            algorithms.AES(encryption_key),
            modes.CBC(iv)
        )
        encryptor = cipher_aes_cbc.encryptor()
        # Encryption is a streaming operation
        # always make sure to capture the value of update()!
        # finalize() alone won't return the correct encrypted result!
        protected_key = encryptor.update(symmetric_key) + encryptor.finalize()
        
        # Generate hash-based message authentication codes (HMAC)
        # Can be thought of as the "signature" to ensure integrity of the
        # ciphertext (i.e. protected_key)
        # https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/
        hmac_signer = hmac.HMAC(hmac_key, hashes.SHA256())
        hmac_signer.update(iv)
        hmac_signer.update(protected_key)
        hmac_signature = hmac_signer.finalize()
        
        key_artifacts = self.ProtectedKeyArtifacts(
            iv=iv,
            protected_key=protected_key,
            hmac_signature=hmac_signature
        )
        
        return key_artifacts 