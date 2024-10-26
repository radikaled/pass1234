import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

def generate_hmac(hmac_key: bytes, data: bytes) -> bytes:
    hmac_signer = hmac.HMAC(hmac_key, hashes.SHA256())
    hmac_signer.update(data)
    hmac_signature = hmac_signer.finalize()
    
    return hmac_signature

def verify_hmac(hmac_key: bytes, data: bytes, hmac_signature: bytes) -> bool:
    hmac_key = hmac_key
        
    hmac_signer = hmac.HMAC(hmac_key, hashes.SHA256())
    hmac_signer.update(data)
        
    try:
        hmac_signer.verify(hmac_signature)
        return True
    except InvalidSignature:
        return False

def encrypt(unencrypted_data: bytes, aes_key: bytes) -> tuple['bytes', 'bytes']:
    iv = os.urandom(16) # 128-bits

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(unencrypted_data) + padder.finalize()
    
    # Encrypt data using AES-256-CBC (Cipher Block Chaining)
    cipher_aes_cbc = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv)
    )
    encryptor = cipher_aes_cbc.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return iv, encrypted_data

def decrypt(iv: bytes, encrypted_data: bytes, aes_key: bytes) -> bytes:
    # Decrypt data using AES-256-CBC (Cipher Block Chaining)
    cipher_aes_cbc = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv)
    )
    decryptor = cipher_aes_cbc.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

    return decrypted_data