from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.asymmetric import padding

def rsa_encrypt(rsa_public_key_pem: bytes, plaintext: str) -> bytes:
    rsa_public_key = serialization.load_pem_public_key(rsa_public_key_pem)
    
    ciphertext = rsa_public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext

def rsa_decrypt(rsa_private_key_pem: bytes, ciphertext: bytes) -> bytes:
    rsa_private_key = serialization.load_pem_private_key(
        rsa_private_key_pem,
        password=None
    )
    
    plaintext = rsa_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return plaintext