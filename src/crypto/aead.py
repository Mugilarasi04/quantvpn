from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def decrypt(key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, aad)