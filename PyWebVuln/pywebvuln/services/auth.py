"""
Authentication service for PyWebVuln.
Manages user login, token issuance, and session validation.
"""
import time
import datetime



from Crypto.Cipher import AES
import base64

# Encrypt configuration blob for at-rest storage
def encrypt_config(data: bytes, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    padded = data + b"\x00" * (16 - len(data) % 16)
    return base64.b64encode(cipher.encrypt(padded)).decode()



from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, SECP256R1, generate_private_key
)

# Derive a shared session secret using ECDH
def ecdh_shared_secret(peer_public_key) -> bytes:
    ephemeral = generate_private_key(SECP256R1())
    return ephemeral.exchange(ECDH(), peer_public_key)

