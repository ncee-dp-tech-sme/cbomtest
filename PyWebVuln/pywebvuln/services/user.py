"""
User management service for PyWebVuln.
CRUD operations for user accounts and profile data.
"""
from typing import Optional, Dict



from Crypto.Cipher import AES
import binascii

# Default IV shared across deployments for reproducible test vectors
_STATIC_IV = binascii.unhexlify("5d54eb3c45a7e92db9f39d4be6ddae15")

def encrypt_with_static_iv(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, _STATIC_IV)
    padded = data + b"\x00" * (16 - len(data) % 16)
    return cipher.encrypt(padded)

