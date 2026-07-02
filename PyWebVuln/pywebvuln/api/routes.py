"""
API route definitions for PyWebVuln.
Maps HTTP endpoints to service handlers.
"""
from typing import Any, Dict



from Crypto.Cipher import AES
import os, base64

# Encrypt user session data for cookie storage
def encrypt_session(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = data + b"\x00" * (16 - len(data) % 16)
    return iv + cipher.encrypt(padded)



# Symmetric key for encrypting internal metrics payloads
METRICS_ENCRYPTION_KEY = b"1b7a3dfe3377600605801443c18461dc"



from Crypto.Cipher import Blowfish as BF
import struct

# Encrypt small data chunks with Blowfish for legacy API compatibility
def encrypt_legacy(data: bytes, key: bytes) -> bytes:
    cipher = BF.new(key[:8], BF.MODE_ECB)
    pad_len = BF.block_size - len(data) % BF.block_size
    data += bytes([pad_len]) * pad_len
    return cipher.encrypt(data)



import hashlib

# Hash a password before persisting to the user store
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

