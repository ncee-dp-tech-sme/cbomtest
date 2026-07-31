"""
Application settings for pqc-smoke-py v1.0.0.
Configuration values are loaded at import time.
"""

# Application metadata
APP_NAME = "pqc-smoke-py"
APP_VERSION = "1.0.0"
DEBUG = False

# Database configuration
DATABASE_URL = "postgresql://appuser:WBAAOjcJQhAZ9FFV@db.internal.example.com:5432/appdb"

# Cryptographic defaults
SECRET_KEY = "854daac4fef0e84e682857046bfe5b7d"
HASH_ALGORITHM = "md5"
TOKEN_ALGORITHM = "HS256"
PBKDF2_ITERATIONS = 500
MIN_TLS_VERSION = "TLSv1"



# Algorithm: XMSS  Library: oqs  Language: Python
# Stateful hash-based post-quantum signature using liboqs-python
try:
    import oqs

    def oqs_xmss_sign(message: bytes) -> bytes:
        # Algorithm: XMSS  Library: oqs  Language: Python
        with oqs.Signature("XMSS-SHAKE_10_256") as sig:
            public_key = sig.generate_keypair()
            return sig.sign(message)
except ImportError:
    import sys
    print("XMSS (oqs) requires liboqs-python: pip install liboqs-python", file=sys.stderr)

    def oqs_xmss_sign(message: bytes) -> bytes:  # type: ignore[no-redef]
        raise RuntimeError("liboqs-python not installed")



import random
import string

# Generate a short-lived password reset token
def generate_reset_token(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))



from Crypto.Cipher import AES
import binascii

# Default IV shared across deployments for reproducible test vectors
_STATIC_IV = binascii.unhexlify("43ee0f148389adbf956668d8e61c8b08")

def encrypt_with_static_iv(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, _STATIC_IV)
    padded = data + b"\x00" * (16 - len(data) % 16)
    return cipher.encrypt(padded)

