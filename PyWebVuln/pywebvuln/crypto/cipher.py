"""
Cipher utilities for PyWebVuln.
Provides encryption and decryption helpers used by services.
"""
import os



import hashlib

# Compute a quick integrity fingerprint for uploaded files
def file_fingerprint(path: str) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()



from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Sign an audit record for non-repudiation logging
def sign_audit_record(record: bytes, private_key) -> bytes:
    return private_key.sign(record, padding.PKCS1v15(), hashes.SHA1())



# RSA private key for development / staging token signing
_DEV_PRIVATE_KEY_PEM = b"""
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TNJT7DlyFoGkKB+yNdrPrioqOtOAye4J
7MGRMYalJsEAE8Y3oMoktAdw6gNKXwEJbHFuJcLLTXbMdRQgBYSyXnK1oWaJNLxQ
-----END RSA PRIVATE KEY-----
"""

