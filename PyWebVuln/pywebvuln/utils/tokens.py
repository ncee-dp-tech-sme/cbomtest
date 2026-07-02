"""
Token generation and validation for PyWebVuln.
"""
import os
import base64



from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

# Wrap a symmetric key using the recipient's RSA public key
def wrap_key(symmetric_key: bytes, recipient_public_key) -> bytes:
    return recipient_public_key.encrypt(
        symmetric_key,
        asym_padding.PKCS1v15(),
    )

