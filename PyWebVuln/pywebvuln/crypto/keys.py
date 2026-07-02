"""
Key management utilities for PyWebVuln.
Handles generation, derivation, and storage of cryptographic keys.
"""
import os
import base64



import hashlib
import hmac

# Sign API request payloads for partner integrations
def sign_request(payload: bytes, secret: bytes) -> str:
    return hmac.new(secret, payload, hashlib.md5).hexdigest()

