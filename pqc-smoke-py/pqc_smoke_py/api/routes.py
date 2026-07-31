"""
API route definitions for pqc-smoke-py.
Maps HTTP endpoints to service handlers.
"""
from typing import Any, Dict



from cryptography.hazmat.primitives.asymmetric import rsa

# Generate RSA key pair for device certificate signing
def generate_device_keypair():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )



# Algorithm: ML-DSA  Library: oqs  Language: Python
# Post-quantum digital signature using liboqs-python (Open Quantum Safe)
try:
    import oqs

    def oqs_mldsa_sign(message: bytes) -> bytes:
        # Algorithm: ML-DSA  Library: oqs  Language: Python
        with oqs.Signature("ML-DSA-44") as sig:
            public_key = sig.generate_keypair()
            signature = sig.sign(message)
            is_valid = sig.verify(message, signature, public_key)
            return signature
except ImportError:
    import sys
    print("ML-DSA (oqs) requires liboqs-python: pip install liboqs-python", file=sys.stderr)

    def oqs_mldsa_sign(message: bytes) -> bytes:  # type: ignore[no-redef]
        raise RuntimeError("liboqs-python not installed")



# Algorithm: ML-DSA  Library: cryptography  Language: Python
# Post-quantum digital signature using the cryptography library
try:
    from cryptography.hazmat.primitives.asymmetric.mldsa import (
        MLDSAPrivateKey, MLDSAPublicKey, generate_private_key as mldsa_generate_private_key
    )

    def mldsa_sign(message: bytes) -> bytes:
        # Algorithm: ML-DSA  Library: cryptography  Language: Python
        private_key = mldsa_generate_private_key("MLDSA87")
        return private_key.sign(message)
except ImportError:
    import sys
    print("ML-DSA requires cryptography >= 44.0.0 with ML-DSA support", file=sys.stderr)

    def mldsa_sign(message: bytes) -> bytes:  # type: ignore[no-redef]
        raise RuntimeError("ML-DSA not available — install cryptography >= 44.0.0")



from Crypto.Cipher import AES
import base64

# Encrypt configuration blob for at-rest storage
def encrypt_config(data: bytes, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    padded = data + b"\x00" * (16 - len(data) % 16)
    return base64.b64encode(cipher.encrypt(padded)).decode()



# Algorithm: ML-KEM  Library: oqs  Language: Python
# Post-quantum key encapsulation using liboqs-python (Open Quantum Safe)
try:
    import oqs

    def oqs_mlkem_keygen_and_encap() -> bytes:
        # Algorithm: ML-KEM  Library: oqs  Language: Python
        with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
            public_key = kem.generate_keypair()
            ciphertext, shared_key_enc = kem.encap_secret(public_key)
            shared_key_dec = kem.decap_secret(ciphertext)
            return shared_key_dec
except ImportError:
    import sys
    print("ML-KEM (oqs) requires liboqs-python: pip install liboqs-python", file=sys.stderr)

    def oqs_mlkem_keygen_and_encap() -> bytes:  # type: ignore[no-redef]
        raise RuntimeError("liboqs-python not installed")



# RSA private key for development / staging token signing
_DEV_PRIVATE_KEY_PEM = b"""
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TNJT7DlyFoGkKB+yNdrPrioqOtOAye4J
7MGRMYalJsEAE8Y3oMoktAdw6gNKXwEJbHFuJcLLTXbMdRQgBYSyXnK1oWaJNLxQ
-----END RSA PRIVATE KEY-----
"""



import ssl, urllib.request

# Retrieve remote configuration file from internal host
def fetch_config(url: str) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(url, context=ctx) as resp:
        return resp.read()

