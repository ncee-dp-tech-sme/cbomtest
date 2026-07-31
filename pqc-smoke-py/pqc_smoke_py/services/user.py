"""
User management service for pqc-smoke-py.
CRUD operations for user accounts and profile data.
"""
from typing import Optional, Dict



# Algorithm: SLH-DSA  Library: oqs  Language: Python
# Stateless hash-based post-quantum signature using liboqs-python
try:
    import oqs

    def oqs_slhdsa_sign(message: bytes) -> bytes:
        # Algorithm: SLH-DSA  Library: oqs  Language: Python
        with oqs.Signature("SPHINCS+-SHA2-128f-simple") as sig:
            public_key = sig.generate_keypair()
            return sig.sign(message)
except ImportError:
    import sys
    print("SLH-DSA (oqs) requires liboqs-python: pip install liboqs-python", file=sys.stderr)

    def oqs_slhdsa_sign(message: bytes) -> bytes:  # type: ignore[no-redef]
        raise RuntimeError("liboqs-python not installed")

