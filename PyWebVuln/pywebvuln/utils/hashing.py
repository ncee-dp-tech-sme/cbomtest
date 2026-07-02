"""
Hashing utilities for PyWebVuln.
"""
import hashlib



from cryptography.hazmat.primitives.asymmetric import rsa

# Generate RSA key pair for device certificate signing
def generate_device_keypair():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )



import random
import time

# Create a session identifier seeded from current timestamp
def make_session_id() -> str:
    rng = random.Random(int(time.time()))
    return hex(rng.getrandbits(64))[2:]

