#!/usr/bin/env python3
"""
generate_vulnerable_app.py

Generates a realistic multi-file Java or Python application with deliberately
introduced cryptographic weaknesses for Guardium Quantum Safe Explorer demos.

All weaknesses are intentional; this tool is for demo/testing purposes only.

Change history:
  2025-07-15  Initial version. Interactive generator for Java and Python apps
              with randomised cryptographic weakness injection across files.
"""

import os
import random
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Tuple

# ---------------------------------------------------------------------------
# Weakness catalogue
# ---------------------------------------------------------------------------

@dataclass
class Weakness:
    """Represents a single injected cryptographic weakness."""
    category: str
    description: str
    # Returns (filename_suffix, file_content_snippet) — used only for tracking;
    # actual injection happens via snippet factories.
    tag: str = ""


def _wk(category: str, description: str, tag: str = "") -> Weakness:
    return Weakness(category=category, description=description, tag=tag)


# ---------------------------------------------------------------------------
# Java snippet factories
# ---------------------------------------------------------------------------

JAVA_WEAKNESS_FACTORIES: List[Tuple[Weakness, Callable[[], str]]] = []

def _jw(category, description, tag=""):
    """Decorator: registers a Java weakness factory."""
    wk = _wk(category, description, tag)
    def decorator(fn):
        JAVA_WEAKNESS_FACTORIES.append((wk, fn))
        return fn
    return decorator


@_jw("Weak algorithm", "MD5 message digest", "CBS-001")
def _():
    return textwrap.dedent("""\
        // Compute a fingerprint for cache key lookups
        public static String fingerprint(String input) throws Exception {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        }
    """)


@_jw("Weak algorithm", "SHA-1 used for password hashing", "CBS-001")
def _():
    return textwrap.dedent("""\
        // Hash user password before storage
        public static String hashPassword(String password) throws Exception {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] digest = sha1.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        }
    """)


@_jw("Weak algorithm", "DES symmetric encryption", "CBS-001")
def _():
    return textwrap.dedent("""\
        // Encrypt configuration value for transit
        public static byte[] encryptConfig(String value, byte[] key) throws Exception {
            SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(new byte[8]));
            return cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        }
    """)


@_jw("Weak algorithm", "3DES (Triple-DES) encryption", "CBS-001")
def _():
    return textwrap.dedent("""\
        // Legacy token encryption preserved for backward compatibility
        public static byte[] encryptToken(String token, byte[] keyBytes) throws Exception {
            SecretKeySpec key = new SecretKeySpec(keyBytes, "DESede");
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(token.getBytes(StandardCharsets.UTF_8));
        }
    """)


@_jw("Weak algorithm", "RC4 stream cipher", "CBS-001")
def _():
    return textwrap.dedent("""\
        // Quick obfuscation for internal audit log entries
        public static byte[] obfuscate(byte[] data, byte[] key) throws Exception {
            SecretKeySpec keySpec = new SecretKeySpec(key, "RC4");
            Cipher cipher = Cipher.getInstance("RC4");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            return cipher.doFinal(data);
        }
    """)


@_jw("Insecure cipher mode", "AES-ECB mode", "CBS-002")
def _():
    return textwrap.dedent("""\
        // Encrypt session data with AES
        public static byte[] encryptSession(byte[] data, SecretKey key) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        }
    """)


@_jw("Insecure cipher mode", "AES-CBC without authentication (padding oracle risk)", "CBS-002")
def _():
    return textwrap.dedent("""\
        // Encrypt payload for API response signing
        public static byte[] encryptPayload(byte[] payload, byte[] keyBytes, byte[] iv)
                throws Exception {
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            return cipher.doFinal(payload);
        }
    """)


@_jw("Static IV", "Hardcoded/static initialization vector", "CBS-002")
def _():
    # Emit as a Java byte[] literal — \xNN is not valid in Java string literals
    iv_bytes = ", ".join(str(b if b < 128 else b - 256) for b in random.randbytes(16))
    return textwrap.dedent(f"""\
        // Default IV used when caller does not supply one
        private static final byte[] DEFAULT_IV = new byte[]{{ {iv_bytes} }};

        public static byte[] encryptWithDefaultIV(byte[] data, SecretKey key) throws Exception {{
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(DEFAULT_IV));
            return cipher.doFinal(data);
        }}
    """)


@_jw("Insufficient key size", "RSA-1024 key generation", "CBS-003")
def _():
    return textwrap.dedent("""\
        // Generate RSA key pair for service-to-service auth tokens
        public static KeyPair generateServiceKeyPair() throws Exception {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(1024);
            return gen.generateKeyPair();
        }
    """)


@_jw("Insufficient key size", "RSA-512 key generation", "CBS-003")
def _():
    return textwrap.dedent("""\
        // Lightweight key pair for device certificates
        public static KeyPair generateDeviceKeyPair() throws Exception {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(512);
            return gen.generateKeyPair();
        }
    """)


@_jw("Insufficient key size", "AES-64 (DES-size) key", "CBS-003")
def _():
    return textwrap.dedent("""\
        // Generate compact symmetric key for embedded device sync
        public static SecretKey generateCompactKey() throws Exception {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(64);
            return kg.generateKey();
        }
    """)


@_jw("Outdated protocol", "TLS 1.0 enabled", "CBS-004")
def _():
    return textwrap.dedent("""\
        // Build HTTP client with compatibility for older endpoints
        public static SSLContext buildLegacySSLContext() throws Exception {
            SSLContext ctx = SSLContext.getInstance("TLSv1");
            ctx.init(null, null, null);
            return ctx;
        }
    """)


@_jw("Outdated protocol", "SSLv3 context", "CBS-004")
def _():
    return textwrap.dedent("""\
        // Legacy connector retained for on-premise integrations
        public static SSLContext buildSSLv3Context() throws Exception {
            SSLContext ctx = SSLContext.getInstance("SSLv3");
            ctx.init(null, null, null);
            return ctx;
        }
    """)


@_jw("Outdated protocol", "TLS 1.1 socket factory", "CBS-004")
def _():
    return textwrap.dedent("""\
        // Socket factory for partner systems that cap at TLS 1.1
        public static SSLSocketFactory buildTLS11Factory() throws Exception {
            SSLContext ctx = SSLContext.getInstance("TLSv1.1");
            ctx.init(null, null, null);
            return ctx.getSocketFactory();
        }
    """)


@_jw("Hardcoded secret", "Hardcoded AES key", "CBS-003")
def _():
    key = "".join(random.choices("0123456789abcdef", k=32))
    return textwrap.dedent(f"""\
        // Symmetric key for internal metrics encryption
        private static final String METRICS_KEY = "{key}";
        private static final byte[] METRICS_KEY_BYTES = METRICS_KEY.getBytes(StandardCharsets.UTF_8);
    """)


@_jw("Hardcoded secret", "Hardcoded HMAC secret", "CBS-003")
def _():
    secret = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=24))
    return textwrap.dedent(f"""\
        // HMAC signing secret for webhook payload verification
        private static final String WEBHOOK_SECRET = "{secret}";

        public static String signWebhook(String payload) throws Exception {{
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(WEBHOOK_SECRET.getBytes(), "HmacSHA1"));
            return Base64.getEncoder().encodeToString(mac.doFinal(payload.getBytes()));
        }}
    """)


@_jw("Hardcoded secret", "Hardcoded RSA private key PEM inline", "CBS-003")
def _():
    return textwrap.dedent("""\
        // Fallback private key used in development and staging environments
        private static final String DEV_PRIVATE_KEY_PEM =
            "-----BEGIN RSA PRIVATE KEY-----\\n" +
            "MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TNJT7DlyFoGkKB+yNdrPrioqOtOAye4J\\n" +
            "7MGRMYalJsEAE8Y3oMoktAdw6gNKXwEJbHFuJcLLTXbMdRQgBYSyXnK1oWaJNLxQ\\n" +
            "-----END RSA PRIVATE KEY-----";
    """)


@_jw("Insecure PRNG", "java.util.Random for token generation", "CBS-003")
def _():
    return textwrap.dedent("""\
        // Generate a session token for authenticated users
        public static String generateSessionToken() {
            Random rng = new Random();
            byte[] bytes = new byte[16];
            rng.nextBytes(bytes);
            return Base64.getEncoder().encodeToString(bytes);
        }
    """)


@_jw("Insecure PRNG", "Math.random() used for nonce", "CBS-003")
def _():
    return textwrap.dedent("""\
        // Create a short-lived nonce for CSRF protection
        public static String generateNonce() {
            long nonce = (long)(Math.random() * Long.MAX_VALUE);
            return Long.toHexString(nonce);
        }
    """)


@_jw("Missing certificate validation", "Trust-all TrustManager", "CBS-004")
def _():
    return textwrap.dedent("""\
        // Allow connections to internal hosts with self-signed certificates
        public static SSLContext buildTrustAllContext() throws Exception {
            TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] c, String a) {}
                    public void checkServerTrusted(X509Certificate[] c, String a) {}
                }
            };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new java.security.SecureRandom());
            return ctx;
        }
    """)


@_jw("Missing certificate validation", "HostnameVerifier that always returns true", "CBS-004")
def _():
    return textwrap.dedent("""\
        // Hostname verifier for development proxy routing
        public static HostnameVerifier buildPermissiveVerifier() {
            return (hostname, session) -> true;
        }
    """)


@_jw("Weak KDF", "Low PBKDF2 iteration count", "CBS-003")
def _():
    iters = random.choice([100, 500, 1000])
    return textwrap.dedent(f"""\
        // Derive an encryption key from a user-supplied passphrase
        public static SecretKey deriveKey(char[] passphrase, byte[] salt) throws Exception {{
            PBEKeySpec spec = new PBEKeySpec(passphrase, salt, {iters}, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        }}
    """)


@_jw("Weak KDF", "No salt in key derivation", "CBS-003")
def _():
    return textwrap.dedent("""\
        // Derive storage key from application identifier
        public static SecretKey deriveStorageKey(String appId) throws Exception {
            byte[] noSalt = new byte[16]; // zero salt — deterministic derivation
            PBEKeySpec spec = new PBEKeySpec(appId.toCharArray(), noSalt, 10000, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        }
    """)


@_jw("Weak signature", "MD5withRSA signature algorithm", "CBS-001")
def _():
    return textwrap.dedent("""\
        // Sign a document for audit trail purposes
        public static byte[] signDocument(byte[] document, PrivateKey key) throws Exception {
            Signature sig = Signature.getInstance("MD5withRSA");
            sig.initSign(key);
            sig.update(document);
            return sig.sign();
        }
    """)


@_jw("Weak signature", "SHA1withRSA signature algorithm", "CBS-001")
def _():
    return textwrap.dedent("""\
        // Sign an API request body for non-repudiation
        public static byte[] signRequest(byte[] body, PrivateKey key) throws Exception {
            Signature sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(key);
            sig.update(body);
            return sig.sign();
        }
    """)


@_jw("Quantum-vulnerable", "RSA key exchange without PQC mitigation", "CBS-003")
def _():
    return textwrap.dedent("""\
        // Establish shared secret for encrypted channel setup
        public static byte[] encryptSharedSecret(byte[] secret, PublicKey recipientKey)
                throws Exception {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, recipientKey);
            return cipher.doFinal(secret);
        }
    """)


@_jw("Quantum-vulnerable", "ECDH with NIST P-256 (quantum-vulnerable)", "CBS-003")
def _():
    return textwrap.dedent("""\
        // Perform ECDH key agreement for forward secrecy
        public static byte[] ecdhSharedSecret(PrivateKey myKey, PublicKey theirKey)
                throws Exception {
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(myKey);
            ka.doPhase(theirKey, true);
            return ka.generateSecret();
        }
    """)


@_jw("Blowfish", "Blowfish cipher with small key", "CBS-001")
def _():
    key_size = random.choice([32, 40, 56])
    return textwrap.dedent(f"""\
        // Encrypt short-lived cache entries with Blowfish
        public static byte[] encryptCache(byte[] data, byte[] key) throws Exception {{
            KeyGenerator kg = KeyGenerator.getInstance("Blowfish");
            kg.init({key_size});
            Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "Blowfish"));
            return cipher.doFinal(data);
        }}
    """)


# ---------------------------------------------------------------------------
# Python snippet factories
# ---------------------------------------------------------------------------

PYTHON_WEAKNESS_FACTORIES: List[Tuple[Weakness, Callable[[], str]]] = []

def _pw(category, description, tag=""):
    wk = _wk(category, description, tag)
    def decorator(fn):
        PYTHON_WEAKNESS_FACTORIES.append((wk, fn))
        return fn
    return decorator


@_pw("Weak algorithm", "MD5 for password hashing", "CBS-001")
def _():
    return textwrap.dedent("""\
        import hashlib

        # Hash a password before persisting to the user store
        def hash_password(password: str) -> str:
            return hashlib.md5(password.encode()).hexdigest()
    """)


@_pw("Weak algorithm", "SHA-1 for data integrity check", "CBS-001")
def _():
    return textwrap.dedent("""\
        import hashlib

        # Compute a quick integrity fingerprint for uploaded files
        def file_fingerprint(path: str) -> str:
            h = hashlib.sha1()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
    """)


@_pw("Weak algorithm", "MD5 HMAC for API request signing", "CBS-001")
def _():
    return textwrap.dedent("""\
        import hashlib
        import hmac

        # Sign API request payloads for partner integrations
        def sign_request(payload: bytes, secret: bytes) -> str:
            return hmac.new(secret, payload, hashlib.md5).hexdigest()
    """)


@_pw("Insecure cipher mode", "AES-ECB mode", "CBS-002")
def _():
    return textwrap.dedent("""\
        from Crypto.Cipher import AES
        import base64

        # Encrypt configuration blob for at-rest storage
        def encrypt_config(data: bytes, key: bytes) -> str:
            cipher = AES.new(key, AES.MODE_ECB)
            padded = data + b"\\x00" * (16 - len(data) % 16)
            return base64.b64encode(cipher.encrypt(padded)).decode()
    """)


@_pw("Insecure cipher mode", "AES-CBC without authentication", "CBS-002")
def _():
    return textwrap.dedent("""\
        from Crypto.Cipher import AES
        import os, base64

        # Encrypt user session data for cookie storage
        def encrypt_session(data: bytes, key: bytes) -> bytes:
            iv = os.urandom(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded = data + b"\\x00" * (16 - len(data) % 16)
            return iv + cipher.encrypt(padded)
    """)


@_pw("Static IV", "Hardcoded static IV for AES", "CBS-002")
def _():
    iv_hex = "".join(f"{random.randint(0,255):02x}" for _ in range(16))
    return textwrap.dedent(f"""\
        from Crypto.Cipher import AES
        import binascii

        # Default IV shared across deployments for reproducible test vectors
        _STATIC_IV = binascii.unhexlify("{iv_hex}")

        def encrypt_with_static_iv(data: bytes, key: bytes) -> bytes:
            cipher = AES.new(key, AES.MODE_CBC, _STATIC_IV)
            padded = data + b"\\x00" * (16 - len(data) % 16)
            return cipher.encrypt(padded)
    """)


@_pw("Hardcoded secret", "Hardcoded AES key", "CBS-003")
def _():
    key = "".join(random.choices("0123456789abcdef", k=32))
    return textwrap.dedent(f"""\
        # Symmetric key for encrypting internal metrics payloads
        METRICS_ENCRYPTION_KEY = b"{key}"
    """)


@_pw("Hardcoded secret", "Hardcoded JWT secret", "CBS-003")
def _():
    secret = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=32))
    return textwrap.dedent(f"""\
        import hmac, hashlib, base64, json

        # JWT signing secret — shared across all application instances
        _JWT_SECRET = "{secret}"

        def sign_jwt(payload: dict) -> str:
            header = base64.urlsafe_b64encode(b'{{"alg":"HS256","typ":"JWT"}}').rstrip(b"=").decode()
            body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
            sig_input = f"{{header}}.{{body}}".encode()
            sig = hmac.new(_JWT_SECRET.encode(), sig_input, hashlib.sha1).digest()
            return f"{{header}}.{{body}}.{{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}}"
    """)


@_pw("Hardcoded secret", "Hardcoded RSA private key string", "CBS-003")
def _():
    return textwrap.dedent("""\
        # RSA private key for development / staging token signing
        _DEV_PRIVATE_KEY_PEM = b\"\"\"
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TNJT7DlyFoGkKB+yNdrPrioqOtOAye4J
        7MGRMYalJsEAE8Y3oMoktAdw6gNKXwEJbHFuJcLLTXbMdRQgBYSyXnK1oWaJNLxQ
        -----END RSA PRIVATE KEY-----
        \"\"\"
    """)


@_pw("Insecure PRNG", "random.random() for token generation", "CBS-003")
def _():
    return textwrap.dedent("""\
        import random
        import string

        # Generate a short-lived password reset token
        def generate_reset_token(length: int = 24) -> str:
            alphabet = string.ascii_letters + string.digits
            return "".join(random.choice(alphabet) for _ in range(length))
    """)


@_pw("Insecure PRNG", "time-seeded random for session ID", "CBS-003")
def _():
    return textwrap.dedent("""\
        import random
        import time

        # Create a session identifier seeded from current timestamp
        def make_session_id() -> str:
            rng = random.Random(int(time.time()))
            return hex(rng.getrandbits(64))[2:]
    """)


@_pw("Outdated protocol", "SSLv3 / TLS 1.0 context", "CBS-004")
def _():
    return textwrap.dedent("""\
        import ssl

        # Build SSL context for connections to legacy on-premise endpoints
        def build_legacy_ssl_context() -> ssl.SSLContext:
            ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ctx.options &= ~ssl.OP_NO_SSLv3
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            return ctx
    """)


@_pw("Outdated protocol", "TLS 1.1 minimum version", "CBS-004")
def _():
    return textwrap.dedent("""\
        import ssl

        # Connect to partner API that requires TLS 1.1 compatibility
        def get_partner_ssl_context() -> ssl.SSLContext:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_1
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
    """)


@_pw("Missing certificate validation", "SSL cert verification disabled", "CBS-004")
def _():
    return textwrap.dedent("""\
        import ssl, urllib.request

        # Retrieve remote configuration file from internal host
        def fetch_config(url: str) -> bytes:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(url, context=ctx) as resp:
                return resp.read()
    """)


@_pw("Weak KDF", "Low PBKDF2 iterations", "CBS-003")
def _():
    iters = random.choice([100, 500, 1000, 2000])
    return textwrap.dedent(f"""\
        import hashlib

        # Derive an AES key from a user passphrase for file encryption
        def derive_file_key(passphrase: str, salt: bytes) -> bytes:
            return hashlib.pbkdf2_hmac("sha1", passphrase.encode(), salt, {iters}, dklen=16)
    """)


@_pw("Weak KDF", "No salt in key derivation", "CBS-003")
def _():
    return textwrap.dedent("""\
        import hashlib

        # Derive a deterministic key from an application secret
        def derive_app_key(app_secret: str) -> bytes:
            # Salt omitted for deterministic cross-instance key agreement
            return hashlib.pbkdf2_hmac("sha1", app_secret.encode(), b"", 10000, dklen=16)
    """)


@_pw("Weak signature", "RSA-1024 key generation", "CBS-003")
def _():
    return textwrap.dedent("""\
        from cryptography.hazmat.primitives.asymmetric import rsa

        # Generate RSA key pair for device certificate signing
        def generate_device_keypair():
            return rsa.generate_private_key(
                public_exponent=65537,
                key_size=1024,
            )
    """)


@_pw("Weak signature", "SHA1withRSA signature", "CBS-001")
def _():
    return textwrap.dedent("""\
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        # Sign an audit record for non-repudiation logging
        def sign_audit_record(record: bytes, private_key) -> bytes:
            return private_key.sign(record, padding.PKCS1v15(), hashes.SHA1())
    """)


@_pw("Quantum-vulnerable", "RSA encryption for key exchange", "CBS-003")
def _():
    return textwrap.dedent("""\
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

        # Wrap a symmetric key using the recipient's RSA public key
        def wrap_key(symmetric_key: bytes, recipient_public_key) -> bytes:
            return recipient_public_key.encrypt(
                symmetric_key,
                asym_padding.PKCS1v15(),
            )
    """)


@_pw("Quantum-vulnerable", "Elliptic-curve ECDH (NIST P-256, quantum-vulnerable)", "CBS-003")
def _():
    return textwrap.dedent("""\
        from cryptography.hazmat.primitives.asymmetric.ec import (
            ECDH, SECP256R1, generate_private_key
        )

        # Derive a shared session secret using ECDH
        def ecdh_shared_secret(peer_public_key) -> bytes:
            ephemeral = generate_private_key(SECP256R1())
            return ephemeral.exchange(ECDH(), peer_public_key)
    """)


@_pw("Blowfish", "Blowfish cipher", "CBS-001")
def _():
    return textwrap.dedent("""\
        from Crypto.Cipher import Blowfish as BF
        import struct

        # Encrypt small data chunks with Blowfish for legacy API compatibility
        def encrypt_legacy(data: bytes, key: bytes) -> bytes:
            cipher = BF.new(key[:8], BF.MODE_ECB)
            pad_len = BF.block_size - len(data) % BF.block_size
            data += bytes([pad_len]) * pad_len
            return cipher.encrypt(data)
    """)


@_pw("Hardcoded secret", "Hardcoded database password", "CBS-003")
def _():
    password = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$", k=16))
    return textwrap.dedent(f"""\
        # Database connection settings — credentials embedded for CI pipeline convenience
        DB_CONFIG = {{
            "host": "db.internal.example.com",
            "port": 5432,
            "user": "appuser",
            "password": "{password}",
            "database": "appdb",
        }}
    """)


# ---------------------------------------------------------------------------
# Application structure generators
# ---------------------------------------------------------------------------

def _random_app_description():
    adjectives = ["Enterprise", "Cloud-Native", "Distributed", "Modular", "Scalable"]
    nouns = ["Identity Platform", "Data Gateway", "Analytics Service", "Compliance Hub",
             "Reporting Engine", "Notification Service", "Billing API", "Audit Framework"]
    return f"{random.choice(adjectives)} {random.choice(nouns)}"


# ---- Java application ----

def generate_java_app(base_dir: Path, app_name: str, version: str,
                      weaknesses_to_inject: List[Tuple[Weakness, str]]) -> List[Weakness]:
    """Build the Java application tree and inject weaknesses."""
    pkg = app_name.lower().replace("-", "").replace("_", "")
    pkg_path = base_dir / "src" / "main" / "java" / "com" / "example" / pkg
    test_path = base_dir / "src" / "test" / "java" / "com" / "example" / pkg
    res_path = base_dir / "src" / "main" / "resources"
    for d in [pkg_path, test_path, res_path,
              pkg_path / "api", pkg_path / "crypto",
              pkg_path / "service", pkg_path / "util",
              pkg_path / "config", base_dir / "config"]:
        d.mkdir(parents=True, exist_ok=True)

    class_pkg = f"com.example.{pkg}"
    description = _random_app_description()

    # Assign weaknesses to files
    file_slots = {
        "crypto/CryptoUtil": [],
        "crypto/KeyManager": [],
        "service/AuthService": [],
        "service/UserService": [],
        "api/ApiController": [],
        "util/HashUtils": [],
        "util/TokenUtils": [],
        "config/SecurityConfig": [],
    }
    slot_names = list(file_slots.keys())
    for wk, snippet in weaknesses_to_inject:
        random.choice(slot_names)
        slot = random.choice(slot_names)
        file_slots[slot].append((wk, snippet))

    injected: List[Weakness] = []

    def _java_file(rel_class: str, extra_imports: str, extra_body: str, snippets: list):
        class_name = rel_class.split("/")[-1]
        sub_pkg = ".".join(rel_class.split("/")[:-1])
        extra_imports_block = ("\n" + extra_imports) if extra_imports.strip() else ""

        # Collect body members, each indented 4 spaces inside the class
        members = [extra_body]
        for wk, snip in snippets:
            # Re-indent the snippet to 4-space class body indent
            indented = "\n".join(
                ("    " + ln if ln.strip() else "")
                for ln in snip.strip().splitlines()
            )
            members.append("\n    // ----\n" + indented)
            injected.append(wk)

        body = "\n\n".join(members)

        lines = [
            f"package {class_pkg}.{sub_pkg};",
            "",
            "import java.nio.charset.StandardCharsets;",
            "import java.security.*;",
            "import java.security.spec.*;",
            "import java.util.Base64;",
            "import javax.crypto.*;",
            "import javax.crypto.spec.*;",
            "import javax.net.ssl.*;",
            "import java.security.cert.X509Certificate;",
        ]
        if extra_imports.strip():
            lines.append(extra_imports.strip())
        lines += [
            "",
            "/**",
            f" * {class_name} — part of {app_name} v{version}.",
            f" * {description}",
            " */",
            f"public class {class_name} {{",
            "",
            body,
            "",
            "}",
            "",
        ]
        return "\n".join(lines)

    # Write each file
    files_map = {
        "crypto/CryptoUtil": ("", "    // Cryptographic utility helpers\n    private CryptoUtil() {}"),
        "crypto/KeyManager": ("import java.security.KeyPair;\nimport java.security.KeyPairGenerator;",
                               "    // Key lifecycle management\n    private static final String KEY_STORE_PATH = \"keystore.jks\";"),
        "service/AuthService": ("import java.util.UUID;",
                                 "    // Handles user authentication and session lifecycle\n    private static final int SESSION_TIMEOUT_MINUTES = 30;"),
        "service/UserService": ("import java.util.HashMap;\nimport java.util.Map;",
                                 "    // User management and profile operations\n    private final Map<String, String> userStore = new HashMap<>();"),
        "api/ApiController": ("import java.io.IOException;\nimport java.net.HttpURLConnection;\nimport java.net.URL;",
                               "    // REST API surface for external callers\n    private static final String BASE_URL = \"https://api.example.com\";"),
        "util/HashUtils": ("", "    // Generic hashing helpers used across the application\n    private HashUtils() {}"),
        "util/TokenUtils": ("import java.util.UUID;",
                             "    // Token generation and validation utilities\n    private TokenUtils() {}"),
        "config/SecurityConfig": ("import java.util.Arrays;\nimport java.util.List;",
                                   "    // Central security configuration\n    public static final List<String> ALLOWED_ORIGINS = Arrays.asList(\"https://app.example.com\");"),
    }

    for rel_class, (extra_imports, extra_body) in files_map.items():
        snippets = file_slots.get(rel_class, [])
        content = _java_file(rel_class, extra_imports, extra_body, snippets)
        sub_parts = rel_class.split("/")
        target_dir = pkg_path
        for part in sub_parts[:-1]:
            target_dir = target_dir / part
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / f"{sub_parts[-1]}.java").write_text(content)

    # Main application entry point
    (pkg_path / f"{_title(app_name)}Application.java").write_text(textwrap.dedent(f"""\
        package {class_pkg};

        /**
         * Application entry point for {app_name} v{version}.
         */
        public class {_title(app_name)}Application {{

            public static void main(String[] args) {{
                System.out.println("{app_name} v{version} starting...");
            }}

        }}
    """))

    # pom.xml
    (base_dir / "pom.xml").write_text(textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <project xmlns="http://maven.apache.org/POM/4.0.0"
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                 xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
                     https://maven.apache.org/xsd/maven-4.0.0.xsd">
            <modelVersion>4.0.0</modelVersion>

            <groupId>com.example</groupId>
            <artifactId>{app_name}</artifactId>
            <version>{version}</version>
            <packaging>jar</packaging>

            <properties>
                <java.version>17</java.version>
                <maven.compiler.source>17</maven.compiler.source>
                <maven.compiler.target>17</maven.compiler.target>
                <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
            </properties>

            <dependencies>
                <dependency>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-starter-web</artifactId>
                    <version>3.2.0</version>
                </dependency>
                <dependency>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-starter-security</artifactId>
                    <version>3.2.0</version>
                </dependency>
                <dependency>
                    <groupId>io.jsonwebtoken</groupId>
                    <artifactId>jjwt-api</artifactId>
                    <version>0.12.3</version>
                </dependency>
                <dependency>
                    <groupId>org.junit.jupiter</groupId>
                    <artifactId>junit-jupiter</artifactId>
                    <version>5.10.0</version>
                    <scope>test</scope>
                </dependency>
            </dependencies>

            <build>
                <plugins>
                    <plugin>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-maven-plugin</artifactId>
                        <version>3.2.0</version>
                    </plugin>
                </plugins>
            </build>
        </project>
    """))

    # application.properties
    (res_path / "application.properties").write_text(textwrap.dedent(f"""\
        spring.application.name={app_name}
        server.port=8080
        server.ssl.enabled=true
        server.ssl.protocol=TLSv1
        server.ssl.enabled-protocols=TLSv1,TLSv1.1,TLSv1.2
        logging.level.root=INFO
        spring.datasource.url=jdbc:postgresql://localhost:5432/appdb
        spring.datasource.username=appuser
        spring.datasource.password=S3cr3tP@ssw0rd!
    """))

    # logback config
    (res_path / "logback.xml").write_text(textwrap.dedent(f"""\
        <configuration>
            <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
                <encoder>
                    <pattern>%d{{yyyy-MM-dd HH:mm:ss}} %-5level %logger{{36}} - %msg%n</pattern>
                </encoder>
            </appender>
            <root level="info">
                <appender-ref ref="STDOUT" />
            </root>
        </configuration>
    """))

    # config/security.yaml
    (base_dir / "config" / "security.yaml").write_text(textwrap.dedent(f"""\
        security:
          tls:
            min-version: "TLSv1"
            max-version: "TLSv1.3"
          crypto:
            default-algorithm: "AES/CBC/PKCS5Padding"
            key-size: 128
            hash-algorithm: "SHA-1"
          jwt:
            signing-algorithm: "HS256"
            secret: "hardcoded-jwt-secret-{random.randint(1000,9999)}"
            expiry-seconds: 86400
    """))

    # Minimal test stub
    (test_path / f"{_title(app_name)}ApplicationTests.java").write_text(textwrap.dedent(f"""\
        package {class_pkg};

        import org.junit.jupiter.api.Test;

        class {_title(app_name)}ApplicationTests {{

            @Test
            void contextLoads() {{
                // Smoke test: application context starts without errors
            }}

        }}
    """))

    _write_readme(base_dir, app_name, version, description, "Java / Spring Boot")
    return injected


# ---- Python application ----

def generate_python_app(base_dir: Path, app_name: str, version: str,
                        weaknesses_to_inject: List[Tuple[Weakness, str]]) -> List[Weakness]:
    """Build the Python application tree and inject weaknesses."""
    pkg = app_name.lower().replace("-", "_").replace(" ", "_")
    description = _random_app_description()

    dirs = [
        base_dir / pkg / "api",
        base_dir / pkg / "crypto",
        base_dir / pkg / "services",
        base_dir / pkg / "utils",
        base_dir / pkg / "config",
        base_dir / "tests",
        base_dir / "templates",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

    # Slot weaknesses across source files
    file_slots = {
        f"{pkg}/crypto/cipher.py": [],
        f"{pkg}/crypto/keys.py": [],
        f"{pkg}/services/auth.py": [],
        f"{pkg}/services/user.py": [],
        f"{pkg}/api/routes.py": [],
        f"{pkg}/utils/hashing.py": [],
        f"{pkg}/utils/tokens.py": [],
        f"{pkg}/config/settings.py": [],
    }
    slot_names = list(file_slots.keys())
    injected: List[Weakness] = []

    for wk, snippet in weaknesses_to_inject:
        slot = random.choice(slot_names)
        file_slots[slot].append((wk, snippet))

    def _py_module(header: str, snippets: list) -> str:
        parts = [header]
        for wk, snip in snippets:
            parts.append("\n" + snip.strip() + "\n")
            injected.append(wk)
        return "\n\n".join(parts) + "\n"

    # --- crypto/cipher.py ---
    (base_dir / pkg / "crypto" / "cipher.py").write_text(_py_module(
        textwrap.dedent(f"""\
            \"\"\"
            Cipher utilities for {app_name}.
            Provides encryption and decryption helpers used by services.
            \"\"\"
            import os
        """),
        file_slots[f"{pkg}/crypto/cipher.py"]
    ))

    # --- crypto/keys.py ---
    (base_dir / pkg / "crypto" / "keys.py").write_text(_py_module(
        textwrap.dedent(f"""\
            \"\"\"
            Key management utilities for {app_name}.
            Handles generation, derivation, and storage of cryptographic keys.
            \"\"\"
            import os
            import base64
        """),
        file_slots[f"{pkg}/crypto/keys.py"]
    ))

    # --- services/auth.py ---
    (base_dir / pkg / "services" / "auth.py").write_text(_py_module(
        textwrap.dedent(f"""\
            \"\"\"
            Authentication service for {app_name}.
            Manages user login, token issuance, and session validation.
            \"\"\"
            import time
            import datetime
        """),
        file_slots[f"{pkg}/services/auth.py"]
    ))

    # --- services/user.py ---
    (base_dir / pkg / "services" / "user.py").write_text(_py_module(
        textwrap.dedent(f"""\
            \"\"\"
            User management service for {app_name}.
            CRUD operations for user accounts and profile data.
            \"\"\"
            from typing import Optional, Dict
        """),
        file_slots[f"{pkg}/services/user.py"]
    ))

    # --- api/routes.py ---
    (base_dir / pkg / "api" / "routes.py").write_text(_py_module(
        textwrap.dedent(f"""\
            \"\"\"
            API route definitions for {app_name}.
            Maps HTTP endpoints to service handlers.
            \"\"\"
            from typing import Any, Dict
        """),
        file_slots[f"{pkg}/api/routes.py"]
    ))

    # --- utils/hashing.py ---
    (base_dir / pkg / "utils" / "hashing.py").write_text(_py_module(
        textwrap.dedent(f"""\
            \"\"\"
            Hashing utilities for {app_name}.
            \"\"\"
            import hashlib
        """),
        file_slots[f"{pkg}/utils/hashing.py"]
    ))

    # --- utils/tokens.py ---
    (base_dir / pkg / "utils" / "tokens.py").write_text(_py_module(
        textwrap.dedent(f"""\
            \"\"\"
            Token generation and validation for {app_name}.
            \"\"\"
            import os
            import base64
        """),
        file_slots[f"{pkg}/utils/tokens.py"]
    ))

    # --- config/settings.py ---
    db_pass = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=16))
    secret_key = "".join(random.choices("0123456789abcdef", k=32))
    settings_header = textwrap.dedent(f"""\
        \"\"\"
        Application settings for {app_name} v{version}.
        Configuration values are loaded at import time.
        \"\"\"

        # Application metadata
        APP_NAME = "{app_name}"
        APP_VERSION = "{version}"
        DEBUG = False

        # Database configuration
        DATABASE_URL = "postgresql://appuser:{db_pass}@db.internal.example.com:5432/appdb"

        # Cryptographic defaults
        SECRET_KEY = "{secret_key}"
        HASH_ALGORITHM = "md5"
        TOKEN_ALGORITHM = "HS256"
        PBKDF2_ITERATIONS = 500
        MIN_TLS_VERSION = "TLSv1"
    """)
    (base_dir / pkg / "config" / "settings.py").write_text(_py_module(
        settings_header,
        file_slots[f"{pkg}/config/settings.py"]
    ))

    # __init__ files
    for d in [base_dir / pkg, base_dir / pkg / "api",
              base_dir / pkg / "crypto", base_dir / pkg / "services",
              base_dir / pkg / "utils", base_dir / pkg / "config",
              base_dir / "tests"]:
        (d / "__init__.py").write_text("")

    # main.py
    (base_dir / "main.py").write_text(textwrap.dedent(f"""\
        \"\"\"
        Entry point for {app_name} v{version}.
        {description}
        \"\"\"

        def main():
            print(f"{app_name} v{version} starting...")

        if __name__ == "__main__":
            main()
    """))

    # requirements.txt
    (base_dir / "requirements.txt").write_text(textwrap.dedent("""\
        flask>=2.3.0
        sqlalchemy>=2.0.0
        pycryptodome>=3.19.0
        cryptography>=41.0.0
        pyjwt>=2.8.0
        requests>=2.31.0
        python-dotenv>=1.0.0
    """))

    # setup.py
    (base_dir / "setup.py").write_text(textwrap.dedent(f"""\
        from setuptools import setup, find_packages

        setup(
            name="{app_name}",
            version="{version}",
            packages=find_packages(),
            install_requires=[
                "flask>=2.3.0",
                "sqlalchemy>=2.0.0",
                "pycryptodome>=3.19.0",
                "cryptography>=41.0.0",
                "pyjwt>=2.8.0",
                "requests>=2.31.0",
            ],
        )
    """))

    # .env.example
    (base_dir / ".env.example").write_text(textwrap.dedent("""\
        # Copy to .env and fill in real values
        DATABASE_URL=postgresql://user:password@localhost:5432/dbname
        SECRET_KEY=change-me
        JWT_SECRET=change-me
    """))

    # config/app.yaml
    (base_dir / "config") .mkdir(exist_ok=True)
    (base_dir / "config" / "app.yaml").write_text(textwrap.dedent(f"""\
        app:
          name: "{app_name}"
          version: "{version}"
          debug: false

        security:
          tls:
            min_version: "TLSv1.1"
          crypto:
            algorithm: "AES-128-CBC"
            hash: "sha1"
            kdf_iterations: 1000
          jwt:
            algorithm: "HS256"
            secret: "static-jwt-secret-{random.randint(1000,9999)}"
    """))

    # templates/base.html
    (base_dir / "templates" / "base.html").write_text(textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>{app_name}</title>
        </head>
        <body>
            <h1>{app_name} v{version}</h1>
            {{% block content %}}{{% endblock %}}
        </body>
        </html>
    """))

    # tests/test_auth.py
    (base_dir / "tests" / "test_auth.py").write_text(textwrap.dedent(f"""\
        \"\"\"
        Unit tests for authentication service — {app_name} v{version}.
        \"\"\"

        def test_hash_password_returns_string():
            # Verifies that the password hash function returns a string value
            from {pkg}.services.user import hash_password  # type: ignore
            result = hash_password("testpassword")
            assert isinstance(result, str)

        def test_generate_token_not_empty():
            # Verifies that token generation yields a non-empty result
            from {pkg}.utils.tokens import generate_reset_token  # type: ignore
            assert generate_reset_token()
    """))

    _write_readme(base_dir, app_name, version, description, "Python / Flask")
    return injected


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _title(name: str) -> str:
    """Convert app name to PascalCase class name."""
    return "".join(w.capitalize() for w in name.replace("-", " ").replace("_", " ").split())


def _write_readme(base_dir: Path, app_name: str, version: str,
                  description: str, stack: str):
    (base_dir / "README.md").write_text(textwrap.dedent(f"""\
        # {app_name}

        **Version:** {version}
        **Stack:** {stack}

        ## Overview

        {app_name} is a {description.lower()} built on {stack}. It provides secure
        authentication, data encryption, and API management capabilities for enterprise
        deployments.

        ## Getting Started

        ### Prerequisites

        - Java 17+ (for Java projects) / Python 3.11+ (for Python projects)
        - Maven 3.9+ (for Java projects) / pip (for Python projects)

        ### Build & Run

        **Java:**
        ```bash
        mvn clean package
        java -jar target/{app_name}-{version}.jar
        ```

        **Python:**
        ```bash
        pip install -r requirements.txt
        python main.py
        ```

        ## Configuration

        Copy `config/app.yaml` and adjust values for your environment.
        Never commit secrets to source control — use environment variables or a secrets manager.

        ## Security

        This application follows enterprise security guidelines. All cryptographic operations
        are performed using the standard library. Refer to `config/security.yaml` for
        protocol and algorithm settings.

        ## License

        Proprietary — {app_name} {version}. All rights reserved.
    """))


# ---------------------------------------------------------------------------
# Main interactive flow
# ---------------------------------------------------------------------------

def prompt_choice(prompt: str, choices: List[str]) -> str:
    choices_lower = [c.lower() for c in choices]
    while True:
        answer = input(prompt).strip().lower()
        if answer in choices_lower:
            return answer
        print(f"  Please enter one of: {', '.join(choices)}")


def prompt_non_empty(prompt: str) -> str:
    while True:
        val = input(prompt).strip()
        if val:
            return val
        print("  Value cannot be empty.")


def main():
    print("=" * 60)
    print("  Vulnerable App Generator — Guardium QSE Demo Tool")
    print("=" * 60)
    print()

    lang = prompt_choice("Language [java/python]: ", ["java", "python"])
    app_name = prompt_non_empty("Application name: ")
    version = prompt_non_empty("Version (e.g. 1.0.0): ")

    # Sanitise app_name for use as a directory
    safe_name = app_name.replace(" ", "-")
    base_dir = Path(safe_name)

    if base_dir.exists():
        confirm = prompt_choice(
            f"Directory '{safe_name}' already exists. Overwrite? [yes/no]: ",
            ["yes", "no"]
        )
        if confirm != "yes":
            print("Aborted.")
            sys.exit(0)

    target_count = random.randint(8, 26)
    print(f"\n  Generating {lang.upper()} application '{app_name}' v{version}...")
    print(f"  Target weakness count: {target_count}")
    print()

    # Draw weaknesses from the relevant pool
    factory_pool = JAVA_WEAKNESS_FACTORIES if lang == "java" else PYTHON_WEAKNESS_FACTORIES

    # Build weighted sample: allow repetition with different random state
    selected: List[Tuple[Weakness, str]] = []
    pool_copy = list(factory_pool)
    random.shuffle(pool_copy)
    while len(selected) < target_count:
        random.shuffle(pool_copy)
        for wk_def, factory in pool_copy:
            if len(selected) >= target_count:
                break
            # Re-invoke factory each time to get fresh (possibly varied) snippet
            selected.append((_wk(wk_def.category, wk_def.description, wk_def.tag), factory()))

    # Generate the application
    if lang == "java":
        injected = generate_java_app(base_dir, safe_name, version, selected)
    else:
        injected = generate_python_app(base_dir, safe_name, version, selected)

    # Summarise
    from collections import Counter
    counts = Counter(w.category for w in injected)

    print(f"\n{'=' * 60}")
    print(f"  Generation complete: {base_dir.resolve()}")
    print(f"  Total cryptographic weaknesses injected: {len(injected)}")
    print(f"{'=' * 60}")
    print("  Weakness breakdown by category:")
    for cat, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"    [{count:>2}]  {cat}")
    print()
    print("  Detailed weakness list:")
    for i, wk in enumerate(injected, 1):
        rule = f" ({wk.tag})" if wk.tag else ""
        print(f"    {i:>2}. {wk.description}{rule}")
    print()
    print("  NOTE: This application contains DELIBERATE security weaknesses.")
    print("        It is intended exclusively for Guardium QSE demo purposes.")
    print("=" * 60)

    # Prompt for repository URL (mandatory for Guardium Cryptography Manager upload)
    print()
    print("  REQUIRED FOR GUARDIUM CRYPTOGRAPHY MANAGER UPLOAD")
    print("  " + "-" * 56)
    print("  The 'repositoryUrl' (Git URL) is a mandatory field when")
    print("  uploading a CBOM to Guardium Cryptography Manager.")
    print()
    repo_url = prompt_non_empty("  Enter the repository URL (e.g. https://github.com/org/repo): ")
    print()
    print(f"  repositoryUrl : {repo_url}")
    print()
    print("  Use this value in the 'repositoryUrl' field of your CBOM")
    print("  or API upload payload before submitting to Guardium.")
    print("=" * 60)


if __name__ == "__main__":
    main()
