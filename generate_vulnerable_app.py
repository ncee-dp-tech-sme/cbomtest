#!/usr/bin/env python3
"""
generate_vulnerable_app.py

Generates a realistic multi-file Java or Python application with deliberately
introduced cryptographic weaknesses for Guardium Quantum Safe Explorer demos.

All weaknesses are intentional; this tool is for demo/testing purposes only.

Change history:
  2025-07-15  Initial version. Interactive generator for Java and Python apps
              with randomised cryptographic weakness injection across files.
  2026-07-31  Added PQC algorithm discovery targets: Java/JCA (ML-KEM, ML-DSA),
              Java/BouncyCastle (ML-KEM, ML-DSA, SLH-DSA), Python/cryptography
              (ML-KEM, ML-DSA), Python/oqs (ML-KEM, ML-DSA, SLH-DSA, XMSS).
              Updated pom.xml generation to include BouncyCastle dependency.
              Updated requirements.txt generation to include liboqs-python.
 2026-07-31  Fix: added `import java.util.Random;` to the common Java import
              block in `_java_file()` so the CBS-003 insecure-PRNG snippet
              (which uses `java.util.Random`) compiles in every target class.
  2026-08-01  Phase 2: Added local temp file strategy helpers (_make_temp_dir,
              _ensure_gitignore_entry) for project-local, git-ignored temp
              directories during multi-language app generation.
  2026-08-01  Phase 3: Added snippet factories for Go (19), JavaScript (21),
              C# (18), Dart (7), C/C++ (17) — all CBS-001..004 + PQC patterns.
  2026-08-01  Phase 4: Added generator functions for all 5 new languages with
              build file templates, snippet distribution, and GSKit platform guard.
  2026-08-01  Phase 5: Extended main() with FACTORY_POOL_MAP and GENERATOR_MAP;
              language prompt now supports java/python/go/javascript/csharp/dart/c.
  2026-07-31  Phase 6: Added 3 more Dart factories (AES-ECB CBS-002, RSA/PKCS1
              CBS-003, insecure PRNG CBS-003) to match other language coverage.
              Added 5 C/C++ Crypto++ factories (MD5, SHA-1, AES-ECB, RSA-1024,
              hardcoded key) and 2 liboqs-C PQC factories (ML-KEM, ML-DSA) that
              were missing from Phase 3.
  2026-08-02  Fix: overwrite confirmation in main() now removes the existing
              directory before calling the generator, so generators that guard
              with `if base_dir.exists(): return []` (Go, JS, C#, Dart) no
              longer produce zero weaknesses when the target dir already exists.
"""

import os
import random
import shutil
import sys
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Tuple

import platform_guard

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
# Local temp file strategy
# ---------------------------------------------------------------------------

# Create a project-local, timestamped temp directory under .gen-tmp/.
# Never uses OS-managed temp locations (no tempfile, $TMPDIR, %TEMP%).
def _make_temp_dir(lang: str, app_name: str) -> Path:
    project_root = Path(__file__).parent
    tmp_root = project_root / ".gen-tmp"
    tmp_root.mkdir(exist_ok=True)
    safe_name = app_name[:20]
    run_dir = tmp_root / f"{int(time.time())}-{lang}-{safe_name}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


# Add an entry to .gitignore at project root if it is not already present.
def _ensure_gitignore_entry(project_root: Path, entry: str) -> None:
    gi = project_root / ".gitignore"
    if gi.exists():
        if entry not in gi.read_text():
            with gi.open("a") as f:
                f.write(f"\n{entry}\n")
    else:
        gi.write_text(f"{entry}\n")


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
# Java PQC discovery targets — Java/JCA (Java 21+ built-in KEM API)
# ---------------------------------------------------------------------------

# Algorithm: ML-KEM  Library: Java JCA  Language: Java
@_jw("PQC algorithm", "ML-KEM key encapsulation via JCA KEM API", "CBS-003")
def _():
    param = random.choice(["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
    return textwrap.dedent(f"""\
        // Algorithm: ML-KEM  Library: Java JCA  Language: Java
        // Key encapsulation for post-quantum secure key exchange
        public static byte[] mlKemEncapsulate(PublicKey recipientPublicKey) throws Exception {{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("{param}");
            KeyPair kp = kpg.generateKeyPair();
            javax.crypto.KEM kem = javax.crypto.KEM.getInstance("{param}");
            javax.crypto.KEM.Encapsulator enc = kem.newEncapsulator(recipientPublicKey);
            javax.crypto.KEM.Encapsulated encapsulated = enc.encapsulate();
            return encapsulated.encapsulation();
        }}
    """)


# Algorithm: ML-DSA  Library: Java JCA  Language: Java
@_jw("PQC algorithm", "ML-DSA digital signature via JCA Signature API", "CBS-003")
def _():
    param = random.choice(["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
    return textwrap.dedent(f"""\
        // Algorithm: ML-DSA  Library: Java JCA  Language: Java
        // Post-quantum digital signature for document signing
        public static byte[] mlDsaSign(byte[] document, PrivateKey signingKey) throws Exception {{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("{param}");
            KeyPair kp = kpg.generateKeyPair();
            Signature sig = Signature.getInstance("{param}");
            sig.initSign(signingKey);
            sig.update(document);
            return sig.sign();
        }}
    """)


# ---------------------------------------------------------------------------
# Java PQC discovery targets — Java/BouncyCastle
# ---------------------------------------------------------------------------

# Algorithm: ML-KEM  Library: BouncyCastle  Language: Java
@_jw("PQC algorithm", "ML-KEM key encapsulation via BouncyCastle", "CBS-003")
def _():
    param = random.choice(["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
    return textwrap.dedent(f"""\
        // Algorithm: ML-KEM  Library: BouncyCastle  Language: Java
        // Register BC provider and perform post-quantum key encapsulation
        public static byte[] bcMlKemEncapsulate() throws Exception {{
            if (java.security.Security.getProvider("BC") == null) {{
                java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            }}
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("{param}", "BC");
            KeyPair kp = kpg.generateKeyPair();
            javax.crypto.KeyAgreement ka = javax.crypto.KeyAgreement.getInstance("{param}", "BC");
            ka.init(kp.getPrivate());
            ka.doPhase(kp.getPublic(), true);
            return ka.generateSecret();
        }}
    """)


# Algorithm: ML-DSA  Library: BouncyCastle  Language: Java
@_jw("PQC algorithm", "ML-DSA digital signature via BouncyCastle", "CBS-003")
def _():
    param = random.choice(["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
    return textwrap.dedent(f"""\
        // Algorithm: ML-DSA  Library: BouncyCastle  Language: Java
        // Post-quantum digital signature using BouncyCastle provider
        public static byte[] bcMlDsaSign(byte[] data) throws Exception {{
            if (java.security.Security.getProvider("BC") == null) {{
                java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            }}
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("{param}", "BC");
            KeyPair kp = kpg.generateKeyPair();
            Signature sig = Signature.getInstance("{param}", "BC");
            sig.initSign(kp.getPrivate());
            sig.update(data);
            return sig.sign();
        }}
    """)


# Algorithm: SLH-DSA  Library: BouncyCastle  Language: Java
@_jw("PQC algorithm", "SLH-DSA hash-based signature via BouncyCastle", "CBS-003")
def _():
    param = random.choice(["SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
                            "SLH-DSA-SHA2-192s", "SLH-DSA-SHAKE-128s"])
    return textwrap.dedent(f"""\
        // Algorithm: SLH-DSA  Library: BouncyCastle  Language: Java
        // Stateless hash-based post-quantum signature using BouncyCastle
        public static byte[] bcSlhDsaSign(byte[] message) throws Exception {{
            if (java.security.Security.getProvider("BC") == null) {{
                java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            }}
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("{param}", "BC");
            KeyPair kp = kpg.generateKeyPair();
            Signature sig = Signature.getInstance("{param}", "BC");
            sig.initSign(kp.getPrivate());
            sig.update(message);
            return sig.sign();
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


# ---------------------------------------------------------------------------
# Python PQC discovery targets — Python/cryptography library
# ---------------------------------------------------------------------------

# Algorithm: ML-KEM  Library: cryptography  Language: Python
@_pw("PQC algorithm", "ML-KEM key encapsulation via cryptography library", "CBS-003")
def _():
    param = random.choice(["MLKEM512", "MLKEM768", "MLKEM1024"])
    return textwrap.dedent(f"""\
        # Algorithm: ML-KEM  Library: cryptography  Language: Python
        # Post-quantum key encapsulation using the cryptography library
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: F401
            from cryptography.hazmat.primitives.asymmetric.mlkem import (
                MLKEMPrivateKey, MLKEMPublicKey, generate_private_key as mlkem_generate_private_key
            )

            def mlkem_keygen_and_encap() -> bytes:
                # Algorithm: ML-KEM  Library: cryptography  Language: Python
                private_key = mlkem_generate_private_key("{param}")
                public_key = private_key.public_key()
                ciphertext, shared_key = public_key.encapsulate()
                return shared_key
        except ImportError:
            import sys
            print("ML-KEM requires cryptography >= 44.0.0 with ML-KEM support", file=sys.stderr)

            def mlkem_keygen_and_encap() -> bytes:  # type: ignore[no-redef]
                raise RuntimeError("ML-KEM not available — install cryptography >= 44.0.0")
    """)


# Algorithm: ML-DSA  Library: cryptography  Language: Python
@_pw("PQC algorithm", "ML-DSA digital signature via cryptography library", "CBS-003")
def _():
    param = random.choice(["MLDSA44", "MLDSA65", "MLDSA87"])
    return textwrap.dedent(f"""\
        # Algorithm: ML-DSA  Library: cryptography  Language: Python
        # Post-quantum digital signature using the cryptography library
        try:
            from cryptography.hazmat.primitives.asymmetric.mldsa import (
                MLDSAPrivateKey, MLDSAPublicKey, generate_private_key as mldsa_generate_private_key
            )

            def mldsa_sign(message: bytes) -> bytes:
                # Algorithm: ML-DSA  Library: cryptography  Language: Python
                private_key = mldsa_generate_private_key("{param}")
                return private_key.sign(message)
        except ImportError:
            import sys
            print("ML-DSA requires cryptography >= 44.0.0 with ML-DSA support", file=sys.stderr)

            def mldsa_sign(message: bytes) -> bytes:  # type: ignore[no-redef]
                raise RuntimeError("ML-DSA not available — install cryptography >= 44.0.0")
    """)


# ---------------------------------------------------------------------------
# Python PQC discovery targets — Python/oqs (liboqs-python)
# ---------------------------------------------------------------------------

# Algorithm: ML-KEM  Library: oqs  Language: Python
@_pw("PQC algorithm", "ML-KEM key encapsulation via liboqs-python", "CBS-003")
def _():
    param = random.choice(["Kyber512", "Kyber768", "Kyber1024",
                            "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
    return textwrap.dedent(f"""\
        # Algorithm: ML-KEM  Library: oqs  Language: Python
        # Post-quantum key encapsulation using liboqs-python (Open Quantum Safe)
        try:
            import oqs

            def oqs_mlkem_keygen_and_encap() -> bytes:
                # Algorithm: ML-KEM  Library: oqs  Language: Python
                with oqs.KeyEncapsulation("{param}") as kem:
                    public_key = kem.generate_keypair()
                    ciphertext, shared_key_enc = kem.encap_secret(public_key)
                    shared_key_dec = kem.decap_secret(ciphertext)
                    return shared_key_dec
        except ImportError:
            import sys
            print("ML-KEM (oqs) requires liboqs-python: pip install liboqs-python", file=sys.stderr)

            def oqs_mlkem_keygen_and_encap() -> bytes:  # type: ignore[no-redef]
                raise RuntimeError("liboqs-python not installed")
    """)


# Algorithm: ML-DSA  Library: oqs  Language: Python
@_pw("PQC algorithm", "ML-DSA digital signature via liboqs-python", "CBS-003")
def _():
    param = random.choice(["Dilithium2", "Dilithium3", "Dilithium5",
                            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
    return textwrap.dedent(f"""\
        # Algorithm: ML-DSA  Library: oqs  Language: Python
        # Post-quantum digital signature using liboqs-python (Open Quantum Safe)
        try:
            import oqs

            def oqs_mldsa_sign(message: bytes) -> bytes:
                # Algorithm: ML-DSA  Library: oqs  Language: Python
                with oqs.Signature("{param}") as sig:
                    public_key = sig.generate_keypair()
                    signature = sig.sign(message)
                    is_valid = sig.verify(message, signature, public_key)
                    return signature
        except ImportError:
            import sys
            print("ML-DSA (oqs) requires liboqs-python: pip install liboqs-python", file=sys.stderr)

            def oqs_mldsa_sign(message: bytes) -> bytes:  # type: ignore[no-redef]
                raise RuntimeError("liboqs-python not installed")
    """)


# Algorithm: SLH-DSA  Library: oqs  Language: Python
@_pw("PQC algorithm", "SLH-DSA hash-based signature via liboqs-python", "CBS-003")
def _():
    param = random.choice(["SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHA2-128f-simple",
                            "SPHINCS+-SHAKE-128s-simple", "SLH-DSA-SHA2-128s",
                            "SLH-DSA-SHA2-128f"])
    return textwrap.dedent(f"""\
        # Algorithm: SLH-DSA  Library: oqs  Language: Python
        # Stateless hash-based post-quantum signature using liboqs-python
        try:
            import oqs

            def oqs_slhdsa_sign(message: bytes) -> bytes:
                # Algorithm: SLH-DSA  Library: oqs  Language: Python
                with oqs.Signature("{param}") as sig:
                    public_key = sig.generate_keypair()
                    return sig.sign(message)
        except ImportError:
            import sys
            print("SLH-DSA (oqs) requires liboqs-python: pip install liboqs-python", file=sys.stderr)

            def oqs_slhdsa_sign(message: bytes) -> bytes:  # type: ignore[no-redef]
                raise RuntimeError("liboqs-python not installed")
    """)


# Algorithm: XMSS  Library: oqs  Language: Python
@_pw("PQC algorithm", "XMSS stateful hash-based signature via liboqs-python", "CBS-003")
def _():
    param = random.choice(["XMSS-SHA2_10_256", "XMSS-SHA2_16_256",
                            "XMSS-SHAKE_10_256", "XMSSMT-SHA2_20/2_256"])
    return textwrap.dedent(f"""\
        # Algorithm: XMSS  Library: oqs  Language: Python
        # Stateful hash-based post-quantum signature using liboqs-python
        try:
            import oqs

            def oqs_xmss_sign(message: bytes) -> bytes:
                # Algorithm: XMSS  Library: oqs  Language: Python
                with oqs.Signature("{param}") as sig:
                    public_key = sig.generate_keypair()
                    return sig.sign(message)
        except ImportError:
            import sys
            print("XMSS (oqs) requires liboqs-python: pip install liboqs-python", file=sys.stderr)

            def oqs_xmss_sign(message: bytes) -> bytes:  # type: ignore[no-redef]
                raise RuntimeError("liboqs-python not installed")
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
            "import java.util.Random;",
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
                <!-- BouncyCastle: PQC algorithm support (ML-KEM, ML-DSA, SLH-DSA) -->
                <dependency>
                    <groupId>org.bouncycastle</groupId>
                    <artifactId>bcprov-jdk18on</artifactId>
                    <version>1.78.1</version>
                </dependency>
                <dependency>
                    <groupId>org.bouncycastle</groupId>
                    <artifactId>bcpkix-jdk18on</artifactId>
                    <version>1.78.1</version>
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
        cryptography>=44.0.0
        pyjwt>=2.8.0
        requests>=2.31.0
        python-dotenv>=1.0.0
        # liboqs-python: PQC algorithm support (ML-KEM, ML-DSA, SLH-DSA, XMSS)
        liboqs-python>=0.10.0
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
                "cryptography>=44.0.0",
                "pyjwt>=2.8.0",
                "requests>=2.31.0",
                "liboqs-python>=0.10.0",
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
# Multi-language generator helpers
# ---------------------------------------------------------------------------

# Round-robin distribute (Weakness, snippet_str) pairs across file_map buckets.
# PQC snippets (ML-KEM / ML-DSA / SLH-DSA) always land in the designated pqc bucket.
def _distribute(snippets, file_map, pqc_key=None):
    keys = list(file_map.keys())
    pqc_terms = ("ml-kem", "ml-dsa", "slh-dsa")
    rr_idx = 0
    for wk, snippet in snippets:
        desc_lower = wk.description.lower()
        if pqc_key and any(t in desc_lower for t in pqc_terms):
            file_map[pqc_key].append((wk, snippet))
        else:
            file_map[keys[rr_idx % len(keys)]].append((wk, snippet))
            rr_idx += 1


# ---- Go application ----

def generate_go_app(base_dir: Path, app_name: str, version: str,
                    weaknesses_to_inject: List[Tuple[Weakness, Callable[[], str]]]) -> List[Weakness]:
    """Build the Go application tree and inject weaknesses."""
    if base_dir.exists():
        return []

    app_lower = app_name.lower().replace("-", "").replace("_", "")
    crypto_dir = base_dir / "crypto"
    crypto_dir.mkdir(parents=True, exist_ok=True)

    file_map = {
        "crypto/hash.go": [],
        "crypto/cipher.go": [],
        "crypto/tls.go": [],
        "crypto/pqc.go": [],
    }
    snippets = list(weaknesses_to_inject)
    _distribute(snippets, file_map, pqc_key="crypto/pqc.go")

    injected: List[Weakness] = []
    for rel_path, entries in file_map.items():
        parts = [
            "package crypto",
            "",
        ]
        for wk, snip in entries:
            parts.append("")
            parts.append(snip.strip())
            injected.append(wk)
        (base_dir / rel_path).write_text("\n".join(parts) + "\n")

    (base_dir / "go.mod").write_text(textwrap.dedent(f"""\
        module github.com/example/{app_lower}

        go 1.22

        require golang.org/x/crypto v0.23.0
    """))
    return injected


# ---- JavaScript application ----

def generate_js_app(base_dir: Path, app_name: str, version: str,
                    weaknesses_to_inject: List[Tuple[Weakness, Callable[[], str]]]) -> List[Weakness]:
    """Build the JavaScript application tree and inject weaknesses."""
    if base_dir.exists():
        return []

    app_lower = app_name.lower().replace("-", "_").replace(" ", "_")
    src_dir = base_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)

    file_map = {
        "src/hash.js": [],
        "src/cipher.js": [],
        "src/tls.js": [],
        "src/jwt.js": [],
        "src/pqc.js": [],
    }
    snippets = list(weaknesses_to_inject)
    _distribute(snippets, file_map, pqc_key="src/pqc.js")

    injected: List[Weakness] = []
    for rel_path, entries in file_map.items():
        parts = []
        for wk, snip in entries:
            parts.append(snip.strip())
            injected.append(wk)
        (base_dir / rel_path).write_text("\n\n".join(parts) + "\n")

    app_name_lower = app_name.lower().replace(" ", "-")
    import json
    (base_dir / "package.json").write_text(json.dumps({
        "name": app_name_lower,
        "version": version,
        "description": "Demo application",
        "main": "src/index.js",
        "dependencies": {
            "jsonwebtoken": "^9.0.0",
            "mlkem": "^1.0.0",
            "@noble/post-quantum": "^0.2.0",
        },
    }, indent=2) + "\n")
    return injected


# ---- C# application ----

def generate_csharp_app(base_dir: Path, app_name: str, version: str,
                        weaknesses_to_inject: List[Tuple[Weakness, Callable[[], str]]]) -> List[Weakness]:
    """Build the C# application tree and inject weaknesses."""
    if base_dir.exists():
        return []

    class_name = _title(app_name)
    crypto_dir = base_dir / "Crypto"
    crypto_dir.mkdir(parents=True, exist_ok=True)

    file_map = {
        "Crypto/Hash.cs": [],
        "Crypto/Cipher.cs": [],
        "Crypto/Tls.cs": [],
        "Crypto/Pqc.cs": [],
    }
    snippets = list(weaknesses_to_inject)
    _distribute(snippets, file_map, pqc_key="Crypto/Pqc.cs")

    injected: List[Weakness] = []
    for rel_path, entries in file_map.items():
        using_lines = []
        body_lines = []
        for wk, snip in entries:
            for line in snip.strip().splitlines():
                if line.startswith("using "):
                    if line not in using_lines:
                        using_lines.append(line)
                else:
                    body_lines.append("    " + line if line.strip() else "")
            body_lines.append("")
            injected.append(wk)

        parts = [f"// {class_name} — demo application"]
        if using_lines:
            parts.extend(using_lines)
        parts += [
            f"namespace {class_name}.Crypto;",
            "",
            "public static partial class CryptoHelpers",
            "{",
        ]
        parts.extend(body_lines)
        parts.append("}")
        (base_dir / rel_path).write_text("\n".join(parts) + "\n")

    (base_dir / f"{class_name}.csproj").write_text(textwrap.dedent(f"""\
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup>
            <OutputType>Exe</OutputType>
            <TargetFramework>net9.0</TargetFramework>
          </PropertyGroup>
        </Project>
    """))
    return injected


# ---- Dart application ----

def generate_dart_app(base_dir: Path, app_name: str, version: str,
                      weaknesses_to_inject: List[Tuple[Weakness, Callable[[], str]]]) -> List[Weakness]:
    """Build the Dart application tree and inject weaknesses."""
    if base_dir.exists():
        return []

    app_lower = app_name.lower().replace("-", "_").replace(" ", "_")
    lib_src = base_dir / "lib" / "src"
    lib_src.mkdir(parents=True, exist_ok=True)

    file_map = {
        "lib/src/hash.dart": [],
        "lib/src/cipher.dart": [],
        "lib/src/kdf.dart": [],
    }
    snippets = list(weaknesses_to_inject)
    _distribute(snippets, file_map)

    injected: List[Weakness] = []
    for rel_path, entries in file_map.items():
        parts = []
        for wk, snip in entries:
            parts.append(snip.strip())
            injected.append(wk)
        (base_dir / rel_path).write_text("\n\n".join(parts) + "\n")

    (base_dir / "pubspec.yaml").write_text(textwrap.dedent(f"""\
        name: {app_lower}
        version: {version}
        environment:
          sdk: ">=3.0.0 <4.0.0"
        dependencies:
          crypto: ^3.0.0
          cryptography: ^2.7.0
          pointycastle: ^3.9.0
    """))
    return injected


# ---- C/C++ application ----

def generate_c_app(base_dir: Path, app_name: str, version: str,
                   weaknesses_to_inject: List[Tuple[Weakness, Callable[[], str]]]) -> List[Weakness]:
    """Build the C/C++ application tree and inject weaknesses. Raises PlatformError for GSKit-crypto on macOS."""
    # Check GSKit-crypto platform guard before touching the filesystem
    for wk, _ in weaknesses_to_inject:
        if "gskit" in wk.description.lower():
            platform_guard.assert_supported("c", "gskit-crypto")
            break

    if base_dir.exists():
        return []

    src_dir = base_dir / "src"
    src_dir.mkdir(parents=True, exist_ok=True)

    class_name = _title(app_name)
    file_map = {
        "src/hash.c": [],
        "src/cipher.c": [],
        "src/tls.c": [],
        "src/pqc.c": [],
    }
    snippets = list(weaknesses_to_inject)
    _distribute(snippets, file_map, pqc_key="src/pqc.c")

    injected: List[Weakness] = []
    for rel_path, entries in file_map.items():
        parts = []
        for wk, snip in entries:
            parts.append(snip.strip())
            injected.append(wk)
        (base_dir / rel_path).write_text("\n\n".join(parts) + "\n")

    (base_dir / "CMakeLists.txt").write_text(textwrap.dedent(f"""\
        cmake_minimum_required(VERSION 3.16)
        project({class_name} VERSION {version})
        find_package(OpenSSL REQUIRED)
        add_executable({class_name} src/hash.c src/cipher.c src/tls.c src/pqc.c)
        target_link_libraries({class_name} OpenSSL::SSL OpenSSL::Crypto)
    """))
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
    # Maps are resolved at call-time so all factory lists are already populated.
    FACTORY_POOL_MAP = {
        "java":       JAVA_WEAKNESS_FACTORIES,
        "python":     PYTHON_WEAKNESS_FACTORIES,
        "go":         GO_WEAKNESS_FACTORIES,
        "javascript": JS_WEAKNESS_FACTORIES,
        "csharp":     CSHARP_WEAKNESS_FACTORIES,
        "dart":       DART_WEAKNESS_FACTORIES,
        "c":          C_WEAKNESS_FACTORIES,
    }
    GENERATOR_MAP = {
        "java":       generate_java_app,
        "python":     generate_python_app,
        "go":         generate_go_app,
        "javascript": generate_js_app,
        "csharp":     generate_csharp_app,
        "dart":       generate_dart_app,
        "c":          generate_c_app,
    }
    LANG_LABELS = {
        "java": "Java / Spring Boot",
        "python": "Python / Flask",
        "go": "Go",
        "javascript": "JavaScript / Node.js",
        "csharp": "C# / .NET",
        "dart": "Dart",
        "c": "C / C++",
    }

    print("=" * 60)
    print("  Vulnerable App Generator — Guardium QSE Demo Tool")
    print("=" * 60)
    print()
    print("  Supported languages:")
    for key, label in LANG_LABELS.items():
        print(f"    {key:<12}  {label}")
    print()

    lang = prompt_choice(
        "Language [java/python/go/javascript/csharp/dart/c]: ",
        list(FACTORY_POOL_MAP.keys()),
    )
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
        shutil.rmtree(base_dir)

    factory_pool = FACTORY_POOL_MAP[lang]
    target_count = random.randint(8, 26)
    print(f"\n  Generating {LANG_LABELS[lang]} application '{app_name}' v{version}...")
    print(f"  Target weakness count: {target_count}")
    print()

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
    injected = GENERATOR_MAP[lang](base_dir, safe_name, version, selected)

    # Summarise
    from collections import Counter
    counts = Counter(w.category for w in injected)

    print(f"\n{'=' * 60}")
    print(f"  Generation complete: {base_dir.resolve()}")
    print(f"  Language: {LANG_LABELS[lang]}")
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




# ===========================================================================
# Go snippet factories
# ===========================================================================

GO_WEAKNESS_FACTORIES: List[Tuple[Weakness, Callable[[], str]]] = []

def _gw(category, description, tag=""):
    """Decorator: registers a Go weakness factory."""
    wk = _wk(category, description, tag)
    def decorator(fn):
        GO_WEAKNESS_FACTORIES.append((wk, fn))
        return fn
    return decorator


# CBS-001: MD5
@_gw("Weak algorithm", "MD5 hash via crypto/md5", "CBS-001")
def _():
    return textwrap.dedent("""\
        import (
            "crypto/md5"
            "fmt"
        )

        // computeFingerprint returns a hex MD5 fingerprint for cache keying.
        func computeFingerprint(data []byte) string {
            sum := md5.Sum(data)
            return fmt.Sprintf("%x", sum)
        }
    """)


# CBS-001: SHA-1
@_gw("Weak algorithm", "SHA-1 hash via crypto/sha1", "CBS-001")
def _():
    return textwrap.dedent("""\
        import (
            "crypto/sha1"
            "fmt"
        )

        // hashContent returns a SHA-1 digest used for legacy checksum validation.
        func hashContent(data []byte) string {
            sum := sha1.Sum(data)
            return fmt.Sprintf("%x", sum)
        }
    """)


# CBS-001: DES-CBC
@_gw("Weak algorithm", "DES-CBC encryption via crypto/des", "CBS-001")
def _():
    return textwrap.dedent("""\
        import (
            "crypto/cipher"
            "crypto/des"
        )

        // encryptDES encrypts payload using DES-CBC for backward-compatible storage.
        func encryptDES(key, iv, plaintext []byte) ([]byte, error) {
            block, err := des.NewCipher(key)
            if err != nil {
                return nil, err
            }
            dst := make([]byte, len(plaintext))
            cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, plaintext)
            return dst, nil
        }
    """)


# CBS-001: RC4
@_gw("Weak algorithm", "RC4 stream cipher via crypto/rc4", "CBS-001")
def _():
    return textwrap.dedent("""\
        import "crypto/rc4"

        // streamEncrypt applies RC4 to data for lightweight obfuscation.
        func streamEncrypt(key, data []byte) ([]byte, error) {
            c, err := rc4.NewCipher(key)
            if err != nil {
                return nil, err
            }
            dst := make([]byte, len(data))
            c.XORKeyStream(dst, data)
            return dst, nil
        }
    """)


# CBS-001: MD4 (x/crypto)
@_gw("Weak algorithm", "MD4 hash via golang.org/x/crypto/md4", "CBS-001")
def _():
    return textwrap.dedent("""\
        import (
            "fmt"
            "golang.org/x/crypto/md4"
        )

        // legacyChecksum computes an MD4 digest for protocol compatibility.
        func legacyChecksum(data []byte) string {
            h := md4.New()
            h.Write(data)
            return fmt.Sprintf("%x", h.Sum(nil))
        }
    """)


# CBS-001: RIPEMD-160
@_gw("Weak algorithm", "RIPEMD-160 via golang.org/x/crypto/ripemd160", "CBS-001")
def _():
    return textwrap.dedent("""\
        import (
            "fmt"
            "golang.org/x/crypto/ripemd160"
        )

        // ripemdDigest produces a RIPEMD-160 hash for address derivation.
        func ripemdDigest(data []byte) string {
            h := ripemd160.New()
            h.Write(data)
            return fmt.Sprintf("%x", h.Sum(nil))
        }
    """)


# CBS-002: AES-ECB (direct block.Encrypt without mode)
@_gw("Insecure cipher mode", "AES-ECB via direct block.Encrypt", "CBS-002")
def _():
    return textwrap.dedent("""\
        import "crypto/aes"

        // encryptBlock encrypts a single 16-byte block directly (ECB equivalent).
        func encryptBlock(key, plaintext []byte) ([]byte, error) {
            block, err := aes.NewCipher(key)
            if err != nil {
                return nil, err
            }
            dst := make([]byte, aes.BlockSize)
            block.Encrypt(dst, plaintext[:aes.BlockSize])
            return dst, nil
        }
    """)


# CBS-002: AES-CBC without MAC
@_gw("Insecure cipher mode", "AES-CBC without HMAC authentication", "CBS-002")
def _():
    return textwrap.dedent("""\
        import (
            "crypto/aes"
            "crypto/cipher"
        )

        // encryptCBC encrypts data with AES-CBC but applies no MAC.
        func encryptCBC(key, iv, plaintext []byte) ([]byte, error) {
            block, err := aes.NewCipher(key)
            if err != nil {
                return nil, err
            }
            dst := make([]byte, len(plaintext))
            cipher.NewCBCEncrypter(block, iv).CryptBlocks(dst, plaintext)
            return dst, nil
        }
    """)


# CBS-002: Static IV
@_gw("Static IV", "Hardcoded static AES IV", "CBS-002")
def _():
    iv_bytes = ", ".join(f"0x{random.randint(0,255):02x}" for _ in range(16))
    return textwrap.dedent(f"""\
        import (
            "crypto/aes"
            "crypto/cipher"
        )

        // defaultIV is reused across all encryption calls for consistency.
        var defaultIV = []byte{{{iv_bytes}}}

        func encryptWithStaticIV(key, plaintext []byte) ([]byte, error) {{
            block, err := aes.NewCipher(key)
            if err != nil {{
                return nil, err
            }}
            dst := make([]byte, len(plaintext))
            cipher.NewCBCEncrypter(block, defaultIV).CryptBlocks(dst, plaintext)
            return dst, nil
        }}
    """)


# CBS-003: RSA-1024
@_gw("Weak key size", "RSA-1024 key generation", "CBS-003")
def _():
    return textwrap.dedent("""\
        import (
            "crypto/rand"
            "crypto/rsa"
        )

        // generateServiceKey creates an RSA signing key for the internal API.
        func generateServiceKey() (*rsa.PrivateKey, error) {
            return rsa.GenerateKey(rand.Reader, 1024)
        }
    """)


# CBS-003: Insecure PRNG (math/rand)
@_gw("Insecure PRNG", "math/rand used for token generation", "CBS-003")
def _():
    return textwrap.dedent("""\
        import (
            "fmt"
            "math/rand"
        )

        // generateToken produces a numeric session token.
        func generateToken() string {
            return fmt.Sprintf("%016d", rand.Int63())
        }
    """)


# CBS-003: Hardcoded HMAC key
@_gw("Hardcoded secret", "Hardcoded HMAC-SHA256 key", "CBS-003")
def _():
    key_bytes = ", ".join(f"0x{random.randint(0,255):02x}" for _ in range(32))
    return textwrap.dedent(f"""\
        import (
            "crypto/hmac"
            "crypto/sha256"
            "fmt"
        )

        // signingKey is the shared HMAC secret for webhook validation.
        var signingKey = []byte{{{key_bytes}}}

        func signPayload(data []byte) string {{
            mac := hmac.New(sha256.New, signingKey)
            mac.Write(data)
            return fmt.Sprintf("%x", mac.Sum(nil))
        }}
    """)


# CBS-003: PBKDF2 low iterations
@_gw("Weak key derivation", "PBKDF2 with only 100 iterations", "CBS-003")
def _():
    iters = random.randint(100, 200)
    return textwrap.dedent(f"""\
        import (
            "crypto/sha1"
            "golang.org/x/crypto/pbkdf2"
        )

        // deriveKey stretches a passphrase for database credential encryption.
        func deriveKey(password, salt []byte) []byte {{
            return pbkdf2.Key(password, salt, {iters}, 16, sha1.New)
        }}
    """)


# CBS-003: ECDH P-256 (quantum-vulnerable)
@_gw("Quantum-vulnerable key exchange", "ECDH P-256 key exchange", "CBS-003")
def _():
    return textwrap.dedent("""\
        import (
            "crypto/ecdh"
            "crypto/rand"
        )

        // generateECDHKey creates a P-256 ephemeral key for session establishment.
        func generateECDHKey() (*ecdh.PrivateKey, error) {
            return ecdh.P256().GenerateKey(rand.Reader)
        }
    """)


# CBS-003: bcrypt low cost
@_gw("Weak key derivation", "bcrypt with cost factor 4", "CBS-003")
def _():
    return textwrap.dedent("""\
        import "golang.org/x/crypto/bcrypt"

        // hashPassword stores a user password with bcrypt at minimum cost.
        func hashPassword(password []byte) ([]byte, error) {
            return bcrypt.GenerateFromPassword(password, 4)
        }
    """)


# CBS-003: Blowfish ECB-equivalent
@_gw("Weak algorithm", "Blowfish direct block encrypt (ECB-equivalent)", "CBS-003")
def _():
    return textwrap.dedent("""\
        import "golang.org/x/crypto/blowfish"

        // encryptBlowfish applies a single Blowfish block cipher operation.
        func encryptBlowfish(key, plaintext []byte) ([]byte, error) {
            c, err := blowfish.NewCipher(key)
            if err != nil {
                return nil, err
            }
            dst := make([]byte, blowfish.BlockSize)
            c.Encrypt(dst, plaintext[:blowfish.BlockSize])
            return dst, nil
        }
    """)


# CBS-004: TLS 1.0
@_gw("Insecure TLS", "TLS 1.0 minimum version", "CBS-004")
def _():
    return textwrap.dedent("""\
        import (
            "crypto/tls"
            "net/http"
        )

        // newLegacyClient creates an HTTP client that allows TLS 1.0 connections.
        func newLegacyClient() *http.Client {
            return &http.Client{
                Transport: &http.Transport{
                    TLSClientConfig: &tls.Config{
                        MinVersion: tls.VersionTLS10,
                    },
                },
            }
        }
    """)


# CBS-004: InsecureSkipVerify
@_gw("Insecure TLS", "InsecureSkipVerify disables certificate validation", "CBS-004")
def _():
    return textwrap.dedent("""\
        import (
            "crypto/tls"
            "net/http"
        )

        // newInternalClient skips TLS verification for internal service calls.
        func newInternalClient() *http.Client {
            return &http.Client{
                Transport: &http.Transport{
                    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
                },
            }
        }
    """)


# PQC Discovery: ML-KEM-768 via golang.org/x/crypto/mlkem
@_gw("PQC algorithm", "ML-KEM-768 key encapsulation", "CBS-001")
def _():
    return textwrap.dedent("""\
        // Algorithm: ML-KEM  Library: x/crypto  Language: Go
        import (
            "crypto/rand"
            "golang.org/x/crypto/mlkem"
        )

        // mlkemEncapsulate performs ML-KEM-768 key encapsulation.
        func mlkemEncapsulate() ([]byte, error) {
            dk, err := mlkem.GenerateKey768(rand.Reader)
            if err != nil {
                return nil, err
            }
            ek := dk.EncapsulationKey()
            ciphertext, sharedKey, err := ek.Encapsulate()
            _ = ciphertext
            return sharedKey, err
        }
    """)


# ===========================================================================
# JavaScript / TypeScript snippet factories
# ===========================================================================

JS_WEAKNESS_FACTORIES: List[Tuple[Weakness, Callable[[], str]]] = []

def _jsw(category, description, tag=""):
    """Decorator: registers a JavaScript/TypeScript weakness factory."""
    wk = _wk(category, description, tag)
    def decorator(fn):
        JS_WEAKNESS_FACTORIES.append((wk, fn))
        return fn
    return decorator


# CBS-001: MD5
@_jsw("Weak algorithm", "MD5 hash via node:crypto", "CBS-001")
def _():
    return textwrap.dedent("""\
        const crypto = require('node:crypto');

        // computeFingerprint returns a hex MD5 fingerprint for cache keying.
        function computeFingerprint(data) {
            return crypto.createHash('md5').update(data).digest('hex');
        }
    """)


# CBS-001: SHA-1
@_jsw("Weak algorithm", "SHA-1 hash via node:crypto", "CBS-001")
def _():
    return textwrap.dedent("""\
        const crypto = require('node:crypto');

        // hashContent returns a SHA-1 digest for legacy checksum validation.
        function hashContent(data) {
            return crypto.createHash('sha1').update(data).digest('hex');
        }
    """)


# CBS-001: DES-CBC
@_jsw("Weak algorithm", "DES-CBC encryption via node:crypto", "CBS-001")
def _():
    return textwrap.dedent("""\
        const crypto = require('node:crypto');

        // encryptDES encrypts payload using DES-CBC for backward-compatible storage.
        function encryptDES(key, iv, plaintext) {
            const cipher = crypto.createCipheriv('des-cbc', key, iv);
            return Buffer.concat([cipher.update(plaintext), cipher.final()]);
        }
    """)


# CBS-001: RC4
@_jsw("Weak algorithm", "RC4 stream cipher via node:crypto", "CBS-001")
def _():
    return textwrap.dedent("""\
        const crypto = require('node:crypto');

        // streamEncrypt applies RC4 for lightweight payload obfuscation.
        function streamEncrypt(key, data) {
            const cipher = crypto.createCipheriv('rc4', key, '');
            return Buffer.concat([cipher.update(data), cipher.final()]);
        }
    """)


# CBS-001: HMAC-MD5
@_jsw("Weak algorithm", "HMAC-MD5 via node:crypto", "CBS-001")
def _():
    return textwrap.dedent("""\
        const crypto = require('node:crypto');

        // signRequest signs API payloads with HMAC-MD5 for partner integrations.
        function signRequest(payload, secret) {
            return crypto.createHmac('md5', secret).update(payload).digest('hex');
        }
    """)


# CBS-001: HMAC-SHA1
@_jsw("Weak algorithm", "HMAC-SHA1 via node:crypto", "CBS-001")
def _():
    return textwrap.dedent("""\
        const crypto = require('node:crypto');

        // signWebhook signs webhook bodies with HMAC-SHA1 for delivery verification.
        function signWebhook(body, secret) {
            return crypto.createHmac('sha1', secret).update(body).digest('hex');
        }
    """)


# CBS-002: AES-128-ECB
@_jsw("Insecure cipher mode", "AES-128-ECB via node:crypto", "CBS-002")
def _():
    return textwrap.dedent("""\
        const crypto = require('node:crypto');

        // encryptConfig encrypts a configuration blob using AES-ECB.
        function encryptConfig(key, plaintext) {
            const cipher = crypto.createCipheriv('aes-128-ecb', key, '');
            return Buffer.concat([cipher.update(plaintext), cipher.final()]);
        }
    """)


# CBS-002: AES-128-CBC without MAC
@_jsw("Insecure cipher mode", "AES-128-CBC without MAC via node:crypto", "CBS-002")
def _():
    return textwrap.dedent("""\
        const crypto = require('node:crypto');

        // encryptSession encrypts session data with AES-CBC but no MAC.
        function encryptSession(key, iv, plaintext) {
            const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
            return Buffer.concat([cipher.update(plaintext), cipher.final()]);
        }
    """)


# CBS-002: Static IV
@_jsw("Static IV", "Hardcoded all-zero AES IV", "CBS-002")
def _():
    return textwrap.dedent("""\
        const crypto = require('node:crypto');

        // IV reused across all encryption calls for reproducibility.
        const IV = Buffer.alloc(16, 0);

        function encryptWithStaticIV(key, plaintext) {
            const cipher = crypto.createCipheriv('aes-128-cbc', key, IV);
            return Buffer.concat([cipher.update(plaintext), cipher.final()]);
        }
    """)


# CBS-003: Insecure PRNG
@_jsw("Insecure PRNG", "Math.random() used for token generation", "CBS-003")
def _():
    return textwrap.dedent("""\
        // generateToken produces a reset token using a non-cryptographic PRNG.
        function generateToken(length = 24) {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            return Array.from({ length }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
        }
    """)


# CBS-003: Hardcoded AES key
@_jsw("Hardcoded secret", "Hardcoded AES-128 key", "CBS-003")
def _():
    key_hex = "".join(f"{random.randint(0,255):02x}" for _ in range(16))
    return textwrap.dedent(f"""\
        const crypto = require('node:crypto');

        // Symmetric key for internal metrics payload encryption.
        const KEY = Buffer.from('{key_hex}', 'hex');

        function encryptMetrics(plaintext) {{
            const iv = Buffer.alloc(16, 0);
            const cipher = crypto.createCipheriv('aes-128-cbc', KEY, iv);
            return Buffer.concat([cipher.update(plaintext), cipher.final()]);
        }}
    """)


# CBS-003: PBKDF2 low iterations
@_jsw("Weak key derivation", "PBKDF2 with 100 iterations via node:crypto", "CBS-003")
def _():
    iters = random.randint(100, 200)
    return textwrap.dedent(f"""\
        const crypto = require('node:crypto');

        // deriveKey stretches a passphrase for database credential encryption.
        function deriveKey(password, salt) {{
            return crypto.pbkdf2Sync(password, salt, {iters}, 16, 'sha1');
        }}
    """)


# CBS-003: RSA-1024
@_jsw("Weak key size", "RSA-1024 key generation via node:crypto", "CBS-003")
def _():
    return textwrap.dedent("""\
        const crypto = require('node:crypto');

        // generateServiceKey creates an RSA signing key for the internal API.
        function generateServiceKey() {
            return crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
        }
    """)


# CBS-004: TLS minVersion TLSv1
@_jsw("Insecure TLS", "TLS 1.0 minimum version via node:tls", "CBS-004")
def _():
    return textwrap.dedent("""\
        const tls = require('node:tls');

        // createLegacyServer starts a TLS server that accepts TLS 1.0 connections.
        function createLegacyServer(options) {
            return tls.createServer({ ...options, minVersion: 'TLSv1' });
        }
    """)


# CBS-004: rejectUnauthorized false
@_jsw("Insecure TLS", "rejectUnauthorized:false disables cert validation", "CBS-004")
def _():
    return textwrap.dedent("""\
        const https = require('node:https');

        // fetchInternal bypasses TLS verification for internal service endpoints.
        function fetchInternal(url, callback) {
            https.request(url, { rejectUnauthorized: false }, callback).end();
        }
    """)


# CBS-003: Hardcoded JWT secret (jsonwebtoken)
@_jsw("Hardcoded secret", "Hardcoded JWT secret in jwt.sign()", "CBS-003")
def _():
    secret = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=32))
    return textwrap.dedent(f"""\
        const jwt = require('jsonwebtoken');

        // issueToken signs a user session token with a hardcoded secret.
        function issueToken(payload) {{
            return jwt.sign(payload, '{secret}', {{ algorithm: 'HS256' }});
        }}
    """)


# CBS-001: HMAC-SHA1 JWT algorithm
@_jsw("Weak algorithm", "HS1 (HMAC-SHA1) JWT algorithm", "CBS-001")
def _():
    return textwrap.dedent("""\
        const jwt = require('jsonwebtoken');

        // issueCompatToken signs a token using HS1 for legacy client compatibility.
        function issueCompatToken(payload, key) {
            return jwt.sign(payload, key, { algorithm: 'HS1' });
        }
    """)


# CBS-003: JWT with no expiry
@_jsw("Hardcoded secret", "JWT signed with no expiry", "CBS-003")
def _():
    return textwrap.dedent("""\
        const jwt = require('jsonwebtoken');

        // issueServiceToken creates a long-lived token for service-to-service auth.
        function issueServiceToken(payload, secret) {
            return jwt.sign(payload, secret);
        }
    """)


# CBS-004: JWT verify ignoring expiry
@_jsw("Insecure TLS", "jwt.verify with ignoreExpiration:true", "CBS-004")
def _():
    return textwrap.dedent("""\
        const jwt = require('jsonwebtoken');

        // decodeToken validates a JWT but ignores expiration for debugging.
        function decodeToken(token, secret) {
            return jwt.verify(token, secret, { ignoreExpiration: true });
        }
    """)


# PQC Discovery: ML-KEM via mlkem npm
@_jsw("PQC algorithm", "ML-KEM-768 key encapsulation via mlkem", "CBS-001")
def _():
    return textwrap.dedent("""\
        // Algorithm: ML-KEM  Library: mlkem-npm  Language: JavaScript
        const { MlKem768 } = require('mlkem');

        // mlkemEncapsulate performs ML-KEM-768 key encapsulation.
        async function mlkemEncapsulate() {
            const [ek, dk] = await MlKem768.generateKeyPair();
            const [ciphertext, sharedKey] = await MlKem768.encap(ek);
            return { ciphertext, sharedKey };
        }
    """)


# PQC Discovery: ML-DSA via @noble/post-quantum
@_jsw("PQC algorithm", "ML-DSA-44 signing via @noble/post-quantum", "CBS-001")
def _():
    return textwrap.dedent("""\
        // Algorithm: ML-DSA  Library: mldsa-npm  Language: JavaScript
        const { ml_dsa44 } = require('@noble/post-quantum/ml-dsa');

        // mldsaSign generates a key pair and signs a message with ML-DSA-44.
        function mldsaSign(message) {
            const keys = ml_dsa44.keygen();
            return ml_dsa44.sign(keys.secretKey, message);
        }
    """)



# ===========================================================================
# C# snippet factories
# ===========================================================================

CSHARP_WEAKNESS_FACTORIES: List[Tuple[Weakness, Callable[[], str]]] = []

def _csw(category, description, tag=""):
    """Decorator: registers a C# weakness factory."""
    wk = _wk(category, description, tag)
    def decorator(fn):
        CSHARP_WEAKNESS_FACTORIES.append((wk, fn))
        return fn
    return decorator


# CBS-001: MD5
@_csw("Weak algorithm", "MD5 hash via System.Security.Cryptography", "CBS-001")
def _():
    return textwrap.dedent("""\
        using System.Security.Cryptography;

        // Compute a fingerprint for cache key lookups.
        public static string ComputeFingerprint(byte[] data)
        {
            using var md5 = MD5.Create();
            return Convert.ToHexString(md5.ComputeHash(data));
        }
    """)


# CBS-001: SHA-1
@_csw("Weak algorithm", "SHA-1 hash via System.Security.Cryptography", "CBS-001")
def _():
    return textwrap.dedent("""\
        using System.Security.Cryptography;

        // Hash content for legacy checksum validation.
        public static string HashContent(byte[] data)
        {
            using var sha1 = SHA1.Create();
            return Convert.ToHexString(sha1.ComputeHash(data));
        }
    """)


# CBS-001: DES-CBC
@_csw("Weak algorithm", "DES-CBC encryption", "CBS-001")
def _():
    return textwrap.dedent("""\
        using System.Security.Cryptography;

        // Encrypt a value using DES-CBC for backward-compatible storage.
        public static byte[] EncryptDES(byte[] key, byte[] iv, byte[] plaintext)
        {
            using var des = DES.Create();
            using var enc = des.CreateEncryptor(key, iv);
            return enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }
    """)


# CBS-001: 3DES
@_csw("Weak algorithm", "Triple-DES encryption", "CBS-001")
def _():
    return textwrap.dedent("""\
        using System.Security.Cryptography;

        // Encrypt configuration data with 3DES for legacy protocol support.
        public static byte[] Encrypt3DES(byte[] key, byte[] iv, byte[] plaintext)
        {
            using var tdes = TripleDES.Create();
            using var enc = tdes.CreateEncryptor(key, iv);
            return enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }
    """)


# CBS-001: RC2
@_csw("Weak algorithm", "RC2 encryption", "CBS-001")
def _():
    return textwrap.dedent("""\
        using System.Security.Cryptography;

        // Encrypt a session blob using RC2 for client compatibility.
        public static byte[] EncryptRC2(byte[] key, byte[] iv, byte[] plaintext)
        {
            using var rc2 = RC2.Create();
            using var enc = rc2.CreateEncryptor(key, iv);
            return enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }
    """)


# CBS-001: HMAC-MD5
@_csw("Weak algorithm", "HMAC-MD5 for request signing", "CBS-001")
def _():
    return textwrap.dedent("""\
        using System.Security.Cryptography;

        // Sign API payloads with HMAC-MD5 for partner integrations.
        public static string SignRequest(byte[] payload, byte[] key)
        {
            using var hmac = new HMACMD5(key);
            return Convert.ToHexString(hmac.ComputeHash(payload));
        }
    """)


# CBS-001: HMAC-SHA1
@_csw("Weak algorithm", "HMAC-SHA1 for webhook verification", "CBS-001")
def _():
    return textwrap.dedent("""\
        using System.Security.Cryptography;

        // Sign webhook bodies with HMAC-SHA1 for delivery verification.
        public static string SignWebhook(byte[] body, byte[] key)
        {
            using var hmac = new HMACSHA1(key);
            return Convert.ToHexString(hmac.ComputeHash(body));
        }
    """)


# CBS-001: RSA without OAEP
@_csw("Weak algorithm", "RSA PKCS#1 v1.5 padding (no OAEP)", "CBS-001")
def _():
    return textwrap.dedent("""\
        using System.Security.Cryptography;

        // Encrypt a session key with RSA PKCS#1 v1.5 for legacy clients.
        public static byte[] EncryptRSALegacy(RSA rsa, byte[] data)
        {
            return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
        }
    """)


# CBS-002: AES-ECB
@_csw("Insecure cipher mode", "AES-ECB mode", "CBS-002")
def _():
    return textwrap.dedent("""\
        using System.Security.Cryptography;

        // Encrypt a configuration blob with AES-ECB.
        public static byte[] EncryptECB(byte[] key, byte[] plaintext)
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Key = key;
            using var enc = aes.CreateEncryptor();
            return enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }
    """)


# CBS-002: Static IV
@_csw("Static IV", "Hardcoded static AES IV", "CBS-002")
def _():
    iv_bytes = ", ".join(f"0x{random.randint(0,255):02x}" for _ in range(16))
    return textwrap.dedent(f"""\
        using System.Security.Cryptography;

        // Default IV reused across encryption calls for reproducibility.
        private static readonly byte[] DefaultIV = {{ {iv_bytes} }};

        public static byte[] EncryptWithStaticIV(byte[] key, byte[] plaintext)
        {{
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = DefaultIV;
            using var enc = aes.CreateEncryptor();
            return enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }}
    """)


# CBS-003: RSA-1024
@_csw("Weak key size", "RSA-1024 key generation", "CBS-003")
def _():
    return textwrap.dedent("""\
        using System.Security.Cryptography;

        // Generate an RSA key for internal API signing.
        public static RSA GenerateServiceKey()
        {
            return RSA.Create(1024);
        }
    """)


# CBS-003: Hardcoded AES key
@_csw("Hardcoded secret", "Hardcoded AES key derived from string literal", "CBS-003")
def _():
    secret = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=16))
    return textwrap.dedent(f"""\
        using System.Security.Cryptography;
        using System.Text;

        // Symmetric key for encrypting internal metrics payloads.
        private static readonly byte[] MetricsKey = Encoding.UTF8.GetBytes("{secret}");
    """)


# CBS-003: Insecure PRNG
@_csw("Insecure PRNG", "System.Random seeded with TickCount", "CBS-003")
def _():
    return textwrap.dedent("""\
        // Generate a session token using a non-cryptographic PRNG.
        public static string GenerateToken(int length = 24)
        {
            var rng = new Random(Environment.TickCount);
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Range(0, length).Select(_ => chars[rng.Next(chars.Length)]).ToArray());
        }
    """)


# CBS-003: PBKDF2 low iterations
@_csw("Weak key derivation", "PBKDF2 with 100 iterations and SHA-1", "CBS-003")
def _():
    iters = random.randint(100, 200)
    return textwrap.dedent(f"""\
        using System.Security.Cryptography;
        using System.Text;

        // Derive an encryption key from a passphrase using PBKDF2.
        public static byte[] DeriveKey(string password, byte[] salt)
        {{
            using var kdf = new Rfc2898DeriveBytes(password, salt, {iters}, HashAlgorithmName.SHA1);
            return kdf.GetBytes(16);
        }}
    """)


# CBS-004: TLS 1.0
@_csw("Insecure TLS", "SslProtocols.Tls (TLS 1.0) in AuthenticateAsClient", "CBS-004")
def _():
    return textwrap.dedent("""\
        using System.Net.Security;
        using System.Security.Authentication;

        // Authenticate over TLS 1.0 for legacy server compatibility.
        public static async Task AuthenticateLegacy(SslStream stream, string host)
        {
            await stream.AuthenticateAsClientAsync(host, null, SslProtocols.Tls, false);
        }
    """)


# PQC Discovery: ML-KEM-768 (.NET 9)
@_csw("PQC algorithm", "ML-KEM-768 key encapsulation (.NET 9)", "CBS-001")
def _():
    return textwrap.dedent("""\
        // Algorithm: ML-KEM  Library: dotnet-crypto  Language: C#
        // #if NET9_0_OR_GREATER
        using System.Security.Cryptography;

        // Encapsulate a shared secret using ML-KEM-768.
        public static (byte[] Ciphertext, byte[] SharedSecret) MlKemEncapsulate()
        {
            using var key = MLKem768.GenerateKey();
            byte[] pubKey = key.ExportEncapsulationKey();
            MLKem768.TryEncapsulate(pubKey, out byte[] ciphertext, out byte[] sharedSecret);
            return (ciphertext, sharedSecret);
        }
        // #endif
    """)


# PQC Discovery: ML-DSA-44 (.NET 9)
@_csw("PQC algorithm", "ML-DSA-44 digital signature (.NET 9)", "CBS-001")
def _():
    return textwrap.dedent("""\
        // Algorithm: ML-DSA  Library: dotnet-crypto  Language: C#
        // #if NET9_0_OR_GREATER
        using System.Security.Cryptography;

        // Sign a message using ML-DSA-44.
        public static byte[] MlDsaSign(byte[] message)
        {
            using var key = MLDsa44.GenerateKey();
            return key.SignData(message);
        }
        // #endif
    """)


# PQC Discovery: SLH-DSA-SHA2-128s (.NET 9)
@_csw("PQC algorithm", "SLH-DSA-SHA2-128s digital signature (.NET 9)", "CBS-001")
def _():
    return textwrap.dedent("""\
        // Algorithm: SLH-DSA Library: dotnet-crypto  Language: C#
        // #if NET9_0_OR_GREATER
        using System.Security.Cryptography;

        // Sign a message using SLH-DSA with the minimal SHA2-128s parameter set.
        public static byte[] SlhDsaSign(byte[] message)
        {
            using var key = SlhDsaSha2_128s.GenerateKey();
            return key.SignData(message);
        }
        // #endif
    """)



# ===========================================================================
# Dart snippet factories
# ===========================================================================

DART_WEAKNESS_FACTORIES: List[Tuple[Weakness, Callable[[], str]]] = []

def _dw(category, description, tag=""):
    """Decorator: registers a Dart weakness factory."""
    wk = _wk(category, description, tag)
    def decorator(fn):
        DART_WEAKNESS_FACTORIES.append((wk, fn))
        return fn
    return decorator


# CBS-001: MD5
@_dw("Weak algorithm", "MD5 hash via package:crypto", "CBS-001")
def _():
    return textwrap.dedent("""\
        import 'package:crypto/crypto.dart';

        // Compute a fingerprint for cache key lookups.
        String computeFingerprint(List<int> data) {
          final digest = md5.convert(data);
          return digest.toString();
        }
    """)


# CBS-001: SHA-1
@_dw("Weak algorithm", "SHA-1 hash via package:crypto", "CBS-001")
def _():
    return textwrap.dedent("""\
        import 'package:crypto/crypto.dart';

        // Hash content for legacy checksum validation.
        String hashContent(List<int> data) {
          final digest = sha1.convert(data);
          return digest.toString();
        }
    """)


# CBS-001: HMAC-MD5
@_dw("Weak algorithm", "HMAC-MD5 for API request signing", "CBS-001")
def _():
    return textwrap.dedent("""\
        import 'package:crypto/crypto.dart';

        // Sign API payloads with HMAC-MD5 for partner integrations.
        String signRequest(List<int> payload, List<int> secret) {
          final hmac = Hmac(md5, secret);
          return hmac.convert(payload).toString();
        }
    """)


# CBS-002: AES-CBC without MAC
@_dw("Insecure cipher mode", "AES-CBC without MAC via package:cryptography", "CBS-002")
def _():
    return textwrap.dedent("""\
        import 'package:cryptography/cryptography.dart';

        // Encrypt session data with AES-CBC but no MAC.
        Future<List<int>> encryptSession(List<int> data, SecretKey key) async {
          final algorithm = AesCbc.with128bits(macAlgorithm: MacAlgorithm.empty);
          final secretBox = await algorithm.encrypt(data, secretKey: key);
          return secretBox.cipherText;
        }
    """)


# CBS-003: Predictable sequential key
@_dw("Hardcoded secret", "Predictable sequential AES key", "CBS-003")
def _():
    return textwrap.dedent("""\
        import 'package:cryptography/cryptography.dart';

        // Generate a key from a sequential byte pattern for test reproducibility.
        SecretKey buildTestKey() {
          return SecretKey(List<int>.generate(16, (i) => i));
        }
    """)


# CBS-003: Hardcoded HMAC secret
@_dw("Hardcoded secret", "Hardcoded HMAC secret key literal", "CBS-003")
def _():
    key_bytes = ", ".join(f"0x{random.randint(0,255):02x}" for _ in range(16))
    return textwrap.dedent(f"""\
        import 'package:cryptography/cryptography.dart';

        // Shared HMAC secret for webhook payload validation.
        final _webhookSecret = SecretKey([{key_bytes}]);
    """)


# CBS-003: PBKDF2 low iterations
@_dw("Weak key derivation", "PBKDF2 with 100 iterations", "CBS-003")
def _():
    iters = random.randint(100, 200)
    return textwrap.dedent(f"""\
        import 'package:cryptography/cryptography.dart';

        // Derive an AES key from a passphrase using PBKDF2.
        Future<SecretKey> deriveKey(List<int> password, List<int> salt) {{
          final kdf = Pbkdf2(
            macAlgorithm: Hmac.sha1(),
            iterations: {iters},
            bits: 128,
          );
          return kdf.deriveKey(secretKey: SecretKey(password), nonce: salt);
        }}
    """)


# CBS-002: AES-ECB via package:cryptography
@_dw("Insecure cipher mode", "AES-ECB mode via package:cryptography", "CBS-002")
def _():
    return textwrap.dedent("""\
        import 'package:cryptography/cryptography.dart';

        // Encrypt a configuration block with AES-ECB for backward compatibility.
        Future<List<int>> encryptConfig(List<int> data, SecretKey key) async {
          final algorithm = AesEcb();
          final secretBox = await algorithm.encrypt(data, secretKey: key);
          return secretBox.cipherText;
        }
    """)


# CBS-003: RSA PKCS#1 v1.5 via pointycastle
@_dw("Weak algorithm", "RSA PKCS#1 v1.5 encryption via pointycastle", "CBS-003")
def _():
    return textwrap.dedent("""\
        import 'package:pointycastle/pointycastle.dart';
        import 'package:pointycastle/asymmetric/api.dart';

        // Wrap a session key with the recipient's RSA public key.
        Uint8List encryptSessionKey(RSAPublicKey publicKey, Uint8List sessionKey) {
          final cipher = AsymmetricBlockCipher('RSA/PKCS1');
          cipher.init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
          return cipher.process(sessionKey);
        }
    """)


# CBS-003: Insecure PRNG (math.Random)
@_dw("Insecure PRNG", "math.Random used for security-sensitive token generation", "CBS-003")
def _():
    return textwrap.dedent("""\
        import 'dart:math';

        // Generate a session nonce for request deduplication.
        String generateNonce() {
          final rng = Random();
          return List<int>.generate(16, (_) => rng.nextInt(256))
              .map((b) => b.toRadixString(16).padLeft(2, '0'))
              .join();
        }
    """)


# ===========================================================================
# C / C++ snippet factories
# ===========================================================================

C_WEAKNESS_FACTORIES: List[Tuple[Weakness, Callable[[], str]]] = []

def _cw(category, description, tag=""):
    """Decorator: registers a C/C++ weakness factory."""
    wk = _wk(category, description, tag)
    def decorator(fn):
        C_WEAKNESS_FACTORIES.append((wk, fn))
        return fn
    return decorator


# CBS-001: MD5 via OpenSSL
@_cw("Weak algorithm", "MD5 via OpenSSL EVP", "CBS-001")
def _():
    return textwrap.dedent("""\
        #include <openssl/evp.h>
        #include <string.h>

        /* Compute an MD5 fingerprint for cache key generation. */
        int compute_fingerprint(const unsigned char *data, size_t len,
                                unsigned char *out, unsigned int *out_len) {
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
            EVP_DigestUpdate(ctx, data, len);
            EVP_DigestFinal_ex(ctx, out, out_len);
            EVP_MD_CTX_free(ctx);
            return 0;
        }
    """)


# CBS-001: SHA-1 via OpenSSL
@_cw("Weak algorithm", "SHA-1 via OpenSSL EVP", "CBS-001")
def _():
    return textwrap.dedent("""\
        #include <openssl/evp.h>

        /* Hash content for legacy checksum validation. */
        int hash_content(const unsigned char *data, size_t len,
                         unsigned char *out, unsigned int *out_len) {
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
            EVP_DigestUpdate(ctx, data, len);
            EVP_DigestFinal_ex(ctx, out, out_len);
            EVP_MD_CTX_free(ctx);
            return 0;
        }
    """)


# CBS-001: DES-CBC via OpenSSL
@_cw("Weak algorithm", "DES-CBC via OpenSSL EVP", "CBS-001")
def _():
    return textwrap.dedent("""\
        #include <openssl/evp.h>

        /* Encrypt a payload using DES-CBC for backward-compatible storage. */
        int encrypt_des(const unsigned char *key, const unsigned char *iv,
                        const unsigned char *in, int in_len,
                        unsigned char *out, int *out_len) {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv);
            EVP_EncryptUpdate(ctx, out, &len, in, in_len);
            *out_len = len;
            EVP_EncryptFinal_ex(ctx, out + len, &len);
            *out_len += len;
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
    """)


# CBS-001: RC4 via OpenSSL
@_cw("Weak algorithm", "RC4 via OpenSSL EVP", "CBS-001")
def _():
    return textwrap.dedent("""\
        #include <openssl/evp.h>

        /* Apply RC4 stream cipher for lightweight obfuscation. */
        int stream_encrypt(const unsigned char *key, int key_len,
                           unsigned char *data, int data_len) {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int out_len = 0;
            EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, key, NULL);
            EVP_EncryptUpdate(ctx, data, &out_len, data, data_len);
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
    """)


# CBS-002: AES-128-ECB via OpenSSL
@_cw("Insecure cipher mode", "AES-128-ECB via OpenSSL EVP", "CBS-002")
def _():
    return textwrap.dedent("""\
        #include <openssl/evp.h>

        /* Encrypt a configuration blob with AES-128-ECB. */
        int encrypt_config(const unsigned char *key, const unsigned char *in,
                           int in_len, unsigned char *out, int *out_len) {
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
            EVP_EncryptUpdate(ctx, out, &len, in, in_len);
            *out_len = len;
            EVP_EncryptFinal_ex(ctx, out + len, &len);
            *out_len += len;
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
    """)


# CBS-002: Static IV via OpenSSL
@_cw("Static IV", "Hardcoded AES IV via OpenSSL", "CBS-002")
def _():
    iv_hex = ", ".join(f"0x{random.randint(0,255):02x}" for _ in range(16))
    return textwrap.dedent(f"""\
        #include <openssl/evp.h>

        /* Default IV reused across encryption calls for reproducibility. */
        static const unsigned char DEFAULT_IV[] = {{ {iv_hex} }};

        int encrypt_with_static_iv(const unsigned char *key, const unsigned char *in,
                                   int in_len, unsigned char *out, int *out_len) {{
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            int len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, DEFAULT_IV);
            EVP_EncryptUpdate(ctx, out, &len, in, in_len);
            *out_len = len;
            EVP_EncryptFinal_ex(ctx, out + len, &len);
            *out_len += len;
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }}
    """)


# CBS-003: RSA-1024 via OpenSSL
@_cw("Weak key size", "RSA-1024 key generation via OpenSSL", "CBS-003")
def _():
    return textwrap.dedent("""\
        #include <openssl/rsa.h>
        #include <openssl/pem.h>

        /* Generate a 1024-bit RSA key for internal API signing. */
        RSA *generate_service_key(void) {
            BIGNUM *e = BN_new();
            BN_set_word(e, RSA_F4);
            RSA *rsa = RSA_new();
            RSA_generate_key_ex(rsa, 1024, e, NULL);
            BN_free(e);
            return rsa;
        }
    """)


# CBS-003: Hardcoded AES key via OpenSSL
@_cw("Hardcoded secret", "Hardcoded AES key literal", "CBS-003")
def _():
    key_bytes = ", ".join(f"0x{random.randint(0,255):02x}" for _ in range(16))
    return textwrap.dedent(f"""\
        #include <openssl/evp.h>

        /* Symmetric key for internal metrics payload encryption. */
        static const unsigned char METRICS_KEY[] = {{ {key_bytes} }};
    """)


# CBS-003: PBKDF2 low iterations via OpenSSL
@_cw("Weak key derivation", "PBKDF2-SHA1 with 100 iterations via OpenSSL", "CBS-003")
def _():
    iters = random.randint(100, 200)
    return textwrap.dedent(f"""\
        #include <openssl/evp.h>

        /* Derive an AES key from a passphrase using PBKDF2. */
        int derive_key(const char *password, int pass_len,
                       const unsigned char *salt, int salt_len,
                       unsigned char *out) {{
            return PKCS5_PBKDF2_HMAC(password, pass_len, salt, salt_len,
                                     {iters}, EVP_sha1(), 16, out);
        }}
    """)


# CBS-004: TLS 1.0 via OpenSSL
@_cw("Insecure TLS", "TLS 1.0 maximum version via OpenSSL SSL_CTX", "CBS-004")
def _():
    return textwrap.dedent("""\
        #include <openssl/ssl.h>

        /* Create a TLS context restricted to TLS 1.0 for legacy server support. */
        SSL_CTX *create_legacy_ctx(void) {
            SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
            SSL_CTX_set_max_proto_version(ctx, TLS1_VERSION);
            return ctx;
        }
    """)


# CBS-004: Certificate verification disabled via OpenSSL
@_cw("Insecure TLS", "SSL_VERIFY_NONE disables certificate validation", "CBS-004")
def _():
    return textwrap.dedent("""\
        #include <openssl/ssl.h>

        /* Disable certificate verification for internal service connections. */
        void disable_cert_verify(SSL_CTX *ctx) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        }
    """)


# CBS-001: MD5 via Libgcrypt
@_cw("Weak algorithm", "MD5 via Libgcrypt gcry_md_open", "CBS-001")
def _():
    return textwrap.dedent("""\
        #include <gcrypt.h>

        /* Compute an MD5 digest for cache key generation. */
        void compute_md5(const void *data, size_t len, unsigned char *out) {
            gcry_md_hd_t h;
            gcry_md_open(&h, GCRY_MD_MD5, 0);
            gcry_md_write(h, data, len);
            unsigned char *digest = gcry_md_read(h, GCRY_MD_MD5);
            memcpy(out, digest, 16);
            gcry_md_close(h);
        }
    """)


# CBS-001: DES via Libgcrypt
@_cw("Weak algorithm", "DES-CBC via Libgcrypt gcry_cipher_open", "CBS-001")
def _():
    return textwrap.dedent("""\
        #include <gcrypt.h>

        /* Encrypt data with DES-CBC for backward-compatible protocol support. */
        gcry_error_t encrypt_des(const void *key, const void *iv,
                                 void *data, size_t len) {
            gcry_cipher_hd_t h;
            gcry_cipher_open(&h, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC, 0);
            gcry_cipher_setkey(h, key, 8);
            gcry_cipher_setiv(h, iv, 8);
            gcry_error_t err = gcry_cipher_encrypt(h, data, len, NULL, 0);
            gcry_cipher_close(h);
            return err;
        }
    """)


# CBS-001: MD5 via Nettle
@_cw("Weak algorithm", "MD5 via Nettle nettle_md5_init", "CBS-001")
def _():
    return textwrap.dedent("""\
        #include <nettle/md5.h>

        /* Compute an MD5 fingerprint using Nettle. */
        void compute_fingerprint(const uint8_t *data, size_t len,
                                 uint8_t *out) {
            struct md5_ctx ctx;
            nettle_md5_init(&ctx);
            md5_update(&ctx, len, data);
            md5_digest(&ctx, MD5_DIGEST_SIZE, out);
        }
    """)


# CBS-003: Hardcoded key via Nettle
@_cw("Hardcoded secret", "Hardcoded AES key literal (Nettle)", "CBS-003")
def _():
    key_bytes = ", ".join(f"0x{random.randint(0,255):02x}" for _ in range(16))
    return textwrap.dedent(f"""\
        #include <stdint.h>

        /* Symmetric key for encrypting internal metrics payloads. */
        static const uint8_t METRICS_KEY[16] = {{ {key_bytes} }};
    """)


# CBS-001: MD5 via GSKit-crypto  (PLATFORM: Linux, Windows only)
# PLATFORM: Linux, Windows only
@_cw("Weak algorithm", "MD5 via GSKit-crypto gsk_attribute_set_enum", "CBS-001")
def _():
    return textwrap.dedent("""\
        #include <gsk_ssl.h>

        /* Configure GSKit handle to use MD5 for message digest. */
        int set_md5_digest(gsk_handle handle) {
            return gsk_attribute_set_enum(handle, GSK_MD_ALG, GSK_MD5);
        }
    """)


# CBS-004: SSLv3 via GSKit-crypto  (PLATFORM: Linux, Windows only)
# PLATFORM: Linux, Windows only
@_cw("Insecure TLS", "SSLv3 enabled via GSKit-crypto", "CBS-004")
def _():
    return textwrap.dedent("""\
        #include <gsk_ssl.h>

        /* Enable SSLv3 for legacy mainframe client compatibility. */
        int enable_sslv3(gsk_handle handle) {
            return gsk_attribute_set_enum(handle,
                       GSK_PROTOCOL_SSLV3, GSK_PROTOCOL_SSLV3_ON);
        }
    """)


# ===========================================================================
# C / C++ — Crypto++ snippet factories
# ===========================================================================

# CBS-001: MD5 via Crypto++
@_cw("Weak algorithm", "MD5 via Crypto++ HashFilter", "CBS-001")
def _():
    return textwrap.dedent("""\
        #include <cryptopp/md5.h>
        #include <cryptopp/hex.h>
        #include <cryptopp/filters.h>
        #include <string>

        /* Compute an MD5 fingerprint for cache key generation. */
        std::string compute_fingerprint(const std::string &data) {
            CryptoPP::MD5 hash;
            std::string digest;
            CryptoPP::StringSource ss(data, true,
                new CryptoPP::HashFilter(hash,
                    new CryptoPP::HexEncoder(
                        new CryptoPP::StringSink(digest))));
            return digest;
        }
    """)


# CBS-001: SHA-1 via Crypto++
@_cw("Weak algorithm", "SHA-1 via Crypto++ HashFilter", "CBS-001")
def _():
    return textwrap.dedent("""\
        #include <cryptopp/sha.h>
        #include <cryptopp/hex.h>
        #include <cryptopp/filters.h>
        #include <string>

        /* Hash content for legacy checksum validation. */
        std::string hash_content(const std::string &data) {
            CryptoPP::SHA1 hash;
            std::string digest;
            CryptoPP::StringSource ss(data, true,
                new CryptoPP::HashFilter(hash,
                    new CryptoPP::HexEncoder(
                        new CryptoPP::StringSink(digest))));
            return digest;
        }
    """)


# CBS-002: AES-ECB via Crypto++
@_cw("Insecure cipher mode", "AES-ECB mode via Crypto++ ECB_Mode", "CBS-002")
def _():
    return textwrap.dedent("""\
        #include <cryptopp/aes.h>
        #include <cryptopp/modes.h>
        #include <cryptopp/filters.h>
        #include <string>

        /* Encrypt a configuration blob with AES-128-ECB. */
        std::string encrypt_config(const CryptoPP::byte *key,
                                   const std::string &plaintext) {
            CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
            enc.SetKey(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
            std::string cipher;
            CryptoPP::StringSource ss(plaintext, true,
                new CryptoPP::StreamTransformationFilter(enc,
                    new CryptoPP::StringSink(cipher)));
            return cipher;
        }
    """)


# CBS-003: RSA-1024 via Crypto++
@_cw("Weak key size", "RSA-1024 key generation via Crypto++", "CBS-003")
def _():
    return textwrap.dedent("""\
        #include <cryptopp/rsa.h>
        #include <cryptopp/osrng.h>

        /* Generate a 1024-bit RSA key for internal API signing. */
        CryptoPP::RSA::PrivateKey generate_service_key() {
            CryptoPP::AutoSeededRandomPool rng;
            CryptoPP::RSA::PrivateKey key;
            key.GenerateRandomWithKeySize(rng, 1024);
            return key;
        }
    """)


# CBS-003: Hardcoded AES key via Crypto++
@_cw("Hardcoded secret", "Hardcoded AES key literal (Crypto++)", "CBS-003")
def _():
    key_bytes = ", ".join(f"0x{random.randint(0,255):02x}" for _ in range(16))
    return textwrap.dedent(f"""\
        #include <cryptopp/aes.h>

        /* Symmetric key for internal metrics payload encryption. */
        static const CryptoPP::byte METRICS_KEY[CryptoPP::AES::DEFAULT_KEYLENGTH] = {{
            {key_bytes}
        }};
    """)


# ===========================================================================
# C / C++ — liboqs (Open Quantum Safe) PQC discovery factories
# ===========================================================================

# PQC Discovery: ML-KEM-768 via liboqs C API
@_cw("PQC algorithm", "ML-KEM-768 key encapsulation via liboqs", "CBS-003")
def _():
    return textwrap.dedent("""\
        #include <oqs/oqs.h>
        #include <stdlib.h>

        /* Post-quantum key encapsulation using liboqs ML-KEM-768. */
        int kem_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret) {
            OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
            if (kem == NULL) return -1;
            uint8_t *public_key  = malloc(kem->length_public_key);
            uint8_t *secret_key  = malloc(kem->length_secret_key);
            OQS_KEM_keypair(kem, public_key, secret_key);
            OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
            OQS_KEM_free(kem);
            free(public_key);
            free(secret_key);
            return 0;
        }
    """)


# PQC Discovery: ML-DSA-44 via liboqs C API
@_cw("PQC algorithm", "ML-DSA-44 digital signature via liboqs", "CBS-003")
def _():
    return textwrap.dedent("""\
        #include <oqs/oqs.h>
        #include <stdlib.h>

        /* Post-quantum digital signature using liboqs ML-DSA-44. */
        int sign_message(const uint8_t *msg, size_t msg_len,
                         uint8_t *sig, size_t *sig_len) {
            OQS_SIG *sig_alg = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
            if (sig_alg == NULL) return -1;
            uint8_t *public_key  = malloc(sig_alg->length_public_key);
            uint8_t *secret_key  = malloc(sig_alg->length_secret_key);
            OQS_SIG_keypair(sig_alg, public_key, secret_key);
            OQS_SIG_sign(sig_alg, sig, sig_len, msg, msg_len, secret_key);
            OQS_SIG_free(sig_alg);
            free(public_key);
            free(secret_key);
            return 0;
        }
    """)


if __name__ == "__main__":
    main()
