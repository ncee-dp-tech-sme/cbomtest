# Implementation Plan — Multi-Language Weak Crypto Generator Extension

**Prompt:** Create a detailed, structured implementation plan for extending the existing weak cryptographic function code generation system to support C/C++, C#, Dart, Go, JavaScript/TypeScript, and post-quantum cryptography (PQC) algorithm discovery, with cross-platform compatibility, platform detection guards, and a project-local temp file strategy.

---

## Section 1 — Compatibility Matrix

All libraries are evaluated as *code-generation targets*. The generator emits source code; it has no runtime dependency on any of them. "Support" = generated code is syntactically correct and the library exists on that platform.

| Language | Library | macOS | Windows | Linux | Notes |
|---|---|---|---|---|---|
| C/C++ | OpenSSL | ✅ Full | ⚠️ Partial | ✅ Full | Windows needs vcpkg/MSVC installer; API identical |
| C/C++ | Libgcrypt | ✅ Full | ⚠️ Partial | ✅ Full | Windows via MSYS2/cygwin only |
| C/C++ | Nettle | ✅ Full | ⚠️ Partial | ✅ Full | Windows via MSYS2/MinGW; no official MSVC port |
| C/C++ | Crypto++ | ✅ Full | ✅ Full | ✅ Full | NuGet + vcpkg on Windows |
| C/C++ | GSKit-crypto | ❌ None | ⚠️ Partial | ✅ Full | IBM product-bundled SDK; not available standalone on macOS. **PLATFORM GUARD REQUIRED.** |
| C/C++ | liboqs | ✅ Full | ✅ Full | ✅ Full | CMake-based, fully cross-platform |
| C# | .NET Cryptography | ✅ Full | ✅ Full | ✅ Full | .NET 6+; PQC (ML-KEM/ML-DSA/SLH-DSA) requires .NET 9+ |
| Dart | cryptography | ✅ Full | ✅ Full | ✅ Full | Pure Dart, no native bindings |
| Go | crypto (stdlib) | ✅ Full | ✅ Full | ✅ Full | No restrictions |
| Go | golang.org/x/crypto | ✅ Full | ✅ Full | ✅ Full | No restrictions |
| Go | hash (stdlib) | ✅ Full | ✅ Full | ✅ Full | No restrictions |
| JS/TS | node:crypto | ✅ Full | ✅ Full | ✅ Full | Node 18+ built-in |
| JS/TS | jsonwebtoken | ✅ Full | ✅ Full | ✅ Full | Pure JS npm package |
| C# PQC | ML-KEM (.NET 9) | ✅ Full | ✅ Full | ✅ Full | Requires .NET 9 |
| C# PQC | ML-DSA (.NET 9) | ✅ Full | ✅ Full | ✅ Full | Requires .NET 9 |
| C# PQC | SLH-DSA (.NET 9) | ✅ Full | ✅ Full | ✅ Full | Requires .NET 9 |
| Go PQC | ML-KEM (x/crypto/mlkem) | ✅ Full | ✅ Full | ✅ Full | golang.org/x/crypto v0.23.0+ |
| JS/TS PQC | ML-KEM (mlkem npm) | ✅ Full | ✅ Full | ✅ Full | Pure JS |
| JS/TS PQC | ML-DSA (mldsa npm) | ✅ Full | ✅ Full | ✅ Full | Pure JS |

**Single library requiring a platform guard:** `GSKit-crypto` (C/C++) is not available on macOS as a standalone SDK.

---

## Section 2 — Platform Detection Module

### Location
New file: `platform_guard.py` at project root (sibling of `generate_vulnerable_app.py`). Stdlib only.

### Public API

```python
PLATFORM: str  # "macos" | "windows" | "linux"

class PlatformError(RuntimeError): ...

def current_platform() -> str: ...
def assert_supported(language: str, library: str) -> None: ...
def is_supported(language: str, library: str) -> bool: ...
```

### Implementation

```python
import sys

def current_platform() -> str:
    p = sys.platform
    if p == "darwin":  return "macos"
    if p == "win32":   return "windows"
    return "linux"

_UNSUPPORTED = {
    ("macos", "c", "gskit-crypto"):
        "GSKit-crypto is an IBM product-bundled library not distributed as a "
        "standalone SDK on macOS. Install IBM MQ or Db2 on Linux/Windows to "
        "obtain the GSKit development headers.",
}

def assert_supported(language: str, library: str) -> None:
    key = (current_platform(), language.lower(), library.lower())
    reason = _UNSUPPORTED.get(key)
    if reason:
        raise PlatformError(
            f"[PLATFORM ERROR] Cannot generate '{library}' ({language}) code on "
            f"{current_platform().upper()}.\n"
            f"Reason: {reason}\n"
            f"Action: Run this generator on Linux or Windows, or choose a "
            f"different library."
        )
```

### Error Message Contract
- Always starts with `[PLATFORM ERROR]`
- Names the unsupported library and current OS
- Provides a concrete remediation step
- Never silently falls back to partial generation

---

## Section 3 — Code Generator Extension Architecture

### 3.1 New Factory Lists

```python
C_WEAKNESS_FACTORIES:          List[Tuple[Weakness, Callable[[], str]]] = []
CSHARP_WEAKNESS_FACTORIES:     List[Tuple[Weakness, Callable[[], str]]] = []
DART_WEAKNESS_FACTORIES:       List[Tuple[Weakness, Callable[[], str]]] = []
GO_WEAKNESS_FACTORIES:         List[Tuple[Weakness, Callable[[], str]]] = []
JS_WEAKNESS_FACTORIES:         List[Tuple[Weakness, Callable[[], str]]] = []
```

### 3.2 New Decorator Helpers

```python
def _cw(category, description, tag=""):   # C / C++
def _csw(category, description, tag=""):  # C#
def _dw(category, description, tag=""):   # Dart
def _gw(category, description, tag=""):   # Go
def _jsw(category, description, tag=""):  # JavaScript / TypeScript
```

### 3.3 New Generator Functions

- `generate_c_app(base_dir, app_name, version, weaknesses_to_inject) -> List[Weakness]`
- `generate_csharp_app(...)`
- `generate_dart_app(...)`
- `generate_go_app(...)`
- `generate_js_app(...)`

Each function: (a) calls `platform_guard.assert_supported()` for relevant libraries, (b) creates output directory tree, (c) distributes injected snippets across realistically-named source files, (d) writes build files (CMakeLists.txt, .csproj, pubspec.yaml, go.mod, package.json), (e) returns List[Weakness].

### 3.4 main() Extension

```python
FACTORY_POOL_MAP = {
    "java": JAVA_WEAKNESS_FACTORIES,
    "python": PYTHON_WEAKNESS_FACTORIES,
    "c": C_WEAKNESS_FACTORIES,
    "csharp": CSHARP_WEAKNESS_FACTORIES,
    "dart": DART_WEAKNESS_FACTORIES,
    "go": GO_WEAKNESS_FACTORIES,
    "javascript": JS_WEAKNESS_FACTORIES,
}
GENERATOR_MAP = {
    "java": generate_java_app,
    "python": generate_python_app,
    "c": generate_c_app,
    "csharp": generate_csharp_app,
    "dart": generate_dart_app,
    "go": generate_go_app,
    "javascript": generate_js_app,
}
```

### 3.5 File Organisation

Keep all code in `generate_vulnerable_app.py` (stdlib only). Add language-specific sections using banner comments. `platform_guard.py` lives as a separate sibling file for independent testing.

---

## Section 4 — Weak Cryptographic Pattern Coverage

### C/C++ — OpenSSL
| CBS Rule | Pattern | API |
|---|---|---|
| CBS-001 | MD5 | `EVP_md5()` |
| CBS-001 | SHA-1 | `EVP_sha1()` |
| CBS-001 | DES-CBC | `EVP_des_cbc()` |
| CBS-001 | RC4 | `EVP_rc4()` |
| CBS-002 | AES-128-ECB | `EVP_aes_128_ecb()` |
| CBS-002 | Static IV | Hardcoded `unsigned char iv[]` |
| CBS-003 | RSA-1024 | `RSA_generate_key(1024, ...)` |
| CBS-003 | PBKDF2 low iters | `PKCS5_PBKDF2_HMAC(... 100 ...)` |
| CBS-003 | Hardcoded AES key | Inline `unsigned char key[] = {0x2b, ...}` |
| CBS-004 | TLS 1.0 | `SSL_CTX_set_max_proto_version(ctx, TLS1_VERSION)` |
| CBS-004 | Cert verification disabled | `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL)` |

### C/C++ — Crypto++
| CBS Rule | Pattern | API |
|---|---|---|
| CBS-001 | MD5 | `CryptoPP::Weak::MD5` |
| CBS-001 | DES-ECB | `CryptoPP::DES::Encryption` |
| CBS-002 | AES-ECB | `CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption` |
| CBS-003 | Insecure PRNG | `CryptoPP::LC_RNG` |
| CBS-003 | RSA-512 | `GenerateRandomWithKeySize(rng, 512)` |
| CBS-001 | RC4 | `CryptoPP::ARC4` |

### C/C++ — GSKit-crypto (Linux/Windows only — platform guard on macOS)
| CBS Rule | Pattern | API |
|---|---|---|
| CBS-001 | MD5 | `gsk_attribute_set_enum(handle, GSK_MD_ALG, GSK_MD5)` |
| CBS-003 | RSA-1024 | `gsk_create_key_pair(..., 1024, ...)` |
| CBS-004 | SSLv3 | `gsk_attribute_set_enum(handle, GSK_PROTOCOL_SSLV3, GSK_PROTOCOL_SSLV3_ON)` |
| CBS-004 | TLS 1.0 | `GSK_TLS_V10_CIPHER_SPECS` in cipher spec string |

### C/C++ — Libgcrypt
| CBS Rule | Pattern | API |
|---|---|---|
| CBS-001 | MD5 | `gcry_md_open(&h, GCRY_MD_MD5, 0)` |
| CBS-001 | SHA-1 | `gcry_md_open(&h, GCRY_MD_SHA1, 0)` |
| CBS-001 | DES | `gcry_cipher_open(&h, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC, 0)` |
| CBS-002 | AES-ECB | `gcry_cipher_open(&h, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0)` |
| CBS-003 | Insecure seed | `srand(time(NULL))` used instead of gcry entropy |

### C/C++ — liboqs (PQC discovery)
| Tag | Pattern | API |
|---|---|---|
| PQC-Discovery | ML-KEM-512 | `OQS_KEM_new("ML-KEM-512")` + `OQS_KEM_encaps()` |
| PQC-Discovery | ML-DSA-44 | `OQS_SIG_new("ML-DSA-44")` + `OQS_SIG_sign()` |
| PQC-Discovery | SLH-DSA-SHA2-128s | `OQS_SIG_new("SLH-DSA-SHA2-128s")` |

### C/C++ — Nettle
| CBS Rule | Pattern | API |
|---|---|---|
| CBS-001 | MD5 | `nettle_md5_init()` + `md5_update()` + `md5_digest()` |
| CBS-001 | SHA-1 | `sha1_init()` |
| CBS-001 | DES-CBC | `des_set_key()` + `nettle_cbc_encrypt()` |
| CBS-001 | Blowfish | `blowfish128_set_key()` |
| CBS-002 | AES-ECB | `aes128_set_encrypt_key()` without CBC wrapper |
| CBS-003 | Hardcoded key | Inline `uint8_t key[16] = { 0xde, 0xad, ... }` |

### C# — .NET Cryptography
| CBS Rule | Pattern | API |
|---|---|---|
| CBS-001 | MD5 | `MD5.Create()` |
| CBS-001 | SHA-1 | `SHA1.Create()` |
| CBS-001 | DES-CBC | `DES.Create()` + `CreateEncryptor(key, iv)` |
| CBS-001 | 3DES | `TripleDES.Create()` |
| CBS-001 | RC2 | `RC2.Create()` |
| CBS-002 | AES-ECB | `aes.Mode = CipherMode.ECB` |
| CBS-002 | Static IV | Hardcoded `byte[] iv = new byte[] { 0x00, ... }` |
| CBS-003 | RSA-1024 | `RSA.Create(1024)` |
| CBS-003 | Hardcoded AES key | Inline `byte[] key = Encoding.UTF8.GetBytes(...)` |
| CBS-003 | Insecure PRNG | `new Random(Environment.TickCount)` |
| CBS-003 | PBKDF2 low iters | `new Rfc2898DeriveBytes(pwd, salt, 100, HashAlgorithmName.SHA1)` |
| CBS-004 | TLS 1.0 | `AuthenticateAsClient(..., SslProtocols.Tls)` |
| CBS-001 | HMAC-MD5 | `HMACMD5(key)` |
| CBS-001 | HMAC-SHA1 | `HMACSHA1(key)` |
| CBS-001 | RSA without OAEP | `rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1)` |
| PQC-Discovery | ML-KEM-768 | `MLKem768.TryEncapsulate(...)` (.NET 9) |
| PQC-Discovery | ML-DSA-44 | `MLDsa44.GenerateKey()` (.NET 9) |
| PQC-Discovery | SLH-DSA-SHA2-128s | `SlhDsaSha2_128s.GenerateKey()` (.NET 9) |

### Dart — cryptography
| CBS Rule | Pattern | API |
|---|---|---|
| CBS-001 | MD5 | `const Md5().convert(bytes)` |
| CBS-001 | SHA-1 | `const Sha1().convert(bytes)` |
| CBS-002 | AES-CBC no MAC | `AesCbc.with128bits(macAlgorithm: MacAlgorithm.empty)` |
| CBS-003 | Predictable key | `SecretKey(List<int>.generate(16, (i) => i))` |
| CBS-003 | Hardcoded HMAC secret | Inline `final key = SecretKey([0x61, ...])` |
| CBS-003 | PBKDF2 low iters | `Pbkdf2(iterations: 100, mac: Hmac.sha1(), bits: 128)` |
| CBS-001 | HMAC-MD5 | `Hmac.md5().calculateMac(data, secretKey: key)` |

### Go — crypto stdlib + hash
| CBS Rule | Pattern | Import + API |
|---|---|---|
| CBS-001 | MD5 | `crypto/md5` · `md5.Sum(data)` |
| CBS-001 | SHA-1 | `crypto/sha1` · `sha1.Sum(data)` |
| CBS-001 | DES-CBC | `crypto/des` · `des.NewCipher(key)` + `cipher.NewCBCEncrypter()` |
| CBS-001 | RC4 | `crypto/rc4` · `rc4.NewCipher(key)` |
| CBS-002 | AES-ECB | `crypto/aes` · direct `block.Encrypt()` without mode |
| CBS-002 | AES-CBC no HMAC | `cipher.NewCBCEncrypter()` without MAC |
| CBS-002 | Static IV | Hardcoded `iv := []byte{0x00, ...}` |
| CBS-003 | RSA-1024 | `crypto/rsa` · `rsa.GenerateKey(rand.Reader, 1024)` |
| CBS-003 | ECDH P-256 (quantum) | `crypto/ecdh` · `ecdh.P256().GenerateKey(rand.Reader)` |
| CBS-003 | Insecure PRNG | `math/rand` (not `crypto/rand`) |
| CBS-003 | Hardcoded HMAC key | `crypto/hmac` with inline key literal |
| CBS-004 | TLS 1.0 | `tls.Config{MinVersion: tls.VersionTLS10}` |
| CBS-004 | InsecureSkipVerify | `tls.Config{InsecureSkipVerify: true}` |
| CBS-003 | PBKDF2 low iters | `golang.org/x/crypto/pbkdf2` · `pbkdf2.Key(pwd, salt, 100, 16, sha1.New)` |
| PQC-Discovery | ML-KEM-768 | `golang.org/x/crypto/mlkem` · `mlkem.GenerateKey768(rand.Reader)` |

### Go — golang.org/x/crypto supplementary
| CBS Rule | Pattern | API |
|---|---|---|
| CBS-001 | MD4 | `golang.org/x/crypto/md4` |
| CBS-001 | RIPEMD-160 | `golang.org/x/crypto/ripemd160` |
| CBS-003 | bcrypt low cost | `bcrypt.GenerateFromPassword(pwd, 4)` |
| CBS-003 | Blowfish ECB-equiv | `blowfish.NewCipher(key)` + direct block encrypt |

### JavaScript/TypeScript — node:crypto
| CBS Rule | Pattern | API |
|---|---|---|
| CBS-001 | MD5 | `crypto.createHash('md5')` |
| CBS-001 | SHA-1 | `crypto.createHash('sha1')` |
| CBS-001 | DES-CBC | `crypto.createCipheriv('des-cbc', key, iv)` |
| CBS-001 | RC4 | `crypto.createCipheriv('rc4', key, '')` |
| CBS-002 | AES-128-ECB | `crypto.createCipheriv('aes-128-ecb', key, '')` |
| CBS-002 | AES-128-CBC no MAC | `crypto.createCipheriv('aes-128-cbc', key, iv)` without authenticate |
| CBS-002 | Static IV | `const iv = Buffer.alloc(16, 0)` |
| CBS-003 | Insecure PRNG | `Math.random()` for token generation |
| CBS-003 | Hardcoded AES key | `const KEY = Buffer.from('...', 'hex')` |
| CBS-003 | PBKDF2 low iters | `crypto.pbkdf2Sync(pwd, salt, 100, 16, 'sha1')` |
| CBS-003 | RSA-1024 | `crypto.generateKeyPairSync('rsa', { modulusLength: 1024 })` |
| CBS-001 | HMAC-MD5 | `crypto.createHmac('md5', key)` |
| CBS-001 | HMAC-SHA1 | `crypto.createHmac('sha1', key)` |
| CBS-004 | TLS minVersion 'TLSv1' | `tls.createServer({ minVersion: 'TLSv1' })` |
| CBS-004 | rejectUnauthorized false | `https.request({ rejectUnauthorized: false })` |

### JavaScript/TypeScript — jsonwebtoken
| CBS Rule | Pattern | API |
|---|---|---|
| CBS-003 | Hardcoded JWT secret | `jwt.sign(payload, 'hardcoded-secret', { algorithm: 'HS256' })` |
| CBS-001 | HMAC-SHA1 JWT algorithm | `jwt.sign(payload, key, { algorithm: 'HS1' })` |
| CBS-003 | No expiry on JWT | `jwt.sign(payload, secret)` — no `expiresIn` |
| CBS-004 | Ignore JWT expiry on verify | `jwt.verify(token, secret, { ignoreExpiration: true })` |
| CBS-003 | Weak RSA key for RS256 | `jwt.sign(payload, rsa1024PrivateKey, { algorithm: 'RS256' })` |

---

## Section 5 — PQC Quantum Safe Explorer Integration

### Identification Comment Convention

Every PQC snippet must include the canonical identification comment as the first line of the returned snippet:

```
// Algorithm: ML-KEM  Library: dotnet-crypto  Language: C#
// Algorithm: ML-DSA  Library: dotnet-crypto  Language: C#
// Algorithm: SLH-DSA Library: dotnet-crypto  Language: C#
// Algorithm: ML-KEM  Library: x/crypto       Language: Go
// Algorithm: ML-KEM  Library: mlkem-npm      Language: JavaScript
// Algorithm: ML-DSA  Library: mldsa-npm      Language: JavaScript
```

### C# PQC (three @_csw factories)

| Algorithm | Variants | Key API |
|---|---|---|
| ML-KEM | MLKem512, MLKem768, MLKem1024 | `MLKem768.TryEncapsulate(pubKey, out ct, out ss)` |
| ML-DSA | MLDsa44, MLDsa65, MLDsa87 | `MLDsa44.GenerateKey(); key.SignData(msg)` |
| SLH-DSA | SlhDsaSha2_128s/128f/192s, SlhDsaShake_128s | `SlhDsaSha2_128s.GenerateKey(); key.SignData(msg)` |

All require .NET 9. Wrap with `#if NET9_0_OR_GREATER` comment in generated code.

### Go PQC (one @_gw factory)

```go
// Algorithm: ML-KEM  Library: x/crypto  Language: Go
func mlkemEncapsulate() ([]byte, error) {
    dk, err := mlkem.GenerateKey768(rand.Reader)
    if err != nil { return nil, err }
    ek := dk.EncapsulationKey()
    ciphertext, sharedKey, err := ek.Encapsulate()
    _ = ciphertext
    return sharedKey, err
}
```

go.mod must include `golang.org/x/crypto v0.23.0`.

### JavaScript/TypeScript PQC (two @_jsw factories)

| Algorithm | npm package | Sample API |
|---|---|---|
| ML-KEM | `mlkem` | `const { MlKem768 } = require('mlkem'); const [ek, dk] = await MlKem768.generateKeyPair();` |
| ML-DSA | `@noble/post-quantum` | `const { ml_dsa44 } = require('@noble/post-quantum/ml-dsa'); const keys = ml_dsa44.keygen();` |

### Weak/Misconfigured PQC Patterns (for QSE detection testing)

- **Re-used ML-KEM keypair**: Generate once, store as constant, reuse for all encapsulations
- **ML-DSA key material hardcoded**: Base64-encoded ML-DSA private key seed as string literal
- **Legacy Kyber512 name**: Use `"Kyber512"` instead of `"ML-KEM-512"` (detectable as non-standard)
- **SLH-DSA minimal parameters**: Use weakest parameter set (`SHA2-128s`) to verify QSE records it

All PQC factories must use try/except ImportError (Python) or #if guards (C#) — no crash if library absent.

---

## Section 6 — Local Temp File Strategy

### Directory Convention

```
PROJECT_ROOT/
└── .gen-tmp/
    └── <timestamp>-<lang>-<appname>/
        └── (intermediate files)
```

- Name: `.gen-tmp` at project root (same directory as `generate_vulnerable_app.py`)
- Run subdirectory: `{unix_timestamp}-{lang}-{safe_name[:20]}` to avoid collisions
- Add `.gen-tmp/` to `.gitignore`

### Creation Helper

```python
def _make_temp_dir(lang: str, app_name: str) -> Path:
    import time
    project_root = Path(__file__).parent
    tmp_root = project_root / ".gen-tmp"
    tmp_root.mkdir(exist_ok=True)
    run_dir = tmp_root / f"{int(time.time())}-{lang}-{app_name[:20]}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir
```

**Key rule:** Always use `Path(__file__).parent`. Never use `tempfile.mkdtemp()`, `tempfile.gettempdir()`, `os.environ.get("TMPDIR")`, `os.environ.get("TEMP")`, or any OS-managed temp location.

### Cleanup

```python
tmp_dir = _make_temp_dir(lang, safe_name)
try:
    # ... generation logic ...
    pass
finally:
    import shutil
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir, ignore_errors=True)
```

### .gitignore Auto-Update

```python
def _ensure_gitignore_entry(project_root: Path, entry: str) -> None:
    gi = project_root / ".gitignore"
    if gi.exists():
        if entry not in gi.read_text():
            with gi.open("a") as f:
                f.write(f"\n{entry}\n")
    else:
        gi.write_text(f"{entry}\n")
```

---

## Section 7 — Documentation Requirements

### generate_vulnerable_app.py
- Language section banner comments for each new language
- Single-line `# CBS-XXX: <description>` comment per factory
- Canonical `# Algorithm: X  Library: Y  Language: Z` comment in every PQC snippet string
- `# PLATFORM: Linux, Windows only` above platform-restricted factory decorators
- Change history entry in module docstring

### platform_guard.py
- Module docstring covering: purpose, full list of unsupported combinations with rationale, how to add a new restriction, error message format contract

### README.md and docs/README.md (both files)
- New languages in Usage section prompt
- New "Generated Structure" subsections per language
- Extended "Weakness Catalogue" tables for all new libraries
- New "Platform Compatibility" section (reference matrix from Section 1)
- "Temp File Strategy" note under Requirements
- Extended PQC table rows for C#, Go, JS/TS

### docs/CONTRIBUTING.md (new file)
1. Adding a weakness factory: decorator pattern, tag values, snippet indentation rules
2. Adding a new language: checklist — factory list, decorator, generator function, FACTORY_POOL_MAP/GENERATOR_MAP, build file template, README
3. Adding a platform restriction: `_UNSUPPORTED` dict entry, error format, test requirement
4. CBS rule IDs reference
5. PQC snippet conventions: identification comment format, graceful error handling, parameter randomisation

---

## Section 8 — Testing Plan

### Test Organisation

```
tests/
├── test_platform_guard.py
├── test_factories_c.py
├── test_factories_csharp.py
├── test_factories_dart.py
├── test_factories_go.py
├── test_factories_js.py
├── test_generator_c.py
├── test_generator_csharp.py
├── test_generator_dart.py
├── test_generator_go.py
├── test_generator_js.py
├── test_pqc_coverage.py
└── test_temp_strategy.py
```

### Platform Guard Tests (test_platform_guard.py)

| Test ID | Description | Pass Condition |
|---|---|---|
| PG-01 | `current_platform()` returns one of {macos, windows, linux} | No exception |
| PG-02 | `assert_supported("c","openssl")` does not raise on any platform | No exception |
| PG-03 | `assert_supported("c","gskit-crypto")` raises PlatformError on darwin | Raises PlatformError; message contains "[PLATFORM ERROR]" |
| PG-04 | `assert_supported("c","gskit-crypto")` does NOT raise on Linux (mocked) | No exception |
| PG-05 | PG-03 error message names library, OS, and remediation step | Message contains "gskit-crypto", "macOS", actionable text |
| PG-06 | `is_supported()` returns False for unsupported combination | Returns False |
| PG-07 | `is_supported()` returns True for supported combination | Returns True |

### Snippet Factory Tests (parametrized per language)

| Test ID | Check |
|---|---|
| SF-01 | Factory returns non-empty string |
| SF-02 | Snippet does not contain `/tmp`, `C:\\Temp`, or `tempfile` |
| SF-03 | PQC factories: snippet contains `Algorithm:` identification comment |
| SF-04 | Weakness tag is one of: CBS-001, CBS-002, CBS-003, CBS-004 |
| SF-05 | Factory called twice returns valid (possibly different) strings |

### Integration Tests (per generator function)

| Test ID | Check |
|---|---|
| GI-01 | Output directory has correct structure (spot-check key files) |
| GI-02 | Returns non-empty List[Weakness] |
| GI-03 | No file written outside provided base_dir |
| GI-04 | Build file is syntactically valid (regex spot-check) |
| GI-05 | Raises PlatformError for GSKit-crypto on macOS (mocked) |
| GI-06 | All injected weaknesses have non-empty tag field |

### PQC Coverage Tests

| Test ID | Check |
|---|---|
| PQC-01 | C# factory pool has ≥1 ML-KEM, ≥1 ML-DSA, ≥1 SLH-DSA factory |
| PQC-02 | Go factory pool has ≥1 ML-KEM snippet using golang.org/x/crypto/mlkem |
| PQC-03 | JS factory pool has ≥1 ML-KEM and ≥1 ML-DSA snippet |
| PQC-04 | All PQC snippets contain exactly one `Algorithm:` comment |
| PQC-05 | C# PQC snippets reference .NET 9 API (MLKem, MLDsa, SlhDsa) |

### Temp File Strategy Tests

| Test ID | Check |
|---|---|
| TF-01 | `_make_temp_dir()` creates directory inside `PROJECT_ROOT/.gen-tmp/` |
| TF-02 | Run-specific temp dir deleted after successful generation |
| TF-03 | Temp dir deleted even when generation raises mid-way |
| TF-04 | `.gen-tmp/` line appears in `.gitignore` after `_ensure_gitignore_entry()` |
| TF-05 | Two concurrent calls do not collide (timestamp prefix uniqueness) |

### Cross-Platform CI Notes

All tests run on all three platforms without installing target languages — they only verify text content. Platform guard tests mock `sys.platform` to exercise all code paths:

```python
def test_gskit_blocked_on_macos():
    with patch.object(sys, 'platform', 'darwin'):
        import importlib, platform_guard
        importlib.reload(platform_guard)
        with pytest.raises(platform_guard.PlatformError):
            platform_guard.assert_supported("c", "gskit-crypto")
```

---

## Recommended Implementation Order

1. Create `platform_guard.py` + `tests/test_platform_guard.py`
2. Implement local temp strategy helpers + `tests/test_temp_strategy.py`
3. Add factory lists, decorators, and snippet factories: **Go** → **JavaScript** → **C#** → **Dart** → **C/C++**
4. Implement generator functions for each new language
5. Extend `main()` with new prompt choices, FACTORY_POOL_MAP, GENERATOR_MAP
6. Write integration and PQC tests
7. Update README.md, docs/README.md; create docs/CONTRIBUTING.md
8. Add change history entry to module docstring
