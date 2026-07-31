# generate_vulnerable_app.py

A demo tool that interactively generates realistic multi-file Java or Python applications with deliberately introduced cryptographic weaknesses, for showcasing the value of **IBM Guardium Quantum Safe Explorer**.
After running **IBM Guardium Quantum Safe Explorer** the results can be uploaded **IBM Guardium Cryptography Manager** after adding the required metadata,(gitUrl or repositoryUrl & repositoryId).

> **Note:** This tool is exclusively for client demos and should NEVER be used in production.


---

## Usage

```bash
python3 generate_vulnerable_app.py
```

You will be prompted for:

- **Language** — `java`, `python`, `go`, `javascript`, `csharp`, `dart`, or `c`
- **Application name** — used as the output directory name
- **Version number** — e.g. `1.0.0`

---

## Execution Flow

1. Prompts for language, application name, and version
2. Creates a named output directory with a realistic multi-file application tree
3. Randomly selects **8–26 weaknesses** from 143 distinct weakness factories (33 Java · 28 Python · 19 Go · 21 JavaScript · 18 C# · 7 Dart · 17 C/C++)
4. Distributes them across source files using PQC-aware routing (PQC snippets always land in the dedicated `pqc.*` file)
5. Prints a categorised summary with rule IDs (`CBS-001` through `CBS-004`)
6. Prompts for `repositoryUrl` required for Guardium Cryptography Manager upload

---

## Generated Structure

### Java

```
AppName/
├── pom.xml                               (Spring Boot 3.2, JUnit 5, BouncyCastle 1.78.1)
├── README.md
├── config/security.yaml                  (hardcoded TLS 1.0, weak JWT secret)
└── src/main/java/com/example/…/
    ├── api/ApiController.java
    ├── config/SecurityConfig.java
    ├── crypto/CryptoUtil.java
    ├── crypto/KeyManager.java
    ├── service/AuthService.java
    ├── service/UserService.java
    ├── util/HashUtils.java
    └── util/TokenUtils.java
```

### Python

```
AppName/
├── main.py · requirements.txt · setup.py · .env.example   (cryptography ≥44, liboqs-python)
├── config/app.yaml                       (SHA-1, AES-128-CBC, hardcoded JWT)
├── templates/base.html
├── tests/test_auth.py
└── appname/
    ├── api/routes.py
    ├── crypto/cipher.py · crypto/keys.py
    ├── services/auth.py · services/user.py
    └── utils/hashing.py · utils/tokens.py · config/settings.py
```

### Go

```
AppName/
├── go.mod                                (golang.org/x/crypto v0.23.0)
└── crypto/
    ├── hash.go
    ├── cipher.go
    ├── tls.go
    └── pqc.go
```

### JavaScript / Node.js

```
AppName/
├── package.json                          (jsonwebtoken, mlkem, @noble/post-quantum)
└── src/
    ├── hash.js
    ├── cipher.js
    ├── tls.js
    ├── jwt.js
    └── pqc.js
```

### C# / .NET

```
AppName/
├── AppName.csproj                        (net9.0)
└── Crypto/
    ├── Hash.cs
    ├── Cipher.cs
    ├── Tls.cs
    └── Pqc.cs
```

### Dart

```
AppName/
├── pubspec.yaml                          (crypto ^3.0.0, cryptography ^2.7.0)
└── lib/src/
    ├── hash.dart
    ├── cipher.dart
    └── kdf.dart
```

### C / C++

```
AppName/
├── CMakeLists.txt                        (OpenSSL required)
└── src/
    ├── hash.c
    ├── cipher.c
    ├── tls.c
    └── pqc.c
```

---

## Platform Compatibility

All libraries are **code-generation targets only** — the generator emits source code and has no runtime dependency on any of them.

| Language | Library | macOS | Windows | Linux | Notes |
|---|---|---|---|---|---|
| C/C++ | OpenSSL | ✅ | ⚠️ | ✅ | Windows needs vcpkg/MSVC installer |
| C/C++ | Libgcrypt | ✅ | ⚠️ | ✅ | Windows via MSYS2/cygwin only |
| C/C++ | Nettle | ✅ | ⚠️ | ✅ | Windows via MSYS2/MinGW |
| C/C++ | Crypto++ | ✅ | ✅ | ✅ | NuGet + vcpkg on Windows |
| C/C++ | **GSKit-crypto** | ❌ | ⚠️ | ✅ | **Platform guard enforced** — IBM product SDK, not available standalone on macOS |
| C/C++ | liboqs | ✅ | ✅ | ✅ | CMake-based, fully cross-platform |
| C# | .NET Cryptography | ✅ | ✅ | ✅ | PQC requires .NET 9+ |
| Dart | cryptography | ✅ | ✅ | ✅ | Pure Dart |
| Go | crypto + x/crypto | ✅ | ✅ | ✅ | No restrictions |
| JS/TS | node:crypto | ✅ | ✅ | ✅ | Node 18+ built-in |
| JS/TS | jsonwebtoken | ✅ | ✅ | ✅ | Pure JS npm package |

The generator enforces platform restrictions at generation time via [`platform_guard.py`](platform_guard.py). Attempting to generate a GSKit-crypto app on macOS raises a clear `[PLATFORM ERROR]` with remediation steps.

---

## Weakness Catalogue

Weaknesses are mapped to the rules defined in [`cbom-security.yaml`](cbom-security.yaml).

### Generator rules (CBS-001 – CBS-004)

| Rule    | Category                              | Examples                                                                                     |
|---------|---------------------------------------|----------------------------------------------------------------------------------------------|
| CBS-001 | Weak / deprecated algorithm           | MD5, SHA-1, DES, 3DES, RC4, Blowfish, MD5withRSA, SHA1withRSA                               |
| CBS-002 | Insecure cipher mode                  | AES-ECB, AES-CBC (no AEAD), static / hardcoded IVs                                          |
| CBS-003 | Insufficient key size / hardcoded material | RSA-512/1024, AES-64, PBKDF2 <2000 iters, no salt, hardcoded keys / passwords / PEM / JWT secrets, insecure PRNG, quantum-vulnerable RSA / ECDH, **PQC algorithms (see below)** |
| CBS-004 | Outdated protocol                     | SSLv3, TLS 1.0, TLS 1.1, trust-all TrustManager, certificate validation disabled            |

### PQC algorithm discovery targets

The generator also injects **post-quantum cryptography (PQC) code** so that IBM Quantum Safe Explorer can enumerate modern algorithms alongside the classical weaknesses. Each snippet uses correct canonical API calls, includes `// Algorithm: X  Library: Y  Language: Z` inline comments for QSE parsing, and fails gracefully when the required library is absent.

| Algorithm | Library | Language | Notes |
|-----------|---------|----------|-------|
| ML-KEM (FIPS 203) | Java JCA | Java | `javax.crypto.KEM.getInstance("ML-KEM-{512\|768\|1024}")` — Java 21+ |
| ML-DSA (FIPS 204) | Java JCA | Java | `Signature.getInstance("ML-DSA-{44\|65\|87}")` — Java 21+ |
| ML-KEM (FIPS 203) | BouncyCastle | Java | `KeyPairGenerator.getInstance("ML-KEM-...", "BC")`, auto-registers BC provider |
| ML-DSA (FIPS 204) | BouncyCastle | Java | `Signature.getInstance("ML-DSA-...", "BC")` |
| SLH-DSA (FIPS 205) | BouncyCastle | Java | `Signature.getInstance("SLH-DSA-SHA2-...", "BC")` |
| ML-KEM (FIPS 203) | cryptography | Python | `cryptography.hazmat.primitives.asymmetric.mlkem` — requires `cryptography >= 44.0.0` |
| ML-DSA (FIPS 204) | cryptography | Python | `cryptography.hazmat.primitives.asymmetric.mldsa` — requires `cryptography >= 44.0.0` |
| ML-KEM (FIPS 203) | oqs | Python | `oqs.KeyEncapsulation("ML-KEM-...")` — requires `liboqs-python` |
| ML-DSA (FIPS 204) | oqs | Python | `oqs.Signature("ML-DSA-...")` |
| SLH-DSA (FIPS 205) | oqs | Python | `oqs.Signature("SLH-DSA-SHA2-...")` |
| XMSS | oqs | Python | `oqs.Signature("XMSS-SHA2_10_256")` — stateful hash-based signature |
| ML-KEM (FIPS 203) | dotnet-crypto | C# | `MLKem768.TryEncapsulate(...)` — .NET 9+ |
| ML-DSA (FIPS 204) | dotnet-crypto | C# | `MLDsa44.GenerateKey(); key.SignData(msg)` — .NET 9+ |
| SLH-DSA (FIPS 205) | dotnet-crypto | C# | `SlhDsaSha2_128s.GenerateKey(); key.SignData(msg)` — .NET 9+ |
| ML-KEM (FIPS 203) | x/crypto | Go | `mlkem.GenerateKey768(rand.Reader)` — golang.org/x/crypto v0.23.0+ |
| ML-KEM (FIPS 203) | mlkem-npm | JavaScript | `MlKem768.generateKeyPair()` — `mlkem` npm package |
| ML-DSA (FIPS 204) | mldsa-npm | JavaScript | `ml_dsa44.keygen()` — `@noble/post-quantum` npm package |

### Extended CWE rules (CBS-005 – CBS-012)

The following rules were added from `cwe.yaml` to cover additional CWE mappings detected by IBM Guardium Quantum Safe Explorer:

| Rule    | CWE       | Name                                              | Severity |
|---------|-----------|---------------------------------------------------|----------|
| CBS-005 | CWE-259   | Use of Hard-coded Password                        | high     |
| CBS-006 | CWE-321   | Use of Hard-coded Cryptographic Key               | critical |
| CBS-007 | CWE-335   | Incorrect Usage of Seeds in PRNG                  | high     |
| CBS-008 | CWE-338   | Use of Cryptographically Weak PRNG                | critical |
| CBS-009 | CWE-759   | Use of a One-Way Hash without a Salt              | high     |
| CBS-010 | CWE-780   | Use of RSA Algorithm without OAEP                 | high     |
| CBS-011 | CWE-916   | Password Hash With Insufficient Computational Effort | critical |
| CBS-012 | CWE-1204  | Generation of Weak Initialization Vector (IV)     | high     |

### Compliance rule (CBC-001)

| Rule    | Category              | Description                                        |
|---------|-----------------------|----------------------------------------------------|
| CBC-001 | Expired certificate   | Certificates expired or close to expiration date   |

---

## Requirements

- Python 3.8+ (standard library only — no external dependencies for the generator itself)
- The generated **Java** app targets Java 17 / Maven 3.9+; BouncyCastle PQC snippets require Java 17+ with `bcprov-jdk18on` on the classpath
- The generated **Python** app lists its runtime dependencies in `requirements.txt`; PQC snippets require `cryptography >= 44.0.0` and/or `liboqs-python >= 0.10.0`
- The generated **Go** app requires Go 1.22+ and `golang.org/x/crypto v0.23.0+`
- The generated **JavaScript** app requires Node 18+ and the npm packages listed in `package.json`
- The generated **C#** app targets .NET 9 (PQC APIs require .NET 9+)
- The generated **Dart** app requires Dart SDK ≥ 3.0.0
- The generated **C/C++** app requires OpenSSL development headers (+ optional GSKit/Libgcrypt/Nettle)
- **Temp file strategy:** intermediate files are written to `.gen-tmp/` at the project root (auto-added to `.gitignore`) and removed after generation completes
- Created by Erwin Friethoff, Senior Security Architect at IBM. Please reach out for questions or suggestions.

<script data-goatcounter="https://ncee-data-sme.goatcounter.com/count" async src="//gc.zgo.at/count.js"></script>
