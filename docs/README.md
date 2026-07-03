# generate_vulnerable_app.py

A demo tool that interactively generates realistic multi-file Java or Python applications with deliberately introduced cryptographic weaknesses, for showcasing the value of **IBM Guardium Quantum Safe Explorer**.
After running **IBM Guardium Quantum Safe Explorer** the results can be uploaded **IBM Guardium Cryptography Manager** after adding the required metadata,(gitUrl or repositoryUrl & repositoryId).

> **Note:** This tool is exclusively for client demos and should NEVER be used in production.


Github Repository [`cbomtest`](https://github.com/ncee-dp-tech-sme/cbomtest)
---

## Usage

```bash
python3 generate_vulnerable_app.py
```

You will be prompted for:

- **Language** — `java` or `python`
- **Application name** — used as the output directory name
- **Version number** — e.g. `1.0.0`

---

## Execution Flow

1. Prompts for language (`java`/`python`), application name, and version
2. Creates a named output directory with a realistic multi-module application tree
3. Randomly selects **8–26 weaknesses** from 28 distinct weakness factories (14 Java, 14 Python)
4. Distributes them naturally across 8 source files per language
5. Prints a categorised summary with rule IDs (`CBS-001` through `CBS-004`)

---

## Generated Structure

### Java

```
AppName/
├── pom.xml                               (Spring Boot 3.2, JUnit 5)
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
├── main.py · requirements.txt · setup.py · .env.example
├── config/app.yaml                       (SHA-1, AES-128-CBC, hardcoded JWT)
├── templates/base.html
├── tests/test_auth.py
└── appname/
    ├── api/routes.py
    ├── crypto/cipher.py · crypto/keys.py
    ├── services/auth.py · services/user.py
    └── utils/hashing.py · utils/tokens.py · config/settings.py
```

---

## Weakness Catalogue

Weaknesses are mapped to the rules defined in [`cbom-security.yaml`](https://github.com/ncee-dp-tech-sme/cbomtest/blob/main/cbom-security.yaml):

| Rule    | Category                              | Examples                                                                                     |
|---------|---------------------------------------|----------------------------------------------------------------------------------------------|
| CBS-001 | Weak / deprecated algorithm           | MD5, SHA-1, DES, 3DES, RC4, Blowfish, MD5withRSA, SHA1withRSA                               |
| CBS-002 | Insecure cipher mode                  | AES-ECB, AES-CBC (no AEAD), static / hardcoded IVs                                          |
| CBS-003 | Insufficient key size / hardcoded material | RSA-512/1024, AES-64, PBKDF2 <2000 iters, no salt, hardcoded keys / passwords / PEM / JWT secrets, insecure PRNG, quantum-vulnerable RSA / ECDH |
| CBS-004 | Outdated protocol                     | SSLv3, TLS 1.0, TLS 1.1, trust-all TrustManager, certificate validation disabled            |

---

## Requirements

- Python 3.8+ (standard library only — no external dependencies for the generator itself)
- The generated **Java** app targets Java 17 / Maven 3.9+
- The generated **Python** app lists its runtime dependencies in `requirements.txt`
- Created by Erwin Friethoff, Senior Security Architect at IBM. Please reach out for questions or suggestions. 
