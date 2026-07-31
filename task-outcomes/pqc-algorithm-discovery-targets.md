## Prompt
Update the existing main program to generate code that enables the Quantum Safe Explorer to discover and enumerate the following cryptographic algorithms across multiple languages and libraries.

## Changes Made to `generate_vulnerable_app.py`

### New PQC weakness factories added (11 total)

**Java/JCA (2 factories)**
- `ML-KEM` — `KeyPairGenerator.getInstance("ML-KEM-{512|768|1024}")` + `javax.crypto.KEM.getInstance(...)`
- `ML-DSA` — `KeyPairGenerator.getInstance("ML-DSA-{44|65|87}")` + `Signature.getInstance(...)`

**Java/BouncyCastle (3 factories)**
- `ML-KEM` — `KeyPairGenerator.getInstance("ML-KEM-...", "BC")` with `BouncyCastleProvider` registration
- `ML-DSA` — `Signature.getInstance("ML-DSA-...", "BC")` with BC provider
- `SLH-DSA` — `Signature.getInstance("SLH-DSA-SHA2-...", "BC")` with BC provider

**Python/cryptography (2 factories)**
- `ML-KEM` — `from cryptography.hazmat.primitives.asymmetric.mlkem import generate_private_key`
- `ML-DSA` — `from cryptography.hazmat.primitives.asymmetric.mldsa import generate_private_key`

**Python/oqs (4 factories)**
- `ML-KEM` — `oqs.KeyEncapsulation("ML-KEM-{512|768|1024}")`
- `ML-DSA` — `oqs.Signature("ML-DSA-{44|65|87}")`
- `SLH-DSA` — `oqs.Signature("SLH-DSA-SHA2-...")`
- `XMSS` — `oqs.Signature("XMSS-SHA2_10_256")`

### Dependency updates
- **pom.xml template**: Added `bcprov-jdk18on:1.78.1` and `bcpkix-jdk18on:1.78.1`
- **requirements.txt template**: Bumped `cryptography>=44.0.0`, added `liboqs-python>=0.10.0`
- **setup.py template**: Same dependency updates mirrored

### Module docstring
Added change history entry dated 2026-07-31.

## Verification
- AST parse: OK
- Java factory count: 33 (was 22), Python factory count: 28 (was 22)
- All 11 PQC factories confirmed registered and producing correct snippets
- End-to-end generation: Java and Python apps generated successfully, PQC snippets appear in source files
- BouncyCastle present in generated pom.xml (4 matching lines)
- liboqs-python present in generated requirements.txt
