Create a Python script called `generate_vulnerable_app.py` that, when executed, interactively generates a complete multi-file Java or Python application with deliberately introduced cryptographic weaknesses. This tool is exclusively for client demos to showcase the value of Guardium Quantum Safe Explorer and will never be used in production.

**Execution Flow:**

1. When the script is run, prompt the user for:
   - Language choice: Java or Python
   - Application name (used as the output directory name)
   - Version number

2. Create a directory named after the application and generate a realistic multi-folder, multi-file application structure inside it. The application should resemble a web application with frontend and backend components (or a sufficiently complex multi-module application) — including configuration files, dependency manifests, README, and multiple source code files organized in subdirectories (e.g., `src/`, `config/`, `utils/`, `crypto/`, `api/`, `templates/` or equivalent Java package structure).

3. Deliberately introduce a random number of cryptographic weaknesses throughout the generated codebase. The number of weaknesses should vary randomly between 5 and 25+ per generation. Read and reference the file `@cbom-security.yaml` for examples of cryptographic weaknesses to introduce. Types of weaknesses to include (but not limited to):
   - Use of broken or weak algorithms (MD5, SHA-1, DES, 3DES, RC4, Blowfish with small keys)
   - Hardcoded cryptographic keys, passwords, or secrets
   - Use of ECB mode for block ciphers
   - Insufficient key lengths (e.g., RSA-1024, AES-128 where 256 is needed)
   - Use of deprecated or insecure TLS/SSL versions (SSLv3, TLS 1.0, TLS 1.1)
   - Insecure random number generation (using non-cryptographic PRNGs for security purposes)
   - Missing or improper certificate validation
   - Static/reused initialization vectors (IVs) or nonces
   - Improper key derivation (e.g., low PBKDF2 iterations, no salt)
   - Use of custom/homegrown cryptographic implementations
   - Weak digital signature algorithms
   - Quantum-vulnerable algorithms without mitigation markers
   - Any other weaknesses found in `cbom-security.yaml` or that you deem relevant for demonstrating quantum-safe analysis tooling

4. The weaknesses should be spread naturally across different files and modules so they appear realistic and are not all clustered in one place.

5. After all files are generated and saved to the output directory, print a summary to the console stating exactly how many cryptographic weaknesses were deliberately included and optionally a brief categorized list of the weakness types introduced.

**Requirements:**
- The generator script itself (`generate_vulnerable_app.py`) should be a single executable Python file with no external dependencies beyond the standard library.
- The generated application code should look realistic and plausible — not obviously placeholder or dummy code.
- Include appropriate file structures: build files (`pom.xml`/`build.gradle` for Java, `requirements.txt`/`setup.py` for Python), configuration files, and a README with the application name and version.
- Add code comments in the generated source that do NOT indicate the weaknesses — the weaknesses should be hidden as they would be in real codebases.
- Ensure variety: running the generator multiple times should produce different applications with different distributions and counts of weaknesses.- Java code should compile/build