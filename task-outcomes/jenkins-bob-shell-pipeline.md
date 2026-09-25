# Task: Create Jenkins pipeline using IBM Bob CLI for vulnerability scanning

Timestamp: Wed Sep 23 22:43:40 CEST 2026

---

## Files created

| File | Description |
|------|-------------|
| `jenkins/Jenkinsfile` | Declarative Jenkins pipeline with 7 stages |
| `jenkins/.bob/rules/security-scanning.md` | Bob Shell workspace custom rules |
| `jenkins/README.md` | Setup and usage documentation |

---

## Jenkinsfile — Pipeline stages

1. **Checkout** — pulls source from SCM
2. **Install Bob Shell** — installs `bob` CLI via curl if not present on the agent
3. **Accept License** — one-time license acceptance (idempotent; safe to re-run)
4. **Prepare** — creates `bob-security-reports/` output directory
5. **Source Code Security Scan** — Bob Shell reviews all source files for CBS-001–CBS-004 weaknesses
6. **Dependency Vulnerability Scan** — Bob Shell reviews dependency manifests for CVEs, EOL packages
7. **Archive Reports** — Markdown reports attached as Jenkins build artifacts

Authentication uses `BOBSHELL_API_KEY` from a Jenkins Secret Text credential (`bobshell-api-key`).
Bob Shell runs in non-interactive mode: `bob --auth-method api-key --approval-mode full-auto -p "..."`.

---

## Custom Rules — .bob/rules/security-scanning.md

Rules loaded by Bob Shell automatically from the workspace `.bob/rules/` directory.

| Rule ID | Area | Severity |
|---------|------|----------|
| CBS-001 | Weak cryptographic algorithms (MD5, SHA-1, DES, RC4, ECB, TLS<1.2) | Critical/High |
| CBS-002 | Hardcoded secrets, API keys, passwords | Critical |
| CBS-003 | Injection: SQL, command, path traversal, XSS, log injection | High |
| CBS-004 | Insecure random number generation | High |
| CBC-001 | Quantum-unsafe algorithms (RSA, ECDSA, DH) | Informational |
| —       | Dependency CVEs, EOL packages, outdated versions | CVSS-based |

Rules also define the required Markdown report output format (Summary + Findings + Recommendations).
