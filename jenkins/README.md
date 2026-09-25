# Jenkins — IBM Bob Shell Security Scan Pipeline

This folder contains everything needed to run an automated security scan of your
source code and dependencies using **IBM Bob Shell** in a Jenkins CI/CD pipeline.

---

## Contents

| Path | Purpose |
|------|---------|
| `Jenkinsfile` | Declarative Jenkins pipeline |
| `.bob/rules/security-scanning.md` | Bob Shell workspace custom rules that sharpen the scan |

---

## How it works

```
Jenkins build
  │
  ├─ Stage: Checkout         — pulls source from SCM
  ├─ Stage: Install Bob Shell — curl-installs bob if not on the agent
  ├─ Stage: Accept License   — one-time license acceptance (no-op on repeat runs)
  ├─ Stage: Prepare          — creates bob-security-reports/ output directory
  ├─ Stage: Source Code Scan — Bob Shell reviews all source files for weaknesses
  ├─ Stage: Dependency Scan  — Bob Shell reviews dependency manifests for CVEs
  └─ Stage: Archive Reports  — Markdown reports attached as Jenkins build artifacts
```

Bob Shell runs in **non-interactive mode** (`bob -p "..."`) so no human interaction
is required.  The `--approval-mode full-auto` flag is used only for writing the
report files; source files are never modified.

---

## Prerequisites

### 1. Jenkins agent

- Linux or macOS agent with `curl` and `bash` available.
- Internet access to `bob.ibm.com` to download Bob Shell and run inference.

### 2. IBM Bob Shell API key (required for CI/CD)

1. Sign in to [bob.ibm.com](https://bob.ibm.com) and navigate to **Settings → API Keys**.
2. Create a new key with **Scope: Inference**.
3. Copy the key value — you will not be able to view it again.

### 3. Jenkins Secret Text credential

Store the API key in Jenkins as a **Secret Text** credential with the exact ID:

```
bobshell-api-key
```

> Jenkins → Manage Jenkins → Credentials → (global) → Add Credential
> Kind: Secret text | ID: `bobshell-api-key` | Secret: `<your key>`

---

## Usage

### Add the pipeline to Jenkins

1. Create a new **Pipeline** job in Jenkins.
2. Set **Definition** to *Pipeline script from SCM*.
3. Point it at your repository and set **Script Path** to `jenkins/Jenkinsfile`.
4. Save and run the build.

### Copy the custom rules into your project

The Bob Shell custom rules must live inside the scanned project's workspace at
`.bob/rules/security-scanning.md`.  Copy the file from this folder:

```bash
mkdir -p .bob/rules
cp jenkins/.bob/rules/security-scanning.md .bob/rules/security-scanning.md
git add .bob/rules/security-scanning.md
git commit -m "Add Bob Shell security scanning custom rules"
```

Bob Shell automatically loads all `.md` files under `.bob/rules/` when it starts,
so no additional configuration is needed.

---

## Output

After a successful run, two Markdown reports are attached to the build as artifacts:

| Report | Contents |
|--------|---------|
| `bob-security-reports/source-scan-report.md` | Source code findings (crypto weaknesses, secrets, injection, etc.) |
| `bob-security-reports/dependency-scan-report.md` | Dependency findings (CVEs, EOL packages, outdated versions) |

Each report contains:
- A **Summary** table with finding counts per severity level.
- A **Findings** table with file, line, severity, rule ID, description and remediation.
- A **Recommendations** section with prioritised next steps.

---

## Custom Rules

The file `.bob/rules/security-scanning.md` instructs Bob Shell to apply the
following rule set during every scan:

| Rule ID | Area | Severity |
|---------|------|----------|
| CBS-001 | Weak cryptographic algorithms | Critical / High |
| CBS-002 | Hardcoded secrets and credentials | Critical |
| CBS-003 | Injection vulnerabilities | High |
| CBS-004 | Insecure random number generation | High |
| CBC-001 | Quantum-unsafe algorithms (RSA, ECDSA) | Informational |
| —       | Dependency CVEs & EOL packages | CVE CVSS score |

These rules mirror the definitions in `cbom-security.yaml` at the repository root.

---

## Environment Variables (pipeline)

| Variable | Source | Purpose |
|----------|--------|---------|
| `BOBSHELL_API_KEY` | Jenkins credential `bobshell-api-key` | Authenticates Bob Shell in non-interactive mode |
| `BOB_REPORT_DIR` | Hardcoded in `Jenkinsfile` (`bob-security-reports`) | Output directory for scan reports |
| `BOB_RULES_DIR` | Hardcoded in `Jenkinsfile` (`.bob/rules`) | Location of workspace custom rules |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `bob: command not found` | Bob Shell not installed / PATH not updated | Ensure the install stage ran successfully; check agent PATH |
| `Authentication failed` | Invalid or missing API key | Verify the `bobshell-api-key` Jenkins credential |
| `Report not found` after scan | Bob Shell exited before writing the file | Check the console log for Bob Shell error output |
| License error on first run | License not yet accepted | Re-run; the Accept License stage handles this automatically |
