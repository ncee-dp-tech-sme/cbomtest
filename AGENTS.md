# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Project Overview

This is an **IBM Guardium Quantum Safe Explorer demo toolset** — a client demo repository, never for production. It contains:

- **`generate_vulnerable_app.py`** — the main generator (stdlib only, no deps). Run interactively to produce Java or Python apps with deliberate crypto weaknesses.
- **`InsecWeb/`** — a pre-generated Java / Spring Boot 3.2 sample app with injected weaknesses (scan results in `qs_explorer_result/`).
- **`PyWebVuln/`** — a pre-generated Python / Flask sample app with injected weaknesses.
- **`Webchat/`** — another pre-generated Java sample app with scan results.
- **`cbom-security.yaml`** — the canonical weakness rule definitions (`CBS-001`–`CBS-004`, `CBC-001`).

## Running the Generator

```bash
python3 generate_vulnerable_app.py
```

No virtual environment needed — stdlib only. Prompts for language, app name, and version. After generation it also prompts for `repositoryUrl` (required for Guardium Cryptography Manager upload).

## Testing the Generated Python App

From within the generated Python app's directory (e.g. `PyWebVuln/`):

```bash
# Install deps
pip install -r requirements.txt

# Run all tests
python -m pytest tests/

# Run a single test
python -m pytest tests/test_auth.py::test_hash_password_returns_string
```

Test imports use the package name derived from the app name (e.g. `from pywebvuln.services.user import ...`). Tests must be run from the **app root directory**, not the repo root, because the package is not installed globally.

## Building the Generated Java App

From within the generated Java app's directory (e.g. `InsecWeb/`):

```bash
mvn clean package
java -jar target/<AppName>-<version>.jar
```

Java 17 required. Maven 3.9+.

## Code Style — `generate_vulnerable_app.py`

- **Weakness factories** are registered via decorators `@_jw(...)` / `@_pw(...)` — add new weaknesses only this way, never by editing `JAVA_WEAKNESS_FACTORIES` / `PYTHON_WEAKNESS_FACTORIES` directly.
- **Weakness counts** are randomly selected: `random.randint(8, 26)` per run. Factories may be called more than once (repetition intentional).
- `cbom-security.yaml` is the single source of truth for rule IDs (`CBS-001`–`CBS-004`). Tag every new weakness factory with the correct rule ID as the `tag` parameter.
- Change history is documented at the **top of the script** in the module docstring — always add an entry when modifying the generator.
- Use `textwrap.dedent(f"""...""")` for all multi-line snippet strings in factories.
- Injected code comments must NOT hint at the weakness (realistic-looking comments only).

## Non-Obvious Conventions

- The generated Java package name is derived by stripping hyphens/underscores from the app name (`app_name.lower().replace("-","").replace("_","")`) — this determines `com.example.<pkg>`.
- The generated Python package name replaces hyphens and spaces with underscores (`app_name.lower().replace("-","_").replace(" ","_")`).
- `repositoryUrl` is prompted **after** file generation and printed to stdout — it is NOT written into any generated file. It must be added manually to the CBOM before uploading to Guardium Cryptography Manager.
- Scan results from IBM Quantum Safe Explorer are stored in `<AppName>/qs_explorer_result/` — these are CycloneDX 1.6 CBOM JSON files plus summary/findings JSON files.
