# Contributing to generate_vulnerable_app.py

This document explains how to extend the generator. All code lives in
[`generate_vulnerable_app.py`](../generate_vulnerable_app.py) (stdlib only)
and [`platform_guard.py`](../platform_guard.py).

---

## CBS Rule IDs

Every weakness factory must be tagged with one of these four rule IDs:

| Rule | Category |
|---|---|
| `CBS-001` | Weak or deprecated algorithm (MD5, SHA-1, DES, RC4, …) |
| `CBS-002` | Insecure cipher mode (ECB, CBC without MAC, static IV) |
| `CBS-003` | Insufficient key size, hardcoded material, insecure PRNG, weak KDF |
| `CBS-004` | Outdated protocol (SSLv3, TLS 1.0, cert validation disabled) |

No other tag values are valid.

---

## 1. Adding a weakness factory

Weakness factories are plain functions decorated with the language-specific
decorator. The decorator appends the factory to the relevant list automatically —
**never edit the `*_WEAKNESS_FACTORIES` lists directly**.

### Pattern

```python
@_jw("Category", "Short description of the weakness", "CBS-00X")
def _():
    return textwrap.dedent("""\
        // Realistic-looking comment — no hint of the weakness
        public static String doSomething(String input) throws Exception {
            ...
        }
    """)
```

### Decorator reference

| Decorator | Language | Factory list |
|---|---|---|
| `@_jw(...)` | Java | `JAVA_WEAKNESS_FACTORIES` |
| `@_pw(...)` | Python | `PYTHON_WEAKNESS_FACTORIES` |
| `@_gw(...)` | Go | `GO_WEAKNESS_FACTORIES` |
| `@_jsw(...)` | JavaScript / TypeScript | `JS_WEAKNESS_FACTORIES` |
| `@_csw(...)` | C# | `CSHARP_WEAKNESS_FACTORIES` |
| `@_dw(...)` | Dart | `DART_WEAKNESS_FACTORIES` |
| `@_cw(...)` | C / C++ | `C_WEAKNESS_FACTORIES` |

### Snippet indentation rules

- Java snippets: write method bodies at **zero indent** inside the factory.
  `_java_file()` re-indents them to 4-space class body indent automatically.
- All other languages: snippets are written verbatim into source files.
  Keep them at zero indent inside the factory string.
- Always use `textwrap.dedent(f"""...""")` (or `textwrap.dedent("""...""")`)
  for multi-line snippet strings.

### Randomised content

Factories that embed variable content (keys, IVs, iteration counts) call
`random.choices()`, `random.randbytes()`, or `random.randint()` inline. This
is intentional — each call to the factory may produce a different output.

### Comments inside snippets

Comments inside snippets must look like **real production code**. They must
**not** hint at the weakness (e.g. do not write `// weak algorithm` or
`// insecure`).

---

## 2. Adding a new language

Follow this checklist in order:

1. **Factory list** — add `NEWLANG_WEAKNESS_FACTORIES: List[...] = []` in a new
   language section with a banner comment.
2. **Decorator helper** — add `def _nlw(category, description, tag="")` following
   the same pattern as the existing decorators.
3. **Snippet factories** — implement at least 6 factories covering CBS-001 through
   CBS-004. Include at least one PQC factory if a PQC library exists for the
   language (see PQC snippet conventions below).
4. **Generator function** — add `generate_newlang_app(base_dir, app_name, version,
   weaknesses_to_inject) -> List[Weakness]`. It must:
   - Call `platform_guard.assert_supported()` for any platform-restricted library
   - Create the output directory tree
   - Write a build file appropriate to the language
   - Distribute snippets using `_distribute()` with PQC routing
   - Return the list of injected `Weakness` objects
5. **`main()` maps** — add the new language key to `FACTORY_POOL_MAP`,
   `GENERATOR_MAP`, and `LANG_LABELS` inside `main()`.
6. **Build file template** — include all dependencies needed to compile/run the
   generated code.
7. **README** — update both `README.md` and `docs/README.md`:
   - Add the language to the Usage prompt list
   - Add an Execution Flow factory count
   - Add a Generated Structure subsection
   - Add a Platform Compatibility row
   - Add Requirements bullet
8. **Tests** — add `tests/test_factories_newlang.py` (SF-01..05) and entries in
   `tests/test_generators.py` (GI-01..06).

---

## 3. Adding a platform restriction

Platform restrictions are enforced by [`platform_guard.py`](../platform_guard.py).

1. Add an entry to `_UNSUPPORTED` in `platform_guard.py`:
   ```python
   ("platform", "language", "library"):
       "Reason sentence. Remediation sentence.",
   ```
   Keys are all lowercase. Platform must be one of: `macos`, `windows`, `linux`.

2. The error message is assembled automatically by `assert_supported()`. It always
   starts with `[PLATFORM ERROR]`, names the library and OS, and includes an
   `Action:` remediation line. Do **not** write a custom error string.

3. Call `platform_guard.assert_supported(language, library)` at the top of the
   relevant generator function, before any files are written.

4. Add tests in `tests/test_platform_guard.py`:
   - One test that asserts `PlatformError` is raised on the restricted platform
     (use `monkeypatch` / `importlib.reload` to mock `sys.platform`)
   - One test that asserts no exception on an allowed platform

---

## 4. PQC snippet conventions

Every PQC snippet **must**:

1. Start with a canonical identification comment as the **first line** of the
   returned snippet string:
   ```
   // Algorithm: ML-KEM  Library: x/crypto       Language: Go
   // Algorithm: ML-DSA  Library: mldsa-npm       Language: JavaScript
   // Algorithm: ML-KEM  Library: dotnet-crypto   Language: C#
   ```
   The format is: `// Algorithm: <name>  Library: <lib-id>  Language: <lang>`

2. Use **correct, canonical API calls** — the snippet must reflect real library
   usage so QSE can recognise the algorithm.

3. Handle missing libraries gracefully. For Python use `try/except ImportError`.
   For C# use `// #if NET9_0_OR_GREATER` guard comments.

4. Be tagged with `CBS-001` (PQC algorithms are tracked as discovery targets
   alongside classical weak-algorithm findings).

5. Route to the dedicated PQC file during generation. The `_distribute()` helper
   does this automatically for any snippet whose weakness description contains
   `ML-KEM`, `ML-DSA`, or `SLH-DSA`.

---

## 5. Change history

Every modification to `generate_vulnerable_app.py` must add an entry to the
**module-level docstring** at the top of the file. Format:

```
  YYYY-MM-DD  Short description. No more than two lines.
```

Entries are ordered chronologically, oldest first. Do **not** add change
history in inline comments.
