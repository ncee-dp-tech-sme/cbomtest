## Prompt

We are implementing the multi-language weak crypto generator extension on branch `feature/multi-language-crypto-generator`. Task: Implement Phase 4 — Generator functions for Go, JS, C#, Dart, C/C++.

---

## Phase 4 — Generator Functions: Summary

**Date:** 2026-08-01
**Branch:** `feature/multi-language-crypto-generator`
**Commit:** `b04b933`

---

### What was done

#### 1. `import platform_guard` added

Added `import platform_guard` to `generate_vulnerable_app.py` (after stdlib imports, before the Weakness catalogue section). Required by `generate_c_app()` for the GSKit-crypto guard.

#### 2. `_distribute()` helper

Added in the new **Multi-language generator helpers** section (between `generate_python_app` and the existing Shared helpers):

```python
def _distribute(snippets, file_map, pqc_key=None):
```

- Round-robin distributes `(Weakness, snippet_str)` pairs across `file_map` buckets.
- PQC snippets (description containing `ml-kem`, `ml-dsa`, `slh-dsa`) always land in the designated `pqc_key` bucket regardless of round-robin position.

#### 3. Five generator functions added

| Function | Build file | Source files |
|---|---|---|
| `generate_go_app()` | `go.mod` | `crypto/{hash,cipher,tls,pqc}.go` |
| `generate_js_app()` | `package.json` | `src/{hash,cipher,tls,jwt,pqc}.js` |
| `generate_csharp_app()` | `<AppName>.csproj` | `Crypto/{Hash,Cipher,Tls,Pqc}.cs` |
| `generate_dart_app()` | `pubspec.yaml` | `lib/src/{hash,cipher,kdf}.dart` |
| `generate_c_app()` | `CMakeLists.txt` | `src/{hash,cipher,tls,pqc}.c` |

All five:
- Return `[]` immediately if `base_dir` already exists (idempotent).
- Return `List[Weakness]` for all injected weaknesses.
- Accept `weaknesses_to_inject: List[Tuple[Weakness, Callable[[], str]]]` (factory pairs) and call each factory once during generation.

`generate_c_app()` additionally checks all weakness descriptions for `"gskit"` before creating any files and calls `platform_guard.assert_supported("c", "gskit-crypto")`, raising `PlatformError` on macOS.

#### 4. `tests/test_generators.py` — 26 integration tests

| Test ID | Description | Languages tested |
|---|---|---|
| GI-01 | Key output files and build file exist | Go, JS, C#, Dart, C |
| GI-02 | Generator returns non-empty `List[Weakness]` | Go, JS, C#, Dart, C |
| GI-03 | No file written outside `base_dir` | Go, JS, C#, Dart, C |
| GI-04 | Build file contains required tokens | Go, JS, C#, Dart, C |
| GI-05 | `generate_c_app()` raises `PlatformError` for GSKit-crypto on mocked macOS | C only |
| GI-06 | All injected weaknesses have non-empty `tag` field | Go, JS, C#, Dart, C |

#### 5. Module docstring updated

Phase 4 entry added to the change history at the top of `generate_vulnerable_app.py`.

---

### Test results

```
379 passed, 76 skipped in 0.27s
```

The 76 skips are expected — they are the `test_sf03_pqc_algorithm_comment` cases for non-PQC snippet factories across all language factory test files (pre-existing behaviour).

All new GI-01..GI-06 tests: **PASSED**.
All pre-existing tests: **PASSED** (no regressions).

---

### Files changed

| File | Change |
|---|---|
| `generate_vulnerable_app.py` | Added `import platform_guard`; added `_distribute()` + 5 generator functions; updated change history |
| `tests/test_generators.py` | New file — 26 integration tests (GI-01..GI-06 × 5 languages) |
