## Prompt
Write the Phase 3 snippet factory tests (SF-01..05) for Go, JavaScript, C#, Dart, and C/C++ weakness factories as described in the implementation plan.

---

# Phase 3 Tests — Snippet Factory Tests (SF-01..05)

**Date:** 2026-07-31  
**Branch:** `feature/multi-language-crypto-generator`  
**Commit:** `f495d74`

## Files Created

| File | Language | Factories covered |
|---|---|---|
| `tests/test_factories_go.py` | Go | 19 |
| `tests/test_factories_js.py` | JavaScript | 21 |
| `tests/test_factories_csharp.py` | C# | 18 |
| `tests/test_factories_dart.py` | Dart | 7 |
| `tests/test_factories_c.py` | C/C++ | 17 |

**Total factories under test: 82**

## Test IDs Implemented

| Test ID | Check | Notes |
|---|---|---|
| SF-01 | Every factory returns a non-empty string | Applied to all factories |
| SF-02 | No snippet contains `/tmp`, `C:\Temp`, or `tempfile` | Applied to all factories |
| SF-03 | PQC factories emit `Algorithm:` identification comment | Skipped (not PQC); active for ML-KEM/ML-DSA/SLH-DSA factories |
| SF-04 | Weakness tag is one of CBS-001..CBS-004 | Applied to all factories |
| SF-05 | Two consecutive calls both return non-empty strings | Applied to all factories |

## Test Run Results

```
platform darwin -- Python 3.14.6, pytest-9.1.1
353 passed, 76 skipped in 0.42s
```

- **353 PASSED** — all SF-01, SF-02, SF-04, SF-05 checks across all 82 new factories plus 19 pre-existing tests.
- **76 SKIPPED** — SF-03 cases for non-PQC factories (correct behaviour: test is skipped with `pytest.skip` when the factory has no PQC keyword in its description).
- **0 FAILED / 0 ERRORS**

## PQC Factory Coverage (SF-03 active)

| Language | PQC factories | Algorithm tags verified |
|---|---|---|
| Go | 1 | ML-KEM |
| JavaScript | 2 | ML-KEM, ML-DSA |
| C# | 3 | ML-KEM, ML-DSA, SLH-DSA |
| Dart | 0 | — (all SF-03 cases skipped) |
| C/C++ | 0 | — (all SF-03 cases skipped) |

## Import Strategy

All test files import the factory lists at module level using:

```python
sys.path.insert(0, str(Path(__file__).parent.parent))
import generate_vulnerable_app as gva
# gva.GO_WEAKNESS_FACTORIES, gva.JS_WEAKNESS_FACTORIES, etc.
```

`main()` is never triggered (guarded by `if __name__ == "__main__"`), so import is safe.

## Git

Committed and pushed to remote on branch `feature/multi-language-crypto-generator`:
```
feat: Phase 3 tests — SF-01..05 factory tests for Go, JS, C#, Dart, C/C++
5 files changed, 373 insertions(+)
```
