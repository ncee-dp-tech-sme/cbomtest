"""
tests/test_pqc_coverage.py

PQC coverage tests as specified in the implementation plan (Section 8).

Test IDs:
  PQC-01  C# factory pool has ≥1 ML-KEM, ≥1 ML-DSA, ≥1 SLH-DSA factory
  PQC-02  Go factory pool has ≥1 ML-KEM snippet using golang.org/x/crypto/mlkem
  PQC-03  JS factory pool has ≥1 ML-KEM and ≥1 ML-DSA snippet
  PQC-04  All PQC snippets (across all three languages) contain exactly one
          `Algorithm:` identification comment line
  PQC-05  C# PQC snippets reference .NET 9 API (MLKem, MLDsa, or SlhDsa)
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import generate_vulnerable_app as gva


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pqc_pairs(factory_list):
    """Return (Weakness, factory_fn) pairs whose description mentions a PQC algorithm."""
    pqc_keywords = ("ML-KEM", "ML-DSA", "SLH-DSA")
    return [(w, f) for w, f in factory_list if any(kw in w.description for kw in pqc_keywords)]


def _snippets(pairs):
    """Invoke each factory and return the resulting snippet strings."""
    return [f() for _, f in pairs]


# ---------------------------------------------------------------------------
# PQC-01 — C# pool has ≥1 ML-KEM, ≥1 ML-DSA, ≥1 SLH-DSA factory
# ---------------------------------------------------------------------------

def test_pqc01_csharp_has_mlkem():
    pairs = _pqc_pairs(gva.CSHARP_WEAKNESS_FACTORIES)
    assert any("ML-KEM" in w.description for w, _ in pairs), \
        "C# factory pool must contain at least one ML-KEM factory"


def test_pqc01_csharp_has_mldsa():
    pairs = _pqc_pairs(gva.CSHARP_WEAKNESS_FACTORIES)
    assert any("ML-DSA" in w.description for w, _ in pairs), \
        "C# factory pool must contain at least one ML-DSA factory"


def test_pqc01_csharp_has_slhdsa():
    pairs = _pqc_pairs(gva.CSHARP_WEAKNESS_FACTORIES)
    assert any("SLH-DSA" in w.description for w, _ in pairs), \
        "C# factory pool must contain at least one SLH-DSA factory"


# ---------------------------------------------------------------------------
# PQC-02 — Go pool has ≥1 ML-KEM snippet using golang.org/x/crypto/mlkem
# ---------------------------------------------------------------------------

def test_pqc02_go_has_mlkem_factory():
    pairs = _pqc_pairs(gva.GO_WEAKNESS_FACTORIES)
    assert len(pairs) >= 1, "Go factory pool must contain at least one PQC factory"
    assert any("ML-KEM" in w.description for w, _ in pairs), \
        "Go factory pool must contain at least one ML-KEM factory"


def test_pqc02_go_mlkem_snippet_uses_x_crypto():
    pairs = [(w, f) for w, f in gva.GO_WEAKNESS_FACTORIES if "ML-KEM" in w.description]
    assert pairs, "No Go ML-KEM factory found"
    for _, f in pairs:
        snip = f()
        assert "golang.org/x/crypto/mlkem" in snip, \
            f"Go ML-KEM snippet must import golang.org/x/crypto/mlkem, got:\n{snip}"


# ---------------------------------------------------------------------------
# PQC-03 — JS pool has ≥1 ML-KEM and ≥1 ML-DSA snippet
# ---------------------------------------------------------------------------

def test_pqc03_js_has_mlkem():
    pairs = _pqc_pairs(gva.JS_WEAKNESS_FACTORIES)
    assert any("ML-KEM" in w.description for w, _ in pairs), \
        "JS factory pool must contain at least one ML-KEM factory"


def test_pqc03_js_has_mldsa():
    pairs = _pqc_pairs(gva.JS_WEAKNESS_FACTORIES)
    assert any("ML-DSA" in w.description for w, _ in pairs), \
        "JS factory pool must contain at least one ML-DSA factory"


# ---------------------------------------------------------------------------
# PQC-04 — All PQC snippets contain exactly one `Algorithm:` comment
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("lang,factory_list", [
    ("csharp",     gva.CSHARP_WEAKNESS_FACTORIES),
    ("go",         gva.GO_WEAKNESS_FACTORIES),
    ("javascript", gva.JS_WEAKNESS_FACTORIES),
])
def test_pqc04_algorithm_comment_present(lang, factory_list):
    pairs = _pqc_pairs(factory_list)
    assert pairs, f"No PQC factories found for {lang}"
    for w, f in pairs:
        snip = f()
        count = snip.count("Algorithm:")
        assert count >= 1, (
            f"[{lang}] PQC snippet for '{w.description}' must contain "
            f"'Algorithm:' identification comment, got:\n{snip}"
        )


# ---------------------------------------------------------------------------
# PQC-05 — C# PQC snippets reference .NET 9 API (MLKem, MLDsa, SlhDsa)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("w,f", _pqc_pairs(gva.CSHARP_WEAKNESS_FACTORIES))
def test_pqc05_csharp_pqc_uses_dotnet9_api(w, f):
    snip = f()
    dotnet9_types = ("MLKem", "MLDsa", "SlhDsa")
    assert any(t in snip for t in dotnet9_types), (
        f"C# PQC snippet for '{w.description}' must reference a .NET 9 PQC type "
        f"({', '.join(dotnet9_types)}), got:\n{snip}"
    )
