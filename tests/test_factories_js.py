"""
tests/test_factories_js.py

Snippet factory tests (SF-01..05) for JavaScript weakness factories.

SF-01  Every factory returns a non-empty string.
SF-02  No snippet contains '/tmp', 'C:\\Temp', or 'tempfile'.
SF-03  PQC factories (description contains ML-KEM, ML-DSA, or SLH-DSA) emit 'Algorithm:'.
SF-04  Weakness tag is one of: CBS-001, CBS-002, CBS-003, CBS-004.
SF-05  Factory called twice returns valid (possibly different) strings — both non-empty.
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import generate_vulnerable_app as gva

VALID_TAGS = {"CBS-001", "CBS-002", "CBS-003", "CBS-004"}
PQC_KEYWORDS = ("ML-KEM", "ML-DSA", "SLH-DSA")
TEMP_PATTERNS = ("/tmp", "C:\\Temp", "tempfile")

_FACTORIES = [
    (i, wk, fn)
    for i, (wk, fn) in enumerate(gva.JS_WEAKNESS_FACTORIES)
]
_IDS = [f"js[{i}]-{wk.tag}-{wk.description[:40]}" for i, wk, fn in _FACTORIES]


# SF-01 — factory returns a non-empty string
@pytest.mark.parametrize("idx,wk,fn", _FACTORIES, ids=_IDS)
def test_sf01_non_empty(idx, wk, fn):
    result = fn()
    assert isinstance(result, str) and len(result.strip()) > 0, \
        f"Factory [{idx}] '{wk.description}' returned empty/non-string"


# SF-02 — no temp-path patterns in snippet
@pytest.mark.parametrize("idx,wk,fn", _FACTORIES, ids=_IDS)
def test_sf02_no_temp_patterns(idx, wk, fn):
    result = fn()
    for pattern in TEMP_PATTERNS:
        assert pattern not in result, \
            f"Factory [{idx}] '{wk.description}' contains forbidden pattern '{pattern}'"


# SF-03 — PQC factories include 'Algorithm:' identification comment
@pytest.mark.parametrize("idx,wk,fn", _FACTORIES, ids=_IDS)
def test_sf03_pqc_algorithm_comment(idx, wk, fn):
    is_pqc = any(kw in wk.description for kw in PQC_KEYWORDS)
    if not is_pqc:
        pytest.skip("Not a PQC factory")
    result = fn()
    assert "Algorithm:" in result, \
        f"PQC factory [{idx}] '{wk.description}' missing 'Algorithm:' comment"


# SF-04 — tag is a known CBS tag
@pytest.mark.parametrize("idx,wk,fn", _FACTORIES, ids=_IDS)
def test_sf04_valid_tag(idx, wk, fn):
    assert wk.tag in VALID_TAGS, \
        f"Factory [{idx}] '{wk.description}' has unknown tag '{wk.tag}'"


# SF-05 — two consecutive calls both return non-empty strings
@pytest.mark.parametrize("idx,wk,fn", _FACTORIES, ids=_IDS)
def test_sf05_double_call_non_empty(idx, wk, fn):
    r1 = fn()
    r2 = fn()
    assert isinstance(r1, str) and len(r1.strip()) > 0, \
        f"Factory [{idx}] first call returned empty"
    assert isinstance(r2, str) and len(r2.strip()) > 0, \
        f"Factory [{idx}] second call returned empty"
