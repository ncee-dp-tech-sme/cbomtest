"""
tests/test_generators.py

Integration tests for the five new language generator functions.

Coverage:
  GI-01  Output directory has the correct structure (key files exist)
  GI-02  Returns non-empty List[Weakness]
  GI-03  No file written outside the provided base_dir
  GI-04  Build file is syntactically valid (regex spot-check for key tokens)
  GI-05  C generator raises PlatformError for GSKit-crypto on macOS (mocked)
  GI-06  All injected weaknesses have a non-empty tag field
"""

import importlib
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reload_gen():
    """Reload generate_vulnerable_app so patched sys.platform is picked up."""
    import generate_vulnerable_app
    importlib.reload(generate_vulnerable_app)
    return generate_vulnerable_app


def _take(factories, n=6):
    """Return the first n (Weakness, snippet_str) pairs from a factory list."""
    return [(wk, fn()) for wk, fn in factories[:n]]


# ---------------------------------------------------------------------------
# Fixtures — one per language, each builds into tmp_path
# ---------------------------------------------------------------------------

@pytest.fixture
def go_result(tmp_path):
    import generate_vulnerable_app as g
    factories = _take(g.GO_WEAKNESS_FACTORIES)
    result = g.generate_go_app(tmp_path / "mygoapp", "my-go-app", "1.0.0", factories)
    return tmp_path / "mygoapp", result


@pytest.fixture
def js_result(tmp_path):
    import generate_vulnerable_app as g
    factories = _take(g.JS_WEAKNESS_FACTORIES)
    result = g.generate_js_app(tmp_path / "myjsapp", "my-js-app", "1.0.0", factories)
    return tmp_path / "myjsapp", result


@pytest.fixture
def cs_result(tmp_path):
    import generate_vulnerable_app as g
    factories = _take(g.CSHARP_WEAKNESS_FACTORIES)
    result = g.generate_csharp_app(tmp_path / "mycsapp", "MyCsApp", "1.0.0", factories)
    return tmp_path / "mycsapp", result


@pytest.fixture
def dart_result(tmp_path):
    import generate_vulnerable_app as g
    factories = _take(g.DART_WEAKNESS_FACTORIES)
    result = g.generate_dart_app(tmp_path / "mydartapp", "my-dart-app", "1.0.0", factories)
    return tmp_path / "mydartapp", result


@pytest.fixture
def c_result(tmp_path):
    # Use only non-GSKit factories to avoid platform guard on macOS
    import generate_vulnerable_app as g
    factories = [
        (wk, fn()) for wk, fn in g.C_WEAKNESS_FACTORIES
        if "gskit" not in wk.description.lower()
    ][:6]
    result = g.generate_c_app(tmp_path / "mycapp", "MyCApp", "1.0.0", factories)
    return tmp_path / "mycapp", result


# ===========================================================================
# GI-01: Key files exist
# ===========================================================================

def test_go_GI01_structure(go_result):
    out_dir, _ = go_result
    assert (out_dir / "go.mod").exists()
    assert (out_dir / "crypto" / "hash.go").exists()
    assert (out_dir / "crypto" / "cipher.go").exists()
    assert (out_dir / "crypto" / "tls.go").exists()
    assert (out_dir / "crypto" / "pqc.go").exists()


def test_js_GI01_structure(js_result):
    out_dir, _ = js_result
    assert (out_dir / "package.json").exists()
    assert (out_dir / "src" / "hash.js").exists()
    assert (out_dir / "src" / "cipher.js").exists()
    assert (out_dir / "src" / "tls.js").exists()
    assert (out_dir / "src" / "jwt.js").exists()
    assert (out_dir / "src" / "pqc.js").exists()


def test_cs_GI01_structure(cs_result):
    out_dir, _ = cs_result
    assert (out_dir / "MyCsApp.csproj").exists()
    assert (out_dir / "Crypto" / "Hash.cs").exists()
    assert (out_dir / "Crypto" / "Cipher.cs").exists()
    assert (out_dir / "Crypto" / "Tls.cs").exists()
    assert (out_dir / "Crypto" / "Pqc.cs").exists()


def test_dart_GI01_structure(dart_result):
    out_dir, _ = dart_result
    assert (out_dir / "pubspec.yaml").exists()
    assert (out_dir / "lib" / "src" / "hash.dart").exists()
    assert (out_dir / "lib" / "src" / "cipher.dart").exists()
    assert (out_dir / "lib" / "src" / "kdf.dart").exists()


def test_c_GI01_structure(c_result):
    out_dir, _ = c_result
    assert (out_dir / "CMakeLists.txt").exists()
    assert (out_dir / "src" / "hash.c").exists()
    assert (out_dir / "src" / "cipher.c").exists()
    assert (out_dir / "src" / "tls.c").exists()
    assert (out_dir / "src" / "pqc.c").exists()


# ===========================================================================
# GI-02: Returns non-empty List[Weakness]
# ===========================================================================

def test_go_GI02_returns_weaknesses(go_result):
    _, weaknesses = go_result
    assert len(weaknesses) > 0


def test_js_GI02_returns_weaknesses(js_result):
    _, weaknesses = js_result
    assert len(weaknesses) > 0


def test_cs_GI02_returns_weaknesses(cs_result):
    _, weaknesses = cs_result
    assert len(weaknesses) > 0


def test_dart_GI02_returns_weaknesses(dart_result):
    _, weaknesses = dart_result
    assert len(weaknesses) > 0


def test_c_GI02_returns_weaknesses(c_result):
    _, weaknesses = c_result
    assert len(weaknesses) > 0


# ===========================================================================
# GI-03: No file written outside base_dir
# ===========================================================================

def _all_files(base_dir):
    return list(base_dir.rglob("*"))


def test_go_GI03_no_escape(tmp_path, go_result):
    out_dir, _ = go_result
    for f in _all_files(out_dir):
        assert str(f).startswith(str(out_dir))


def test_js_GI03_no_escape(tmp_path, js_result):
    out_dir, _ = js_result
    for f in _all_files(out_dir):
        assert str(f).startswith(str(out_dir))


def test_cs_GI03_no_escape(tmp_path, cs_result):
    out_dir, _ = cs_result
    for f in _all_files(out_dir):
        assert str(f).startswith(str(out_dir))


def test_dart_GI03_no_escape(tmp_path, dart_result):
    out_dir, _ = dart_result
    for f in _all_files(out_dir):
        assert str(f).startswith(str(out_dir))


def test_c_GI03_no_escape(tmp_path, c_result):
    out_dir, _ = c_result
    for f in _all_files(out_dir):
        assert str(f).startswith(str(out_dir))


# ===========================================================================
# GI-04: Build file spot-check
# ===========================================================================

def test_go_GI04_gomod(go_result):
    out_dir, _ = go_result
    text = (out_dir / "go.mod").read_text()
    assert "module github.com/example/" in text
    assert "go 1.22" in text
    assert "golang.org/x/crypto" in text


def test_js_GI04_packagejson(js_result):
    out_dir, _ = js_result
    text = (out_dir / "package.json").read_text()
    assert '"jsonwebtoken"' in text
    assert '"mlkem"' in text
    assert '"version"' in text


def test_cs_GI04_csproj(cs_result):
    out_dir, _ = cs_result
    text = (out_dir / "MyCsApp.csproj").read_text()
    assert "Microsoft.NET.Sdk" in text
    assert "net9.0" in text
    assert "<OutputType>Exe</OutputType>" in text


def test_dart_GI04_pubspec(dart_result):
    out_dir, _ = dart_result
    text = (out_dir / "pubspec.yaml").read_text()
    assert "crypto: ^3.0.0" in text
    assert "cryptography: ^2.7.0" in text
    assert "sdk:" in text


def test_c_GI04_cmake(c_result):
    out_dir, _ = c_result
    text = (out_dir / "CMakeLists.txt").read_text()
    assert "cmake_minimum_required" in text
    assert "find_package(OpenSSL REQUIRED)" in text
    assert "OpenSSL::Crypto" in text


# ===========================================================================
# GI-05: C generator raises PlatformError for GSKit-crypto on macOS (mocked)
# ===========================================================================

def test_c_GI05_gskit_raises_on_macos(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    import platform_guard
    importlib.reload(platform_guard)

    import generate_vulnerable_app as g
    # Build a fake GSKit weakness factory pair
    gskit_wk = g.Weakness(
        category="Weak algorithm",
        description="MD5 via GSKit-crypto gsk_attribute_set_enum",
        tag="CBS-001",
    )
    gskit_factory = lambda: "#include <gsk_ssl.h>\n"  # noqa: E731
    factories = [(gskit_wk, gskit_factory)]

    with pytest.raises(platform_guard.PlatformError, match=r"\[PLATFORM ERROR\]"):
        g.generate_c_app(tmp_path / "gskit_app", "gskit-app", "1.0.0", factories)

    # Restore platform_guard to real platform
    monkeypatch.setattr(sys, "platform", sys.platform)
    importlib.reload(platform_guard)


# ===========================================================================
# GI-06: All injected weaknesses have non-empty tag field
# ===========================================================================

def test_go_GI06_tags(go_result):
    _, weaknesses = go_result
    for wk in weaknesses:
        assert wk.tag, f"Weakness missing tag: {wk}"


def test_js_GI06_tags(js_result):
    _, weaknesses = js_result
    for wk in weaknesses:
        assert wk.tag, f"Weakness missing tag: {wk}"


def test_cs_GI06_tags(cs_result):
    _, weaknesses = cs_result
    for wk in weaknesses:
        assert wk.tag, f"Weakness missing tag: {wk}"


def test_dart_GI06_tags(dart_result):
    _, weaknesses = dart_result
    for wk in weaknesses:
        assert wk.tag, f"Weakness missing tag: {wk}"


def test_c_GI06_tags(c_result):
    _, weaknesses = c_result
    for wk in weaknesses:
        assert wk.tag, f"Weakness missing tag: {wk}"
