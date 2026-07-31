"""
tests/test_platform_guard.py

Unit tests for platform_guard.py.

Coverage:
  PG-01  current_platform() returns a known value
  PG-02  assert_supported("c", "openssl") never raises (supported everywhere)
  PG-03  assert_supported("c", "gskit-crypto") raises PlatformError on darwin
  PG-04  assert_supported("c", "gskit-crypto") does NOT raise on Linux
  PG-05  PG-03 error message names library, OS, and actionable remediation
  PG-06  is_supported() returns False for the unsupported combination
  PG-07  is_supported() returns True for a supported combination
"""

import importlib
import sys
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reload_guard():
    """Re-import platform_guard so PLATFORM constant reflects patched sys.platform."""
    import platform_guard
    importlib.reload(platform_guard)
    return platform_guard


# ---------------------------------------------------------------------------
# PG-01 — current_platform() returns a known value
# ---------------------------------------------------------------------------

def test_current_platform_known_value():
    import platform_guard
    result = platform_guard.current_platform()
    assert result in {"macos", "windows", "linux"}, f"Unexpected platform string: {result!r}"


# ---------------------------------------------------------------------------
# PG-02 — assert_supported("c", "openssl") never raises on any platform
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mock_platform", ["darwin", "win32", "linux"])
def test_openssl_always_supported(mock_platform):
    with patch.object(sys, "platform", mock_platform):
        pg = _reload_guard()
        pg.assert_supported("c", "openssl")  # must not raise


# ---------------------------------------------------------------------------
# PG-03 — assert_supported("c", "gskit-crypto") raises PlatformError on darwin
# ---------------------------------------------------------------------------

def test_gskit_blocked_on_macos():
    with patch.object(sys, "platform", "darwin"):
        pg = _reload_guard()
        with pytest.raises(pg.PlatformError):
            pg.assert_supported("c", "gskit-crypto")


# ---------------------------------------------------------------------------
# PG-04 — assert_supported("c", "gskit-crypto") does NOT raise on Linux
# ---------------------------------------------------------------------------

def test_gskit_allowed_on_linux():
    with patch.object(sys, "platform", "linux"):
        pg = _reload_guard()
        pg.assert_supported("c", "gskit-crypto")  # must not raise


def test_gskit_allowed_on_windows():
    with patch.object(sys, "platform", "win32"):
        pg = _reload_guard()
        pg.assert_supported("c", "gskit-crypto")  # must not raise


# ---------------------------------------------------------------------------
# PG-05 — Error message contains library name, OS name, and actionable text
# ---------------------------------------------------------------------------

def test_gskit_error_message_contract():
    with patch.object(sys, "platform", "darwin"):
        pg = _reload_guard()
        with pytest.raises(pg.PlatformError) as exc_info:
            pg.assert_supported("c", "gskit-crypto")
    msg = str(exc_info.value)
    assert "[PLATFORM ERROR]" in msg, "Error must start with [PLATFORM ERROR]"
    assert "gskit-crypto" in msg.lower(), "Error must name the library"
    assert "macos" in msg.lower() or "darwin" in msg.lower() or "MACOS" in msg, \
        "Error must name the OS"
    # Actionable text: must mention an alternative OS or 'Action:'
    assert "Action:" in msg, "Error must contain an 'Action:' remediation line"
    assert "Linux" in msg or "Windows" in msg, \
        "Action must name an alternative platform"


# ---------------------------------------------------------------------------
# PG-06 — is_supported() returns False for the unsupported combination
# ---------------------------------------------------------------------------

def test_is_supported_returns_false_for_gskit_on_macos():
    with patch.object(sys, "platform", "darwin"):
        pg = _reload_guard()
        assert pg.is_supported("c", "gskit-crypto") is False


# ---------------------------------------------------------------------------
# PG-07 — is_supported() returns True for a supported combination
# ---------------------------------------------------------------------------

def test_is_supported_returns_true_for_openssl():
    import platform_guard
    assert platform_guard.is_supported("c", "openssl") is True


def test_is_supported_returns_true_for_gskit_on_linux():
    with patch.object(sys, "platform", "linux"):
        pg = _reload_guard()
        assert pg.is_supported("c", "gskit-crypto") is True


# ---------------------------------------------------------------------------
# Case-insensitivity check — language/library matching is case-insensitive
# ---------------------------------------------------------------------------

def test_assert_supported_case_insensitive_on_macos():
    with patch.object(sys, "platform", "darwin"):
        pg = _reload_guard()
        with pytest.raises(pg.PlatformError):
            pg.assert_supported("C", "GSKit-Crypto")  # mixed case must still block
