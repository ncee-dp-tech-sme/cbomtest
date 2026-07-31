#!/usr/bin/env python3
"""
platform_guard.py

Purpose:
    Provides lightweight, stdlib-only platform detection and enforcement for
    the generate_vulnerable_app.py code generator. Prevents generation of
    code snippets that target libraries unavailable on the current OS.

Unsupported combinations:
    - macOS + C/C++ + GSKit-crypto:
        GSKit-crypto is bundled exclusively with IBM MQ / Db2 on Linux and
        Windows. It is not distributed as a standalone SDK on macOS.
        Install IBM MQ or Db2 on a Linux or Windows host to obtain the GSKit
        development headers, then re-run the generator there.

How to add a new restriction:
    1. Add an entry to _UNSUPPORTED:
           ("platform", "language", "library"): "Explanation + remediation."
       Keys are all lowercase. Platform is one of: macos, windows, linux.
    2. The error message is assembled automatically by assert_supported().
       It always starts with [PLATFORM ERROR] and names the library, OS,
       and a concrete remediation step — do NOT write custom error strings.
    3. Add a test in tests/test_platform_guard.py covering the new combination
       (blocked platform) and at least one allowed platform (mocked).

Error message format contract:
    [PLATFORM ERROR] Cannot generate '<library>' (<language>) code on <OS>.
    Reason: <entry from _UNSUPPORTED>
    Action: Run this generator on <alternative> or choose a different library.

Change history:
  2026-08-01  Initial version. Platform detection and GSKit-crypto guard.
"""

import sys

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

class PlatformError(RuntimeError):
    """Raised when a requested library is not available on the current OS."""


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

# Resolved once at import time; tests may reload the module after patching
# sys.platform to exercise different code paths.
def current_platform() -> str:
    """Return normalised platform string: 'macos' | 'windows' | 'linux'."""
    p = sys.platform
    if p == "darwin":
        return "macos"
    if p == "win32":
        return "windows"
    return "linux"


# Resolved at import time for use as a module-level constant.
PLATFORM: str = current_platform()


# ---------------------------------------------------------------------------
# Unsupported combinations
# ---------------------------------------------------------------------------

# Keys: (platform, language_lower, library_lower)
# Values: human-readable reason + remediation (no trailing period required).
_UNSUPPORTED: dict = {
    ("macos", "c", "gskit-crypto"):
        "GSKit-crypto is an IBM product-bundled library not distributed as a "
        "standalone SDK on macOS. Install IBM MQ or Db2 on Linux or Windows "
        "to obtain the GSKit development headers.",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_supported(language: str, library: str) -> bool:
    """Return True if the library can be targeted on the current platform."""
    key = (current_platform(), language.lower(), library.lower())
    return key not in _UNSUPPORTED


def assert_supported(language: str, library: str) -> None:
    """Raise PlatformError if the library cannot be targeted on this OS."""
    key = (current_platform(), language.lower(), library.lower())
    reason = _UNSUPPORTED.get(key)
    if reason:
        platform_label = current_platform().upper()
        alternatives = {"macos": "Linux or Windows", "windows": "Linux", "linux": "Windows"}.get(
            current_platform(), "another platform"
        )
        raise PlatformError(
            f"[PLATFORM ERROR] Cannot generate '{library}' ({language}) code on "
            f"{platform_label}.\n"
            f"Reason: {reason}\n"
            f"Action: Run this generator on {alternatives}, or choose a "
            f"different library."
        )
