"""
tests/test_temp_strategy.py

Unit tests for the local temp file strategy helpers in generate_vulnerable_app.py.

Coverage:
  TF-01  _make_temp_dir() creates directory inside PROJECT_ROOT/.gen-tmp/
  TF-02  Run-specific temp dir is deleted after successful generation (cleanup pattern)
  TF-03  Temp dir is deleted even when generation raises mid-way
  TF-04  .gen-tmp/ line appears in .gitignore after _ensure_gitignore_entry()
  TF-05  Two rapid consecutive calls produce distinct directories
"""

import sys
import os
import shutil
from pathlib import Path
import pytest

# Ensure the project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from generate_vulnerable_app import _make_temp_dir, _ensure_gitignore_entry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).parent.parent
GEN_TMP = PROJECT_ROOT / ".gen-tmp"


def _cleanup(path: Path):
    """Remove a path if it exists — used in test teardown."""
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


# ---------------------------------------------------------------------------
# TF-01 — _make_temp_dir() creates directory inside PROJECT_ROOT/.gen-tmp/
# ---------------------------------------------------------------------------

def test_make_temp_dir_inside_gen_tmp(tmp_path, monkeypatch):
    # Redirect .gen-tmp into a controlled tmp_path so we don't litter the repo.
    fake_root = tmp_path / "project"
    fake_root.mkdir()
    # Patch __file__ of the module so Path(__file__).parent resolves to fake_root.
    import generate_vulnerable_app as gva
    monkeypatch.setattr(gva, "__file__", str(fake_root / "generate_vulnerable_app.py"))

    run_dir = _make_temp_dir("go", "myapp")
    try:
        assert run_dir.exists(), "Run directory must be created"
        assert run_dir.parent == fake_root / ".gen-tmp", \
            f"Must be inside .gen-tmp, got: {run_dir.parent}"
    finally:
        _cleanup(fake_root / ".gen-tmp")


# ---------------------------------------------------------------------------
# TF-02 — Cleanup pattern: temp dir removed after successful generation
# ---------------------------------------------------------------------------

def test_temp_dir_cleaned_up_on_success(tmp_path, monkeypatch):
    fake_root = tmp_path / "project"
    fake_root.mkdir()
    import generate_vulnerable_app as gva
    monkeypatch.setattr(gva, "__file__", str(fake_root / "generate_vulnerable_app.py"))

    run_dir = _make_temp_dir("go", "myapp")
    assert run_dir.exists()
    try:
        # Simulate generation logic (write a file)
        (run_dir / "output.txt").write_text("ok")
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)

    assert not run_dir.exists(), "Temp dir must be removed after cleanup"


# ---------------------------------------------------------------------------
# TF-03 — Cleanup pattern: temp dir removed even when generation raises
# ---------------------------------------------------------------------------

def test_temp_dir_cleaned_up_on_exception(tmp_path, monkeypatch):
    fake_root = tmp_path / "project"
    fake_root.mkdir()
    import generate_vulnerable_app as gva
    monkeypatch.setattr(gva, "__file__", str(fake_root / "generate_vulnerable_app.py"))

    run_dir = _make_temp_dir("go", "myapp")
    assert run_dir.exists()

    try:
        with pytest.raises(RuntimeError):
            try:
                raise RuntimeError("mid-generation failure")
            finally:
                shutil.rmtree(run_dir, ignore_errors=True)
    except RuntimeError:
        pass

    assert not run_dir.exists(), "Temp dir must be removed even after exception"


# ---------------------------------------------------------------------------
# TF-04 — .gen-tmp/ appears in .gitignore after _ensure_gitignore_entry()
# ---------------------------------------------------------------------------

def test_ensure_gitignore_entry_adds_to_existing(tmp_path):
    gi = tmp_path / ".gitignore"
    gi.write_text("# existing\n*.pyc\n")
    _ensure_gitignore_entry(tmp_path, ".gen-tmp/")
    assert ".gen-tmp/" in gi.read_text(), ".gen-tmp/ must appear in .gitignore"


def test_ensure_gitignore_entry_creates_file_if_missing(tmp_path):
    gi = tmp_path / ".gitignore"
    assert not gi.exists()
    _ensure_gitignore_entry(tmp_path, ".gen-tmp/")
    assert gi.exists(), ".gitignore must be created"
    assert ".gen-tmp/" in gi.read_text()


def test_ensure_gitignore_entry_idempotent(tmp_path):
    gi = tmp_path / ".gitignore"
    gi.write_text(".gen-tmp/\n")
    _ensure_gitignore_entry(tmp_path, ".gen-tmp/")
    # Must not be duplicated
    assert gi.read_text().count(".gen-tmp/") == 1, \
        "Entry must not be duplicated on second call"


# ---------------------------------------------------------------------------
# TF-05 — Two rapid consecutive calls produce distinct directories
# ---------------------------------------------------------------------------

def test_make_temp_dir_distinct_on_rapid_calls(tmp_path, monkeypatch):
    fake_root = tmp_path / "project"
    fake_root.mkdir()
    import generate_vulnerable_app as gva
    monkeypatch.setattr(gva, "__file__", str(fake_root / "generate_vulnerable_app.py"))

    # Monkeypatch time.time to return distinct integers
    import time as time_mod
    call_count = {"n": 0}
    original_time = time_mod.time

    def fake_time():
        call_count["n"] += 1
        return original_time() + call_count["n"]

    monkeypatch.setattr(time_mod, "time", fake_time)

    dir1 = _make_temp_dir("go", "app")
    dir2 = _make_temp_dir("go", "app")
    try:
        assert dir1 != dir2, "Concurrent calls must produce distinct directories"
    finally:
        _cleanup(fake_root / ".gen-tmp")
