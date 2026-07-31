"""
Unit tests for authentication service — pqc-smoke-py v1.0.0.
"""

def test_hash_password_returns_string():
    # Verifies that the password hash function returns a string value
    from pqc_smoke_py.services.user import hash_password  # type: ignore
    result = hash_password("testpassword")
    assert isinstance(result, str)

def test_generate_token_not_empty():
    # Verifies that token generation yields a non-empty result
    from pqc_smoke_py.utils.tokens import generate_reset_token  # type: ignore
    assert generate_reset_token()
