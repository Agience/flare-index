"""Shamir K-of-M secret sharing primitive."""
import pytest

from flare.crypto import fresh_master_key
from flare.oracle.threshold import (
    PRIME,
    Share,
    reconstruct_secret,
    split_secret,
)


def test_split_and_reconstruct_round_trip():
    secret = fresh_master_key()
    shares = split_secret(secret, k=3, m=5)
    assert len(shares) == 5
    # Reconstruct from any 3 of 5
    for combo in [shares[:3], shares[1:4], [shares[0], shares[2], shares[4]]]:
        assert reconstruct_secret(combo) == secret


def test_reconstruction_fails_with_too_few_shares():
    secret = fresh_master_key()
    shares = split_secret(secret, k=3, m=5)
    # With only 2 of 3 shares the recovered value is essentially random
    # — almost certainly not equal to the secret.
    recovered = reconstruct_secret(shares[:2])
    assert recovered != secret


def test_k_equals_m_requires_all_shares():
    secret = fresh_master_key()
    shares = split_secret(secret, k=3, m=3)
    assert reconstruct_secret(shares) == secret
    assert reconstruct_secret(shares[:2]) != secret


def test_shares_are_independent_per_split():
    secret = fresh_master_key()
    a = split_secret(secret, k=2, m=3)
    b = split_secret(secret, k=2, m=3)
    # Different randomness => different share values, but the secret
    # reconstructs the same.
    assert any(a[i].y_bytes != b[i].y_bytes for i in range(3))
    assert reconstruct_secret(a[:2]) == secret
    assert reconstruct_secret(b[:2]) == secret


def test_invalid_inputs():
    with pytest.raises(ValueError):
        split_secret(b"x" * 32, k=0, m=3)
    with pytest.raises(ValueError):
        split_secret(b"x" * 32, k=4, m=3)
    with pytest.raises(ValueError):
        split_secret(b"x" * 33, k=2, m=3)  # >32 bytes
