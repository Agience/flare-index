from cryptography.exceptions import InvalidTag
import pytest

from flare.crypto import (
    decrypt_cell,
    derive_cell_key,
    encrypt_cell,
    fresh_master_key,
)


def test_hkdf_deterministic():
    mk = b"\x01" * 32
    k1 = derive_cell_key(mk, "ctx", 7)
    k2 = derive_cell_key(mk, "ctx", 7)
    assert k1 == k2
    assert len(k1) == 32


def test_hkdf_separates_contexts_and_clusters():
    mk = b"\x01" * 32
    a = derive_cell_key(mk, "ctx_a", 0)
    b = derive_cell_key(mk, "ctx_b", 0)
    c = derive_cell_key(mk, "ctx_a", 1)
    assert len({a, b, c}) == 3


def test_context_id_no_nul_byte():
    mk = b"\x01" * 32
    with pytest.raises(ValueError):
        derive_cell_key(mk, "bad\x00ctx", 0)


def test_master_key_min_entropy():
    with pytest.raises(ValueError):
        derive_cell_key(b"short", "ctx", 0)


def test_aead_round_trip_with_aad():
    mk = fresh_master_key()
    key = derive_cell_key(mk, "ctx", 3)
    aad = b"ctx:3"
    cell = encrypt_cell(key, b"hello world", associated=aad)
    assert decrypt_cell(key, cell, associated=aad) == b"hello world"


def test_aead_rejects_swapped_aad():
    mk = fresh_master_key()
    key = derive_cell_key(mk, "ctx", 3)
    cell = encrypt_cell(key, b"payload", associated=b"ctx:3")
    with pytest.raises(InvalidTag):
        decrypt_cell(key, cell, associated=b"ctx:4")


def test_aead_rejects_wrong_key():
    mk = fresh_master_key()
    key1 = derive_cell_key(mk, "ctx", 0)
    key2 = derive_cell_key(mk, "ctx", 1)
    cell = encrypt_cell(key1, b"payload")
    with pytest.raises(InvalidTag):
        decrypt_cell(key2, cell)
