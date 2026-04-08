"""Batch wire protocol unit tests.

Properties pinned:
- Round-trip: a signed batch request decodes to the same cell keys
  the oracle put in.
- Origin authentication: a response that does NOT carry a valid
  signature from the *expected* oracle DID is rejected.
- Tamper detection: flipping any byte of any per-cell ciphertext or
  any per-entry status field breaks the response signature.
- Replay: the same batch nonce cannot be used twice.
- Eavesdropper: a passive observer of the request + response cannot
  recover the cell keys without the requester's ephemeral X25519
  private key.
"""
from __future__ import annotations

import pytest

from flare.identity import Identity
from flare.wire import (
    BatchEntry,
    BatchIssueKeyResponse,
    NonceCache,
    WireError,
    build_batch_request,
    encrypt_and_sign_batch_response,
    verify_and_decrypt_batch_response,
    verify_batch_request,
)


def _make_keys(n: int) -> list[bytes]:
    return [(b"k" + bytes([i])) * 16 for i in range(n)]


def test_round_trip_grants_only():
    requester = Identity.generate()
    oracle = Identity.generate()
    cells = [("ctx_a", 0), ("ctx_a", 1), ("ctx_b", 0)]
    keys = _make_keys(3)
    m = build_batch_request(requester, cells)
    verify_batch_request(m.request, NonceCache())
    response = encrypt_and_sign_batch_response(
        m.request, keys, [None, None, None], oracle,
    )
    decrypted = verify_and_decrypt_batch_response(m, response, oracle.did)
    assert [d.key for d in decrypted] == keys
    # Phase 4: every entry carries a TTL.
    assert all(d.valid_until_ns > 0 for d in decrypted)


def test_round_trip_mixed_grant_and_deny():
    requester = Identity.generate()
    oracle = Identity.generate()
    cells = [("ctx_a", 0), ("ctx_b", 0), ("ctx_c", 0)]
    keys = _make_keys(3)
    keys[1] = None  # type: ignore[assignment]
    m = build_batch_request(requester, cells)
    response = encrypt_and_sign_batch_response(
        m.request, keys, [None, "denied_no_grant", None], oracle,  # type: ignore[arg-type]
    )
    decrypted = verify_and_decrypt_batch_response(m, response, oracle.did)
    assert decrypted[0] is not None and decrypted[0].key == keys[0]
    assert decrypted[1] is None
    assert decrypted[2] is not None and decrypted[2].key == keys[2]


def test_wrong_oracle_did_rejected():
    requester = Identity.generate()
    real_oracle = Identity.generate()
    rogue_oracle = Identity.generate()
    cells = [("ctx", 0)]
    m = build_batch_request(requester, cells)
    response = encrypt_and_sign_batch_response(
        m.request, _make_keys(1), [None], rogue_oracle,
    )
    # Caller expected real_oracle but got a response signed by the rogue.
    with pytest.raises(WireError, match="oracle DID mismatch|signature"):
        verify_and_decrypt_batch_response(m, response, real_oracle.did)


def test_response_signature_tamper_detected():
    requester = Identity.generate()
    oracle = Identity.generate()
    cells = [("ctx", 0), ("ctx", 1)]
    m = build_batch_request(requester, cells)
    keys = _make_keys(2)
    response = encrypt_and_sign_batch_response(m.request, keys, [None, None], oracle)
    # Flip one byte of the ciphertext on entry 1 — signature should fail.
    bad_ct = list(response.entries[1].ciphertext_b64 or "")
    bad_ct[5] = "A" if bad_ct[5] != "A" else "B"
    tampered = response.model_copy()
    tampered.entries[1] = response.entries[1].model_copy(
        update={"ciphertext_b64": "".join(bad_ct)}
    )
    with pytest.raises(WireError):
        verify_and_decrypt_batch_response(m, tampered, oracle.did)


def test_replay_rejected():
    requester = Identity.generate()
    cells = [("ctx", 0)]
    m = build_batch_request(requester, cells)
    cache = NonceCache()
    verify_batch_request(m.request, cache)
    with pytest.raises(WireError, match="replay"):
        verify_batch_request(m.request, cache)


def test_expired_ttl_returns_none():
    """A cell key whose valid_until_ns has passed must be dropped at decode."""
    import time
    requester = Identity.generate()
    oracle = Identity.generate()
    cells = [("ctx", 0)]
    m = build_batch_request(requester, cells)
    # Issue with a 1-nanosecond TTL — guaranteed to be expired by the
    # time we decode.
    response = encrypt_and_sign_batch_response(
        m.request, _make_keys(1), [None], oracle,
        cell_key_ttl_ns=1,
        issued_at_ns=time.time_ns() - 10**9,  # issued 1 second ago
    )
    decrypted = verify_and_decrypt_batch_response(m, response, oracle.did)
    assert decrypted == [None]


def test_eavesdropper_cannot_recover_keys():
    """An attacker who sees the request + response but not the
    requester's ephemeral X25519 private key cannot decrypt."""
    requester = Identity.generate()
    oracle = Identity.generate()
    cells = [("ctx", 0)]
    m = build_batch_request(requester, cells)
    response = encrypt_and_sign_batch_response(m.request, _make_keys(1), [None], oracle)

    shadow = build_batch_request(requester, cells)  # different eph_priv
    forged = type(m)(request=m.request, eph_priv=shadow.eph_priv)
    with pytest.raises(Exception):
        verify_and_decrypt_batch_response(forged, response, oracle.did)
