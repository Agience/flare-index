"""Wire protocol unit tests.

These pin down the security properties of the auth + ECIES layer in
isolation, so a failure here points at the wire code rather than at
the oracle service that wraps it.
"""
import time

import pytest

from flare.identity import Identity
from flare.wire import (
    CLOCK_SKEW_NS,
    NonceCache,
    WireError,
    build_request,
    decrypt_response,
    encrypt_response,
    verify_request,
)


def test_round_trip_signed_request_and_ecies_response():
    ident = Identity.generate()
    materials = build_request(ident, "ctx", 7)
    cache = NonceCache()
    verify_request(materials.request, cache)

    cell_key = b"k" * 32
    response = encrypt_response(materials.request, cell_key)
    recovered = decrypt_response(materials, response)
    assert recovered == cell_key


def test_replay_rejected():
    ident = Identity.generate()
    materials = build_request(ident, "ctx", 0)
    cache = NonceCache()
    verify_request(materials.request, cache)
    with pytest.raises(WireError, match="replay"):
        verify_request(materials.request, cache)


def test_timestamp_skew_rejected():
    ident = Identity.generate()
    now = time.time_ns()
    materials = build_request(ident, "ctx", 0, now_ns=now)
    cache = NonceCache()
    # Verifying "much later" should fail (outside skew window).
    too_late = now + 2 * CLOCK_SKEW_NS
    with pytest.raises(WireError, match="skew"):
        verify_request(materials.request, cache, now_ns=too_late)


def test_signature_tamper_rejected():
    ident = Identity.generate()
    materials = build_request(ident, "ctx", 0)
    bad = materials.request.model_copy(update={"context_id": "different"})
    with pytest.raises(WireError, match="signature"):
        verify_request(bad, NonceCache())


def test_response_aad_binds_to_request():
    """A captured response cannot be redirected to a different request."""
    ident = Identity.generate()
    m1 = build_request(ident, "ctx_a", 0)
    m2 = build_request(ident, "ctx_b", 0)
    response = encrypt_response(m1.request, b"k" * 32)
    # Try to "replay" m1's response materials against m2.
    # We forge by giving the wrong materials object.
    forged_materials = type(m1)(request=m2.request, eph_priv=m1.eph_priv)
    with pytest.raises(Exception):
        decrypt_response(forged_materials, response)


def test_eavesdropper_cannot_recover_key():
    """Whoever holds the request bytes but not the requester's eph_priv
    learns nothing about the cell key."""
    ident = Identity.generate()
    materials = build_request(ident, "ctx", 0)
    response = encrypt_response(materials.request, b"k" * 32)

    # Build a 'shadow' materials with a fresh eph_priv — what an
    # attacker would have if they only saw the public request.
    shadow = build_request(ident, "ctx", 0)
    forged = type(materials)(request=materials.request, eph_priv=shadow.eph_priv)
    with pytest.raises(Exception):
        decrypt_response(forged, response)
