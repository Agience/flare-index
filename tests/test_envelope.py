"""Envelope encryption: two-layer CWK + CEK key hierarchy.

CWK (Context Wrapping Key) is HKDF-derived per context from the master
key — deterministic, oracle derives on the fly. CEK (Cell Encryption
Key) is random per cell, wrapped by CWK. The oracle unwraps the CEK
at key-issuance time.

This decouples the cell encryption key from the HKDF derivation path,
enabling cross-context sharing (re-wrap CEK under a different CWK)
and future per-grantee CWK wrapping.
"""
from __future__ import annotations

from datetime import datetime

from flare.crypto import (
    derive_cwk,
    fresh_master_key,
    generate_cek,
    unwrap_cek,
    wrap_cek,
)

T0 = datetime(2026, 4, 7, 12, 0, 0)


def test_cwk_derivation_is_deterministic():
    mk = fresh_master_key()
    cwk1 = derive_cwk(mk, "ctx_a")
    cwk2 = derive_cwk(mk, "ctx_a")
    assert cwk1 == cwk2


def test_cwk_differs_across_contexts():
    mk = fresh_master_key()
    assert derive_cwk(mk, "ctx_a") != derive_cwk(mk, "ctx_b")


def test_cwk_differs_across_master_keys():
    mk1 = fresh_master_key()
    mk2 = fresh_master_key()
    assert derive_cwk(mk1, "ctx_a") != derive_cwk(mk2, "ctx_a")


def test_cek_wrap_unwrap_round_trip():
    cwk = fresh_master_key()
    cek = generate_cek()
    aad = b"ctx:0"
    wrapped = wrap_cek(cwk, cek, aad=aad)
    recovered = unwrap_cek(cwk, wrapped, aad=aad)
    assert recovered == cek


def test_cek_wrap_rejects_wrong_cwk():
    cwk1 = fresh_master_key()
    cwk2 = fresh_master_key()
    cek = generate_cek()
    wrapped = wrap_cek(cwk1, cek, aad=b"ctx:0")
    import pytest
    with pytest.raises(Exception):
        unwrap_cek(cwk2, wrapped, aad=b"ctx:0")


def test_cek_wrap_rejects_wrong_aad():
    cwk = fresh_master_key()
    cek = generate_cek()
    wrapped = wrap_cek(cwk, cek, aad=b"ctx:0")
    import pytest
    with pytest.raises(Exception):
        unwrap_cek(cwk, wrapped, aad=b"ctx:1")


def test_cross_context_cek_wrapping():
    """The same CEK can be wrapped under two different CWKs."""
    mk = fresh_master_key()
    cek = generate_cek()
    cwk_a = derive_cwk(mk, "ctx_a")
    cwk_b = derive_cwk(mk, "ctx_b")
    wrapped_a = wrap_cek(cwk_a, cek, aad=b"ctx_a:0")
    wrapped_b = wrap_cek(cwk_b, cek, aad=b"ctx_b:0")
    assert unwrap_cek(cwk_a, wrapped_a, aad=b"ctx_a:0") == cek
    assert unwrap_cek(cwk_b, wrapped_b, aad=b"ctx_b:0") == cek


def test_end_to_end_envelope_query(flare_stack):
    """Full pipeline: bootstrap with envelope encryption -> query -> hits."""
    s = flare_stack
    hits, trace = s.engine.search(s.alice, s.av[0], k=5, nprobe=4, now=T0)
    assert hits and all(h.context_id == "workspace_alice" for h in hits)
    assert trace.decrypted_cells > 0


def test_grant_then_query_with_envelope(flare_stack):
    """Grant path also works with envelope encryption."""
    from flare.lightcone import Edge
    s = flare_stack
    grant = s.ledger.add_grant(
        grantor_identity=s.alice, grantee=s.carol.did,
        context_id="workspace_alice", issued_at=T0,
    )
    s.graph.add_edge(Edge(s.carol.did, "workspace_alice", "granted"))
    hits, trace = s.engine.search(
        s.carol, s.av[0], k=5, nprobe=4,
        now=datetime(2026, 4, 7, 12, 0, 1),
    )
    assert any(h.context_id == "workspace_alice" for h in hits)
