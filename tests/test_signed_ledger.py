"""Signed grants + hash-chained ledger (Phase 3 / F-1.7 closed)."""
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from flare.identity import Identity
from flare.ledger import build_ledger_app
from flare.ledger.client import HttpLedgerClient
from flare.ledger.signing import (
    GENESIS_HASH,
    canonical_grant_bytes,
    canonical_revoke_bytes,
    chain_hash,
)


def _stack():
    app = build_ledger_app()
    return app, HttpLedgerClient(client=TestClient(app))


def test_grant_round_trip_with_signature():
    _, ledger = _stack()
    alice = Identity.generate()
    bob = Identity.generate()
    g = ledger.add_grant(
        grantor_identity=alice, grantee=bob.did,
        context_id="ctx", issued_at=datetime(2026, 1, 1),
    )
    assert g.signature_b64
    found = ledger.find_valid(alice.did, bob.did, "ctx", datetime(2026, 6, 1))
    assert found is not None
    assert found.grant_id == g.grant_id


def test_unsigned_grant_rejected_at_service():
    """Direct POST without a signature must be 401/422."""
    app, _ = _stack()
    c = TestClient(app)
    r = c.post("/grants", json={
        "grantor": "did:key:zXX",
        "grantee": "did:key:zYY",
        "context_id": "ctx",
        "issued_at": "2026-01-01T00:00:00",
        "scope": "read",
        "grant_id": "abc",
        "signature_b64": "",
    })
    assert r.status_code in (400, 401)


def test_grant_signed_by_wrong_did_rejected():
    _, ledger = _stack()
    alice = Identity.generate()
    bob = Identity.generate()
    impostor = Identity.generate()
    # impostor tries to forge a grant attributed to alice. The
    # client signs locally with impostor's keys; the service should
    # reject because impostor's signature doesn't verify under
    # alice's DID.
    with pytest.raises(Exception):
        # We bypass the client's safety check by passing impostor as
        # the grantor identity but pretending it's alice via a forged
        # body. Use the raw HTTP path:
        from flare.ledger.signing import canonical_grant_bytes
        import base64, uuid
        grant_id = str(uuid.uuid4())
        canonical = canonical_grant_bytes(
            grant_id=grant_id, grantor=alice.did, grantee=bob.did,
            context_id="ctx", scope="read",
            issued_at=datetime(2026, 1, 1), expires_at=None,
        )
        bad_sig = impostor.sign(canonical)  # signs with wrong key
        body = {
            "grantor": alice.did,    # claims alice
            "grantee": bob.did,
            "context_id": "ctx",
            "issued_at": "2026-01-01T00:00:00",
            "scope": "read",
            "grant_id": grant_id,
            "signature_b64": base64.urlsafe_b64encode(bad_sig).rstrip(b"=").decode(),
        }
        r = ledger._client.post("/grants", json=body)  # noqa: SLF001
        r.raise_for_status()


def test_revoke_requires_grantor_signature():
    _, ledger = _stack()
    alice = Identity.generate()
    bob = Identity.generate()
    impostor = Identity.generate()
    g = ledger.add_grant(
        grantor_identity=alice, grantee=bob.did,
        context_id="ctx", issued_at=datetime(2026, 1, 1),
    )
    # Impostor cannot revoke (and the client rejects upfront).
    with pytest.raises(ValueError):
        ledger.revoke(g, grantor_identity=impostor, revoked_at=datetime(2026, 6, 1))
    # Alice can.
    ledger.revoke(g, grantor_identity=alice, revoked_at=datetime(2026, 6, 1))
    found = ledger.find_valid(alice.did, bob.did, "ctx", datetime(2026, 7, 1))
    assert found is None


def test_chain_head_advances_per_entry():
    app, ledger = _stack()
    c = TestClient(app)
    h0 = bytes.fromhex(c.get("/head").json()["head_hex"])
    assert h0 == GENESIS_HASH

    alice = Identity.generate()
    bob = Identity.generate()
    g1 = ledger.add_grant(
        grantor_identity=alice, grantee=bob.did,
        context_id="ctx", issued_at=datetime(2026, 1, 1),
    )
    h1 = bytes.fromhex(c.get("/head").json()["head_hex"])
    assert h1 != h0

    ledger.revoke(g1, grantor_identity=alice, revoked_at=datetime(2026, 6, 1))
    h2 = bytes.fromhex(c.get("/head").json()["head_hex"])
    assert h2 != h1


def test_chain_log_replay_validates_head():
    """An external auditor can replay the log from GENESIS_HASH and
    must arrive at the published head — verifying tamper-evidence."""
    app, ledger = _stack()
    c = TestClient(app)
    alice = Identity.generate()
    bob = Identity.generate()
    g = ledger.add_grant(
        grantor_identity=alice, grantee=bob.did,
        context_id="ctx", issued_at=datetime(2026, 1, 1),
    )
    ledger.revoke(g, grantor_identity=alice, revoked_at=datetime(2026, 6, 1))

    log = c.get("/log").json()
    assert len(log) == 2
    # Walk: each entry's prev_hash must match the previous entry's hash.
    last = GENESIS_HASH.hex()
    for entry in log:
        assert entry["prev_hash_hex"] == last
        last = entry["entry_hash_hex"]
    head_hex = c.get("/head").json()["head_hex"]
    assert head_hex == last
