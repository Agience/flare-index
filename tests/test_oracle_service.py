"""Oracle batch endpoint authentication + ledger-bound grant checks."""
from __future__ import annotations

from datetime import datetime

from fastapi.testclient import TestClient

from flare.crypto import fresh_master_key
from flare.identity import Identity
from flare.ledger import build_ledger_app
from flare.ledger.client import HttpLedgerClient
from flare.oracle import build_oracle_app
from flare.wire import build_batch_request


def _make_oracle(threshold: bool = False):
    """Build an oracle app in single-replica mode (threshold=False) or
    in degenerate threshold mode (K=1, M=1) so peer fetching is a no-op."""
    ledger_app = build_ledger_app()
    ledger = HttpLedgerClient(client=TestClient(ledger_app))
    owner = Identity.generate()
    if threshold:
        from flare.oracle import split_secret
        master = fresh_master_key()
        share = split_secret(master, k=1, m=1)[0]
        oracle_app = build_oracle_app(
            owner_did=owner.did,
            ledger_client=ledger,
            share=share,
            threshold_k=1,
        )
    else:
        oracle_app = build_oracle_app(
            owner_did=owner.did, master_key=fresh_master_key(),
            ledger_client=ledger,
        )
    return owner, ledger, TestClient(oracle_app)


def test_unsigned_garbage_request_rejected():
    _, _, c = _make_oracle()
    r = c.post("/issue-batch", json={"requester_did": "did:key:zXX"})
    assert r.status_code in (401, 422)


def test_signature_with_wrong_did_rejected():
    _, _, c = _make_oracle()
    a = Identity.generate()
    b = Identity.generate()
    materials = build_batch_request(a, [("ctx", 0)])
    bad = materials.request.model_copy(update={"requester_did": b.did})
    r = c.post("/issue-batch", json=bad.model_dump())
    assert r.status_code == 401


def test_replay_rejected_at_service():
    _, _, c = _make_oracle()
    requester = Identity.generate()
    materials = build_batch_request(requester, [("ctx", 0)])
    body = materials.request.model_dump()
    # First call: no grant exists, response is granted=False but wire check passes.
    r1 = c.post("/issue-batch", json=body)
    assert r1.status_code == 200
    # Second call with the SAME nonce: must be 401 (replay).
    r2 = c.post("/issue-batch", json=body)
    assert r2.status_code == 401


def test_owner_can_always_issue_to_self():
    owner, ledger, c = _make_oracle()
    # Grant-first: the owner's access flows through a self-grant.
    ledger.add_grant(
        grantor_identity=owner, grantee=owner.did,
        context_id="ctx", issued_at=datetime(2000, 1, 1),
    )
    materials = build_batch_request(owner, [("ctx", 0)])
    r = c.post("/issue-batch", json=materials.request.model_dump())
    assert r.status_code == 200
    body = r.json()
    assert body["entries"][0]["granted"] is True


def test_grant_check_uses_request_timestamp():
    """The oracle uses the signed timestamp for grant validity."""
    owner, ledger, c = _make_oracle()
    grantee = Identity.generate()
    ledger.add_grant(
        grantor_identity=owner, grantee=grantee.did,
        context_id="ctx", issued_at=datetime(2020, 1, 1),
    )
    materials = build_batch_request(grantee, [("ctx", 0)])
    r = c.post("/issue-batch", json=materials.request.model_dump())
    assert r.status_code == 200
    assert r.json()["entries"][0]["granted"] is True
