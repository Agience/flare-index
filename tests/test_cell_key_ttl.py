"""Cell-key TTL: query engine enforces the oracle-signed expiry."""
from __future__ import annotations

import time
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from flare.crypto import fresh_master_key
from flare.identity import Identity
from flare.ledger import build_ledger_app
from flare.ledger.client import HttpLedgerClient
from flare.oracle import build_oracle_app
from flare.wire import build_batch_request


def test_oracle_response_carries_signed_ttl():
    """The valid_until_ns field is inside the AAD-bound canonical
    bytes, so any tampering breaks the response signature."""
    from datetime import datetime as _dt
    ledger_app = build_ledger_app()
    ledger = HttpLedgerClient(client=TestClient(ledger_app))
    owner = Identity.generate()
    master = fresh_master_key()
    oracle_app = build_oracle_app(
        owner_did=owner.did, ledger_client=ledger, master_key=master,
    )
    c = TestClient(oracle_app)
    # Grant-first: the owner's access flows through a self-grant.
    ledger.add_grant(
        grantor_identity=owner, grantee=owner.did,
        context_id="ctx", issued_at=_dt(2000, 1, 1),
    )

    materials = build_batch_request(owner, [("ctx", 0)])
    r = c.post("/issue-batch", json=materials.request.model_dump())
    assert r.status_code == 200
    body = r.json()
    entry = body["entries"][0]
    assert entry["granted"] is True
    assert entry["valid_until_ns"] > time.time_ns()


def test_query_engine_drops_expired_keys(monkeypatch, flare_stack):
    """Force a tiny TTL by monkey-patching the oracle service constant.

    Verifies that even though the oracle issued cell keys, the query
    engine refuses to use them once their TTL has passed.
    """
    import flare.wire as wire
    # Monkey-patch the default TTL to 1 nanosecond by intercepting
    # encrypt_and_sign_batch_response.
    real = wire.encrypt_and_sign_batch_response

    def expired(*args, **kwargs):
        kwargs["cell_key_ttl_ns"] = 1
        kwargs["issued_at_ns"] = time.time_ns() - 10**9
        return real(*args, **kwargs)

    monkeypatch.setattr("flare.oracle.service.encrypt_and_sign_batch_response", expired)

    s = flare_stack
    hits, trace = s.engine.search(s.alice, s.av[0], k=3, nprobe=4, now=datetime(2026, 1, 1))
    # Every Alice cell got an oracle response, but every issued key
    # was expired by the time we tried to use it.
    assert all(h.context_id != "workspace_alice" for h in hits)
