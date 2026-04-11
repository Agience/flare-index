"""Threshold oracle integration: K-of-M oracles must cooperate to issue keys.

The fixture `flare_stack` already runs Alice and Bob in threshold mode
(K=2 of M=3), so the standard end-to-end queries already exercise the
peer share-fetch path. These tests pin the **threshold-specific**
properties:

- A coordinator with no peer cooperation cannot issue keys.
- A coordinator with at least K-1 cooperating peers can issue keys.
- A peer that does NOT find the requester in its (independent) ledger
  refuses to release its share.
"""
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from flare.identity import Identity
from flare.lightcone import Edge
from flare.oracle import (
    PeerEndpoint,
    PeerShareFetcher,
    build_oracle_app,
    split_secret,
)
from flare.oracle.client import HttpOracleClient
from flare.crypto import fresh_master_key
from flare.ledger import build_ledger_app
from flare.ledger.client import HttpLedgerClient


def test_owner_query_succeeds_with_full_quorum(flare_stack):
    s = flare_stack
    hits, trace = s.engine.search(s.alice, s.av[0], k=3, nprobe=4, now=datetime(2026, 1, 1))
    # Owner cells were granted -> peer share-fetch must have happened
    # because each replica only has 1 share and K=2.
    assert any(c.context_id == "workspace_alice" for c in trace.oracle_granted)
    assert hits and any(h.context_id == "workspace_alice" for h in hits)


def test_threshold_with_no_peers_denies():
    """A coordinator running K=2 with zero cooperating peers must deny."""
    from datetime import datetime as _dt
    ledger_app = build_ledger_app()
    ledger = HttpLedgerClient(client=TestClient(ledger_app))
    owner = Identity.generate()
    master = fresh_master_key()
    shares = split_secret(master, k=2, m=2)
    coord_id = Identity.generate()
    # No peer endpoints — fetcher will return zero shares.
    fetcher = PeerShareFetcher(coord_identity=coord_id, peers=[], needed=1)
    app = build_oracle_app(
        owner_did=owner.did,
        ledger_client=ledger,
        share=shares[0],
        threshold_k=2,
        peer_share_fetcher=fetcher,
        oracle_identity=coord_id,
    )
    c = TestClient(app)
    # Grant-first: the owner's access flows through a self-grant, so
    # the ledger check passes and the denial comes from the threshold
    # quorum failure, not from a missing grant.
    ledger.add_grant(
        grantor_identity=owner, grantee=owner.did,
        context_id="ctx", issued_at=_dt(2000, 1, 1),
    )

    from flare.wire import build_batch_request
    materials = build_batch_request(owner, [("ctx", 0)])
    r = c.post("/issue-batch", json=materials.request.model_dump())
    assert r.status_code == 200
    body = r.json()
    # All entries denied, with reason DENIED_THRESHOLD.
    assert body["entries"][0]["granted"] is False
    assert "threshold" in body["entries"][0]["denied_reason"]


def test_peer_refuses_share_release_for_unauthorized_requester(flare_stack):
    """Each peer independently checks the ledger before releasing.

    A coordinator that asks Alice's peer-2 for a share on behalf of
    Carol (who has no grant) must be refused, even though peer-2 trusts
    the coordinator's signature.
    """
    s = flare_stack
    # Coordinator = alice replica 1; peer = alice replica 2.
    coord_id = s.alice_replicas.oracle_identities[0]
    peer_client = TestClient(s.alice_replicas.apps[1])

    from flare.oracle.peer_wire import build_peer_request
    from flare.wire import build_batch_request

    # Carol has NO grant from Alice for workspace_alice.
    inner = build_batch_request(s.carol, [("workspace_alice", 0)])
    materials = build_peer_request(coord_id, inner.request)
    r = peer_client.post("/peer/share", json=materials.request.model_dump())
    assert r.status_code == 403


def test_peer_refuses_unknown_coordinator(flare_stack):
    """A coordinator whose DID is not in the peer's allowlist is refused."""
    s = flare_stack
    rogue_coord = Identity.generate()  # not in any allowlist
    peer_client = TestClient(s.alice_replicas.apps[1])

    from flare.oracle.peer_wire import build_peer_request
    from flare.wire import build_batch_request
    inner = build_batch_request(s.alice, [("workspace_alice", 0)])
    materials = build_peer_request(rogue_coord, inner.request)
    r = peer_client.post("/peer/share", json=materials.request.model_dump())
    assert r.status_code == 401
