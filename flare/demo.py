"""In-process FLARE demo (Alice / Bob / Carol).

Spins up real FastAPI apps for the ledger, storage, and two oracles
(one per data owner) inside this process, wires them via FastAPI
TestClient, and runs the docs/flare-index.md §Data Flow scenario
end to end with synthetic vectors.

This is the in-process variant. `flare/demo_compose.py` runs the same
scenario against actual running services in the docker-compose stack.
`flare/showcase.py` runs the same flow with REAL semantic embeddings
on hand-curated text.

Run:
    make demo
"""
from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np
from fastapi.testclient import TestClient

from .bootstrap import bootstrap_context
from .crypto import fresh_master_key
from .identity import Identity
from .ledger import build_ledger_app
from .ledger.client import HttpLedgerClient
from .lightcone import Edge, LightConeGraph
from .oracle import build_oracle_app
from .oracle.client import HttpOracleClient, OracleClient
from .query import FlareQueryEngine
from .storage import build_storage_app
from .storage.client import HttpStorageClient


def _vecs(n: int, dim: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    v = rng.normal(size=(n, dim)).astype(np.float32)
    v /= np.linalg.norm(v, axis=1, keepdims=True) + 1e-9
    return v, np.arange(n, dtype=np.int64)


def _print_trace(label: str, trace, hits) -> None:
    print(f"\n--- {label} ---")
    print(f"  candidates:        {len(trace.candidate_cells)}")
    print(f"  authorized ctx:    {sorted(trace.authorized_contexts)}")
    print(f"  after light cone:  {len(trace.light_cone_filtered)}")
    print(f"  oracle granted:    {len(trace.oracle_granted)}")
    print(f"  oracle denied:     {len(trace.oracle_denied)}")
    print(f"  decrypted cells:   {trace.decrypted_cells}")
    print(f"  hits:              {[(h.context_id, h.vector_id, round(h.score,3)) for h in hits]}")


def main() -> None:
    print("=" * 70)
    print("FLARE in-process demo — services run as FastAPI apps via TestClient")
    print("=" * 70)

    dim = 32

    # 1. Identities
    alice = Identity.generate()
    bob = Identity.generate()
    carol = Identity.generate()
    print(f"alice: {alice.did}")
    print(f"bob:   {bob.did}")
    print(f"carol: {carol.did}")

    # 2. Bring up the ledger as a FastAPI app, wrap with starlette TestClient.
    ledger_app = build_ledger_app()
    ledger_client = HttpLedgerClient(client=TestClient(ledger_app))

    # 3. Storage as a FastAPI app.
    storage_app = build_storage_app()
    storage_client = HttpStorageClient(client=TestClient(storage_app))

    # 4. Two oracle services, each with its own master key AND its
    #    own Ed25519 signing identity (used to authenticate batch
    #    issue responses end-to-end).
    alice_master = fresh_master_key()
    bob_master = fresh_master_key()
    alice_oracle_id = Identity.generate()
    bob_oracle_id = Identity.generate()
    alice_oracle_app = build_oracle_app(
        owner_did=alice.did,
        ledger_client=HttpLedgerClient(client=TestClient(ledger_app)),
        master_key=alice_master,
        oracle_identity=alice_oracle_id,
    )
    bob_oracle_app = build_oracle_app(
        owner_did=bob.did,
        ledger_client=HttpLedgerClient(client=TestClient(ledger_app)),
        master_key=bob_master,
        oracle_identity=bob_oracle_id,
    )
    alice_oracle_url = "http://oracle-alice.local"
    bob_oracle_url = "http://oracle-bob.local"
    alice_test_client = TestClient(alice_oracle_app)
    bob_test_client = TestClient(bob_oracle_app)

    def resolve_oracle(endpoint: str) -> OracleClient:
        if endpoint == alice_oracle_url:
            return HttpOracleClient(client=alice_test_client)
        if endpoint == bob_oracle_url:
            return HttpOracleClient(client=bob_test_client)
        raise KeyError(endpoint)

    # 5. Owners bootstrap their contexts.
    av, aids = _vecs(200, dim, seed=1)
    bv, bids = _vecs(200, dim, seed=2)
    bootstrap_context(
        storage=storage_client,
        context_id="workspace_alice",
        owner_identity=alice,
        oracle_endpoint=alice_oracle_url,
        oracle_did=alice_oracle_id.did,
        vectors=av, ids=aids,
        master_key=alice_master, nlist=8,
    )
    bootstrap_context(
        storage=storage_client,
        context_id="workspace_bob",
        owner_identity=bob,
        oracle_endpoint=bob_oracle_url,
        oracle_did=bob_oracle_id.did,
        vectors=bv, ids=bids,
        master_key=bob_master, nlist=8,
    )

    # 6. Light cone: each principal owns their workspace.
    graph = LightConeGraph()
    graph.add_context("workspace_alice")
    graph.add_context("workspace_bob")
    graph.add_edge(Edge(alice.did, "workspace_alice", "owns"))
    graph.add_edge(Edge(bob.did, "workspace_bob", "owns"))

    engine = FlareQueryEngine(
        storage=storage_client,
        lightcone=graph,
        oracle_resolver=resolve_oracle,
    )

    now = datetime(2026, 4, 7, 12, 0, 0)
    q = av[0]

    # 7. Bob queries before any grant.
    hits, trace = engine.search(bob, q, k=3, nprobe=4, now=now)
    _print_trace("Bob queries (no grant from Alice yet)", trace, hits)
    assert all(h.context_id == "workspace_bob" for h in hits)

    # 8. Alice grants Bob.
    grant = ledger_client.add_grant(
        grantor_identity=alice, grantee=bob.did,
        context_id="workspace_alice", issued_at=now,
    )
    graph.add_edge(Edge(bob.did, "workspace_alice", "granted"))
    print("\n[grant] Alice -> Bob on workspace_alice (grant_id=%s)" % grant.grant_id[:8])

    hits, trace = engine.search(bob, q, k=3, nprobe=4, now=now + timedelta(seconds=1))
    _print_trace("Bob queries again", trace, hits)
    assert any(h.context_id == "workspace_alice" for h in hits)

    # 9. Carol — no grants, no light cone reachability.
    hits, trace = engine.search(carol, q, k=3, nprobe=4, now=now)
    _print_trace("Carol queries (unauthorized)", trace, hits)
    assert hits == []

    # 10. Revoke. Note: light cone edge stays; oracle alone enforces it.
    revoked_at = now + timedelta(seconds=2)
    ledger_client.revoke(grant, grantor_identity=alice, revoked_at=revoked_at)
    engine.invalidate_cell_keys()  # drop cached pre-revoke keys
    print("\n[revoke] Alice -> Bob revoked (no re-encryption, no key rotation)")

    hits, trace = engine.search(bob, q, k=3, nprobe=4, now=revoked_at + timedelta(seconds=1))
    _print_trace("Bob queries after revocation", trace, hits)
    assert all(h.context_id != "workspace_alice" for h in hits)

    print("\nAll FLARE invariants held end-to-end (in-process).")


if __name__ == "__main__":
    main()
