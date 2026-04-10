"""Cross-process FLARE demo against the docker-compose stack.

Reads service URLs from environment variables and runs the same
Alice / Bob / Carol scenario as `flare/demo.py`, but every HTTP call
goes over a real socket to a real container. Each `make demo-compose`
invocation generates fresh identities and master keys.

Required env vars (set in docker-compose.yml on the `demo` service):
    LEDGER_URL          e.g. http://ledger:8000
    STORAGE_URL         e.g. http://storage:8000
    ORACLE_ALICE_URL    e.g. http://oracle-alice:8001
    ORACLE_BOB_URL      e.g. http://oracle-bob:8001

The Alice/Bob master keys must already be loaded into the running
oracle services. The compose file generates them once at stack startup
and exposes the matching DIDs to this demo process.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta

import numpy as np

from .bootstrap import bootstrap_context
from .identity import Identity, ed25519_pubkey_from_did
from .ledger.client import HttpLedgerClient
from .lightcone import Edge, LightConeGraph
from .oracle.client import HttpOracleClient, OracleClient
from .query import FlareQueryEngine
from .storage.client import HttpStorageClient


def _vecs(n, dim, seed):
    rng = np.random.default_rng(seed)
    v = rng.normal(size=(n, dim)).astype(np.float32)
    v /= np.linalg.norm(v, axis=1, keepdims=True) + 1e-9
    return v, np.arange(n, dtype=np.int64)


def _trace(label, t, hits):
    print(f"\n--- {label} ---")
    print(f"  candidates={len(t.candidate_cells)} authorized={sorted(t.authorized_contexts)}")
    print(f"  granted={len(t.oracle_granted)} denied={len(t.oracle_denied)} decrypted={t.decrypted_cells}")
    print(f"  hits={[(h.context_id, h.vector_id, round(h.score,3)) for h in hits]}")


def main() -> None:
    ledger_url = os.environ["LEDGER_URL"]
    storage_url = os.environ["STORAGE_URL"]
    alice_url = os.environ["ORACLE_ALICE_URL"]
    bob_url = os.environ["ORACLE_BOB_URL"]
    alice_master_hex = os.environ["ALICE_MASTER_KEY_HEX"]
    bob_master_hex = os.environ["BOB_MASTER_KEY_HEX"]
    alice_did = os.environ["ALICE_DID"]
    bob_did = os.environ["BOB_DID"]
    alice_owner_signing_hex = os.environ["ALICE_OWNER_SIGNING_KEY_HEX"]
    bob_owner_signing_hex = os.environ["BOB_OWNER_SIGNING_KEY_HEX"]
    # Each owner has 3 oracle replicas in the compose stack. The demo
    # points at replica 1 of each owner via ORACLE_*_URL; the threshold
    # protocol then fans out to the other replicas.
    alice_oracle_did = os.environ["ALICE_ORACLE_1_DID"]
    bob_oracle_did = os.environ["BOB_ORACLE_1_DID"]

    # Sanity: the DIDs published by the oracle services must match.
    ledger = HttpLedgerClient(ledger_url)
    storage = HttpStorageClient(storage_url)

    alice_oracle = HttpOracleClient(alice_url)
    bob_oracle = HttpOracleClient(bob_url)
    a_info = alice_oracle.info()
    b_info = bob_oracle.info()
    print("alice oracle /info:", a_info)
    print("bob   oracle /info:", b_info)
    if a_info["owner_did"] != alice_did or a_info["oracle_did"] != alice_oracle_did:
        print("ERROR: alice oracle identity mismatch", file=sys.stderr); sys.exit(2)
    if b_info["owner_did"] != bob_did or b_info["oracle_did"] != bob_oracle_did:
        print("ERROR: bob oracle identity mismatch", file=sys.stderr); sys.exit(2)

    # In this prototype the demo container plays the role of all data
    # owners (the oracles already hold matching master keys via env
    # vars; the demo holds the matching owner Ed25519 signing keys to
    # sign storage writes).
    alice_master = bytes.fromhex(alice_master_hex)
    bob_master = bytes.fromhex(bob_master_hex)
    alice_owner = Identity.from_seed_hex(alice_owner_signing_hex)
    bob_owner = Identity.from_seed_hex(bob_owner_signing_hex)
    if alice_owner.did != alice_did or bob_owner.did != bob_did:
        print("ERROR: owner identity / DID mismatch", file=sys.stderr); sys.exit(2)

    # The querier identity is generated fresh per run.
    bob_querier = Identity.generate()  # acts as Bob the querier
    carol = Identity.generate()
    print("bob querier:", bob_querier.did[:32], "...")
    print("carol     :", carol.did[:32], "...")

    # NOTE: in a real deployment, Bob the data owner and Bob the
    # querier would have the same DID. Here we want the demo to test
    # the *grant* path (alice -> bob_querier), so we use a fresh
    # identity for the querier and have Alice grant *that* DID.

    dim = 32
    av, aids = _vecs(200, dim, 1)
    bv, bids = _vecs(200, dim, 2)
    alice_result = bootstrap_context(
        storage=storage, context_id="workspace_alice",
        owner_identity=alice_owner, oracle_endpoint=alice_url,
        oracle_did=alice_oracle_did,
        vectors=av, ids=aids, master_key=alice_master, nlist=8,
    )
    bob_result = bootstrap_context(
        storage=storage, context_id="workspace_bob",
        owner_identity=bob_owner, oracle_endpoint=bob_url,
        oracle_did=bob_oracle_did,
        vectors=bv, ids=bids, master_key=bob_master, nlist=8,
    )
    # Upload encrypted centroids to oracle services so they can
    # deliver them to authorized queriers via /request-centroids.
    from .oracle.client import HttpOracleClient as _HOC
    _HOC(alice_url).upload_encrypted_centroids(
        alice_owner, "workspace_alice", alice_result.encrypted_centroids,
    )
    _HOC(bob_url).upload_encrypted_centroids(
        bob_owner, "workspace_bob", bob_result.encrypted_centroids,
    )
    print("contexts on storage:", [c.context_id for c in storage.list_contexts()])

    graph = LightConeGraph()
    graph.add_context("workspace_alice")
    graph.add_context("workspace_bob")
    # bob_querier owns nothing yet — he'll get a grant from Alice.

    def resolve(endpoint: str) -> OracleClient:
        return HttpOracleClient(endpoint)

    engine = FlareQueryEngine(storage=storage, lightcone=graph, oracle_resolver=resolve)

    q = av[0]
    now = datetime(2026, 4, 7, 12, 0, 0)

    # 1. Bob the querier sees nothing — no grants, no ownership.
    hits, t = engine.search(bob_querier, q, k=3, nprobe=4, now=now)
    _trace("bob_querier (cold)", t, hits)
    assert hits == []

    # 2. Alice grants bob_querier on workspace_alice.
    grant = ledger.add_grant(
        grantor_identity=alice_owner, grantee=bob_querier.did,
        context_id="workspace_alice", issued_at=now,
    )
    graph.add_edge(Edge(bob_querier.did, "workspace_alice", "granted"))
    print(f"\n[grant] {alice_did[:32]}... -> {bob_querier.did[:32]}... ({grant.grant_id[:8]})")

    hits, t = engine.search(bob_querier, q, k=3, nprobe=4, now=now + timedelta(seconds=1))
    _trace("bob_querier after grant", t, hits)
    assert any(h.context_id == "workspace_alice" for h in hits)

    # 3. Carol — never granted.
    hits, t = engine.search(carol, q, k=3, nprobe=4, now=now)
    _trace("carol", t, hits)
    assert hits == []

    # 4. Revoke. Light-cone stays; oracle alone enforces.
    rt = now + timedelta(seconds=2)
    ledger.revoke(grant, grantor_identity=alice_owner, revoked_at=rt)
    engine.invalidate_cell_keys()
    hits, t = engine.search(bob_querier, q, k=3, nprobe=4, now=rt + timedelta(seconds=1))
    _trace("bob_querier after revoke", t, hits)
    assert all(h.context_id != "workspace_alice" for h in hits)

    print("\nAll FLARE invariants held end-to-end (cross-process).")


if __name__ == "__main__":
    main()
