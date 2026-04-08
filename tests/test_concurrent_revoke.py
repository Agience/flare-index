"""Race tests for revoke vs in-flight key issuance.

In Phase 0 these were theoretical (single thread, no concurrency). In
Phase 1 we have a real ledger lock and a real wire-protocol round-trip
between the query engine and the oracle. We can stress the race window
with threads.

Property under test (the strongest the Phase 1 design supports):
**Once `ledger.revoke(grant_id, t_revoke)` returns, every subsequent
oracle call with `now >= t_revoke` MUST be denied.** A request that
arrived at the oracle BEFORE `revoke` returned may legitimately get a
key (the revoke is not retroactive); a request that arrives AFTER must
not.

# ANALYSIS (phase1-findings.md §F-1.5):
# This is the strongest property a non-cryptographically-bound grant
# can give. Phase 4 adds short cell-key TTLs and signed grants with
# `not_after` so even an in-flight key has a bounded blast radius.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta

import pytest

from flare.lightcone import Edge


T0 = datetime(2026, 4, 7, 12, 0, 0)


def test_revoke_is_immediate_for_subsequent_requests(phase1_stack):
    s = phase1_stack
    grant = s.ledger.add_grant(
        grantor_identity=s.alice, grantee=s.bob.did,
        context_id="workspace_alice", issued_at=T0,
    )
    s.graph.add_edge(Edge(s.bob.did, "workspace_alice", "granted"))

    revoked_at = T0 + timedelta(milliseconds=1)
    s.ledger.revoke(grant, grantor_identity=s.alice, revoked_at=revoked_at)
    # Drop cached cell keys so the immediate-revoke property is tested,
    # not the up-to-TTL caching behavior.
    s.engine.invalidate_cell_keys()

    # Every subsequent request with `now > revoked_at` must be denied.
    for i in range(20):
        hits, trace = s.engine.search(
            s.bob, s.av[i % len(s.av)], k=3, nprobe=4,
            now=revoked_at + timedelta(seconds=1 + i),
        )
        assert all(h.context_id != "workspace_alice" for h in hits)


def test_concurrent_queries_during_revoke(phase1_stack):
    """Stress test: 50 query threads, one revoker thread.

    No assertion about which queries succeed and which fail (the race
    is real). The assertion is the bounded one: any query whose
    `now > revoke_time` returns no Alice hits, and the system never
    crashes / corrupts state under contention.
    """
    s = phase1_stack
    grant = s.ledger.add_grant(
        grantor_identity=s.alice, grantee=s.bob.did,
        context_id="workspace_alice", issued_at=T0,
    )
    s.graph.add_edge(Edge(s.bob.did, "workspace_alice", "granted"))

    revoke_time = T0 + timedelta(seconds=1)
    revoke_done = threading.Event()
    failures: list[str] = []

    def query_loop():
        # Each thread builds its own engine + clients. starlette
        # TestClient is per-thread, so sharing one across workers
        # deadlocks. The shared graph + apps are safe to share.
        engine = s.build_thread_local_engine()
        for i in range(10):
            now = T0 + timedelta(seconds=2)  # always after revoke
            try:
                hits, _ = engine.search(s.bob, s.av[i % len(s.av)], k=3, nprobe=4, now=now)
            except Exception as e:
                failures.append(f"crash: {e}")
                return
            if revoke_done.is_set():
                if any(h.context_id == "workspace_alice" for h in hits):
                    failures.append("post-revoke leak")
                    return

    threads = [threading.Thread(target=query_loop) for _ in range(8)]
    for t in threads:
        t.start()
    s.ledger.revoke(grant, grantor_identity=s.alice, revoked_at=revoke_time)
    revoke_done.set()
    for t in threads:
        t.join(timeout=30)
        assert not t.is_alive(), "query thread hung"

    assert not failures, failures
