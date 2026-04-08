"""Phase 1 end-to-end invariants.

Same four properties pinned in Phase 0, but every step now goes through
the multi-process architecture: storage service, oracle services with
authenticated wire protocol, ledger service, no in-process oracle
shortcut. Tests use ASGI transport so they cover the same code that
docker-compose runs, without needing actual sockets.
"""
from datetime import datetime, timedelta

from flare.lightcone import Edge

T0 = datetime(2026, 4, 7, 12, 0, 0)


def test_owner_sees_own_data(phase1_stack):
    s = phase1_stack
    hits, _ = s.engine.search(s.alice, s.av[0], k=5, nprobe=4, now=T0)
    assert hits and all(h.context_id == "workspace_alice" for h in hits)


def test_unauthorized_principal_sees_nothing(phase1_stack):
    s = phase1_stack
    hits, trace = s.engine.search(s.carol, s.av[0], k=5, nprobe=4, now=T0)
    assert hits == []
    assert trace.oracle_granted == []


def test_grant_then_query_then_revoke(phase1_stack):
    s = phase1_stack

    # Without a grant, Bob never sees Alice (his own ws still works).
    pre, _ = s.engine.search(s.bob, s.av[0], k=5, nprobe=8, now=T0)
    assert all(h.context_id == "workspace_bob" for h in pre)

    grant = s.ledger.add_grant(
        grantor_identity=s.alice, grantee=s.bob.did,
        context_id="workspace_alice", issued_at=T0,
    )
    s.graph.add_edge(Edge(s.bob.did, "workspace_alice", "granted"))

    granted, gtrace = s.engine.search(
        s.bob, s.av[0], k=5, nprobe=8, now=T0 + timedelta(seconds=1)
    )
    assert any(h.context_id == "workspace_alice" for h in granted), \
        "grant should illuminate Alice"
    assert any(c.context_id == "workspace_alice" for c in gtrace.oracle_granted)

    # Revoke. Light-cone edge stays in place — only the ledger changes.
    revoked_at = T0 + timedelta(seconds=2)
    s.ledger.revoke(grant, grantor_identity=s.alice, revoked_at=revoked_at)
    # Drop the cell-key cache so the next query forces a fresh oracle
    # round-trip. Without this, the engine would reuse cached keys
    # issued before the revoke up to their TTL — which is exactly the
    # bound the cell-key TTL provides, not a bug. The test pins the
    # "instant revoke" behavior; `test_cell_key_ttl` pins the
    # "cached up to TTL" behavior.
    s.engine.invalidate_cell_keys()

    after, atrace = s.engine.search(
        s.bob, s.av[0], k=5, nprobe=8, now=revoked_at + timedelta(seconds=1)
    )
    assert all(h.context_id != "workspace_alice" for h in after), \
        "revoke must hide Alice's data"
    assert all(c.context_id != "workspace_alice" for c in atrace.oracle_granted)
    # And the oracle must have actively denied something.
    assert any(c.context_id == "workspace_alice" for c in atrace.oracle_denied)


def test_deny_edge_blocks_authorized_path(phase1_stack):
    s = phase1_stack
    s.graph.add_edge(Edge(s.bob.did, "workspace_alice", "granted"))
    s.graph.add_edge(Edge(s.bob.did, "workspace_alice", "deny", allow=False))
    hits, _ = s.engine.search(s.bob, s.av[0], k=5, nprobe=8, now=T0)
    assert all(h.context_id != "workspace_alice" for h in hits)
