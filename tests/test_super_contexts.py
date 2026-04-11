"""Super-contexts: per-user KNN-generated groupings.

Different users with different light cones see different clusters.
Super-contexts are ephemeral projections, not stored.
"""
from __future__ import annotations

from datetime import datetime

from flare.lightcone import Edge
from flare.supercollections import generate_super_contexts

T0 = datetime(2026, 4, 7, 12, 0, 0)


def test_generates_non_empty_super_contexts(flare_stack):
    """Owner's light cone produces at least one super-context."""
    s = flare_stack
    supers = generate_super_contexts(s.engine, s.alice, k=2, now=T0)
    assert len(supers) > 0
    total_cells = sum(len(sc.member_cells) for sc in supers)
    assert total_cells > 0


def test_super_contexts_are_per_user(flare_stack):
    """Different users with different light cones see different clusters."""
    s = flare_stack
    alice_supers = generate_super_contexts(s.engine, s.alice, k=2, now=T0)
    bob_supers = generate_super_contexts(s.engine, s.bob, k=2, now=T0)

    alice_cells = {c for sc in alice_supers for c in sc.member_cells}
    bob_cells = {c for sc in bob_supers for c in sc.member_cells}

    # Alice only sees workspace_alice, Bob only sees workspace_bob.
    assert all(c.context_id == "workspace_alice" for c in alice_cells)
    assert all(c.context_id == "workspace_bob" for c in bob_cells)


def test_super_contexts_respect_light_cone(flare_stack):
    """After a grant, the grantee's super-contexts include both contexts."""
    s = flare_stack

    # Carol has no grants — no super-contexts.
    carol_before = generate_super_contexts(s.engine, s.carol, k=2, now=T0)
    assert carol_before == []

    # Grant Carol access to Alice's workspace.
    s.ledger.add_grant(
        grantor_identity=s.alice, grantee=s.carol.did,
        context_id="workspace_alice", issued_at=T0,
    )
    s.graph.add_edge(Edge(s.carol.did, "workspace_alice", "granted"))

    carol_after = generate_super_contexts(
        s.engine, s.carol, k=2,
        now=datetime(2026, 4, 7, 12, 0, 1),
    )
    assert len(carol_after) > 0
    carol_cells = {c for sc in carol_after for c in sc.member_cells}
    assert all(c.context_id == "workspace_alice" for c in carol_cells)


def test_super_context_k_clamped(flare_stack):
    """Requesting more clusters than centroids does not crash."""
    s = flare_stack
    supers = generate_super_contexts(s.engine, s.alice, k=999, now=T0)
    assert len(supers) > 0
    # k is clamped to the number of available centroids.
    assert len(supers) <= 999
