"""Path-predicate deny in the light cone (Phase 2 / F-1.6 closed)."""
from flare.lightcone import (
    DenyPath,
    Edge,
    LightConeGraph,
    RequireAllOf,
    RequireSequence,
)


def _g():
    g = LightConeGraph()
    for c in ("ws_a", "ws_b"):
        g.add_context(c)
    return g


def test_require_all_of_blocks_only_paths_through_both():
    """Deny if path traverses BOTH legacy_group AND audit_group.

    Bob can reach ws_a directly OR via legacy_group OR via
    audit_group, but if his only path is via BOTH groups he is
    blocked. Edge-level deny cannot express this.
    """
    g = _g()
    g.add_edge(Edge("alice", "ws_a", "owns"))
    g.add_edge(Edge("bob", "legacy_group", "member"))
    g.add_edge(Edge("legacy_group", "audit_group", "feeds"))
    g.add_edge(Edge("audit_group", "ws_a", "owns"))
    g.add_deny_path(DenyPath(
        predicate=RequireAllOf(frozenset({"legacy_group", "audit_group"})),
        target="ws_a",
    ))
    # Alice still reaches ws_a (no path through the deny set).
    assert "ws_a" in g.authorized_contexts("alice")
    # Bob's only path is via both denied nodes, so he's blocked.
    assert "ws_a" not in g.authorized_contexts("bob")


def test_require_all_of_does_not_block_alternate_paths():
    """If a principal has ANOTHER path that doesn't traverse the
    denied set, they're still authorized."""
    g = _g()
    g.add_edge(Edge("bob", "legacy_group", "member"))
    g.add_edge(Edge("legacy_group", "audit_group", "feeds"))
    g.add_edge(Edge("audit_group", "ws_a", "owns"))
    # Bob also has a direct grant — bypasses the legacy/audit chain.
    g.add_edge(Edge("bob", "ws_a", "granted"))
    g.add_deny_path(DenyPath(
        predicate=RequireAllOf(frozenset({"legacy_group", "audit_group"})),
        target="ws_a",
    ))
    assert "ws_a" in g.authorized_contexts("bob")


def test_require_sequence_subsequence_match():
    g = _g()
    g.add_edge(Edge("alice", "g1", "member"))
    g.add_edge(Edge("g1", "g2", "feeds"))
    g.add_edge(Edge("g2", "ws_a", "owns"))
    g.add_deny_path(DenyPath(
        predicate=RequireSequence(("g1", "g2")),
        target="ws_a",
    ))
    assert "ws_a" not in g.authorized_contexts("alice")


def test_path_predicate_scoped_to_target():
    """A deny scoped to ws_a does not leak into ws_b."""
    g = _g()
    g.add_edge(Edge("alice", "g1", "member"))
    g.add_edge(Edge("g1", "ws_a", "owns"))
    g.add_edge(Edge("g1", "ws_b", "owns"))
    g.add_deny_path(DenyPath(
        predicate=RequireAllOf(frozenset({"g1"})),
        target="ws_a",
    ))
    assert "ws_a" not in g.authorized_contexts("alice")
    assert "ws_b" in g.authorized_contexts("alice")
