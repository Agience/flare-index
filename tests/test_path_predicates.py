"""Path-predicate constraints in the light cone."""
from flare.lightcone import (
    PathConstraint,
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
    """Block if path traverses BOTH legacy_group AND audit_group.

    Bob can reach ws_a directly OR via legacy_group OR via
    audit_group, but if his only path is via BOTH groups he is
    blocked. This cannot be expressed with propagation masks alone.
    """
    g = _g()
    g.add_edge(Edge("alice", "ws_a", "owns"))
    g.add_edge(Edge("bob", "legacy_group", "member"))
    g.add_edge(Edge("legacy_group", "audit_group", "feeds"))
    g.add_edge(Edge("audit_group", "ws_a", "owns"))
    g.add_path_constraint(PathConstraint(
        predicate=RequireAllOf(frozenset({"legacy_group", "audit_group"})),
        target="ws_a",
    ))
    # Alice still reaches ws_a (no path through the constrained set).
    assert "ws_a" in g.authorized_contexts("alice")
    # Bob's only path is via both constrained nodes, so he's blocked.
    assert "ws_a" not in g.authorized_contexts("bob")


def test_require_all_of_does_not_block_alternate_paths():
    """If a principal has ANOTHER path that doesn't traverse the
    constrained set, they're still authorized."""
    g = _g()
    g.add_edge(Edge("bob", "legacy_group", "member"))
    g.add_edge(Edge("legacy_group", "audit_group", "feeds"))
    g.add_edge(Edge("audit_group", "ws_a", "owns"))
    # Bob also has a direct grant — bypasses the legacy/audit chain.
    g.add_edge(Edge("bob", "ws_a", "granted"))
    g.add_path_constraint(PathConstraint(
        predicate=RequireAllOf(frozenset({"legacy_group", "audit_group"})),
        target="ws_a",
    ))
    assert "ws_a" in g.authorized_contexts("bob")


def test_require_sequence_subsequence_match():
    g = _g()
    g.add_edge(Edge("alice", "g1", "member"))
    g.add_edge(Edge("g1", "g2", "feeds"))
    g.add_edge(Edge("g2", "ws_a", "owns"))
    g.add_path_constraint(PathConstraint(
        predicate=RequireSequence(("g1", "g2")),
        target="ws_a",
    ))
    assert "ws_a" not in g.authorized_contexts("alice")


def test_path_predicate_scoped_to_target():
    """A constraint scoped to ws_a does not affect ws_b."""
    g = _g()
    g.add_edge(Edge("alice", "g1", "member"))
    g.add_edge(Edge("g1", "ws_a", "owns"))
    g.add_edge(Edge("g1", "ws_b", "owns"))
    g.add_path_constraint(PathConstraint(
        predicate=RequireAllOf(frozenset({"g1"})),
        target="ws_a",
    ))
    assert "ws_a" not in g.authorized_contexts("alice")
    assert "ws_b" in g.authorized_contexts("alice")
