"""Light-cone graph tests.

The graph models structural reachability through propagating edges
and path-predicate constraints.
"""
from flare.lightcone import Edge, LightConeGraph


def _g():
    g = LightConeGraph()
    for ctx in ("ws_a", "ws_b", "ws_c"):
        g.add_context(ctx)
    return g


def test_owner_reaches_own_context():
    g = _g()
    g.add_edge(Edge("alice", "ws_a", "owns"))
    assert g.authorized_contexts("alice") == {"ws_a"}


def test_hop_limit():
    g = _g()
    g.add_edge(Edge("alice", "group1", "member"))
    g.add_edge(Edge("group1", "ws_b", "owns"))
    assert "ws_b" in g.authorized_contexts("alice", max_hops=2)
    assert "ws_b" not in g.authorized_contexts("alice", max_hops=1)


def test_unreachable_returns_empty():
    g = _g()
    assert g.authorized_contexts("nobody") == set()


def test_remove_edge_drops_reachability():
    g = _g()
    e = Edge("alice", "ws_a", "owns")
    g.add_edge(e)
    assert g.authorized_contexts("alice") == {"ws_a"}
    g.remove_edge(e)
    assert g.authorized_contexts("alice") == set()


# ----- propagation masks -----


def test_null_propagate_mask_excludes_principal():
    """An edge with propagate=None carries no authorization; the principal
    cannot reach the destination via that edge. Other principals with
    propagating edges are unaffected."""
    g = _g()
    g.add_edge(Edge("alice", "ws_a", "granted", propagate=None))
    g.add_edge(Edge("bob", "ws_a", "granted"))
    assert "ws_a" not in g.authorized_contexts("alice")
    assert "ws_a" in g.authorized_contexts("bob")


def test_null_propagate_on_intermediate_blocks_all_traversal():
    """propagate=None on an intermediate edge blocks all traversal through
    it regardless of who tries, while direct edges on other principals work."""
    g = _g()
    g.add_edge(Edge("alice", "group1", "member"))
    g.add_edge(Edge("bob", "group1", "member"))
    g.add_edge(Edge("group1", "ws_a", "owns", propagate=None))
    g.add_edge(Edge("carol", "ws_a", "granted"))
    assert "ws_a" not in g.authorized_contexts("alice")
    assert "ws_a" not in g.authorized_contexts("bob")
    assert "ws_a" in g.authorized_contexts("carol")


def test_narrow_propagate_mask_respected():
    """An edge propagating only {R} does not authorize other permissions."""
    g = _g()
    g.add_edge(Edge("alice", "ws_a", "link", propagate=frozenset("R")))
    assert "ws_a" in g.authorized_contexts("alice", requested_permission="R")
    assert "ws_a" not in g.authorized_contexts("alice", requested_permission="I")


def test_explain_returns_a_path():
    g = _g()
    g.add_edge(Edge("alice", "group1", "member"))
    g.add_edge(Edge("group1", "ws_a", "owns"))
    path = g.explain("alice", "ws_a")
    assert path == ["alice", "group1", "ws_a"]


def test_explain_returns_none_when_blocked():
    g = _g()
    g.add_edge(Edge("alice", "ws_a", "granted", propagate=None))
    assert g.explain("alice", "ws_a") is None
