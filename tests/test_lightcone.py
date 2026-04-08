"""Light-cone graph tests.

The graph models structural reachability through allow/deny edges.
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


# ----- edge-level deny -----


def test_edge_level_deny_blocks_only_targeted_principal():
    """A deny edge alice->ws_a does NOT block bob->ws_a."""
    g = _g()
    g.add_edge(Edge("alice", "ws_a", "granted"))
    g.add_edge(Edge("bob", "ws_a", "granted"))
    g.add_edge(Edge("alice", "ws_a", "deny", allow=False))

    assert "ws_a" not in g.authorized_contexts("alice")
    assert "ws_a" in g.authorized_contexts("bob")


def test_deny_on_intermediate_edge_blocks_path_through_it():
    """A deny on group1->ws_a blocks every principal whose only route
    is via group1, while leaving direct grants intact."""
    g = _g()
    g.add_edge(Edge("alice", "group1", "member"))
    g.add_edge(Edge("bob", "group1", "member"))
    g.add_edge(Edge("group1", "ws_a", "owns"))
    g.add_edge(Edge("carol", "ws_a", "granted"))
    g.add_edge(Edge("group1", "ws_a", "deny", allow=False))

    assert "ws_a" not in g.authorized_contexts("alice")
    assert "ws_a" not in g.authorized_contexts("bob")
    assert "ws_a" in g.authorized_contexts("carol")


def test_explain_returns_a_path():
    g = _g()
    g.add_edge(Edge("alice", "group1", "member"))
    g.add_edge(Edge("group1", "ws_a", "owns"))
    path = g.explain("alice", "ws_a")
    assert path == ["alice", "group1", "ws_a"]


def test_explain_returns_none_when_blocked():
    g = _g()
    g.add_edge(Edge("alice", "ws_a", "granted"))
    g.add_edge(Edge("alice", "ws_a", "deny", allow=False))
    assert g.explain("alice", "ws_a") is None
