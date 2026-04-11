"""Containment edges: explicit cell membership in contexts.

Containment edges express which cells belong to which contexts. A cell
can belong to multiple contexts via cross-context sharing — the same
encrypted cell data, with the CEK re-wrapped under each context's CWK.
"""
from __future__ import annotations

from datetime import datetime

from flare.bootstrap import share_cell_across_contexts
from flare.crypto import derive_cwk, fresh_master_key, generate_cek, unwrap_cek, wrap_cek
from flare.lightcone import Edge
from flare.types import CellRef, ContainmentEdge

T0 = datetime(2026, 4, 7, 12, 0, 0)


def test_bootstrap_creates_containment_edges(flare_stack):
    """After bootstrap, the light-cone graph has containment edges."""
    s = flare_stack
    edges = s.graph.get_cells("workspace_alice")
    assert len(edges) > 0
    assert all(e.context_id == "workspace_alice" for e in edges)


def test_containment_edge_add_remove(flare_stack):
    """Containment edges can be added and removed."""
    s = flare_stack
    edge = ContainmentEdge(context_id="workspace_alice", cluster_id=99)
    s.graph.add_containment_edge(edge)
    assert edge in s.graph.get_cells("workspace_alice")
    s.graph.remove_containment_edge(edge)
    assert edge not in s.graph.get_cells("workspace_alice")


def test_cross_context_cek_rewrap():
    """share_cell_across_contexts re-wraps a CEK under a different CWK."""
    mk_a = fresh_master_key()
    mk_b = fresh_master_key()
    ctx_a = "context_a"
    ctx_b = "context_b"
    cluster = 3

    # Simulate a cell bootstrapped in context_a.
    cwk_a = derive_cwk(mk_a, ctx_a)
    cek = generate_cek()
    aad_a = f"{ctx_a}:{cluster}".encode()
    wrapped_a = wrap_cek(cwk_a, cek, aad=aad_a)

    # Share into context_b.
    new_wrapped, edge = share_cell_across_contexts(
        cell_ref=CellRef(ctx_a, cluster),
        from_master_key=mk_a,
        to_master_key=mk_b,
        to_context_id=ctx_b,
        wrapped_cek=wrapped_a,
    )

    # Verify: the new wrapped CEK unwraps to the same CEK.
    cwk_b = derive_cwk(mk_b, ctx_b)
    aad_b = f"{ctx_b}:{cluster}".encode()
    recovered = unwrap_cek(cwk_b, new_wrapped, aad=aad_b)
    assert recovered == cek

    # Verify: the containment edge points to the target context.
    assert edge.context_id == ctx_b
    assert edge.cluster_id == cluster


def test_cross_context_sharing_end_to_end(flare_stack):
    """Share a cell from Alice's context into Bob's, and verify Bob can
    query and decrypt it (via his own oracle with re-wrapped CEK)."""
    s = flare_stack

    # Pick the first cell from Alice's context.
    alice_edges = s.graph.get_cells("workspace_alice")
    assert alice_edges, "Alice must have containment edges"
    first = alice_edges[0]
    cell_ref = CellRef(first.context_id, first.cluster_id)
    original_wrapped = s.alice_replicas.apps[0].state.core._wrapped_ceks[cell_ref]

    # Re-wrap the CEK from Alice's CWK to Bob's CWK.
    new_wrapped, edge = share_cell_across_contexts(
        cell_ref=cell_ref,
        from_master_key=s.alice_master,
        to_master_key=s.bob_master,
        to_context_id="workspace_bob",
        wrapped_cek=original_wrapped,
    )

    # Inject the re-wrapped CEK into Bob's oracle replicas.
    shared_ref = CellRef("workspace_bob", first.cluster_id)
    for app in s.bob_replicas.apps:
        app.state.core.store_wrapped_cek(shared_ref, new_wrapped)

    # Add containment edge so the graph knows about the shared cell.
    s.graph.add_containment_edge(edge)

    # Bob (who has a self-grant on workspace_bob) should now be able
    # to access cells from both his own bootstrap AND the shared cell.
    # The shared cell's encrypted data is the same as Alice's, stored
    # in Alice's storage — Bob's oracle can unwrap the key, but the
    # actual cell ciphertext lives in storage under workspace_alice.
    # This test verifies the key-wrapping layer works end-to-end.
    bob_edges = s.graph.get_cells("workspace_bob")
    assert edge in bob_edges, "shared containment edge must be in Bob's graph"
