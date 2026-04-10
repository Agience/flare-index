"""Constant-width oracle batch padding (F-0.8)."""
from datetime import datetime

from flare.query import FlareQueryEngine


def test_padding_grows_batch_to_fixed_width(flare_stack):
    """With padding_width=4, the batch must be padded up from nprobe=2
    to 4 cells (the maximum the conftest registers per context)."""
    s = flare_stack
    s.engine.padding_width = 4

    hits, trace = s.engine.search(s.alice, s.av[0], k=3, nprobe=2, now=datetime(2026, 1, 1))
    # Without padding, nprobe=2 would route just 2 candidate cells.
    # With padding=4, the engine pads up to 4 from authorized cells
    # (Alice owns 4 cells in workspace_alice).
    assert len(trace.light_cone_filtered) == 4
    # Real hits still come back from the unpadded cells.
    assert hits and all(h.context_id == "workspace_alice" for h in hits)


def test_padding_caps_at_pool_size(flare_stack):
    """When padding_width exceeds the principal's total authorized
    cell count, the engine pads up to the pool size and stops."""
    s = flare_stack
    s.engine.padding_width = 100  # absurdly large

    hits, trace = s.engine.search(s.alice, s.av[0], k=3, nprobe=2, now=datetime(2026, 1, 1))
    # Alice's total authorized cells across all contexts she can reach.
    total_cells = sum(
        reg.nlist
        for reg in s.storage.list_contexts()
        if reg.context_id in s.graph.authorized_contexts(s.alice.did)
    )
    assert len(trace.light_cone_filtered) == total_cells


def test_padding_disabled_by_default(flare_stack):
    s = flare_stack
    assert s.engine.padding_width == 0
    hits, trace = s.engine.search(s.alice, s.av[0], k=3, nprobe=2, now=datetime(2026, 1, 1))
    # Without padding the filtered set matches the routed candidate count.
    assert len(trace.light_cone_filtered) <= 2


def test_padding_does_not_leak_extra_hits(flare_stack):
    """The padded cells must not contribute hits — only the originally
    routed cells should produce results."""
    s = flare_stack
    s.engine.padding_width = 8

    hits_padded, _ = s.engine.search(s.alice, s.av[0], k=10, nprobe=2, now=datetime(2026, 1, 1))
    s.engine.padding_width = 0
    hits_unpadded, _ = s.engine.search(s.alice, s.av[0], k=10, nprobe=2, now=datetime(2026, 1, 1))

    # The set of returned vector ids should be identical: padding adds
    # noise to the request stream but never to the results.
    padded_ids = {(h.context_id, h.vector_id) for h in hits_padded}
    unpadded_ids = {(h.context_id, h.vector_id) for h in hits_unpadded}
    assert padded_ids == unpadded_ids
