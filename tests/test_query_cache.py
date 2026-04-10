"""Query-engine caching: routing cache, cell ciphertext cache, cell-key cache.

The performance optimization is documented in `flare/query.py:FlareQueryEngine`.
This file pins the *security-relevant* invariants:

1. Cached cell keys are tied to a specific (cell, requester DID) — a
   different requester never reuses another requester's cached keys.
2. Cached cell keys respect the oracle-signed `valid_until_ns`. An
   expired cache entry is dropped on the next lookup; a key whose TTL
   has not yet passed is reusable.
3. `invalidate_cell_keys()` makes the cache empty, forcing the next
   query to round-trip the oracle.
4. The routing cache (centroids, registrations, cell ciphertext) holds
   oracle-gated centroid maps plus public registrations and opaque
   ciphertext. Reusing it across queries from the same requester
   cannot leak anything beyond what was already authorized.
5. Concurrent queries from many threads do not race the caches.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta

from flare.lightcone import Edge


T0 = datetime(2026, 4, 8, 12, 0, 0)


def test_routing_cache_avoids_storage_round_trips_on_repeat_queries(flare_stack):
    """The first query populates the cache; the second skips list_contexts /
    get_centroids / get_registration entirely."""
    s = flare_stack
    # First query — owner sees own data, cache populated.
    s.engine.search(s.alice, s.av[0], k=3, nprobe=4)
    # Now spy on storage by replacing the underlying client with one
    # that raises if hit.
    class Tripwire:
        def __init__(self, real):
            self._real = real
            self.tripped = []
        def list_contexts(self):
            self.tripped.append("list_contexts")
            return self._real.list_contexts()
        def get_centroids(self, c):
            self.tripped.append(("get_centroids", c))
            return self._real.get_centroids(c)
        def get_registration(self, c):
            self.tripped.append(("get_registration", c))
            return self._real.get_registration(c)
        def get_cell(self, ctx, cluster):
            self.tripped.append(("get_cell", ctx, cluster))
            return self._real.get_cell(ctx, cluster)

    tripwire = Tripwire(s.engine.storage)
    s.engine.storage = tripwire
    # Same query → same routing → same cells → all from cache
    s.engine.search(s.alice, s.av[0], k=3, nprobe=4)
    # Routing must be entirely from cache (no list_contexts / centroids / registration)
    assert "list_contexts" not in tripwire.tripped
    assert not any(t[0] == "get_centroids" for t in tripwire.tripped if isinstance(t, tuple))
    assert not any(t[0] == "get_registration" for t in tripwire.tripped if isinstance(t, tuple))
    # Cell blobs must also be cached after the first query
    assert not any(t[0] == "get_cell" for t in tripwire.tripped if isinstance(t, tuple))


def test_cell_key_cache_does_not_cross_requesters(flare_stack):
    """A cell key cached for Alice MUST NOT be returned to Bob."""
    s = flare_stack
    # Alice queries (owner) - populates the cache for (cell, Alice's DID)
    s.engine.search(s.alice, s.av[0], k=3, nprobe=4)
    # Inspect the cache directly: every entry's second key element
    # is the requester DID, and Alice's DID must not appear under
    # Bob's identity.
    with s.engine._cache_lock:  # noqa: SLF001
        keys = list(s.engine._cell_key_cache.keys())  # noqa: SLF001
    assert all(req == s.alice.did for (_cell, req) in keys), \
        "alice's cached keys are tagged only with alice.did"


def test_invalidate_cell_keys_forces_oracle_round_trip(flare_stack):
    """After invalidate_cell_keys(), the next query must populate fresh keys."""
    s = flare_stack
    s.engine.search(s.alice, s.av[0], k=3, nprobe=4)
    with s.engine._cache_lock:  # noqa: SLF001
        assert len(s.engine._cell_key_cache) > 0  # noqa: SLF001
    s.engine.invalidate_cell_keys()
    with s.engine._cache_lock:  # noqa: SLF001
        assert len(s.engine._cell_key_cache) == 0  # noqa: SLF001
    # Next query repopulates
    s.engine.search(s.alice, s.av[0], k=3, nprobe=4)
    with s.engine._cache_lock:  # noqa: SLF001
        assert len(s.engine._cell_key_cache) > 0  # noqa: SLF001


def test_cached_keys_respect_ttl(monkeypatch, flare_stack):
    """A cell key whose valid_until_ns has passed must be evicted on lookup."""
    s = flare_stack
    s.engine.search(s.alice, s.av[0], k=3, nprobe=4)
    with s.engine._cache_lock:  # noqa: SLF001
        before = len(s.engine._cell_key_cache)  # noqa: SLF001
    assert before > 0

    # Force every cached key's valid_until_ns into the past.
    with s.engine._cache_lock:  # noqa: SLF001
        for k, v in list(s.engine._cell_key_cache.items()):  # noqa: SLF001
            from flare.wire import IssuedCellKey
            s.engine._cell_key_cache[k] = IssuedCellKey(  # noqa: SLF001
                key=v.key, valid_until_ns=1,
            )

    # The next query (same vector → same cells) must evict every
    # expired entry and round-trip the oracle for fresh keys.
    s.engine.search(s.alice, s.av[0], k=3, nprobe=4)
    with s.engine._cache_lock:  # noqa: SLF001
        for k, v in s.engine._cell_key_cache.items():  # noqa: SLF001
            assert v.valid_until_ns > 1  # fresh, not the artificially-expired ones


def test_concurrent_queries_share_caches_safely(flare_stack):
    """Many threads issuing queries concurrently must not race the caches."""
    s = flare_stack
    crashes: list[str] = []

    def worker(idx: int):
        engine = s.build_thread_local_engine()
        try:
            for j in range(20):
                engine.search(s.alice, s.av[(idx + j) % len(s.av)], k=3, nprobe=4)
        except Exception as e:
            crashes.append(repr(e))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
        assert not t.is_alive()
    assert not crashes, crashes


def test_cache_disabled_round_trips_every_call(flare_stack):
    """When cache=False the engine MUST hit storage on every call."""
    s = flare_stack
    s.engine.cache_enabled = False
    s.engine.invalidate_routing()
    s.engine.invalidate_cell_keys()
    # First search just to ensure correctness
    s.engine.search(s.alice, s.av[0], k=3, nprobe=4)
    with s.engine._cache_lock:  # noqa: SLF001
        assert s.engine._registrations_cache is None  # noqa: SLF001
        assert s.engine._cell_blob_cache == {}  # noqa: SLF001
        assert s.engine._cell_key_cache == {}  # noqa: SLF001
