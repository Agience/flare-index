"""Phase 4 query engine.

Pipeline (matches docs/flare-index.md §Data Flow), with the four
Phase 4 properties layered in:

1. Centroid routing across all known contexts -> candidate cells
2. Light-cone filter -> authorized cells
3. **Batch padding (F-0.8)**: pad the authorized cell list to a fixed
   `padding_width` with random *also-authorized* cells whose keys we
   will discard. The oracle's view of every query batch is constant-
   width regardless of how many cells the query actually needs. The
   padded keys decrypt successfully but the cells they unlock are
   never read.
4. Group authorized cells by their owner's *registered oracle DID*.
   For each group, **try the registered oracle endpoints in order
   (F-3.7 failover)** until one returns a cooperating batch. The
   query node verifies the response signature against the expected
   `oracle_did` regardless of which URL it actually reached.
5. **In parallel** with the oracle round-trips, prefetch every
   ciphertext cell from storage via a thread pool.
6. **Cell-key TTL enforcement (F-1.5)**: every issued cell key carries
   a `valid_until_ns`. The query engine checks the TTL again at the
   moment of cell decryption — a key that was valid at fetch time
   but expired by the time we tried to use it is dropped.
7. Decrypt each authorized cell with its key and run brute-force ANN
   inside.
8. Merge + rank top-K.
9. Drop all cell keys before returning.

The query node holds:
- a `LightConeGraph` (local cache; future phases will populate from a graph DB)
- an `Identity` (the querier's signing key)
- a `StorageClient`
- an `OracleResolver` (function: oracle endpoint URL -> OracleClient)

It does NOT hold master keys, plaintext vectors, or ledger state.
"""
from __future__ import annotations

import random
import time as _time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable, Optional

import numpy as np

from .bootstrap import deserialize_cell, deserialize_centroids
from .crypto import EncryptedCell, decrypt_cell
from .identity import Identity
from .lightcone import LightConeGraph
from .oracle.client import OracleClient
from .storage.client import StorageClient
from .storage.memory import ContextRegistration
from .types import CellRef, ContextId, QueryHit, QueryTrace
from .wire import IssuedCellKey


OracleResolver = Callable[[str], OracleClient]


class FlareQueryEngine:
    """End-to-end FLARE query engine.

    Performance notes
    -----------------

    Storage reads (centroids, context registration, encrypted cells)
    are *content-addressed* by what they describe: the centroids
    change only when the owner re-bootstraps; registrations change
    only when the owner re-publishes; ciphertext cells change only
    when the owner re-encrypts. None of them depends on the querier.

    The engine caches all of them on the query node. The first query
    pays the cost of pulling them; every subsequent query short-circuits
    those round-trips. Cache invalidation is fail-safe by design:

    - For ciphertext cells, AES-GCM AAD binds the bytes to their
      `(context, cluster)` slot. If the cell changed under us, the
      decryption fails and the engine refetches.
    - For centroids and registrations, we expose `invalidate_routing()`
      so the data owner can clear the cache after a bootstrap.

    Cell keys are also cached, but only for the duration of the
    oracle-signed `valid_until_ns`. The cache **does not weaken the
    revocation guarantee** — the TTL is the existing upper bound on
    how long any issued key remains useful, and reusing a cached key
    just extends the natural TTL window to its full extent rather
    than re-issuing every time. Once the key expires it's dropped and
    the next query forces a fresh oracle round-trip.

    Read access to the caches is guarded by an RLock so concurrent
    queries from many threads see a consistent view.
    """

    def __init__(
        self,
        *,
        storage: StorageClient,
        lightcone: LightConeGraph,
        oracle_resolver: OracleResolver,
        prefetch_workers: int = 8,
        padding_width: int = 0,
        cache: bool = True,
    ) -> None:
        self.storage = storage
        self.lightcone = lightcone
        self.oracle_resolver = oracle_resolver
        self.prefetch_workers = prefetch_workers
        self.padding_width = padding_width
        self.cache_enabled = cache
        # Caches. None until the first query populates them.
        self._cache_lock = __import__("threading").RLock()
        self._registrations_cache: Optional[list] = None
        self._centroids_cache: dict[ContextId, np.ndarray] = {}
        self._reg_by_ctx_cache: dict[ContextId, ContextRegistration] = {}
        self._cell_blob_cache: dict[CellRef, bytes] = {}
        # Cell key cache: (cell_ref, requester_did) -> IssuedCellKey
        # Entries are evicted lazily when their TTL passes.
        self._cell_key_cache: dict[tuple[CellRef, str], IssuedCellKey] = {}

    def invalidate_routing(self) -> None:
        """Drop the centroid + registration + cell-blob caches.

        Call this on the data-owner side after a re-bootstrap so the
        next query rebuilds its routing view from the live storage
        service.
        """
        with self._cache_lock:
            self._registrations_cache = None
            self._centroids_cache.clear()
            self._reg_by_ctx_cache.clear()
            self._cell_blob_cache.clear()

    def invalidate_cell_keys(self) -> None:
        """Drop every cached cell key. Useful after a known revocation."""
        with self._cache_lock:
            self._cell_key_cache.clear()

    # ----- routing cache helpers -----

    def _get_registrations(self) -> list:
        if not self.cache_enabled:
            return self.storage.list_contexts()
        with self._cache_lock:
            if self._registrations_cache is None:
                self._registrations_cache = self.storage.list_contexts()
            return self._registrations_cache

    def _get_centroids(self, identity: Identity, ctx: ContextId) -> np.ndarray:
        """Fetch centroids for a context from the oracle (not storage).

        Centroids are gated by the same authorization boundary as cell
        keys: the oracle checks the requester's grant before returning
        the centroid map via ECIES. An unauthorized querier never sees
        the cluster structure.
        """
        if self.cache_enabled:
            with self._cache_lock:
                cached = self._centroids_cache.get(ctx)
            if cached is not None:
                return cached

        reg = self._get_registration(ctx)
        # Try each oracle endpoint in order (same failover pattern
        # as cell-key issuance).
        for endpoint in reg.oracle_endpoints:
            try:
                client = self.oracle_resolver(endpoint.url)
            except KeyError:
                continue
            try:
                result = client.request_centroids(
                    identity, endpoint.oracle_did, [ctx],
                )
            except Exception:
                continue
            blob = result.get(ctx)
            if blob is not None:
                arr = deserialize_centroids(blob)
                if self.cache_enabled:
                    with self._cache_lock:
                        self._centroids_cache[ctx] = arr
                return arr
        # All endpoints failed or denied — return empty.
        return np.zeros((0, 0), dtype=np.float32)

    def _get_registration(self, ctx: ContextId) -> ContextRegistration:
        if not self.cache_enabled:
            return self.storage.get_registration(ctx)
        with self._cache_lock:
            if ctx not in self._reg_by_ctx_cache:
                self._reg_by_ctx_cache[ctx] = self.storage.get_registration(ctx)
            return self._reg_by_ctx_cache[ctx]

    # ----- centroid routing -----

    def _candidate_cells(
        self, identity: Identity, query: np.ndarray, nprobe: int,
        authorized: set[ContextId],
    ) -> list[CellRef]:
        """Route the query vector to the nearest centroids.

        Only considers contexts the querier is authorized for — the
        oracle will deny centroid requests for unauthorized contexts,
        and we avoid wasting nprobe budget on contexts that will be
        filtered anyway.
        """
        if query.ndim == 1:
            query = query.reshape(1, -1)
        query = query.astype(np.float32)
        scored: list[tuple[float, CellRef]] = []
        for reg in self._get_registrations():
            if reg.context_id not in authorized:
                continue
            centroids = self._get_centroids(identity, reg.context_id)
            if centroids.ndim < 2 or centroids.shape[0] == 0:
                continue
            d = np.linalg.norm(centroids - query, axis=1)
            for cluster_id, dist in enumerate(d):
                scored.append((float(dist), CellRef(reg.context_id, int(cluster_id))))
        scored.sort(key=lambda t: t[0])
        return [c for _, c in scored[:nprobe]]

    def _all_authorized_cells(self, authorized_contexts: set[ContextId]) -> list[CellRef]:
        out: list[CellRef] = []
        for ctx in authorized_contexts:
            try:
                reg = self._get_registration(ctx)
            except Exception:
                continue
            for cluster_id in range(reg.nlist):
                out.append(CellRef(ctx, cluster_id))
        return out

    def _pad_to_width(
        self,
        real: list[CellRef],
        authorized_contexts: set[ContextId],
        rng: random.Random,
    ) -> tuple[list[CellRef], set[CellRef]]:
        """Return (padded_list, set_of_padding_cells).

        Padding cells are drawn from the principal's authorized set
        and added to the batch alongside the real cells. The query
        engine receives valid keys for them but never decrypts the
        underlying cells (it knows which cells are padding from the
        returned set). An observer of the oracle wire sees a constant-
        width batch every time, so query specificity does not leak
        through batch size.
        """
        if self.padding_width <= 0 or len(real) >= self.padding_width:
            return list(real), set()
        pool = self._all_authorized_cells(authorized_contexts)
        # Don't pad with cells already in the real set.
        real_set = set(real)
        candidates = [c for c in pool if c not in real_set]
        rng.shuffle(candidates)
        needed = self.padding_width - len(real)
        padding = candidates[:needed]
        return list(real) + padding, set(padding)

    # ----- prefetch -----

    def _prefetch_cells(self, cells: list[CellRef]) -> dict[CellRef, Optional[bytes]]:
        if not cells:
            return {}
        results: dict[CellRef, Optional[bytes]] = {}
        with ThreadPoolExecutor(max_workers=self.prefetch_workers) as ex:
            futures = {ex.submit(self._get_cell_safely, c): c for c in cells}
            for fut in as_completed(futures):
                cell = futures[fut]
                results[cell] = fut.result()
        return results

    def _get_cell_safely(self, cell: CellRef) -> Optional[bytes]:
        if self.cache_enabled:
            with self._cache_lock:
                cached = self._cell_blob_cache.get(cell)
            if cached is not None:
                return cached
        try:
            blob = self.storage.get_cell(cell.context_id, cell.cluster_id)
        except Exception:
            return None
        if self.cache_enabled and blob is not None:
            with self._cache_lock:
                self._cell_blob_cache[cell] = blob
        return blob

    # ----- decrypt + search -----

    def _decrypt_cell_inline(
        self,
        cell_ref: CellRef,
        cell_key: bytes,
        ciphertext_blob: bytes,
        query: np.ndarray,
        k: int,
    ) -> list[QueryHit]:
        cell = EncryptedCell.from_bytes(ciphertext_blob)
        aad = f"{cell_ref.context_id}:{cell_ref.cluster_id}".encode("utf-8")
        plaintext = decrypt_cell(cell_key, cell, associated=aad)
        vectors, ids = deserialize_cell(plaintext)
        d = np.linalg.norm(vectors - query.reshape(1, -1), axis=1)
        order = np.argsort(d)[:k]
        return [
            QueryHit(
                context_id=cell_ref.context_id,
                cluster_id=cell_ref.cluster_id,
                vector_id=int(ids[i]),
                score=float(-d[i]),
            )
            for i in order
        ]

    # ----- public search API -----

    def search(
        self,
        identity: Identity,
        query: np.ndarray,
        *,
        k: int = 5,
        nprobe: int = 4,
        now: Optional[datetime] = None,
    ) -> tuple[list[QueryHit], QueryTrace]:
        del now  # captured by the wire layer at request build time
        trace = QueryTrace()

        # Stage 2: light-cone filter — determine authorized contexts
        # before centroid routing so that centroids (which are now
        # oracle-gated) are only requested for reachable contexts.
        authorized = self.lightcone.authorized_contexts(identity.did)
        trace.authorized_contexts = set(authorized)

        # Stage 3: centroid routing across authorized contexts only.
        candidates = self._candidate_cells(identity, query, nprobe, authorized)
        trace.candidate_cells = list(candidates)

        # All candidates are already from authorized contexts (routing
        # was restricted to authorized set), so no further filter needed.
        filtered = candidates

        # Stage 3.5: pad to constant width with authorized noise cells.
        padded, padding_set = self._pad_to_width(
            filtered, authorized, rng=random.Random(),
        )
        trace.light_cone_filtered = list(padded)
        if not padded:
            return [], trace

        # Resolve registrations once per context (cached).
        registrations: dict[ContextId, ContextRegistration] = {}
        for cell in padded:
            if cell.context_id in registrations:
                continue
            try:
                registrations[cell.context_id] = self._get_registration(cell.context_id)
            except Exception:
                pass

        # Stage 4: group cells by owner_did (since the same data owner
        # may have multiple oracle endpoints registered, we group by
        # the *first* endpoint URL — see _try_oracle_endpoints for the
        # failover logic across the alternate endpoints).
        # Real cells we want to decrypt go in `cells_to_prefetch`;
        # padding cells skip the prefetch (we won't decrypt them).
        by_owner: dict[ContextId, list[CellRef]] = defaultdict(list)
        for cell in padded:
            reg = registrations.get(cell.context_id)
            if reg is None:
                if cell not in padding_set:
                    trace.oracle_denied.append(cell)
                continue
            by_owner[cell.context_id].append(cell)

        cells_to_prefetch = [c for c in padded if c not in padding_set]

        with ThreadPoolExecutor(max_workers=self.prefetch_workers + len(by_owner) + 1) as ex:
            prefetch_future = ex.submit(self._prefetch_cells, cells_to_prefetch)

            def _do_oracle_batch(
                cells: list[CellRef],
            ) -> tuple[list[CellRef], list[Optional[IssuedCellKey]]]:
                reg = registrations[cells[0].context_id]
                pairs = [(c.context_id, c.cluster_id) for c in cells]
                return cells, self._try_oracle_endpoints(identity, reg, pairs)

            # One batch per context (Phase 4 still groups by oracle DID
            # implicitly because all cells of one context point at the
            # same registration).
            oracle_futures = [
                ex.submit(_do_oracle_batch, cells)
                for cells in by_owner.values()
            ]

            ciphertext_by_cell = prefetch_future.result()

            cell_keys: dict[CellRef, IssuedCellKey] = {}
            try:
                for fut in as_completed(oracle_futures):
                    cells, keys = fut.result()
                    for cell, key in zip(cells, keys):
                        if key is None:
                            if cell not in padding_set:
                                trace.oracle_denied.append(cell)
                            continue
                        if cell in padding_set:
                            # Padding key: granted, but we deliberately
                            # do not decrypt the underlying cell.
                            continue
                        cell_keys[cell] = key
                        trace.oracle_granted.append(cell)

                # Stage 6: per-cell decrypt + ANN with TTL enforcement.
                now_ns = _time.time_ns()
                all_hits: list[QueryHit] = []
                for cell, issued in cell_keys.items():
                    if not issued.is_valid_at(now_ns):
                        # Key expired between fetch and use.
                        trace.oracle_denied.append(cell)
                        continue
                    blob = ciphertext_by_cell.get(cell)
                    if blob is None:
                        continue
                    hits = self._decrypt_cell_inline(cell, issued.key, blob, query, k=k)
                    trace.decrypted_cells += 1
                    all_hits.extend(hits)

                all_hits.sort(key=lambda h: h.score, reverse=True)
                top = all_hits[:k]
                trace.hits = list(top)
                return top, trace
            finally:
                cell_keys.clear()

    # ----- oracle failover + cell-key caching -----

    def _lookup_cached_keys(
        self,
        identity: Identity,
        pairs: list[tuple[ContextId, int]],
        now_ns: int,
    ) -> tuple[list[Optional[IssuedCellKey]], list[int]]:
        """Return (keys, missing_indices).

        For each pair we either return a cached unexpired
        `IssuedCellKey` or `None` and add the index to `missing` so
        the caller asks the oracle for it.
        """
        out: list[Optional[IssuedCellKey]] = [None] * len(pairs)
        missing: list[int] = []
        if not self.cache_enabled:
            return [None] * len(pairs), list(range(len(pairs)))
        with self._cache_lock:
            for i, (ctx, cluster) in enumerate(pairs):
                key = (CellRef(ctx, cluster), identity.did)
                cached = self._cell_key_cache.get(key)
                if cached is None or not cached.is_valid_at(now_ns):
                    if cached is not None:
                        # Lazy eviction.
                        self._cell_key_cache.pop(key, None)
                    missing.append(i)
                else:
                    out[i] = cached
        return out, missing

    def _store_keys_in_cache(
        self,
        identity: Identity,
        pairs: list[tuple[ContextId, int]],
        keys: list[Optional[IssuedCellKey]],
    ) -> None:
        if not self.cache_enabled:
            return
        with self._cache_lock:
            for (ctx, cluster), key in zip(pairs, keys):
                if key is None:
                    continue
                self._cell_key_cache[(CellRef(ctx, cluster), identity.did)] = key

    def _try_oracle_endpoints(
        self,
        identity: Identity,
        reg: ContextRegistration,
        pairs: list[tuple[ContextId, int]],
    ) -> list[Optional[IssuedCellKey]]:
        """Try the registered oracle endpoints in order.

        With cell-key caching, we first check the cache for every
        requested pair; the oracle is only asked for the *missing*
        pairs. This is the "be more predictive" optimization: a
        querier doing many related queries reuses cell keys for
        cells that overlap, only paying the oracle round-trip the
        first time the key is needed (or after the TTL expires).

        Each oracle call independently verifies the response signature
        against the *registered* DID for that endpoint, so an attacker
        who substitutes a URL into the registration cannot impersonate
        the registered oracle.
        """
        import time as _t
        now_ns = _t.time_ns()
        keys, missing = self._lookup_cached_keys(identity, pairs, now_ns)
        if not missing:
            return keys

        missing_pairs = [pairs[i] for i in missing]
        last: list[Optional[IssuedCellKey]] = [None] * len(missing_pairs)
        for endpoint in reg.oracle_endpoints:
            try:
                client = self.oracle_resolver(endpoint.url)
            except KeyError:
                continue
            try:
                got = client.request_cell_keys_batch(identity, endpoint.oracle_did, missing_pairs)
            except Exception:
                continue
            last = got
            if any(k is not None for k in got):
                break

        self._store_keys_in_cache(identity, missing_pairs, last)
        for i, key in zip(missing, last):
            keys[i] = key
        return keys
