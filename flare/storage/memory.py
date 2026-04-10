"""In-memory backing store for the storage service.

Holds three things per context:

1. **Centroids** — stored for registration; public endpoint gated (403).
   Centroid maps are served to authorized queriers via the oracle.
2. **Encrypted cells** — opaque ciphertext, useless without an
   oracle-issued cell key.
3. **Registration metadata** — owner DID, oracle endpoint, dim, nlist.

In Phase 0 these all lived inside `FlareIndex` in the query process.
Phase 1 separates them: the data owner uploads cells + centroids to
storage, then the query node only ever fetches them. The query node
never sees a master key, never sees a plaintext cell, and only ever
holds a cell key for the duration of one search.

# ANALYSIS (phase1-findings.md §F-1.9):
# Storage is unauthenticated for both reads and writes in Phase 1.
# - Read: ciphertext is meaningless without keys, so anonymous reads
#   are by design. The information leak is the centroid topology
#   (already noted in F-0.7) and the existence/cardinality of cells.
# - Write: a malicious actor could upload garbage cells and confuse
#   centroid routing (DoS). Phase 2 binds cell uploads to a signed
#   `ContextRegistration` whose key matches the registered owner DID.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

import numpy as np

from ..types import ContextId, PrincipalId


@dataclass
class OracleEndpoint:
    """One oracle the query node may try to reach for a context.

    A context registration carries a list of these so that the query
    node can fail over from a downed coordinator to a healthy one
    without re-registering. Every endpoint is bound to a specific DID
    so even an attacker who substitutes a URL cannot impersonate the
    expected oracle (the query node verifies the response signature
    against `oracle_did`).
    """
    url: str
    oracle_did: PrincipalId


@dataclass
class ContextRegistration:
    context_id: ContextId
    owner_did: PrincipalId
    # Phase 4: a list of oracle endpoints. The query engine tries them
    # in order and uses the first one whose batch response is
    # cooperative. Phase 0-3 stored a single (url, did); the new shape
    # is backward-compatible because the legacy `oracle_endpoint` /
    # `oracle_did` properties still resolve to the first entry.
    oracle_endpoints: list[OracleEndpoint]
    dim: int
    nlist: int

    @property
    def oracle_endpoint(self) -> str:
        """Convenience: the first registered URL."""
        return self.oracle_endpoints[0].url

    @property
    def oracle_did(self) -> PrincipalId:
        """Convenience: the first registered DID."""
        return self.oracle_endpoints[0].oracle_did

    @classmethod
    def with_single_endpoint(
        cls,
        *,
        context_id: ContextId,
        owner_did: PrincipalId,
        oracle_endpoint: str,
        oracle_did: PrincipalId,
        dim: int,
        nlist: int,
    ) -> "ContextRegistration":
        return cls(
            context_id=context_id,
            owner_did=owner_did,
            oracle_endpoints=[OracleEndpoint(url=oracle_endpoint, oracle_did=oracle_did)],
            dim=dim,
            nlist=nlist,
        )


@dataclass
class StoredContext:
    registration: ContextRegistration
    # (nlist, dim) float32 plaintext
    centroids: np.ndarray
    # cluster_id -> raw bytes (nonce || ciphertext) — see flare/crypto.py
    encrypted_cells: dict[int, bytes] = field(default_factory=dict)


class InMemoryStorage:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._contexts: dict[ContextId, StoredContext] = {}

    def register_context(
        self,
        registration: ContextRegistration,
        centroids: np.ndarray,
    ) -> None:
        with self._lock:
            if registration.context_id in self._contexts:
                raise ValueError(f"context already registered: {registration.context_id}")
            self._contexts[registration.context_id] = StoredContext(
                registration=registration,
                centroids=centroids.astype(np.float32),
            )

    def put_cell(self, context_id: ContextId, cluster_id: int, cell_blob: bytes) -> None:
        with self._lock:
            ctx = self._contexts[context_id]
            ctx.encrypted_cells[cluster_id] = cell_blob

    def get_cell(self, context_id: ContextId, cluster_id: int) -> bytes:
        with self._lock:
            return self._contexts[context_id].encrypted_cells[cluster_id]

    def list_contexts(self) -> list[ContextRegistration]:
        with self._lock:
            return [c.registration for c in self._contexts.values()]

    def get_centroids(self, context_id: ContextId) -> np.ndarray:
        with self._lock:
            return self._contexts[context_id].centroids.copy()

    def get_registration(self, context_id: ContextId) -> ContextRegistration:
        with self._lock:
            return self._contexts[context_id].registration
