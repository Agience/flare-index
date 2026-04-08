"""Owner-side context bootstrap.

A data owner runs this exactly once per context (and again whenever
they want to reindex). It does NOT run on the query node — the query
node never sees a master key, never sees plaintext vectors, and never
calls into this module.

Steps:
1. Train k-means centroids over the owner's vectors (FAISS).
2. Assign each vector to its nearest centroid.
3. Per cluster: serialize (vectors, ids) -> bytes -> AES-GCM encrypt
   under HKDF-derived per-cell key, with `(context_id:cluster_id)`
   AAD binding.
4. Register the context with storage (owner DID, oracle endpoint, dim,
   nlist) and upload the public centroids.
5. Upload each encrypted cell to storage.

After this returns, the master key can — in principle — be moved into
the oracle process and dropped from the bootstrap process. The Phase 1
prototype keeps both references in the same Python process for
testability; the trust boundary is enforced by who *receives* the key,
not by where the bytes were generated.
"""
from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Optional

import faiss  # type: ignore
import numpy as np

from .crypto import derive_cell_key, encrypt_cell
from .identity import Identity
from .storage.client import StorageClient
from .storage.memory import ContextRegistration, OracleEndpoint
from .types import ContextId, PrincipalId


def _serialize_cell(vectors: np.ndarray, ids: np.ndarray) -> bytes:
    buf = io.BytesIO()
    np.savez(buf, vectors=vectors.astype(np.float32), ids=ids.astype(np.int64))
    return buf.getvalue()


def deserialize_cell(blob: bytes) -> tuple[np.ndarray, np.ndarray]:
    buf = io.BytesIO(blob)
    data = np.load(buf, allow_pickle=False)
    return data["vectors"], data["ids"]


@dataclass
class BootstrapResult:
    context_id: ContextId
    nlist: int
    n_vectors: int
    n_cells: int


def bootstrap_context(
    *,
    storage: StorageClient,
    context_id: ContextId,
    owner_identity: Identity,
    vectors: np.ndarray,
    ids: np.ndarray,
    master_key: bytes,
    # Phase 4: pass either a single (oracle_endpoint, oracle_did) pair
    # for backward compatibility OR a list of endpoints for multi-replica
    # registrations the query node can fail over.
    oracle_endpoint: Optional[str] = None,
    oracle_did: Optional[PrincipalId] = None,
    oracle_endpoints: Optional[list[OracleEndpoint]] = None,
    nlist: int = 8,
    seed: int = 0,
) -> BootstrapResult:
    if oracle_endpoints is None:
        if oracle_endpoint is None or oracle_did is None:
            raise ValueError(
                "bootstrap_context: pass either oracle_endpoints or "
                "(oracle_endpoint + oracle_did)"
            )
        oracle_endpoints = [OracleEndpoint(url=oracle_endpoint, oracle_did=oracle_did)]

    if vectors.dtype != np.float32:
        vectors = vectors.astype(np.float32)
    n, dim = vectors.shape
    if ids.shape[0] != n:
        raise ValueError("ids must align with vectors")
    if n < nlist:
        nlist = max(1, n)

    km = faiss.Kmeans(d=dim, k=nlist, niter=20, seed=seed, verbose=False)
    km.train(vectors)
    centroids = np.asarray(km.centroids, dtype=np.float32)
    _, assign = km.index.search(vectors, 1)
    assign = assign.reshape(-1)

    storage.register_context(
        ContextRegistration(
            context_id=context_id,
            owner_did=owner_identity.did,
            oracle_endpoints=list(oracle_endpoints),
            dim=dim,
            nlist=nlist,
        ),
        centroids=centroids,
        owner_identity=owner_identity,
    )

    n_cells = 0
    for cid in range(nlist):
        mask = assign == cid
        if not mask.any():
            continue
        cell_vectors = vectors[mask]
        cell_ids = ids[mask]
        blob = _serialize_cell(cell_vectors, cell_ids)
        cell_key = derive_cell_key(master_key, context_id, cid)
        aad = f"{context_id}:{cid}".encode("utf-8")
        encrypted = encrypt_cell(cell_key, blob, associated=aad)
        storage.put_cell(context_id, cid, encrypted.to_bytes(), owner_identity=owner_identity)
        # Drop key reference promptly. ANALYSIS F-0.2 still applies.
        del cell_key
        n_cells += 1

    return BootstrapResult(
        context_id=context_id,
        nlist=nlist,
        n_vectors=n,
        n_cells=n_cells,
    )
