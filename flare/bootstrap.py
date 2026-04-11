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
   nlist) and upload centroids to storage for backward compat.
5. Upload each encrypted cell to storage.
6. Encrypt centroid map under HKDF-derived centroid key and return in
   the BootstrapResult for oracle injection.

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

from .crypto import (
    derive_cell_key, derive_centroid_key, derive_cwk,
    encrypt_cell, generate_cek, unwrap_cek, wrap_cek,
)
from .identity import Identity
from .ledger.client import GrantLedgerClient
from .storage.client import StorageClient
from .storage.memory import ContextRegistration, OracleEndpoint
from .types import CellRef, ContainmentEdge, ContextId, PrincipalId


def _serialize_cell(vectors: np.ndarray, ids: np.ndarray) -> bytes:
    buf = io.BytesIO()
    np.savez(buf, vectors=vectors.astype(np.float32), ids=ids.astype(np.int64))
    return buf.getvalue()


def deserialize_cell(blob: bytes) -> tuple[np.ndarray, np.ndarray]:
    buf = io.BytesIO(blob)
    data = np.load(buf, allow_pickle=False)
    return data["vectors"], data["ids"]


def _serialize_centroids(centroids: np.ndarray) -> bytes:
    buf = io.BytesIO()
    np.save(buf, centroids.astype(np.float32), allow_pickle=False)
    return buf.getvalue()


def deserialize_centroids(blob: bytes) -> np.ndarray:
    return np.load(io.BytesIO(blob), allow_pickle=False)


@dataclass
class BootstrapResult:
    context_id: ContextId
    nlist: int
    n_vectors: int
    n_cells: int
    encrypted_centroids: bytes = b""  # AES-GCM blob for oracle ingestion
    # Envelope encryption: CWK-wrapped CEKs per cell, to be injected
    # into oracle cores alongside encrypted centroids.
    wrapped_ceks: dict = None  # type: ignore[assignment]  # dict[CellRef, bytes]
    # Containment edges: explicit edges from context to cells.
    containment_edges: list = None  # type: ignore[assignment]  # list[ContainmentEdge]

    def __post_init__(self) -> None:
        if self.wrapped_ceks is None:
            self.wrapped_ceks = {}
        if self.containment_edges is None:
            self.containment_edges = []


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
    # Grant-first access: when provided, bootstrap creates a standing
    # self-grant so the owner's access flows through the ledger like
    # everyone else's — no fast-path bypass.
    ledger_client: Optional[GrantLedgerClient] = None,
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

    # Encrypt centroids under a context-specific key derived from the
    # master key. The encrypted blob is stored in the oracle (not in
    # public storage) and delivered to authorized queriers via ECIES.
    # ANALYSIS: see docs/analysis/security.md A-3.
    centroids_npy = _serialize_centroids(centroids)
    centroid_key = derive_centroid_key(master_key, context_id)
    aad = f"centroids:{context_id}".encode("utf-8")
    encrypted_centroids_cell = encrypt_cell(centroid_key, centroids_npy, associated=aad)
    encrypted_centroids_blob = encrypted_centroids_cell.to_bytes()
    del centroid_key

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

    # Grant-first: create a standing self-grant so the owner's access
    # is mediated by the ledger, not by an oracle bypass.
    if ledger_client is not None:
        from datetime import datetime
        ledger_client.add_grant(
            grantor_identity=owner_identity,
            grantee=owner_identity.did,
            context_id=context_id,
            issued_at=datetime(2000, 1, 1),
        )

    # Envelope encryption: derive CWK once for the context, then
    # generate a random CEK per cell, encrypt with CEK, wrap CEK
    # under CWK. The wrapped CEKs are returned in BootstrapResult
    # for oracle injection.
    cwk = derive_cwk(master_key, context_id)
    wrapped_ceks: dict[CellRef, bytes] = {}
    edges: list[ContainmentEdge] = []

    n_cells = 0
    for cid in range(nlist):
        mask = assign == cid
        if not mask.any():
            continue
        cell_vectors = vectors[mask]
        cell_ids = ids[mask]
        blob = _serialize_cell(cell_vectors, cell_ids)
        aad = f"{context_id}:{cid}".encode("utf-8")
        # Two-layer envelope: random CEK encrypts the cell,
        # CWK wraps the CEK. The oracle derives CWK from the
        # master key and unwraps to get the CEK.
        cek = generate_cek()
        encrypted = encrypt_cell(cek, blob, associated=aad)
        wrapped = wrap_cek(cwk, cek, aad=aad)
        storage.put_cell(context_id, cid, encrypted.to_bytes(), owner_identity=owner_identity)
        wrapped_ceks[CellRef(context_id, cid)] = wrapped
        edges.append(ContainmentEdge(context_id=context_id, cluster_id=cid))
        del cek
        n_cells += 1
    del cwk

    return BootstrapResult(
        context_id=context_id,
        nlist=nlist,
        n_vectors=n,
        n_cells=n_cells,
        encrypted_centroids=encrypted_centroids_blob,
        wrapped_ceks=wrapped_ceks,
        containment_edges=edges,
    )


def share_cell_across_contexts(
    *,
    cell_ref: CellRef,
    from_master_key: bytes,
    to_master_key: bytes,
    to_context_id: ContextId,
    wrapped_cek: bytes,
) -> tuple[bytes, ContainmentEdge]:
    """Re-wrap a cell's CEK under a different context's CWK.

    Returns the new wrapped CEK and a containment edge for the target
    context. The encrypted cell data is NOT re-encrypted — only the
    key wrapping changes. The caller must store the new wrapped CEK
    in the target context's oracle and add the containment edge.
    """
    from_cwk = derive_cwk(from_master_key, cell_ref.context_id)
    from_aad = f"{cell_ref.context_id}:{cell_ref.cluster_id}".encode("utf-8")
    cek = unwrap_cek(from_cwk, wrapped_cek, aad=from_aad)
    del from_cwk

    to_cwk = derive_cwk(to_master_key, to_context_id)
    to_aad = f"{to_context_id}:{cell_ref.cluster_id}".encode("utf-8")
    new_wrapped = wrap_cek(to_cwk, cek, aad=to_aad)
    del to_cwk, cek

    edge = ContainmentEdge(context_id=to_context_id, cluster_id=cell_ref.cluster_id)
    return new_wrapped, edge
