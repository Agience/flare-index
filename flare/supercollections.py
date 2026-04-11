"""Super-contexts: per-user KNN-generated groupings.

A super-context is an ephemeral projection of a user's light-cone-visible
centroids, clustered into thematic groups via k-means. Different users
with different light cones see different clusters.

Super-contexts are not stored — they are recomputed per-user, per-session.
They are a navigational aid, not a security boundary.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

import faiss  # type: ignore
import numpy as np

from .identity import Identity
from .query import FlareQueryEngine
from .types import CellRef, ContextId


@dataclass
class SuperContext:
    """An auto-generated grouping of cells from a user's light cone."""
    super_id: str
    member_cells: list[CellRef] = field(default_factory=list)
    centroid: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.float32))


def generate_super_contexts(
    engine: FlareQueryEngine,
    identity: Identity,
    *,
    k: int = 8,
    now=None,
) -> list[SuperContext]:
    """Cluster a user's visible centroids into super-contexts.

    Steps:
    1. Get authorized contexts from the light cone.
    2. Fetch centroids from oracle for each authorized context.
    3. Concatenate all centroids into a single matrix.
    4. Run k-means with ``k`` clusters on the concatenation.
    5. Assign each original centroid to its nearest super-cluster.
    6. Group CellRefs by super-cluster membership.

    Returns a list of SuperContext objects (ephemeral, not stored).
    """
    from datetime import datetime

    if now is None:
        now = datetime.utcnow()

    # Step 1: authorized contexts from the light cone.
    authorized = engine.lightcone.authorized_contexts(identity.did)
    if not authorized:
        return []

    # Step 2: fetch centroids from the oracle (cached).
    all_centroids: list[np.ndarray] = []
    centroid_to_cells: list[list[CellRef]] = []

    for ctx in sorted(authorized):
        centroids_npy = engine._get_centroids(identity, ctx)
        if centroids_npy is None or centroids_npy.size == 0:
            continue
        nlist = centroids_npy.shape[0]
        all_centroids.append(centroids_npy)
        for cluster_id in range(nlist):
            centroid_to_cells.append([CellRef(ctx, cluster_id)])

    if not all_centroids:
        return []

    # Step 3: concatenate.
    matrix = np.vstack(all_centroids).astype(np.float32)
    n_centroids = matrix.shape[0]
    if n_centroids == 0:
        return []

    # Clamp k to available centroids.
    actual_k = min(k, n_centroids)
    if actual_k < 1:
        return []

    # Step 4: k-means.
    dim = matrix.shape[1]
    km = faiss.Kmeans(d=dim, k=actual_k, niter=20, seed=42, verbose=False)
    km.train(matrix)
    super_centroids = np.asarray(km.centroids, dtype=np.float32)

    # Step 5: assign each original centroid to its nearest super-cluster.
    _, assign = km.index.search(matrix, 1)
    assign = assign.reshape(-1)

    # Step 6: group CellRefs by super-cluster.
    groups: dict[int, list[CellRef]] = {}
    for i, super_idx in enumerate(assign):
        groups.setdefault(int(super_idx), []).extend(centroid_to_cells[i])

    return [
        SuperContext(
            super_id=str(uuid.uuid4()),
            member_cells=cells,
            centroid=super_centroids[idx],
        )
        for idx, cells in sorted(groups.items())
    ]
