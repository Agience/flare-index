"""Centroid topology is oracle-gated (A-3 mitigation).

These tests prove that:
1. Storage no longer serves plaintext centroids (HTTP 403).
2. An *unauthorized* querier cannot obtain centroids from the oracle.
3. An *authorized* querier receives correct (decryptable) centroids.
"""
from __future__ import annotations

from datetime import datetime

import numpy as np
import pytest
from fastapi.testclient import TestClient

from flare.bootstrap import deserialize_centroids
from flare.identity import Identity
from flare.oracle.client import HttpOracleClient


def test_storage_returns_403_for_centroids(flare_stack):
    """GET /contexts/{ctx}/centroids must return 403 now that centroids
    are oracle-gated."""
    s = flare_stack
    # Use the raw TestClient to hit the storage service directly.
    raw = TestClient(s.storage_app)
    resp = raw.get("/contexts/workspace_alice/centroids")
    assert resp.status_code == 403


def test_unauthorized_querier_gets_no_centroids(flare_stack):
    """Carol has no grant to workspace_alice, so the oracle must refuse
    to issue centroids for that context."""
    s = flare_stack
    client = HttpOracleClient(client=s.alice_replicas.test_clients[0])
    oracle_did = s.alice_replicas.oracle_identities[0].did
    result = client.request_centroids(s.carol, oracle_did, ["workspace_alice"])
    # The oracle should not return centroids for an unauthorized context.
    assert result.get("workspace_alice") is None


def test_authorized_querier_gets_correct_centroids(flare_stack):
    """Alice (owner) can obtain centroids from the oracle. The returned
    blob deserializes to the same shape as the original."""
    s = flare_stack
    client = HttpOracleClient(client=s.alice_replicas.test_clients[0])
    oracle_did = s.alice_replicas.oracle_identities[0].did
    result = client.request_centroids(s.alice, oracle_did, ["workspace_alice"])
    blob = result.get("workspace_alice")
    assert blob is not None
    centroids = deserialize_centroids(blob)
    # The conftest registers workspace_alice with nlist=4, dim=16.
    assert centroids.shape == (4, 16)


def test_query_engine_routes_via_oracle_centroids(flare_stack):
    """End-to-end: the query engine successfully routes through
    oracle-gated centroids and returns search results."""
    s = flare_stack
    hits, trace = s.engine.search(s.alice, s.av[0], k=3, nprobe=2)
    assert len(hits) > 0
    assert all(h.context_id == "workspace_alice" for h in hits)
