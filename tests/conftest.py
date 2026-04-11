"""Shared test fixtures for the Phase 3 stack.

`flare_stack` brings up a fresh in-process FLARE stack:
- ledger service
- storage service
- 3 oracle replicas per data owner (Alice + Bob), in **threshold mode**
  with K=2 of M=3, each replica holding one Shamir share of the
  owner's master key
- a wired query engine

All HTTP calls go through `starlette.testclient.TestClient` so the
wire protocol is exercised end-to-end without binding sockets.

Backwards-compatibility aliases `phase1_stack` / `phase2_stack` exist
so the older test files continue to import a fixture by their
historical name without rewriting them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

import numpy as np
import pytest
from fastapi.testclient import TestClient

from flare.bootstrap import bootstrap_context
from flare.crypto import fresh_master_key
from flare.identity import Identity
from flare.ledger import build_ledger_app
from flare.ledger.client import HttpLedgerClient
from flare.lightcone import Edge, LightConeGraph
from flare.oracle import (
    PeerEndpoint,
    PeerShareFetcher,
    Share,
    build_oracle_app,
    split_secret,
)
from flare.oracle.client import HttpOracleClient, OracleClient
from flare.query import FlareQueryEngine
from flare.storage import build_storage_app
from flare.storage.client import HttpStorageClient


THRESHOLD_K = 2
THRESHOLD_M = 3


def _vecs(n: int, dim: int, seed: int):
    rng = np.random.default_rng(seed)
    v = rng.normal(size=(n, dim)).astype(np.float32)
    v /= np.linalg.norm(v, axis=1, keepdims=True) + 1e-9
    return v, np.arange(n, dtype=np.int64)


@dataclass
class ReplicaSet:
    """Three threshold-mode oracle replicas for a single data owner."""
    owner: Identity
    master_key: bytes
    oracle_identities: list[Identity]
    shares: list[Share]
    apps: list[object] = field(default_factory=list)
    test_clients: list[TestClient] = field(default_factory=list)
    base_urls: list[str] = field(default_factory=list)


def _build_replica_set(
    owner: Identity,
    ledger_app,
    label: str,
) -> ReplicaSet:
    master = fresh_master_key()
    oracle_ids = [Identity.generate() for _ in range(THRESHOLD_M)]
    shares = split_secret(master, k=THRESHOLD_K, m=THRESHOLD_M)
    base_urls = [f"http://oracle-{label}-{i+1}.local" for i in range(THRESHOLD_M)]

    # Two-phase build: first construct all replicas with placeholder
    # peer share fetchers, then patch in fetchers that close over the
    # other replicas' TestClients. We can't construct the fetchers
    # until every replica's TestClient exists.
    apps: list[object] = []
    clients: list[TestClient] = []
    cores = []  # to wire fetcher into core later
    for i in range(THRESHOLD_M):
        ledger_client = HttpLedgerClient(client=TestClient(ledger_app))
        app = build_oracle_app(
            owner_did=owner.did,
            ledger_client=ledger_client,
            share=shares[i],
            threshold_k=THRESHOLD_K,
            peer_share_fetcher=None,  # patched below
            oracle_identity=oracle_ids[i],
            allowed_coord_dids={oid.did for oid in oracle_ids},
        )
        apps.append(app)
        clients.append(TestClient(app))
        cores.append(app.state.core)

    # Patch peer share fetchers now that every replica's TestClient exists.
    for i in range(THRESHOLD_M):
        peers = []
        for j in range(THRESHOLD_M):
            if j == i:
                continue
            peers.append(PeerEndpoint(
                oracle_did=oracle_ids[j].did,
                client=clients[j],
            ))
        fetcher = PeerShareFetcher(
            coord_identity=oracle_ids[i],
            peers=peers,
            needed=THRESHOLD_K - 1,
        )
        cores[i]._peer_share_fetcher = fetcher  # noqa: SLF001

    return ReplicaSet(
        owner=owner,
        master_key=master,
        oracle_identities=oracle_ids,
        shares=shares,
        apps=apps,
        test_clients=clients,
        base_urls=base_urls,
    )


@dataclass
class FlareStack:
    alice: Identity
    bob: Identity
    carol: Identity
    alice_replicas: ReplicaSet
    bob_replicas: ReplicaSet
    ledger: HttpLedgerClient
    storage: HttpStorageClient
    alice_url: str   # the URL the storage registration points at (replica 1)
    bob_url: str
    resolve: Callable[[str], OracleClient]
    graph: LightConeGraph
    engine: FlareQueryEngine
    av: np.ndarray
    bv: np.ndarray

    ledger_app: object = None
    storage_app: object = None

    @property
    def alice_master(self) -> bytes:
        return self.alice_replicas.master_key

    @property
    def bob_master(self) -> bytes:
        return self.bob_replicas.master_key

    @property
    def alice_oracle_identity(self) -> Identity:
        # The DID a context registration trusts is the URL-pointed
        # replica's DID. Phase 3 still uses one specific replica as
        # the registered oracle DID per context.
        return self.alice_replicas.oracle_identities[0]

    @property
    def bob_oracle_identity(self) -> Identity:
        return self.bob_replicas.oracle_identities[0]

    @property
    def alice_oracle_app(self) -> object:
        return self.alice_replicas.apps[0]

    @property
    def bob_oracle_app(self) -> object:
        return self.bob_replicas.apps[0]

    def build_thread_local_engine(self) -> FlareQueryEngine:
        storage_local = HttpStorageClient(client=TestClient(self.storage_app))
        a_clients = [TestClient(app) for app in self.alice_replicas.apps]
        b_clients = [TestClient(app) for app in self.bob_replicas.apps]
        a_map = dict(zip(self.alice_replicas.base_urls, a_clients))
        b_map = dict(zip(self.bob_replicas.base_urls, b_clients))

        def resolve(endpoint: str) -> OracleClient:
            if endpoint in a_map:
                return HttpOracleClient(client=a_map[endpoint])
            if endpoint in b_map:
                return HttpOracleClient(client=b_map[endpoint])
            raise KeyError(endpoint)

        return FlareQueryEngine(
            storage=storage_local, lightcone=self.graph, oracle_resolver=resolve,
        )


def _build_stack() -> FlareStack:
    dim = 16
    alice = Identity.generate()
    bob = Identity.generate()
    carol = Identity.generate()

    ledger_app = build_ledger_app()
    ledger = HttpLedgerClient(client=TestClient(ledger_app))

    storage_app = build_storage_app()
    storage = HttpStorageClient(client=TestClient(storage_app))

    alice_replicas = _build_replica_set(alice, ledger_app, "alice")
    bob_replicas = _build_replica_set(bob, ledger_app, "bob")

    alice_url = alice_replicas.base_urls[0]
    bob_url = bob_replicas.base_urls[0]

    # The resolver knows about every replica's URL so the query
    # engine can fail over.
    alice_url_to_client = {
        alice_replicas.base_urls[i]: alice_replicas.test_clients[i]
        for i in range(THRESHOLD_M)
    }
    bob_url_to_client = {
        bob_replicas.base_urls[i]: bob_replicas.test_clients[i]
        for i in range(THRESHOLD_M)
    }

    def resolve(endpoint: str) -> OracleClient:
        if endpoint in alice_url_to_client:
            return HttpOracleClient(client=alice_url_to_client[endpoint])
        if endpoint in bob_url_to_client:
            return HttpOracleClient(client=bob_url_to_client[endpoint])
        raise KeyError(endpoint)

    av, aids = _vecs(120, dim, seed=11)
    bv, bids = _vecs(120, dim, seed=22)

    from flare.storage.memory import OracleEndpoint as _OE
    # Phase 4: register all 3 replicas per owner so the query node
    # can fail over from a downed coordinator to a healthy one.
    alice_endpoints = [
        _OE(url=f"http://oracle-alice-{i+1}.local",
            oracle_did=alice_replicas.oracle_identities[i].did)
        for i in range(THRESHOLD_M)
    ]
    bob_endpoints = [
        _OE(url=f"http://oracle-bob-{i+1}.local",
            oracle_did=bob_replicas.oracle_identities[i].did)
        for i in range(THRESHOLD_M)
    ]
    alice_result = bootstrap_context(
        storage=storage,
        context_id="workspace_alice",
        owner_identity=alice,
        oracle_endpoints=alice_endpoints,
        vectors=av, ids=aids,
        master_key=alice_replicas.master_key,
        ledger_client=ledger,
        nlist=4,
    )
    bob_result = bootstrap_context(
        storage=storage,
        context_id="workspace_bob",
        owner_identity=bob,
        oracle_endpoints=bob_endpoints,
        vectors=bv, ids=bids,
        master_key=bob_replicas.master_key,
        ledger_client=ledger,
        nlist=4,
    )

    # Inject encrypted centroids and wrapped CEKs into every oracle
    # replica so the /request-centroids endpoint can serve them to
    # authorized queriers, and decide_batch can use envelope encryption.
    for app in alice_replicas.apps:
        app.state.core.store_encrypted_centroids(
            "workspace_alice", alice_result.encrypted_centroids,
        )
        for cell_ref, wrapped in alice_result.wrapped_ceks.items():
            app.state.core.store_wrapped_cek(cell_ref, wrapped)
    for app in bob_replicas.apps:
        app.state.core.store_encrypted_centroids(
            "workspace_bob", bob_result.encrypted_centroids,
        )
        for cell_ref, wrapped in bob_result.wrapped_ceks.items():
            app.state.core.store_wrapped_cek(cell_ref, wrapped)

    graph = LightConeGraph()
    graph.add_context("workspace_alice")
    graph.add_context("workspace_bob")
    graph.add_edge(Edge(alice.did, "workspace_alice", "owns"))
    graph.add_edge(Edge(bob.did, "workspace_bob", "owns"))
    # Containment edges: explicit cell membership per context.
    for edge in alice_result.containment_edges:
        graph.add_containment_edge(edge)
    for edge in bob_result.containment_edges:
        graph.add_containment_edge(edge)

    engine = FlareQueryEngine(storage=storage, lightcone=graph, oracle_resolver=resolve)

    return FlareStack(
        alice=alice, bob=bob, carol=carol,
        alice_replicas=alice_replicas, bob_replicas=bob_replicas,
        ledger=ledger, storage=storage,
        alice_url=alice_url, bob_url=bob_url,
        resolve=resolve, graph=graph, engine=engine,
        av=av, bv=bv,
        ledger_app=ledger_app, storage_app=storage_app,
    )


@pytest.fixture
def flare_stack() -> FlareStack:
    return _build_stack()


# Backwards-compatibility aliases
@pytest.fixture
def phase1_stack() -> FlareStack:
    return _build_stack()


@pytest.fixture
def phase2_stack() -> FlareStack:
    return _build_stack()
