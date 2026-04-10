"""Latency + recall benchmarks.

Runs three configurations:

1. **Single-replica oracle** — no peer share-fetching, no padding.
   Lower bound on Phase 4 oracle latency.
2. **Threshold oracle (K=2 of M=3)** — adds the per-query peer
   share-fetch round-trip.
3. **Threshold + padding** — adds constant-width oracle batches
   (padding to `nprobe * 2` cells with random authorized cells).
   Production Phase 4 cost.

All three run against the in-process FLARE stack (FastAPI apps wired
through `starlette.testclient`).

Outputs:
  paper/evals/phase4_bench_single.json
  paper/evals/phase4_bench_threshold.json
  paper/evals/phase4_bench_threshold_padded.json
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import numpy as np
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
    build_oracle_app,
    split_secret,
)
from flare.oracle.client import HttpOracleClient, OracleClient
from flare.query import FlareQueryEngine
from flare.storage import build_storage_app
from flare.storage.client import HttpStorageClient

CTX = "workspace_bench"
DIM = 64
N = 20_000
NLIST = 64
NPROBE = 8
QUERIES = 100
K = 10
THRESHOLD_K = 2
THRESHOLD_M = 3


def _gen():
    rng = np.random.default_rng(7)
    v = rng.normal(size=(N, DIM)).astype(np.float32)
    v /= np.linalg.norm(v, axis=1, keepdims=True) + 1e-9
    ids = np.arange(N, dtype=np.int64)
    qs = rng.normal(size=(QUERIES, DIM)).astype(np.float32)
    qs /= np.linalg.norm(qs, axis=1, keepdims=True) + 1e-9
    return v, ids, qs


def _brute(v, q, k):
    d = np.linalg.norm(v - q.reshape(1, -1), axis=1)
    return np.argsort(d)[:k]


def _build_single_stack():
    owner = Identity.generate()
    oracle_id = Identity.generate()
    master = fresh_master_key()

    ledger_app = build_ledger_app()
    storage_app = build_storage_app()
    storage = HttpStorageClient(client=TestClient(storage_app))

    oracle_app = build_oracle_app(
        owner_did=owner.did,
        ledger_client=HttpLedgerClient(client=TestClient(ledger_app)),
        master_key=master,
        oracle_identity=oracle_id,
    )
    oracle_test_client = TestClient(oracle_app)
    return owner, oracle_id, master, storage, oracle_test_client


def _build_threshold_stack():
    owner = Identity.generate()
    master = fresh_master_key()
    oracle_ids = [Identity.generate() for _ in range(THRESHOLD_M)]
    shares = split_secret(master, k=THRESHOLD_K, m=THRESHOLD_M)

    ledger_app = build_ledger_app()
    storage_app = build_storage_app()
    storage = HttpStorageClient(client=TestClient(storage_app))

    apps = []
    cores = []
    for i in range(THRESHOLD_M):
        app = build_oracle_app(
            owner_did=owner.did,
            ledger_client=HttpLedgerClient(client=TestClient(ledger_app)),
            share=shares[i],
            threshold_k=THRESHOLD_K,
            peer_share_fetcher=None,
            oracle_identity=oracle_ids[i],
            allowed_coord_dids={oid.did for oid in oracle_ids},
        )
        apps.append(app)
        cores.append(app.state.core)

    clients = [TestClient(app) for app in apps]

    for i in range(THRESHOLD_M):
        peers = [
            PeerEndpoint(oracle_did=oracle_ids[j].did, client=clients[j])
            for j in range(THRESHOLD_M) if j != i
        ]
        cores[i]._peer_share_fetcher = PeerShareFetcher(  # noqa: SLF001
            coord_identity=oracle_ids[i], peers=peers, needed=THRESHOLD_K - 1,
        )

    return owner, oracle_ids, master, storage, clients[0], oracle_ids[0]


def _run(label: str, build_fn, *, padding_width: int = 0) -> dict:
    print(f"\n=== {label} ===")
    print(f"Generating {N} x {DIM} synthetic vectors...")
    v, ids, qs = _gen()

    t0 = time.perf_counter()
    truth = [_brute(v, q, K) for q in qs]
    t_plain = time.perf_counter() - t0

    if "single" in label:
        owner, oracle_id, master, storage, oracle_test_client = build_fn()
    else:
        owner, _all_ids, master, storage, oracle_test_client, oracle_id = build_fn()

    result = bootstrap_context(
        storage=storage,
        context_id=CTX,
        owner_identity=owner,
        oracle_endpoint="http://oracle.local",
        oracle_did=oracle_id.did,
        vectors=v, ids=ids,
        master_key=master,
        nlist=NLIST,
    )
    # Inject encrypted centroids into the oracle core(s).
    oracle_test_client.app.state.core.store_encrypted_centroids(
        CTX, result.encrypted_centroids,
    )

    graph = LightConeGraph()
    graph.add_context(CTX)
    graph.add_edge(Edge(owner.did, CTX, "owns"))

    def resolve(_endpoint: str) -> OracleClient:
        return HttpOracleClient(client=oracle_test_client)

    engine = FlareQueryEngine(
        storage=storage, lightcone=graph, oracle_resolver=resolve,
        padding_width=padding_width,
    )

    now = datetime(2026, 4, 7, 12, 0, 0)
    for q in qs[:10]:
        engine.search(owner, q, k=K, nprobe=NPROBE, now=now)

    t0 = time.perf_counter()
    encrypted_hits = []
    for q in qs:
        hits, _ = engine.search(owner, q, k=K, nprobe=NPROBE, now=now)
        encrypted_hits.append([h.vector_id for h in hits])
    t_enc = time.perf_counter() - t0

    rec = [
        len(set(map(int, truth_ids)) & set(hit_ids)) / K
        for truth_ids, hit_ids in zip(truth, encrypted_hits)
    ]
    recall = sum(rec) / len(rec)

    return {
        "phase": 4,
        "config": label,
        "padding_width": padding_width,
        "n_vectors": N,
        "dim": DIM,
        "nlist": NLIST,
        "nprobe": NPROBE,
        "k": K,
        "queries": QUERIES,
        "plaintext_brute_force_total_s": round(t_plain, 4),
        "encrypted_flare_total_s": round(t_enc, 4),
        "plaintext_per_query_ms": round(1000 * t_plain / QUERIES, 3),
        "encrypted_per_query_ms": round(1000 * t_enc / QUERIES, 3),
        "encrypted_overhead_ratio": round(t_enc / t_plain, 3),
        "recall_at_k": round(recall, 4),
    }


def main() -> None:
    out = Path("paper/evals")
    out.mkdir(parents=True, exist_ok=True)

    single = _run("single-replica", _build_single_stack)
    single["notes"] = (
        "Phase 4 single-replica oracle: signed grants, signed + replay-protected "
        "storage writes, Ed25519+ECIES batch wire with TTL on every cell key. "
        "No threshold, no padding. Lower bound on Phase 4 oracle latency."
    )
    print(json.dumps(single, indent=2))
    (out / "phase4_bench_single.json").write_text(json.dumps(single, indent=2))

    threshold = _run("threshold-K2-of-M3", _build_threshold_stack)
    threshold["threshold_k"] = THRESHOLD_K
    threshold["threshold_m"] = THRESHOLD_M
    threshold["notes"] = (
        "Phase 4 threshold (K=2 of M=3): one parallel peer share-fetch round "
        "trip per batch. Reconstructed master key held in coordinator memory "
        "(SecureBytes wrapper, zeroized after use)."
    )
    print(json.dumps(threshold, indent=2))
    (out / "phase4_bench_threshold.json").write_text(json.dumps(threshold, indent=2))

    padded = _run("threshold-K2-of-M3-padded", _build_threshold_stack, padding_width=NPROBE * 2)
    padded["threshold_k"] = THRESHOLD_K
    padded["threshold_m"] = THRESHOLD_M
    padded["notes"] = (
        "Phase 4 threshold + constant-width padding: every oracle batch is "
        "padded to NPROBE*2 cells with random authorized cells whose keys are "
        "discarded. Closes oracle access-pattern leakage at the cost of K extra "
        "ECIES decryptions per query."
    )
    print(json.dumps(padded, indent=2))
    (out / "phase4_bench_threshold_padded.json").write_text(json.dumps(padded, indent=2))

    print(f"\nWrote {out}/phase4_bench_*.json")


if __name__ == "__main__":
    main()
