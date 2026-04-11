"""Per-query latency breakdown for FLARE on real data.

Measures wall-clock time spent in each pipeline stage of a single
query, averaged over many queries on BEIR SciFact. The output is the
honest answer to "where does the 100ms go?".

Prints a table; writes to paper/evals/profile.json.
"""
from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np
from datasets import load_dataset
from fastapi.testclient import TestClient
from sentence_transformers import SentenceTransformer

from flare.bootstrap import bootstrap_context
from flare.crypto import EncryptedCell, decrypt_cell, fresh_master_key
from flare.bootstrap import deserialize_cell
from flare.identity import Identity
from flare.ledger import build_ledger_app
from flare.ledger.client import HttpLedgerClient
from flare.lightcone import Edge, LightConeGraph
from flare.oracle import build_oracle_app
from flare.oracle.client import HttpOracleClient
from flare.query import FlareQueryEngine
from flare.storage import build_storage_app
from flare.storage.client import HttpStorageClient

DATASET = "BeIR/scifact"
EMBED_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
NLIST = 32
NPROBE = 8
K = 10
N_QUERIES = 50
CTX = "scifact"


def main():
    print("Loading dataset + model + embedding...")
    corpus_ds = load_dataset(DATASET, "corpus")["corpus"]
    queries_ds = load_dataset(DATASET, "queries")["queries"]
    model = SentenceTransformer(EMBED_MODEL)
    doc_texts = [(r.get("title", "") + ". " + r.get("text", "")).strip() for r in corpus_ds]
    doc_vecs = model.encode(doc_texts, batch_size=64, normalize_embeddings=True,
                            convert_to_numpy=True, show_progress_bar=False).astype(np.float32)
    q_texts = [r["text"] for r in list(queries_ds)[:N_QUERIES]]
    q_vecs = model.encode(q_texts, batch_size=64, normalize_embeddings=True,
                          convert_to_numpy=True, show_progress_bar=False).astype(np.float32)

    print("Bringing up FLARE stack...")
    owner = Identity.generate()
    master = fresh_master_key()
    oracle_id = Identity.generate()
    ledger_app = build_ledger_app()
    ledger = HttpLedgerClient(client=TestClient(ledger_app))
    storage_app = build_storage_app()
    storage = HttpStorageClient(client=TestClient(storage_app))
    oracle_app = build_oracle_app(
        owner_did=owner.did,
        ledger_client=HttpLedgerClient(client=TestClient(ledger_app)),
        master_key=master,
        oracle_identity=oracle_id,
    )
    oracle_client = TestClient(oracle_app)

    bootstrap_result = bootstrap_context(
        storage=storage, context_id=CTX,
        owner_identity=owner, oracle_endpoint="http://oracle.local",
        oracle_did=oracle_id.did,
        vectors=doc_vecs, ids=np.arange(len(doc_vecs), dtype=np.int64),
        master_key=master, nlist=NLIST,
        ledger_client=ledger,
    )
    oracle_app.state.core.store_encrypted_centroids(
        CTX, bootstrap_result.encrypted_centroids,
    )
    for cell_ref, wrapped in bootstrap_result.wrapped_ceks.items():
        oracle_app.state.core.store_wrapped_cek(cell_ref, wrapped)
    graph = LightConeGraph()
    graph.add_context(CTX)
    graph.add_edge(Edge(owner.did, CTX, "owns"))

    def resolve(_):
        return HttpOracleClient(client=oracle_client)
    engine = FlareQueryEngine(storage=storage, lightcone=graph, oracle_resolver=resolve)

    # Warm-up
    for q in q_vecs[:5]:
        engine.search(owner, q, k=K, nprobe=NPROBE)

    # Profile each stage by re-running the same operations from outside
    # the engine and timing them. (We don't instrument the engine itself
    # because that would change its semantics.)
    print(f"\nProfiling {N_QUERIES} queries...\n")

    timings = defaultdict(list)
    from flare.wire import build_batch_request, verify_and_decrypt_batch_response
    from flare.crypto import EncryptedCell

    for q in q_vecs:
        # 1. list_contexts
        t0 = time.perf_counter()
        regs = storage.list_contexts()
        timings["1. list_contexts"].append(time.perf_counter() - t0)

        # 2. request centroids from oracle (per context)
        t0 = time.perf_counter()
        centroids_by_ctx = {}
        oc = HttpOracleClient(client=oracle_client)
        for r in regs:
            result = oc.request_centroids(owner, oracle_id.did, [r.context_id])
            blob = result.get(r.context_id)
            if blob is not None:
                from flare.bootstrap import deserialize_centroids
                centroids_by_ctx[r.context_id] = deserialize_centroids(blob)
        timings["2. request_centroids (per ctx)"].append(time.perf_counter() - t0)

        # 3. centroid distance / topk
        t0 = time.perf_counter()
        scored = []
        for ctx_id, c in centroids_by_ctx.items():
            d = np.linalg.norm(c - q.reshape(1, -1), axis=1)
            for cluster_id, dist in enumerate(d):
                scored.append((float(dist), ctx_id, int(cluster_id)))
        scored.sort(key=lambda t: t[0])
        top_cells = scored[:NPROBE]
        timings["3. centroid distance + topk"].append(time.perf_counter() - t0)

        # 4. get_registration per ctx (only the contexts in the candidates)
        t0 = time.perf_counter()
        unique_ctxs = list({c[1] for c in top_cells})
        regs_by_ctx = {ctx: storage.get_registration(ctx) for ctx in unique_ctxs}
        timings["4. get_registration"].append(time.perf_counter() - t0)

        # 5. parallel cell prefetch
        from concurrent.futures import ThreadPoolExecutor
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(storage.get_cell, c[1], c[2]): c for c in top_cells}
            cells = {(c[1], c[2]): f.result() for f, c in zip(futs.keys(), top_cells)}
        timings["5. cell prefetch (parallel)"].append(time.perf_counter() - t0)

        # 6. oracle batch (signed Ed25519 + ECIES)
        t0 = time.perf_counter()
        cell_pairs = [(c[1], c[2]) for c in top_cells]
        materials = build_batch_request(owner, cell_pairs)
        r = oracle_client.post("/issue-batch", json=materials.request.model_dump())
        from flare.wire import BatchIssueKeyResponse
        resp = BatchIssueKeyResponse.model_validate(r.json())
        keys = verify_and_decrypt_batch_response(materials, resp, oracle_id.did)
        timings["6. oracle batch (sign+verify+ecies)"].append(time.perf_counter() - t0)

        # 7. decrypt + ANN per cell
        t0 = time.perf_counter()
        all_hits = []
        for (cell_pair, key) in zip(cell_pairs, keys):
            blob = cells[cell_pair]
            ec = EncryptedCell.from_bytes(blob)
            aad = f"{cell_pair[0]}:{cell_pair[1]}".encode("utf-8")
            plaintext = decrypt_cell(key.key, ec, associated=aad)
            vectors, ids = deserialize_cell(plaintext)
            d = np.linalg.norm(vectors - q.reshape(1, -1), axis=1)
            order = np.argsort(d)[:K]
            all_hits.extend([(int(ids[i]), float(-d[i])) for i in order])
        all_hits.sort(key=lambda h: h[1], reverse=True)
        timings["7. decrypt + ANN + merge"].append(time.perf_counter() - t0)

    print(f"{'stage':<45} {'mean ms':>10} {'%':>8}")
    print("-" * 65)
    means = {k: 1000 * np.mean(v) for k, v in timings.items()}
    total = sum(means.values())
    for k, m in means.items():
        print(f"{k:<45} {m:>10.2f} {100*m/total:>7.1f}%")
    print("-" * 65)
    print(f"{'TOTAL':<45} {total:>10.2f} {100.0:>7.1f}%")

    out = Path("paper/evals")
    out.mkdir(parents=True, exist_ok=True)
    (out / "profile.json").write_text(json.dumps(
        {"queries": N_QUERIES, "stages_ms": means, "total_ms": total}, indent=2))
    print(f"\nWrote {out / 'profile.json'}")


if __name__ == "__main__":
    main()
