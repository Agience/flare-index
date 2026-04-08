# Partitioned Encrypted Vector Search — Research Sketch

Date: 2026-04-07

## The Problem

Production vector databases (FAISS, Qdrant, Milvus, Weaviate, OpenSearch k-NN) store embedding indexes in plaintext. Encryption at rest is OS-level only — any process running on the node can read the index. Existing academic solutions are either too slow (FHE) or hardware-gated (TEE). There is no software-only, hardware-agnostic approach that provides meaningful content protection for a partitioned vector index.

## The Idea

Standard approximate nearest neighbor indexes (FAISS IVF, Qdrant's HNSW with partitioning) already divide the vector space into clusters. A query finds the nearest cluster centroids first, then searches within those cells. This two-stage structure is a natural encryption domain boundary:

- **Centroids stay unencrypted** — they encode topology, not content
- **Each cell is encrypted with its own derived key** — only cells needed for a query are ever in plaintext simultaneously
- **The query illuminates a bubble** — only the cells the query routes into are decrypted, ahead of the actual search

This is the "light in a dark space" framing: the search shines a predictable path, pre-derives keys for the cells it will enter, and never exposes the rest.

## Key Architecture

```
Master key (customer-held)
       │
       ▼
   HKDF(master_key, cluster_id) ──► per-cluster derived key
                                           │
                                           ▼
                               AES-GCM encrypt(cluster_cell)
```

The routing layer holds centroids + derives per-cluster keys on demand from the master key. No per-cluster key material needs to be stored — derivation is deterministic. The master key never leaves the routing layer.

**Forward illumination** extension: during centroid routing, pre-derive keys for adjacent cells (nprobe + 1 ring) before the ANN search starts. This hides the exact search path from timing-based observers.

## What's Already Available (Don't Rebuild)

| Component | Library |
|---|---|
| IVF partitioned index | FAISS (Meta, open source) |
| HKDF key derivation | Python `cryptography` library |
| Authenticated encryption | AES-GCM, same library |
| Centroid routing | FAISS `IndexIVFFlat` |

The intellectual contribution is the routing layer + per-cluster key derivation schema + the forward illumination optimization. The rest is composition of commodity components.

## Honest Limitations

**Access pattern leakage**: an observer watching which cells get unlocked can learn topic area from the access pattern, even without reading cell contents. Mitigations:

- Fixed-k illumination: always unlock the same number of clusters regardless of query (adds dummy decryptions)
- Dummy cell accesses: touch random non-relevant cells to obscure the real pattern
- TEE routing layer: run centroid lookup + key derivation inside an SGX/SEV enclave — the adversary sees which cells were read from storage but not why

This limitation should be scoped explicitly in any paper. The threat model this solves is: **an actor with access to stored index data but not to the routing layer at query time**. It does not solve the operator-with-live-process-access problem.

## Where This Could Land

- **arXiv preprint** — privacy-preserving ML / applied cryptography
- **PETS (Privacy Enhancing Technologies Symposium)** — fits the scope
- **Open source library** — a thin Python wrapper around FAISS IVF that adds per-cluster key derivation and cell-level AES-GCM storage

## What's Needed to Make It Real

1. Implement the routing layer + key derivation (days)
2. Benchmark: plaintext IVF vs. partitioned encrypted IVF — measure query latency overhead
3. Formalize the threat model (what attacker, what access, what is and isn't protected)
4. Address or explicitly scope the access pattern leakage
5. Write up and release

## Related Prior Work to Survey

- Forward-private Searchable Symmetric Encryption (SSE) literature
- Private Information Retrieval (PIR) + approximate nearest neighbor combinations
- ORAM-based vector search (academic, high overhead)
- Any FAISS + TEE papers from Meta/FAIR privacy groups

## Related

- [FLARE Index](flare-index.md) — unified synthesis combining this scheme with light-cone graph authorization, oracle-delegated key management, and a decentralized incentive model
- [Light-Cone Graph Authorization](light-cone-graph-authorization.md) — the authorization model whose context_ids map to encryption domains in this scheme

## Status

Hobby / future research. Not tied to Agience product roadmap.
