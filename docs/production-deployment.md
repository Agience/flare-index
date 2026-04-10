# FLARE — Production Deployment Architecture

This document describes how to replace the in-process prototype backends with
production-ready infrastructure. The FLARE interfaces are designed to be
backend-agnostic; each section below identifies the abstraction boundary and
what needs to be implemented to swap it.

## Recommended stack

| Component | Role in FLARE | Production backend |
|---|---|---|
| Light-cone graph | Authorization BFS | **ArangoDB** |
| Context registrations + centroids | Routing metadata | **ArangoDB** |
| Encrypted cell blobs | Ciphertext at rest | **MinIO** (self-hosted) or AWS S3 |
| Centroid routing + in-cell ANN | Query-time vector search | **FAISS** (unchanged, in-process) |
| Post-authorization reranking | Hybrid BM25 + semantic ranking | **OpenSearch** |
| Grant ledger | Tamper-evident grant/revoke log | Ceramic / Ethereum L2 (Phase 3) |
| Oracle key issuance | Threshold key derivation | Existing multi-service oracle stack |

## Why each component goes where it does

### FAISS stays in-process

FLARE's vector search is split across two phases:

1. **Centroid routing** — at query time, find the K nearest centroids to the
   query vector. Centroids are encrypted at rest and delivered to authorized
   queriers via the oracle's ECIES protocol (small: e.g. 8 centroids × 384
   floats ≈ 12 KB per context). FAISS `IndexFlatL2.search` routes in microseconds.
2. **In-cell ANN** — after a cell is decrypted, brute-force ANN over its
   векторы. FAISS `IndexFlatL2` again, on the decrypted float array.

Neither step requires a persistent, distributed vector DB. Any production
vector DB (OpenSearch kNN, Qdrant, Weaviate, Pinecone) expects plaintext
vectors. FLARE's cells contain **encrypted** vectors, so a vector DB cannot
build a meaningful index over them and cannot perform ANN on them. Using one
as a blob store would waste the product entirely.

### OpenSearch for post-authorization reranking

OpenSearch fits cleanly **after** `FlareQueryEngine.search()` returns
authorized hits. At that point, the hits are plaintext chunk IDs. OpenSearch
can:

- Fetch full stored document text by ID
- Apply BM25 or hybrid (BM25 + semantic kNN) reranking within the already-
  authorized result set

This is purely additive. FLARE provides authorization completeness guarantees;
OpenSearch improves relevance ordering within what FLARE already authorized.
These are independent concerns and neither undermines the other.

```
FlareQueryEngine.search(query_vec, principal, k)
  -> list[QueryHit]          # authorized, decrypted, ranked by vector distance
      |
      v
OpenSearch hybrid rerank     # BM25 + dense rerank within the hit set
  -> list[RankedResult]      # final response to the user
```

### ArangoDB for the light-cone graph

ArangoDB's native graph traversal AQL maps almost directly to FLARE's BFS:

```aql
-- Equivalent to LightConeGraph.authorized_contexts(principal, k=4)
FOR v, e, p IN 1..4 OUTBOUND @start GRAPH 'flare_authz'
    FILTER p.edges[*].deny ALL == false
    FILTER IS_SAME_COLLECTION('contexts', v)
    RETURN DISTINCT v._key
```

Allow/deny edges become typed edges in a single ArangoDB graph collection.
Path-predicate deny (`RequireAllOf`, `RequireSequence`) maps to `FILTER`
clauses on `p.vertices[*]._key`.

### ArangoDB for context registrations and centroids

Context registrations (owner DID, oracle endpoints, dimension, nlist) are
document records. Centroids are binary blobs attached to the registration
document. ArangoDB handles both natively. This replaces
`flare/storage/memory.py:InMemoryStorageService`.

### MinIO / S3 for encrypted cell blobs

Encrypted cell blobs are content-addressed: they change only when the owner
re-bootstraps. They are pure binary (AES-256-GCM ciphertext). An object store
is the correct abstraction:

- Key: `{context_id}/{cluster_id}` or a hash of the canonical cell reference
- Value: the encrypted blob bytes
- Access: pre-signed URLs or service-to-service auth; no client ever has
  direct object-store credentials — cells flow through the query engine

S3-compatible stores (MinIO self-hosted, AWS S3, GCS, Azure Blob) all work.
MinIO is recommended for on-premises deployments that need to keep data
within a network boundary.

## Implementation guide

### 1. Storage backend (`flare/storage/`)

The `StorageClient` interface (`flare/storage/client.py`) is what the query
engine and bootstrap call. Implement a new `ArangoMinioStorageClient` that
satisfies the same interface:

| Method | ArangoDB | MinIO/S3 |
|---|---|---|
| `register_context(reg, centroids, owner_identity)` | Insert/upsert document | Upload centroids blob |
| `get_centroids(context_id)` | Fetch document | Download centroids blob |
| `put_cell(context_id, cluster_id, ciphertext)` | — | `PUT {context_id}/{cluster_id}` |
| `get_cell(context_id, cluster_id)` | — | `GET {context_id}/{cluster_id}` |
| `list_contexts()` | `FOR d IN registrations RETURN d` | — |

Owner-signed write verification (nonce + timestamp) is already in
`flare/storage/signing.py` and is transport-agnostic — bring it forward
unchanged.

### 2. Light-cone graph (`flare/lightcone.py`)

`LightConeGraph` exposes three mutating methods (`add_edge`, `add_deny`,
`add_deny_path`) and one query method (`authorized_contexts`). Implement an
`ArangoLightConeGraph` backed by the ArangoDB graph API:

- `add_edge(src, dst, type)` → insert edge document `{_from, _to, type, deny: false}`
- `add_deny(src, dst)` → insert edge document `{_from, _to, deny: true}`
- `authorized_contexts(principal, k)` → execute AQL traversal, return set of context IDs

The existing in-memory implementation stays as the test double and single-
process fallback.

### 3. OpenSearch reranking layer

Add a thin wrapper after `FlareQueryEngine.search()`:

```python
def rerank(hits: list[QueryHit], query: str, opensearch_client) -> list[RankedResult]:
    ids = [h.doc_id for h in hits]
    # Fetch stored text from OpenSearch by ID
    docs = opensearch_client.mget(index="flare_docs", ids=ids)
    # Hybrid rerank: BM25 score from OpenSearch + vector score from FLARE
    ...
```

OpenSearch never sees unauthorized document IDs — FLARE's result set is
already filtered before this layer runs.

## What does not change

- `flare/crypto.py` — HKDF + AES-256-GCM, not backend-dependent
- `flare/oracle/` — threshold key issuance, not storage-dependent
- `flare/ledger/` — grant/revoke logic; only the backing store changes (Phase 3)
- `flare/wire.py` — authenticated wire protocol, not backend-dependent
- `flare/identity.py` — DID resolution, not backend-dependent
- `flare/query.py` — `FlareQueryEngine` query pipeline, unchanged except the
  `StorageClient` and `LightConeGraph` implementations it receives

The encryption boundary, the oracle trust model, the wire security
properties, and the `context_id`-as-single-source-of-truth invariant (see
paper §3.8) are all backend-agnostic by design.

## Deployment topology

```
┌─────────────────────────────────────────────────────┐
│  Query node (stateless, horizontally scalable)       │
│  FlareQueryEngine                                    │
│    ├── LightConeGraph → ArangoDB (read-only query)  │
│    ├── StorageClient  → ArangoDB (registrations)    │
│    │                  → MinIO/S3 (cell blobs)       │
│    └── OracleClient   → Oracle service (K-of-M)     │
└─────────────────────────────────────────────────────┘
         │ authorized plaintext hits
         ▼
┌─────────────────────────────────────────┐
│  OpenSearch reranker (BM25 + hybrid)    │
│  Stores full document text by chunk ID  │
└─────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│  Data owner bootstrap (runs once per context)           │
│  bootstrap_context()                                    │
│    ├── FAISS k-means  → centroids                       │
│    ├── AES-256-GCM    → encrypted cell blobs → MinIO   │
│    └── StorageClient.register_context() → ArangoDB     │
└────────────────────────────────────────────────────────┘
```

## Query-engine caching at scale

The `FlareQueryEngine` ships with three caches that together cut single-query
latency by ~12× on the BEIR SciFact benchmark (103 ms → 8.4 ms, recall
unchanged). This section is for operators deciding whether to enable them in
production. Short answer: **the routing and ciphertext caches are
unconditionally viable; the cell-key cache is viable with one operational
contract.**

### What gets cached

| Cache | Holds | Backed by | Scaling profile | Default |
|---|---|---|---|---|
| Routing cache | `list_contexts()`, centroids, context registrations | Per-pod RAM | Tiny — KB to low MB even at 10⁵ contexts | On |
| Cell ciphertext cache | Encrypted cell blobs by `(context_id, cluster_id)` | Per-pod RAM (consider an LRU cap for very large corpora) | Linear in working set; bounded by `nlist × cell_size × hot_context_count` | On |
| Cell-key cache | `IssuedCellKey` entries keyed by `(cell, requester_did)`, each carrying its oracle-signed `valid_until_ns` | Per-pod RAM | Bounded by `concurrent_querier_count × hot_cell_count` | On |

All three live behind a single `RLock` on the engine. Read access from many
threads is safe and tested (`tests/test_query_cache.py::test_concurrent_queries_share_caches_safely`,
8 worker threads × 20 queries each, no races, no leakage).

### Security analysis of each cache

**Routing cache.** Caches centroid maps delivered by the oracle via ECIES,
plus public context registrations. Centroids are oracle-gated: an
unauthorized querier never receives them. Once cached on the authorized
query node, centroids have the same security profile as cached cell keys.
Context registrations are owner-signed and publicly readable. The only
operational concern is staleness after a re-bootstrap — call
`engine.invalidate_routing()` from the data-owner side when a context is
re-published.

**Cell ciphertext cache.** Caches AES-GCM ciphertext. The bytes are opaque
without an oracle-issued cell key, so caching them on a query node leaks
nothing that an attacker who can read the storage service couldn't already
read. Invalidation is **fail-safe by design**: the AAD on each cell binds it
to its `(context_id, cluster_id)` slot, so if a cell were rewritten under
the cache, decryption would fail and the engine refetches. No manual
invalidation is required for correctness.

**Cell-key cache.** This is the only cache with a security contract. Cached
keys are tied to a specific `(cell, requester_did)` — Alice's keys are never
returned to Bob (`tests/test_query_cache.py::test_cell_key_cache_does_not_cross_requesters`).
Each entry carries the oracle-signed `valid_until_ns` and is evicted on
lookup once expired
(`tests/test_query_cache.py::test_cached_keys_respect_ttl`).

The contract: **a cached key is reusable up to its TTL even after a
revocation**. This is the existing security bound — the cell-key TTL was
always the upper limit on how long an issued key remained useful, and the
cache just exposes that bound to its full extent rather than re-issuing every
time. The cache does **not** weaken the revocation guarantee, but a
deployment that wants *immediate* effect on a known revoke must call
`engine.invalidate_cell_keys()` after the revoke. The default TTL is 60 s; a
deployment can tune it shorter at the oracle to bound the worst case.

### Viability at scale

| Concern | Verdict | Reasoning |
|---|---|---|
| Memory growth | Bounded | Working-set limited; routing cache is tiny, ciphertext cache benefits from a bounded LRU above 10⁴ hot cells, cell-key cache evicts lazily as TTLs expire |
| Cache coherence across pods | **Not a problem** | Each cache layer is content-addressed (routing + ciphertext) or per-querier (cell keys). Two pods serving the same querier independently issue the same key from the oracle and never need to reconcile. No distributed cache needed. |
| Multi-tenant safety | **Pinned by tests** | `test_cell_key_cache_does_not_cross_requesters`. The cache key includes the requester DID. |
| Concurrent reads | **Pinned by tests** | `test_concurrent_queries_share_caches_safely` |
| Behavior under revocation | **Pinned and documented** | `test_invalidate_cell_keys_forces_oracle_round_trip`; `engine.invalidate_cell_keys()` is the contract |
| Behavior under re-bootstrap | Manual | `engine.invalidate_routing()` |
| Behavior under cell rewrite | Automatic | AAD-bound GCM rejects stale cells; engine refetches |

### Sizing recommendations

- **Routing cache**: leave unbounded. It is tiny.
- **Cell ciphertext cache**: leave unbounded for working sets up to ~10⁴ hot
  cells per pod (a few hundred MB at typical SciFact-scale cells); add an
  LRU eviction policy above that. The cells are content-addressed so there
  is no correctness risk to evicting eagerly.
- **Cell-key cache**: bounded by the natural TTL. With a 60 s TTL and
  10³ active queriers per pod hitting an average of 8 cells each, that is
  ~8000 entries per pod, ~250 KB. Negligible.

### Disabling the cache

For tests and audits that need to assert "every query round-trips the
oracle", construct the engine with `cache=False`. Pinned by
`tests/test_query_cache.py::test_cache_disabled_round_trips_every_call`.

### Sidecar pattern (recommended)

The largest practical latency win is to **run `FlareQueryEngine` as a sidecar
proxy** on each application node. The application talks to the proxy over
loopback (sub-microsecond); the proxy handles all FLARE complexity and
amortizes the caches across every query the app makes. The proxy holds:

- the querier `Identity`
- all three caches above
- a connection pool to oracle, storage, and ledger services

This is the canonical Kubernetes sidecar pattern (Istio, Linkerd, Envoy
style). The application has zero crypto knowledge and zero round-trip cost
to the proxy. A reference sidecar is straightforward to build on top of
`FlareQueryEngine` — wrap it in a small FastAPI service exposing
`POST /search { embedding, k }`.

### Sharding for horizontal scale

`context_id` is the natural shard key — every cell already knows its context,
and the encryption boundary aligns with the shard boundary. Each storage
shard hosts a subset of contexts (their centroids, ciphertext cells, and
registrations). The query node consults a routing table (`context_id → shard
URL`) and fans out cell prefetches across shards in parallel.

Three places to put the routing table:

| Option | Pros | Cons |
|---|---|---|
| Static config / DNS | Simple, no new infra | Doesn't rebalance |
| Consistent-hash ring (DHT-style) | Auto-rebalance | Need a coordination layer |
| **Embedded in the grant ledger** (each registration carries a `storage_shard_url`) | Reuses existing infra; signed by owner | Owner picks shard at bootstrap time |

The ledger-embedded option fits FLARE best — the registration is already
owner-signed and already lists oracle endpoints. Adding a `storage_shard_url`
to it is one field. The query engine already does multi-endpoint failover
for oracles; the same pattern extends to multi-shard storage with one extra
dimension on the registration.

## Operational notes

- **Nonce caches**: the current implementation keeps per-process in-memory
  nonce caches (replay protection for storage writes and oracle requests).
  In a multi-replica deployment, this must be backed by a shared store
  (Redis with TTL, or ArangoDB with a TTL index). See `docs/analysis/security.md`.
- **Clock skew**: oracle request freshness windows assume NTP-synchronized
  clocks across all services. Maximum skew is currently 60 s.
- **Engine caches**: see the dedicated section above. Routing and ciphertext
  caches are fail-safe; the cell-key cache requires `invalidate_cell_keys()`
  after a known revoke for immediate effect (otherwise revocation is
  TTL-bounded by the existing oracle-signed `valid_until_ns`).
- **Failover**: oracle endpoints are tried in registration order. For true
  high-availability, register replicas in round-robin order across availability
  zones and set a short per-endpoint timeout in `OracleClient`.
- **TLS**: the wire protocol is content-secure (Ed25519 + ECIES) and does not
  *require* TLS for confidentiality. Production deployments should still
  enable TLS at the transport layer for metadata protection (who is talking
  to whom, request sizes, timing) and for HTTP/2 stream multiplexing.
