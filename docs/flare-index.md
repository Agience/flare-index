# FLARE Index — Forward-Lit Authorized Retrieval over Encrypted Indexes

Status: **Proposal — Research Prototype**
Date: 2026-04-07

## Summary

The FLARE Index is a decentralized, physically-enforced semantic search system where:

- A **single global ontology** is searchable from any participant's position
- Access is enforced **physically** via encryption, not logically via ACLs
- **Grants ARE keys** — issuing a grant extends what the receiver can decrypt
- **Revocation is instant** — an oracle stops issuing keys; no re-encryption needed
- **Participants own their data** by delegating key issuance to oracles they control
- **Nodes earn incentives** for storage and oracle availability via a blockchain ledger

The system unifies three independently-documented ideas:

1. [Light-Cone Graph Authorization](light-cone-graph-authorization.md) — graph reachability determines who can see what
2. [Partitioned Encrypted Vector Search](partitioned-encrypted-vector-search.md) — IVF cluster cells encrypted with per-cluster derived keys
3. **Oracle-Delegated Key Management** (this document) — owner-trusted intermediaries issue ephemeral keys gated by grant validity

No existing system combines all three. Ocean Protocol handles data access economics but not vector search. Solid handles sovereignty but enforces access logically, not physically. FAISS handles vector indexing but in plaintext. The FLARE Index fills the gap.

---

## Architecture

### The FLARE Index Stack

```
┌─────────────────────────────────────────────────────────────────────┐
│  QUERY LAYER                                                        │
│  User submits query embedding → centroid routing → cluster selection │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  AUTHORIZATION LAYER (Light Cone)                                   │
│  Graph traversal: principal → grants → authorized context set       │
│  Output: set of context_ids the principal can reach                 │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  KEY ISSUANCE LAYER (Oracle Network)                                │
│  For each authorized context_id:                                    │
│    ask owner's oracle → oracle checks grant → issues ephemeral key  │
│  Keys are HKDF-derived, never stored, never reused                  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  SEARCH LAYER (Encrypted IVF)                                       │
│  Decrypt authorized cluster cells → ANN search within cells         │
│  Merge results across cells → rank → return                         │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STORAGE LAYER (Distributed Encrypted Shards)                       │
│  Each node stores encrypted cluster shards                          │
│  Shards are ciphertext — useless without oracle-issued keys         │
│  Nodes earn rewards for storage availability                        │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow for a Single Query

```
1. Alice submits query q with embedding e_q

2. Light cone traversal:
   Alice's principal → graph reachability → authorized contexts

3. Centroid routing (oracle-gated encrypted centroids):
   Oracle delivers centroid maps for authorized contexts via ECIES
   e_q compared against centroids → candidate clusters {C3, C7, C15}
   → only clusters in authorized contexts are ever considered

4. Oracle key requests (parallel):
   C3 owned by Alice → Alice's oracle issues key immediately (local)
   C7 owned by Bob → Bob's oracle checks grant ledger → valid → issues key
   C15 owned by Carol → Carol's oracle checks grant ledger → valid → issues key

5. Forward illumination (predictive):
   Model predicts adjacent clusters {C4, C8, C16} might be needed
   → pre-request keys in background (oracle checks, issues or denies)

6. Decryption + ANN search:
   Decrypt C3, C7, C15 cells with issued keys
   → run inner product / cosine similarity within each cell
   → merge, rank, return top-K results

7. Key expiry:
   Ephemeral keys discarded after query completes
   No key material persists on Alice's node
```

---

## Component Design

### 1. Light Cone Authorization Graph

Fully documented in [light-cone-graph-authorization.md](light-cone-graph-authorization.md). Summary of the interface this system consumes:

**Input:** principal_id, query_time
**Output:** set of authorized context_ids (workspace, collection, project, channel, etc.)

The graph is stored in ArangoDB (or equivalent graph DB). Traversal is bounded by hop limit K and edge-type grammar. Deny edges override any allow path. Derived data inherits audience constraints via monotone sensitivity rules.

**Key property for this system:** the context_ids returned by the light cone map 1:1 to encryption domains (cluster partitions). The authorization result is simultaneously the decryption scope.

### 2. Partitioned Encrypted Vector Index

Documented in [partitioned-encrypted-vector-search.md](partitioned-encrypted-vector-search.md). Extended here with context-aligned partitioning and oracle integration.

#### Context-Aligned Clustering

Standard IVF clusters by vector similarity (k-means). This system clusters by **context boundary first**, then by similarity within each context:

```
Context: workspace_42
  └── Cluster C3: vectors 0..1023  (encrypted with key derived from "workspace_42:C3")
  └── Cluster C4: vectors 1024..2047 (encrypted with key derived from "workspace_42:C4")

Context: project_17
  └── Cluster C7: vectors 0..511   (encrypted with key derived from "project_17:C7")
```

Each cluster cell is encrypted with: `AES-GCM(HKDF(owner_master_key, context_id + ":" + cluster_id), cell_data)`

The centroids (cluster centers) remain unencrypted. They encode the topology of the vector space — where clusters are, not what's in them. An observer can see the shape of the space but not the content.

#### Cross-Context Search

A single query touches multiple contexts. The routing layer:

1. Finds the nearest centroids globally (across all contexts)
2. Filters to only authorized contexts (light cone result)
3. Requests keys for authorized clusters from their respective oracles
4. Searches within each decrypted cell independently
5. Merges results using score-based ranking across all cells

The FLARE Index is naturally parallel. Each cell search is independent once the key is in hand.

#### Index Maintenance

When new vectors are added to a context:
- Assign to the nearest cluster within that context
- Re-encrypt the updated cell with the same derived key
- Update the centroid if the cluster has shifted significantly
- Publish the updated centroid (plaintext) to the routing layer

When a context is re-keyed (master key rotation):
- Oracle issues new derived keys for all clusters in that context
- Each cluster cell is decrypted with the old key, re-encrypted with the new key
- This is a bulk operation, not per-query — amortized to key rotation frequency

### 3. Oracle Network

The oracle is the trust anchor. Each data owner delegates their master key to one or more oracle nodes they control.

#### Oracle Responsibilities

1. **Hold the owner's master key** (or a share of it under threshold scheme)
2. **Receive key requests** from querying nodes: `(requester_id, context_id, cluster_id)`
3. **Check grant validity** against the grant ledger (blockchain or local cache)
4. **Derive and issue ephemeral keys** if grant is valid: `HKDF(master_key, context_id + ":" + cluster_id) → cell_key`
5. **Refuse** if grant is revoked, expired, or never existed
6. **Log issuance** (optional, for audit trail)

#### Trust Model

The oracle is trusted by its owner — and only by its owner. The system does not require trust in any central authority, platform operator, or third-party infrastructure.

```
Alice's data → Alice's oracle → Alice decides who gets keys
Bob's data   → Bob's oracle   → Bob decides who gets keys
```

If Alice wants Bob to find her data in search, she issues a grant (published to the ledger). Bob's routing layer discovers the grant. When Bob's query hits Alice's clusters, the routing layer asks Alice's oracle for keys. Alice's oracle checks the ledger, confirms the grant, issues the key. The key is ephemeral — valid for one query, one cluster.

**Revocation:** Alice revokes Bob's grant on the ledger. Next time Bob's query hits Alice's clusters, Alice's oracle checks the ledger, finds no valid grant, refuses. No re-encryption. No key rotation. No coordination. Instant.

#### Threshold Oracle (Availability + Security)

A single oracle is a single point of failure and a single point of compromise. The threshold model mitigates both:

- Owner splits their master key into M shares via Shamir Secret Sharing
- Distributes shares to M oracle nodes (chosen by the owner)
- Any K-of-M must co-sign a key derivation request
- No single oracle can derive keys alone
- Up to M-K oracles can fail without loss of availability

The owner chooses K and M based on their risk tolerance:
- High availability: K=2, M=5 (any 2 of 5)
- High security: K=4, M=5 (need 4 of 5 to agree)
- Paranoid: K=3, M=7 across geographically distributed nodes

#### Oracle Co-Location with Storage Nodes

For performance: co-locate oracle shards with storage nodes. The node that stores cluster C3's encrypted shard also holds one oracle share for that context's owner. Key derivation + cell decryption happen on the same machine. No network round-trip for key issuance.

This is the natural economic incentive: a node that provides both storage and oracle services earns on both. The economics prefer co-location.

### 4. Grant Ledger (Blockchain)

The grant ledger is the public, verifiable record of who has granted access to whom. It does NOT store keys, data, or embeddings. It stores grant records.

#### Grant Record Schema

```json
{
  "grant_id": "uuid",
  "grantor": "alice_did",
  "grantee": "bob_did",
  "context_id": "workspace_42",
  "scope": "read",
  "issued_at": "2026-04-07T12:00:00Z",
  "expires_at": "2026-07-07T12:00:00Z",
  "revoked_at": null,
  "oracle_endpoints": ["oracle1.alice.net", "oracle2.alice.net"],
  "quorum": 2
}
```

#### What the Ledger Enables

1. **Grant discovery:** Bob's routing layer queries the ledger to find all contexts he has access to. This populates his light cone without requiring Alice to push anything.
2. **Oracle routing:** The grant record includes oracle endpoints. Bob's routing layer knows where to request keys.
3. **Revocation verification:** Oracles check the ledger before issuing keys. If `revoked_at` is set, no key issuance.
4. **Audit trail:** Every grant, revocation, and expiration is publicly verifiable.
5. **No central authority:** No platform operator controls the ledger. Grant issuance is self-sovereign.

#### Why Blockchain and Not a Database

A centralized grant database works for single-tenant deployments (Agience today). For a global multi-party ontology:

- **No trusted operator:** No single party controls grant issuance
- **Tamper evidence:** Grants cannot be backdated, silently revoked, or fabricated
- **Availability:** The ledger survives any single party going offline
- **Cross-party discovery:** Participants can discover grants from parties they've never directly communicated with

The ledger does not need high throughput. Grant issuance and revocation are infrequent operations (orders per day, not per second). A lightweight chain or a layer-2 anchored to a mainnet is sufficient.

### 5. Node Incentive Model

Nodes participate in the network by providing storage, oracle services, or both. They earn rewards for availability and correctness.

#### Roles

| Role | What it does | Earns |
|---|---|---|
| **Storage node** | Stores encrypted cluster shards, serves them on request | Per-shard-per-epoch storage fee |
| **Oracle node** | Holds master key shares, issues ephemeral keys on valid grant | Per-issuance fee |
| **Routing node** | Maintains centroids, routes queries to correct storage/oracle nodes | Per-query routing fee |
| **Index node** | Computes embeddings, maintains IVF cluster assignments | Per-indexing-operation fee |

A single physical node can serve multiple roles. Co-location of storage + oracle is incentivized by eliminating network latency.

#### Slashing Conditions

- **Oracle issues key for revoked grant:** stake slashed (detectable if grantee reports it or via audit)
- **Storage node fails to serve shard within SLA:** stake slashed
- **Oracle unavailable beyond threshold:** stake reduced proportionally

#### Economic Flow

```
Query fee (paid by querier)
    │
    ├── Routing fee → routing node
    ├── Oracle fee  → oracle node(s) (split across quorum)
    └── Storage fee → storage node(s) serving the shards
```

The query fee is micro — fractions of a cent. The aggregate across many queries makes hosting worthwhile. This is the Filecoin model applied to vector search infrastructure.

---

## The Global Ontology

The system described above is a substrate. What runs on top of it is a **single, globally-addressable semantic knowledge graph** where:

- Every participant's data exists in the same vector space
- Clusters partition by context boundary (ownership, project, workspace)
- Any cluster can neighbor any other — proximity is semantic, not organizational
- Access is physical: without the key, a cluster is noise

**What this feels like to the user:**

You search with a natural language query. Results come from:
1. Your own data (your clusters, your oracle, instant)
2. Data you've been granted access to (their clusters, their oracles, key request)
3. Nothing else — unauthorized clusters are invisible, not just hidden

If someone grants you access to a new context, the next search illuminates it automatically. No configuration, no import, no sync. The grant on the ledger is the entire mechanism.

**What this feels like at scale:**

Millions of participants, billions of vectors, distributed across thousands of nodes. Each query touches a small number of clusters (IVF routing is O(√N) for N total vectors). Each cluster key request is parallel. The FLARE Index scales horizontally — more nodes, more storage, more oracles, same query latency profile.

The centroids form a global routing table. The clusters are encrypted shards. The oracles are per-owner key servers. The ledger is the grant discovery layer. The light cone graph is the authorization model. Everything composes.

---

## Forward Illumination and Predictive Routing

The "light in a dark space" optimization: don't wait for the exact query result to request keys. Work ahead.

### Static Forward Illumination

During centroid routing, the system identifies a candidate set of clusters. Request keys for all candidates in parallel, even before ANN search confirms which are needed. The overhead is K extra key requests (where K = nprobe - actual_hits). These are cheap — the oracle checks a grant and returns a derived key. If some aren't needed, they expire unused.

### Predictive Forward Illumination

A learned model predicts, given a query embedding and a user's light cone, which clusters the user is likely to search next. This can be:
- N-gram style: user searched C3 → likely to search C4, C7 next
- Embedding-based: query is in region R → adjacent clusters sorted by centroid distance
- Session model: user's search pattern this session suggests narrowing in direction D

Pre-request keys for predicted clusters before the user's next query arrives. If the prediction is correct, the next query is faster — keys are already in hand. If wrong, the keys expire harmlessly.

### Access Pattern Obfuscation via Prediction

The predictive model has a security benefit: if the routing layer always requests keys for a fixed number of clusters K (actual + predicted + random padding), an observer monitoring oracle requests sees a constant-width pattern regardless of query specificity. The real query is hidden in the noise of predictive and padded requests.

This reduces — but does not eliminate — access pattern leakage. The residual leak is which *contexts* (owners) are being queried, not which clusters within those contexts. For most multi-party search scenarios, this is an acceptable threat model.

---

## Technology Stack

### Core Infrastructure

| Component | Technology | Why |
|---|---|---|
| **Vector index** | [FAISS](https://github.com/facebookresearch/faiss) (Meta, BSD) | IVF partitioning is first-class. Python and C++ bindings. GPU support. Most mature ANN library. |
| **Graph database** | [ArangoDB](https://github.com/arangodb/arangodb) (Apache 2.0) | Native graph traversal with AQL. Already used in Agience. Multi-model (document + graph + search). |
| **Key derivation** | [cryptography](https://github.com/pyca/cryptography) (Python, BSD) | HKDF, AES-GCM, Fernet. Audited, widely used. |
| **Secret sharing** | [Shamir's Secret Sharing](https://github.com/blockstack/secret-sharing) or [py-ssss](https://pypi.org/project/ssss/) | Threshold oracle key splitting. Well-understood cryptographic primitive. |
| **Embeddings** | [sentence-transformers](https://github.com/UKPLab/sentence-transformers) (Apache 2.0) or any OpenAI-compatible provider | Model-agnostic — the system works with any embedding model. |

### Blockchain / Ledger

| Option | Characteristics | Best for |
|---|---|---|
| [Ethereum L2 (Arbitrum, Optimism, Base)](https://ethereum.org/) | EVM-compatible, low gas on L2, strong ecosystem | Production mainnet anchoring |
| [Cosmos SDK](https://github.com/cosmos/cosmos-sdk) (Apache 2.0) | App-specific chains, Tendermint BFT consensus, IBC cross-chain | Purpose-built sovereign chain |
| [Hyperledger Fabric](https://github.com/hyperledger/fabric) (Apache 2.0) | Permissioned, no token required, enterprise-focused | Enterprise/consortium deployments where public chain is unacceptable |
| [Ceramic Network](https://github.com/ceramicnetwork/ceramic) (MIT) | Decentralized data streams, DID-anchored, IPFS-backed | Lighter-weight grant streams without full chain overhead |

**Recommendation for prototype:** Ceramic or Ethereum L2. Ceramic is simpler (data streams, no smart contracts needed). Ethereum L2 is more mature for economic incentive models (staking, slashing).

### Identity

| Component | Technology | Why |
|---|---|---|
| **Decentralized identity** | [DID (W3C standard)](https://www.w3.org/TR/did-core/) | Self-sovereign identity, no central authority. Every participant has a DID. |
| **DID method** | [did:key](https://w3c-ccg.github.io/did-method-key/) (simple) or [did:ethr](https://github.com/decentralized-identity/ethr-did-resolver) (Ethereum-anchored) | did:key for prototype, did:ethr for production (on-chain resolution). |
| **Verifiable credentials** | [W3C VC](https://www.w3.org/TR/vc-data-model/) | Grants can be expressed as verifiable credentials — portable, cryptographically signed, revocable. |

### Networking

| Component | Technology | Why |
|---|---|---|
| **P2P messaging** | [libp2p](https://github.com/libp2p/py-libp2p) (MIT) | Peer discovery, pubsub, DHT. Used by IPFS, Filecoin, Ethereum 2. |
| **Encrypted transport** | [Noise Protocol Framework](https://noiseprotocol.org/) (via libp2p) | End-to-end encrypted channels between nodes. No TLS CA dependency. |
| **Content addressing** | [IPFS / CID](https://github.com/ipfs/ipfs) (MIT) | Cluster shards addressable by content hash. Deduplication. Location-independent retrieval. |
| **Shard distribution** | [IPFS Bitswap](https://github.com/ipfs/go-bitswap) or custom protocol on libp2p | Request specific encrypted shards from nodes that have them. |

### Oracle Implementation

| Component | Technology | Why |
|---|---|---|
| **Oracle framework** | Custom service on [FastAPI](https://github.com/tiangolo/fastapi) (MIT) or gRPC | Simple request-response: `(requester_did, context_id, cluster_id) → key or deny` |
| **Grant verification** | Ledger query (cached locally with TTL) | Oracle caches recent grant state, refreshes from chain/stream periodically |
| **Key derivation** | `cryptography.hazmat.primitives.kdf.hkdf.HKDF` | Standard HKDF with SHA-256. Master key + context_id:cluster_id as info parameter. |
| **Threshold co-signing** | [threshold-crypto](https://github.com/poanetwork/threshold_crypto) (Rust, MIT) or Shamir over Python | K-of-M threshold signing for key issuance. No single oracle can derive alone. |
| **TEE (optional, hardened)** | Intel SGX via [Gramine](https://github.com/gramineproject/gramine) (LGPL) or AMD SEV | Master key lives in hardware enclave. Oracle operator cannot extract it. |

### Monitoring and Observability

| Component | Technology |
|---|---|
| **Metrics** | Prometheus + Grafana |
| **Tracing** | OpenTelemetry (query path: routing → auth → oracle → search → merge) |
| **Audit log** | Append-only log per oracle (signed entries) |

---

## Implementation Phases

### Phase 0: Single-Node Proof of Concept

**Goal:** Demonstrate encrypted IVF search with per-cluster key derivation.

- FAISS `IndexIVFFlat` with synthetic data (100K–1M vectors)
- Per-cluster AES-GCM encryption using HKDF-derived keys
- Single master key, single process, no oracle, no network
- Benchmark: plaintext IVF vs. encrypted IVF query latency
- Deliverable: Python library, benchmark results, threat model document

**Tech:** FAISS, cryptography (Python), NumPy

### Phase 1: Oracle + Grant-Gated Search

**Goal:** Multi-party search with oracle-mediated key issuance.

- Two participants, each with their own master key and oracle
- Grants published to a local grant store (simulated ledger)
- Query flow: centroid routing → grant check → oracle key request → decrypted search
- Revocation test: revoke grant, confirm search no longer returns results from that context
- Deliverable: two-party demo, revocation proof

**Tech:** Phase 0 + FastAPI (oracle service), SQLite or in-memory grant store

### Phase 2: Distributed Storage + P2P

**Goal:** Shards distributed across multiple nodes.

- Multiple storage nodes, each holding encrypted shards
- libp2p for peer discovery and shard retrieval
- Routing node maintains global centroid table
- Query crosses node boundaries: routing node dispatches shard requests, collects results
- Deliverable: multi-node cluster, cross-node search demo

**Tech:** Phase 1 + libp2p, IPFS (content-addressed shard storage)

### Phase 3: Blockchain Ledger + Threshold Oracle

**Goal:** Decentralized grant registry and fault-tolerant key issuance.

- Grants published to Ceramic streams or Ethereum L2 smart contract
- Threshold oracle: K-of-M key issuance using Shamir secret sharing
- Oracle liveness: demonstrate continued operation with M-K nodes offline
- Grant discovery: new participant discovers existing grants via ledger query
- Deliverable: fully decentralized prototype, no single point of trust or failure

**Tech:** Phase 2 + Ceramic or Hardhat (Ethereum L2 dev), threshold-crypto

### Phase 4: Incentive Model + Forward Illumination

**Goal:** Economic sustainability and query optimization.

- Token-based rewards for storage and oracle availability
- Slashing for oracle misbehavior (key issuance on revoked grant)
- Predictive forward illumination model (learned from query patterns)
- Access pattern padding (constant-width oracle request batches)
- Deliverable: incentivized network, optimized query latency, privacy analysis

**Tech:** Phase 3 + smart contract (staking/slashing), simple ML model for prediction

---

## Threat Model

### What This System Protects Against

| Threat | Protection |
|---|---|
| Unauthorized data access | Physical — cluster cells are ciphertext without oracle-issued key |
| Compromised storage node | Sees only ciphertext. No keys, no plaintext, no master key. |
| Compromised single oracle node (in threshold mode) | Has only one share. Cannot derive keys alone. |
| Revoked user attempting search | Oracle refuses key issuance. No client-side key to exploit. |
| Platform operator coercion | No platform operator holds keys. Oracles are owner-delegated. |
| Stolen / seized hardware | Encrypted at rest. Keys are ephemeral and not stored on disk. |
| Man-in-the-middle on query path | Noise protocol / TLS between nodes. Keys are derived per-query. |

### What This System Does NOT Protect Against

| Threat | Limitation | Mitigation |
|---|---|---|
| Compromised oracle quorum (K-of-M) | If K oracles are compromised simultaneously, keys can be derived | Increase K, distribute oracles across jurisdictions |
| Access pattern analysis | Observer can infer which contexts are queried (not query content) | Constant-width oracle batches, forward illumination padding |
| Centroid analysis | Oracle-gated: centroids are encrypted at rest and delivered only to authorized queriers via ECIES. Residual: authorized querier sees centroid geometry (same as cell keys + results). | Noise calibration / locality-preserving hashing as optional second layer. |
| Embedding inversion | Given a vector, reconstruct the source text | Model-specific attack, not specific to this system. Current models are resistant. |
| Side-channel on decryption node | Timing/power analysis during cell decryption | Standard side-channel mitigations. TEE for hardened deployments. |
| Malicious grantor | Owner grants access then substitutes poisoned data in the cluster | Out of scope — data integrity is a separate problem (sign cells with owner key) |

---

## Relationship to Existing Systems

| System | Similarity | Key Difference |
|---|---|---|
| **Solid (Berners-Lee)** | Self-sovereign data pods, user-controlled access | Solid is logical ACL enforcement. This is physical (encryption). Solid has no vector search. |
| **Ocean Protocol** | Blockchain-gated data access, economic incentives | Ocean is for flat datasets / data marketplaces, not vector search or semantic retrieval. |
| **Filecoin / IPFS** | Incentivized distributed encrypted storage | Storage only. No search, no graph authorization, no oracle key management. |
| **Weaviate / Qdrant / Milvus** | Distributed vector search | Plaintext indexes. No per-cluster encryption. No grant-gated access. |
| **AWS KMS** | Online key derivation, per-request key issuance | Centralized — single operator controls all keys. Not self-sovereign. |
| **Attribute-Based Encryption (ABE)** | Policy-gated decryption | Not applied to IVF partitions. No oracle delegation. No revocation without re-encryption. |
| **Private Information Retrieval (PIR)** | Query privacy | Hides what was queried, not what is stored. Different threat model. |
| **FHE vector search** | Compute on encrypted data | 3–4 orders of magnitude too slow. Not production-viable. |

**The novel contribution (FLARE Index):** No existing system combines graph-reachability authorization + physically-enforced per-cluster encryption + oracle-delegated ephemeral key issuance + decentralized grant ledger + distributed incentivized storage — all over a semantic vector index.

---

## Open Questions

1. **Cluster granularity vs. key overhead:** How many clusters per context before key derivation overhead dominates? Likely O(100K) clusters is fine — HKDF is microseconds. Need to benchmark.

2. **Cross-context semantic coherence:** If clusters are context-aligned rather than purely similarity-aligned, do cross-context queries suffer accuracy loss? Hypothesis: minor, because the centroid routing still selects by vector distance. Need to benchmark recall@K vs. standard IVF.

3. **Centroid privacy:** Centroids are now encrypted at rest and oracle-gated, so a storage-level adversary learns nothing. An authorized querier sees the centroid map, but the same querier already receives cell keys and decrypted search results. Formal bounding of residual information leakage from centroid geometry in high-dimensional embedding space remains open.

4. **Oracle latency at scale:** With 10,000 participants, each with their own oracle, a query that touches 50 contexts requires 50 parallel oracle requests. Is this feasible at p95 < 200ms? Likely yes if oracles are co-located with storage, but needs measurement.

5. **Incentive equilibrium:** What is the minimum network size for the incentive model to be self-sustaining? Need economic modeling.

6. **Regulatory posture:** Does the grant ledger (even without data content) constitute "processing" under GDPR? Likely no — grant records contain DIDs and context IDs, not personal data. But needs legal review.

---

## References

- [Light-Cone Graph Authorization](light-cone-graph-authorization.md) — authorization model
- [Partitioned Encrypted Vector Search](partitioned-encrypted-vector-search.md) — base encryption scheme
- [FAISS: A Library for Efficient Similarity Search](https://github.com/facebookresearch/faiss) — IVF index implementation
- [W3C DID Core](https://www.w3.org/TR/did-core/) — decentralized identity standard
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) — grant representation
- [libp2p](https://libp2p.io/) — P2P networking
- [Ceramic Network](https://ceramic.network/) — decentralized data streams
- [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) — threshold key management
- [HKDF (RFC 5869)](https://datatracker.ietf.org/doc/html/rfc5869) — key derivation function
- [Noise Protocol Framework](https://noiseprotocol.org/) — encrypted transport
