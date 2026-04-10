# PATENTS

Patent pending. This repository contains inventions for which patent
applications are being prepared. The following invention disclosures
describe the claimed inventions. Use of the source code under the
Apache 2.0 license includes the patent license granted by Section 3
of that license. Independent reimplementations of the described
methods are not covered by the Apache 2.0 patent grant.

Inventor: Ikailo John Sessford
Entity: Ikailo / Agience (to be confirmed)
First public disclosure: April 8, 2026
Jurisdiction: Canada (CIPO), with intent to file PCT

---

## Invention 1 — Path-Predicate Graph Authorization for Information Retrieval ("Light-Cone Authorization")

### Field

Computer security; access control for information retrieval systems.

### Background

Existing access-control models for information retrieval fall into two
categories: role-based access control (RBAC) / attribute-based access
control (ABAC) systems, and cryptographic enforcement systems.

RBAC/ABAC systems (e.g., Solid pods, traditional databases with row-level
security) evaluate access at query time using logical predicates. They
cannot prevent a compromised storage node from leaking data because the
data is stored in plaintext.

Cryptographic enforcement systems (e.g., Attribute-Based Encryption,
Searchable Symmetric Encryption) tie access to key possession but lack
a general model for computing who should receive keys based on
structural relationships in a graph of principals, contexts, and
information nodes.

No existing system computes an access-control decision as
*path-constrained reachability through a typed multigraph*, where:

- The graph contains typed nodes (principals, contexts, information
  nodes, transforms) connected by typed edges (membership, sharing,
  derivation, containment, deny).
- The reachability computation enforces an edge-type grammar (only
  certain sequences of edge types constitute a valid authorization
  path).
- Deny rules operate at two levels: edge-level deny (prune a specific
  transition) and **path-predicate deny** (prune any path whose
  accumulated node set satisfies a predicate, e.g., "deny if the path
  traverses every node in set {A, B}").
- The output is a set of *context identifiers* that simultaneously
  serve as authorization scope and encryption domain boundaries.

### Summary of the Invention

A method and system for computing information-retrieval authorization
as bounded, grammar-constrained, path-predicate-filtered reachability
through a typed multigraph (the "light cone"), comprising:

1. **Typed multigraph representation.** Constructing a directed
   multigraph where nodes are typed as Principal, Context,
   Information, or Transform, and edges are typed (MEMBER_OF,
   SHARED_WITH, POSTED_IN, CONTAINS, DERIVED_FROM, GENERATED_BY,
   DENY, etc.).

2. **Grammar-constrained traversal.** Performing a breadth-first
   search (BFS) from a querying principal, bounded by a hop limit K,
   where at each step only edges whose type is in an allowed set are
   traversed, ensuring only structurally meaningful paths are
   considered.

3. **Edge-level deny.** Pruning specific transitions: a deny edge
   `(X → Y)` causes the traversal to skip the transition from X to Y,
   leaving other paths to Y intact.

4. **Path-predicate deny.** Evaluating constraints against the
   *accumulated path* (the sequence of nodes visited from the
   principal to the current frontier element). A deny predicate is a
   function `matches(path) → bool`; if any active deny predicate
   matches the path to a candidate context, that path is dropped.
   Specific predicate types include:

   a. **RequireAllOf(S):** Deny if every node in a specified set S
      appears in the accumulated path. This expresses "deny any path
      that goes through both A and B" without enumerating every
      concrete transition.

   b. **RequireSequence(S):** Deny if nodes in an ordered tuple S
      appear as a subsequence of the accumulated path. This expresses
      "deny any path that goes through A then B then C in order."

5. **Context-set output.** The traversal outputs the set of context
   identifiers (workspace, collection, project, channel) reachable
   by valid, non-denied paths. This context set simultaneously
   defines the *authorization scope* (what the principal can see)
   and the *encryption domain* (where per-partition encryption keys
   are derived from), so that the graph authorization result directly
   controls which encrypted data partitions can be decrypted.

6. **Monotone sensitivity for derived data.** Information nodes
   produced by Transform nodes inherit the most restrictive audience
   of their inputs, enforced by requiring that the output's authorized
   viewer set is a subset of the intersection of all input audiences.
   This prevents summaries, extractions, or classifications from
   becoming a bypass around the access constraints on the source data.

### Claims

**Claim 1.** A computer-implemented method for authorizing access to
information in a retrieval system, comprising:

(a) storing a typed multigraph comprising principal nodes, context
    nodes, information nodes, and typed directed edges connecting said
    nodes;

(b) receiving a query associated with a querying principal;

(c) performing a bounded breadth-first traversal of said multigraph
    from the querying principal, traversing only edges whose type is
    in a configured allow set, and accumulating, for each frontier
    element, the path of nodes visited from the principal to that
    element;

(d) for each candidate context reached by the traversal, evaluating
    one or more path-predicate deny rules against the accumulated
    path, and discarding the candidate if any deny rule's predicate
    is satisfied by the path;

(e) outputting the set of context identifiers that are reachable by
    at least one valid, non-denied path, wherein said set defines
    both an authorization scope and a set of encryption domain
    identifiers for partitioned encrypted data.

**Claim 2.** The method of Claim 1, wherein the path-predicate deny
rule comprises a RequireAllOf predicate that discards a path if every
node in a specified set appears in the accumulated path.

**Claim 3.** The method of Claim 1, wherein the path-predicate deny
rule comprises a RequireSequence predicate that discards a path if a
specified ordered tuple of nodes appears as a subsequence of the
accumulated path.

**Claim 4.** The method of Claim 1, further comprising enforcing
monotone sensitivity on derived information, wherein an information
node produced by a transform node is authorized for a querying
principal only if the principal is authorized for every input
information node consumed by the transform.

**Claim 5.** The method of Claim 1, wherein the context identifiers
in the output set are used as inputs to a key derivation function to
produce per-partition encryption keys for a partitioned encrypted
vector index, so that graph-reachability authorization and
cryptographic access enforcement share the same domain boundaries.

---

## Invention 2 — Partitioned Encrypted Vector Search with Per-Cluster Key Derivation ("Encrypted IVF")

### Field

Database systems; privacy-preserving approximate nearest neighbor
search.

### Background

Production vector databases (FAISS, Qdrant, Milvus, Weaviate,
OpenSearch k-NN) store embedding indexes in plaintext. Encryption at
rest is OS-level (dm-crypt, LUKS) and provides no protection against
a process with access to the file system. Existing privacy-preserving
approaches include:

- **Fully Homomorphic Encryption (FHE):** Allows computation on
  encrypted data but incurs 1000–10,000× overhead, making it
  impractical for real-time search.
- **Trusted Execution Environments (TEE):** Requires specific hardware
  (Intel SGX, AMD SEV) and limits deployability.
- **Private Information Retrieval (PIR):** Provides server-oblivious
  retrieval but at O(n) server-side cost per query.
- **Searchable Symmetric Encryption (SSE):** Supports keyword search
  but not approximate nearest neighbor vector search.

No existing software-only approach provides sub-second partitioned
vector search over encrypted data using commodity hardware, where each
partition is encrypted under an independently derived key and the
search process decrypts only the partitions needed for each query.

### Summary of the Invention

A method and system for approximate nearest neighbor (ANN) search over
a partitioned encrypted vector index, comprising:

1. **Context-aligned IVF partitioning.** An Inverted File (IVF)
   vector index is partitioned first by *context boundary* (each data
   owner's content forms an independent partition domain), then by
   vector similarity within each context (standard k-means
   clustering). Each partition cell contains a set of vectors
   belonging to one context and one cluster.

2. **Per-cluster deterministic key derivation.** For each partition
   cell, a symmetric encryption key is derived as:

       cell_key = HKDF-SHA256(master_key, info = context_id || 0x00 || cluster_id)

   where `master_key` is the data owner's root secret, `context_id`
   identifies the authorization domain, and `cluster_id` identifies
   the cluster within that domain. The delimiter byte (0x00) is
   forbidden in context identifiers by construction, preventing domain
   collisions. No per-cell key material is stored — derivation is
   deterministic and on-demand from the master key.

3. **Authenticated encryption of partition cells.** Each cell's vector
   data is encrypted using AES-256-GCM with the derived cell key.
   The GCM authentication tag binds the ciphertext to the cell's
   identity (context and cluster), preventing substitution attacks.
   Associated Authenticated Data (AAD) includes the context and
   cluster identifiers.

4. **Unencrypted centroids.** The cluster centroids (center vectors)
   remain unencrypted or encrypted under a separate centroid key.
   Centroids encode the topology of the vector space (where clusters
   are in embedding space) but not the content within them. A querier
   can route to the correct clusters without accessing the cell
   contents.

5. **Forward illumination.** During centroid routing, when the query
   determines the top-nprobe clusters, the system pre-derives keys
   for those clusters plus an additional ring of adjacent clusters
   (nprobe + padding). This serves two purposes:

   a. **Latency hiding:** key derivation for the predicted next cells
      begins before the ANN search requests them.

   b. **Access-pattern obfuscation:** by always unlocking a fixed
      number of clusters regardless of the actual query selectivity,
      an observer cannot determine the true query target from the
      set of decrypted cells.

6. **Query-scoped decryption.** Only the partition cells selected by
   centroid routing AND authorized by the access-control layer are
   decrypted. After the ANN search completes and results are merged,
   all cell keys are discarded. No key material persists beyond the
   query.

### Claims

**Claim 1.** A computer-implemented method for approximate nearest
neighbor search over encrypted vector data, comprising:

(a) partitioning a vector index into cells, wherein each cell is
    associated with a context identifier and a cluster identifier;

(b) for each cell, deriving a symmetric encryption key by applying a
    key derivation function (HKDF) to a master key using an info
    parameter that includes the context identifier, a fixed delimiter
    byte, and the cluster identifier;

(c) encrypting each cell's vector data using an authenticated
    encryption scheme (AES-GCM) with the derived key and associated
    authenticated data binding the ciphertext to the cell's identity;

(d) receiving a query vector and performing centroid routing against
    unencrypted cluster centroids to identify candidate cells;

(e) obtaining decryption keys for the candidate cells from a key
    issuance authority;

(f) decrypting the candidate cells and performing approximate nearest
    neighbor search within the decrypted cells;

(g) discarding all cell keys after the query completes.

**Claim 2.** The method of Claim 1, further comprising forward
illumination, wherein the system derives or requests keys for a fixed
number of cells (the candidate cells plus a padding set of additional
cells) regardless of the actual number of candidate cells, so that the
number of key requests is constant for all queries and does not reveal
the query's selectivity.

**Claim 3.** The method of Claim 1, wherein the context identifier in
step (b) corresponds to an authorization domain output by a
graph-reachability access-control computation, so that the encryption
domain boundaries are identical to the authorization domain boundaries.

**Claim 4.** The method of Claim 1, wherein the master key is held by
a data owner and cell keys are issued on demand by an oracle service
trusted by the owner, and wherein the oracle verifies a grant record
in a ledger before deriving and issuing each cell key, so that
revocation of a grant immediately prevents new cell keys from being
issued without re-encrypting the stored data.

---

## Invention 3 — Threshold Oracle Key Issuance with Per-Peer Verification ("Threshold Oracle Network")

### Field

Distributed systems; cryptographic key management for
privacy-preserving data access.

### Background

Centralized key management services (AWS KMS, HashiCorp Vault) enforce
access by issuing encryption keys based on policy. They are single
points of failure and single points of trust: the key management
service operator can access all protected data.

Threshold cryptography (Shamir secret sharing, threshold ECDSA)
distributes a secret among multiple parties such that a quorum of K
out of M parties is required to reconstruct or use the secret. This
eliminates the single-point-of-trust problem.

However, existing threshold key management systems do not combine:
- Shamir secret sharing of a *symmetric master key* used for
  deterministic key derivation (HKDF),
- per-request grant verification against a distributed ledger,
- per-peer identity verification where the coordinator oracle verifies
  each peer share contributor's identity cryptographically (Ed25519 /
  DID) before accepting their share,
- ephemeral reconstruction that holds the master key in memory only
  for the duration of key derivation, then zeroizes it, and
- a wire protocol with per-request ECIES forward secrecy for delivery
  of derived keys.

### Summary of the Invention

A method and system for threshold key issuance in a distributed
encrypted data retrieval system, comprising:

1. **Shamir K-of-M sharing of master key.** The data owner's master
   key (32 bytes) is split into M shares using Shamir secret sharing
   over a large prime field (GF(2^521 − 1)). Each share is
   distributed to a different oracle host. No single oracle host
   possesses the master key.

2. **Coordinator-peer protocol.** When a cell key is needed:

   a. The querier sends a signed batch request to a coordinator oracle.

   b. The coordinator verifies the querier's identity (Ed25519
      signature on the request, verified against the querier's
      `did:key`).

   c. The coordinator checks grant validity against the ledger for
      each requested cell.

   d. The coordinator sends the verified request to K−1 peer oracle
      hosts, requesting their shares.

   e. Each peer independently verifies the request signature against
      the querier's DID, verifies the coordinator's identity, and
      returns its share.

   f. The coordinator reconstructs the master key from K shares using
      Lagrange interpolation.

   g. The coordinator derives the requested cell keys via HKDF.

   h. The coordinator zeroizes the reconstructed master key and all
      peer shares before returning.

3. **Per-peer identity verification.** Every share exchange between
   coordinator and peer is authenticated: the coordinator presents a
   signed request, and each peer verifies the coordinator's DID. Peers
   refuse to release their share to an unverified coordinator. This
   prevents a compromised network participant from collecting shares
   by impersonating a coordinator.

4. **ECIES forward-secret delivery.** The derived cell keys are
   encrypted to the querier using ECIES (ephemeral X25519 ECDH →
   HKDF → AES-256-GCM). Both parties generate ephemeral X25519
   keypairs per request. The ECIES ciphertext is signed by the
   oracle's long-term Ed25519 key, and the querier verifies this
   signature against the expected oracle DID from the context
   registration. Forward secrecy is intrinsic: compromise of any
   long-term key does not retroactively decrypt past responses.

5. **Grant-gated issuance with instant revocation.** The coordinator
   checks the grant ledger before each key derivation. If the grant
   has been revoked, the oracle returns a denial. Because keys are
   derived on demand (not stored), revocation is instantaneous: there
   is no key to rotate and no re-encryption required. The maximum
   staleness is bounded by the cell-key TTL (Invention 4).

### Claims

**Claim 1.** A computer-implemented method for threshold key issuance
in a distributed encrypted data retrieval system, comprising:

(a) splitting a data owner's master key into M shares using Shamir
    secret sharing, and distributing each share to a different oracle
    host;

(b) receiving, at a coordinator oracle host, a signed request from a
    querier for one or more cell keys, the request including the
    querier's decentralized identifier (DID) and a cryptographic
    signature;

(c) verifying the querier's identity by resolving the DID to a public
    key and verifying the signature;

(d) checking, for each requested cell, that a valid grant exists in a
    ledger authorizing the querier's access;

(e) requesting shares from K−1 peer oracle hosts, wherein each peer
    independently verifies the coordinator's identity and the
    querier's request signature before releasing its share;

(f) reconstructing the master key from K shares using Lagrange
    interpolation over a prime field;

(g) deriving the requested cell keys by applying HKDF to the
    reconstructed master key with cell-identifying info parameters;

(h) encrypting the derived cell keys using ECIES with an ephemeral
    key pair, so that only the querier can decrypt the response;

(i) signing the encrypted response with the oracle's long-term
    signing key;

(j) zeroizing the reconstructed master key and all peer shares from
    memory before returning the response.

**Claim 2.** The method of Claim 1, wherein the Shamir secret sharing
is performed over the prime field GF(p) where p = 2^521 − 1, and each
share is represented as a fixed-width 66-byte big-endian integer.

**Claim 3.** The method of Claim 1, wherein the querier verifies the
response by checking the oracle's Ed25519 signature against an
expected oracle DID obtained from a context registration record in a
storage service, so that a man-in-the-middle that substitutes a
different oracle endpoint cannot forge a valid response.

**Claim 4.** The method of Claim 1, further comprising batch
processing wherein the coordinator collects shares once, reconstructs
the master key once, derives multiple cell keys in a single
reconstruction window, then zeroizes, reducing the number of
threshold reconstructions to one per batch rather than one per cell.

---

## Invention 4 — Cryptographically-Bound Cell Key TTL for Revocation-Consistent Encrypted Search

### Field

Computer security; key lifecycle management for encrypted
information retrieval.

### Background

In encrypted retrieval systems where keys are issued on demand by an
authority (such as the oracle network described in Invention 3),
there is a tension between query performance and revocation latency:

- **Per-query key requests** give instant revocation (every query
  checks the grant ledger) but add a network round-trip per query.
- **Long-lived cached keys** improve performance but create a window
  during which a revoked grant's keys remain usable.

Existing key management systems (e.g., AWS KMS caching, TLS session
tickets) use TTL-based caching but do not cryptographically bind the
TTL to the issued key material in a way that the consumer enforces
independently of the issuer.

### Summary of the Invention

A method for issuing derived encryption keys with a
cryptographically-bound time-to-live (TTL), such that the key
consumer independently enforces the expiration at the moment of use,
comprising:

1. **Oracle-stamped TTL.** When the oracle issues a cell key, it
   includes a `valid_until_ns` timestamp (nanosecond precision) in
   the response. This timestamp is covered by the oracle's Ed25519
   response signature, so the querier cannot extend it.

2. **Consumer-side TTL enforcement.** The query engine caches issued
   cell keys for reuse across queries within the TTL window. At the
   moment of cell decryption (not at key fetch time), the engine
   checks the current wall-clock time against `valid_until_ns`. If
   the key has expired, the engine discards it and forces a fresh
   oracle round-trip, which triggers a new grant validity check.

3. **Bounded revocation latency.** The maximum time between grant
   revocation and effective key expiration is bounded by the TTL
   value. The data owner controls the TTL via oracle configuration,
   trading off query latency (longer TTL = fewer oracle round-trips)
   against revocation tightness (shorter TTL = faster enforcement).

4. **Cache-safe revocation guarantee.** The caching does not weaken
   the revocation model: the TTL is the existing upper bound on how
   long any issued key remains useful. Caching extends the natural
   TTL window to its full extent rather than re-issuing each query.
   Once expired, the key is dropped and the next query forces a fresh
   oracle check. An explicit `invalidate_cell_keys()` call allows
   immediate cache purge when a revocation is known.

5. **Batch padding integration.** When padding is enabled to
   obfuscate access patterns, the pad cells also receive TTL-bound
   keys. The oracle cannot distinguish real cells from padding cells
   in the batch, and the TTL applies uniformly, so the padding
   mechanism does not leak timing information through differential
   key lifetimes.

### Claims

**Claim 1.** A computer-implemented method for managing encryption
key lifetimes in an on-demand key issuance system for encrypted
information retrieval, comprising:

(a) receiving, at a key issuance authority, a request for one or more
    cell keys for encrypted data partitions;

(b) for each authorized cell, deriving a cell key and determining a
    validity timestamp representing the latest time at which the key
    may be used;

(c) including the validity timestamp in a response signed by the
    authority's signing key, so that the timestamp cannot be modified
    by the requester;

(d) at the requester, caching the cell key and validity timestamp;

(e) at the moment of using a cached cell key to decrypt a data
    partition, comparing the current time to the validity timestamp,
    and if the key has expired, discarding the cached key and
    requesting a fresh key from the authority, wherein the fresh
    request triggers a new authorization check against the grant
    ledger;

(f) whereby the maximum latency between revocation of a grant and
    effective key expiration is bounded by the difference between the
    validity timestamp and the time of issuance.

**Claim 2.** The method of Claim 1, further comprising batch padding,
wherein the requester includes additional cell identifiers beyond
those needed for the query, each receiving an identically TTL-bound
key, so that the authority cannot distinguish real requests from
padding requests and the padding keys expire on the same schedule.

**Claim 3.** The method of Claim 1, wherein the key issuance
authority is a threshold oracle network comprising multiple oracle
hosts, and the validity timestamp is determined by the coordinator
oracle and covered by its response signature following threshold
reconstruction of a master key.

---

## Prior Art Differentiation

The following table summarizes how the inventions described above
differ from known prior art:

| System/Approach | What it does | What it lacks |
|---|---|---|
| RBAC / ABAC (Solid, traditional DBs) | Logical access control at query time | No physical encryption enforcement; compromised storage leaks data |
| Attribute-Based Encryption (ABE) | Cryptographic enforcement via attribute policies | No graph-reachability model; no revocation without re-encryption; no vector search |
| Searchable Symmetric Encryption (SSE) | Encrypted keyword search | No approximate nearest neighbor; no multi-owner model |
| Fully Homomorphic Encryption (FHE) | Computation on encrypted data | 1000–10,000× overhead; impractical for real-time ANN |
| Private Information Retrieval (PIR) | Server-oblivious retrieval | O(n) server cost; no ANN support |
| FAISS / Qdrant / Milvus / Weaviate | High-performance ANN search | Plaintext indexes; no per-partition encryption |
| AWS KMS / HashiCorp Vault | Centralized key management | Single point of trust; no threshold distribution; no per-cell derivation |
| Ocean Protocol | Data access economics + blockchain | No encrypted vector search; no IVF partitioning |
| Shamir Secret Sharing (generic) | Threshold secret reconstruction | No per-request grant verification; no ECIES delivery; no cell-key derivation |

## Conception History

The inventions described herein were conceived by the named inventor
over the period March 15, 2026 through April 8, 2026. Contemporaneous
records of conception include:

- AI-assisted development session transcripts (VS Code Copilot and
  Claude Code) from March 15–April 8, 2026, documenting the
  inventor's directions, architectural decisions, and design
  instructions at each stage.
- The design document "Light-Cone Graph Authorization with Semantic
  Ranking" (dated March 31, 2026), which pre-dates the FLARE
  implementation.
- The design document "Partitioned Encrypted Vector Search — Research
  Sketch" (dated April 7, 2026).
- The LinkedIn post dated April 8, 2026 disclosing the FLARE system
  at a high level.
- Git commit history for the FLARE repository showing implementation
  of each invention.

AI tools (GitHub Copilot, Anthropic Claude) were used to assist with
implementation of code and drafting of documentation under the
direction and conception of the named inventor. All inventive
concepts were conceived by the named human inventor.
