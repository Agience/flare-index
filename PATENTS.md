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

**Claim 5.** The method of Claim 1, wherein the key derivation in
step (b) is replaced by a two-layer envelope: a context wrapping key
(CWK) is derived from the master key via HKDF, and a random cell
encryption key (CEK) is wrapped under the CWK, enabling cross-context
sharing of cells by re-wrapping the CEK under a different CWK without
re-encrypting the cell data (see Invention 5).

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

## Invention 5 — Envelope Encryption with Cross-Context Key Re-Wrapping

### Field

Cryptographic key management; privacy-preserving data sharing across
authorization domains.

### Background

Existing per-partition encryption systems (including the single-layer
scheme described in Invention 2) derive cell encryption keys
deterministically from a master key:

    cell_key = HKDF(master_key, context_id || cluster_id)

This creates a rigid coupling between the encryption key and the
authorization domain: a cell encrypted under context A's key cannot
be read through context B's key without re-encrypting the cell data.
Cross-domain data sharing therefore requires either (a) duplicating
and re-encrypting the cell under the target domain's key, or (b)
granting the recipient access to the source domain, which may expose
more data than intended.

Envelope encryption (e.g., AWS KMS data key wrapping) wraps a random
data key under a key-encrypting key, but existing envelope schemes
do not combine:
- Deterministic context wrapping keys derived from a shared master key
  (enabling on-demand derivation without stored key material),
- Random per-cell encryption keys wrapped under the context key
  (enabling cross-context sharing by re-wrapping without re-encryption),
- AAD-bound wrapping that ties the wrapped key to its (context, cell)
  identity (preventing key-substitution attacks), and
- Integration with a threshold oracle that derives the context wrapping
  key from a Shamir-reconstructed master key per request.

### Summary of the Invention

A method and system for two-layer envelope encryption enabling
cross-context data sharing in an encrypted partitioned retrieval
system, comprising:

1. **Context Wrapping Key (CWK).** For each authorization context,
   a symmetric wrapping key is derived deterministically from the
   owner's master key:

       CWK = HKDF-SHA256(master_key, info = "flare/v5/cwk" || 0x00 || context_id)

   The CWK is never stored — the oracle derives it on demand from
   the master key. The HKDF info prefix ensures CWKs are
   domain-separated from cell keys derived under the Invention 2
   scheme.

2. **Cell Encryption Key (CEK).** For each partition cell, a random
   32-byte symmetric key is generated. The cell data is encrypted
   under the CEK using AES-256-GCM with AAD binding to the cell
   identity (context and cluster), identical to Invention 2. The
   CEK is then wrapped (encrypted) under the CWK using AES-256-GCM
   with the same AAD, producing a wrapped CEK blob stored alongside
   the encrypted cell.

3. **Oracle-side unwrapping.** When a querier requests a cell key,
   the oracle:
   (a) derives the CWK from the master key via HKDF,
   (b) loads the wrapped CEK blob for the requested cell,
   (c) unwraps the CEK by AES-256-GCM decryption using the CWK,
   (d) returns the CEK to the querier via the ECIES channel
       (Invention 3).
   The CWK is ephemeral — derived, used, and discarded per batch.

4. **Cross-context sharing by CEK re-wrapping.** To share a cell
   from context A into context B without re-encrypting the cell data:
   (a) derive CWK_A from master_key_A,
   (b) unwrap the CEK from CWK_A,
   (c) derive CWK_B from master_key_B,
   (d) wrap the same CEK under CWK_B with AAD binding to context B,
   (e) store the new wrapped CEK blob and a containment edge
       recording the cell's membership in context B.
   The encrypted cell data is unchanged — only the key wrapping
   changes. The cell can now be decrypted by anyone with access to
   context B's CWK.

5. **Containment edges for multi-context membership.** Explicit
   directed edges in the authorization graph record which cells
   belong to which contexts. A cell shared into a second context
   gains a containment edge from that context without losing its
   edge from the source context. The query engine uses containment
   edges (when present) to enumerate cells per context, replacing
   the naive range(nlist) enumeration that assumes each cell belongs
   to exactly one context.

6. **Backward-compatible hybrid path.** When a wrapped CEK exists
   for a cell, the oracle uses the two-layer envelope path. When no
   wrapped CEK exists (legacy data), the oracle falls back to
   single-layer HKDF derivation (Invention 2). Both paths coexist
   in the same oracle and the same batch response.

### Claims

**Claim 1.** A computer-implemented method for cross-context data
sharing in an encrypted partitioned retrieval system, comprising:

(a) for each authorization context, deriving a context wrapping key
    (CWK) from a master key using a key derivation function;

(b) for each partition cell, generating a random cell encryption key
    (CEK), encrypting the cell data under the CEK with authenticated
    encryption and associated data binding the ciphertext to the
    cell's identity, and wrapping the CEK under the CWK with
    authenticated encryption and associated data;

(c) to share a cell from a source context into a target context:
    unwrapping the CEK using the source context's CWK, wrapping the
    same CEK under the target context's CWK with associated data
    binding to the target context, and storing the new wrapped CEK,
    wherein the encrypted cell data is not re-encrypted;

(d) recording the shared cell's membership in both contexts via
    explicit containment edges in an authorization graph.

**Claim 2.** The method of Claim 1, wherein the CWK is derived
deterministically by a threshold oracle that reconstructs the master
key from Shamir shares per request, derives the CWK via HKDF, unwraps
the CEK, and returns the CEK to the querier, discarding the CWK and
master key after the batch completes.

**Claim 3.** The method of Claim 1, wherein the system supports a
hybrid mode in which cells with wrapped CEKs use the two-layer
envelope path and cells without wrapped CEKs fall back to single-layer
key derivation, enabling incremental migration without re-encrypting
existing data.

**Claim 4.** The method of Claim 1, wherein the containment edges are
stored in the same graph structure used for authorization traversal
(Invention 1), so that the query engine resolves which cells belong
to a context by reading containment edges rather than by enumerating
a fixed partition range.

---

## Invention 6 — Grant-Universal Access with Revocable Self-Grant ("Grant-First Access")

### Field

Computer security; access control for encrypted data systems.

### Background

In systems where an oracle issues encryption keys on behalf of a data
owner (as in Inventions 2–4), the owner typically has an implicit
bypass: the oracle recognizes the requester's identity as the owner
and issues keys without checking the grant ledger. This creates a
parallel authority model:

- Non-owners: access mediated by grants in the ledger.
- Owners: access mediated by identity comparison (`requester == owner`).

The parallel model does not compose with delegation, sharing, or
multi-tenant access. It also means the owner's access cannot be
suspended or audited through the same mechanism used for all other
principals.

### Summary of the Invention

A method for grant-universal access control in an encrypted data
system, comprising:

1. **Self-grant at bootstrap.** When a data owner creates a new
   authorization context and registers it with the system, the
   bootstrap process also creates and signs a grant from the owner
   to themselves in the grant ledger. This self-grant is a regular
   signed grant record, indistinguishable from grants to other
   principals.

2. **No owner bypass.** The key-issuance oracle has no special-case
   check for `requester == owner`. Every key request — including the
   owner's — is authorized by looking up a valid grant in the ledger.
   The oracle may label the decision as "owner" in its trace output
   (for diagnostics), but the authorization path is identical.

3. **Revocable owner access.** Because the owner's access flows
   through a regular grant, it can be revoked using the standard
   revocation mechanism. Revoking the self-grant immediately blocks
   the owner from accessing their own data through the oracle. This
   enables scenarios such as legal holds, multi-signatory custody,
   and administrative suspension.

4. **Re-grantable.** After revocation, the owner (or a delegate with
   grant-signing authority) can create a new self-grant, restoring
   access through the same ledger mechanism.

### Claims

**Claim 1.** A computer-implemented method for uniform access control
in an encrypted data system with an on-demand key issuance authority,
comprising:

(a) at context creation time, creating a signed grant record in a
    grant ledger from the data owner to themselves, said grant being
    stored and validated identically to grants for other principals;

(b) when the data owner requests encryption keys from the key
    issuance authority, verifying authorization exclusively by looking
    up a valid grant in the grant ledger, without any special-case
    identity comparison for the owner;

(c) whereby revoking the owner's self-grant in the ledger immediately
    prevents the key issuance authority from issuing keys to the
    owner, using the same revocation mechanism applied to all other
    principals.

**Claim 2.** The method of Claim 1, further comprising restoring the
owner's access by creating a new self-grant in the ledger after
revocation, using the standard grant creation mechanism.

---

## Invention 7 — Per-User Ephemeral Super-Contexts via Light-Cone-Scoped KNN Clustering

### Field

Information retrieval; privacy-preserving navigation for encrypted
multi-tenant data systems.

### Background

In encrypted retrieval systems with many authorization contexts (each
belonging to different data owners), a principal with access to a
large number of contexts faces a navigation problem: they can search
within individual contexts but have no way to discover thematic
structure across the contexts they can access. Traditional approaches
include:

- Manual taxonomies (user-created folders or tags), which require
  effort and do not scale.
- Global clustering (system-wide topic models), which leaks
  information about contexts the user cannot access and is identical
  for all users.
- Faceted search (metadata-driven), which requires structured
  metadata that encrypted systems typically lack.

No existing approach provides automatic, per-user, privacy-respecting
thematic groupings that reflect only the data visible to each
specific user.

### Summary of the Invention

A method for generating ephemeral, per-user navigational groupings
("super-contexts") over an encrypted partitioned retrieval system,
comprising:

1. **Light-cone scoping.** The authorized context set is computed
   for the querying principal using the graph-reachability mechanism
   of Invention 1. Only centroid data from authorized contexts is
   used; unauthorized contexts contribute nothing.

2. **Oracle-gated centroid collection.** For each authorized context,
   the principal requests centroid vectors from the oracle via the
   authenticated wire protocol (Invention 3). The oracle verifies
   the grant before releasing centroids, so the principal never sees
   centroids for unauthorized contexts.

3. **Concatenated KNN clustering.** All authorized centroid vectors
   are concatenated into a single matrix and clustered using k-means
   with a user-specified number of super-clusters. Each original
   centroid is assigned to its nearest super-cluster.

4. **Per-user projection.** The resulting super-contexts are
   ephemeral — they are not stored in the ledger, storage, or any
   persistent state. They are recomputed per-user, per-session.
   Different users with different light cones (different authorized
   context sets) see different super-context groupings, even over
   the same underlying data.

5. **Query filtering.** Optionally, a super-context identifier can
   be passed to the search engine to restrict centroid routing to
   the cells assigned to that super-context's member set. This
   narrows the search space without changing the security properties.

### Claims

**Claim 1.** A computer-implemented method for generating
privacy-respecting navigational groupings in an encrypted multi-tenant
retrieval system, comprising:

(a) computing a set of authorized contexts for a querying principal
    using graph-reachability authorization;

(b) collecting centroid vectors for each authorized context from a
    key issuance authority that verifies the principal's grant before
    releasing centroids;

(c) concatenating the collected centroids into a single matrix and
    applying KNN clustering to produce a set of super-clusters;

(d) assigning each original centroid to its nearest super-cluster
    and grouping the corresponding partition cells by super-cluster
    membership;

(e) returning the super-clusters as ephemeral, per-user navigational
    groupings that are not persisted and that reflect only the data
    visible to the querying principal.

**Claim 2.** The method of Claim 1, further comprising filtering a
search query to restrict centroid routing to the partition cells
assigned to a specified super-cluster, narrowing the search space
while preserving the encryption and authorization properties of the
underlying system.

---

## Invention 8 — Single-Traversal Multi-Modal Authorization for Heterogeneous Encrypted Indexes ("FLARE-SSE")

### Field

Computer security; encrypted information retrieval combining
approximate nearest neighbor search and lexical search under a shared
authorization model.

### Background

Existing encrypted retrieval systems address either vector search or
lexical search in isolation:

- **SSE systems** (Song-Wagner-Perrig 2000; OXT, Cash et al. 2013;
  Sophos/Diana, Bost 2016–2017) provide encrypted keyword search over
  inverted indexes. They have no model for approximate nearest
  neighbor search, no multi-owner authorization graph, and no notion
  of authorization domening an index by graph reachability.

- **Encrypted ANN systems** (e.g., FLARE Inventions 1–2) provide
  partitioned encrypted vector search scoped by light-cone graph
  authorization. They have no lexical index and cannot find documents
  that are semantically distant but terminologically exact.

When both indexes are deployed for the same corpus, existing approaches
authorize them independently — two separate authorization checks, two
separate key hierarchies, no shared scope computation. This creates two
attack surfaces and a consistency risk: a document retrieval
authorization from one index may diverge from the other.

Additionally, in prior SSE schemes the blind token is used *only* to
locate an encrypted posting list — the decryption key for that list is
derived separately from the base SSE key. An adversary who obtains the
SSE key can decrypt any posting list. In FLARE-SSE, the blind token
also serves as the key derivation input: `HKDF(owner_sse_key,
blind_token)`. Knowing the SSE key alone is insufficient — the
adversary must also know (or recover) the plaintext term to derive the
decryption key for any specific posting list.

### Summary of the Invention

A method and system for encrypted hybrid retrieval over heterogeneous
encrypted indexes — an approximate nearest neighbor (ANN) vector index
and a Searchable Symmetric Encryption (SSE) lexical index — sharing a
single authorization traversal, comprising:

1. **Single-traversal shared authorization scope.** A single
   bounded breadth-first traversal (light-cone BFS, as in Invention 1)
   is performed once per query, producing the set of authorized owner
   identifiers. This scope is passed simultaneously to both the
   encrypted ANN engine (Invention 2) and the encrypted SSE lexical
   engine. No separate authorization check is required for either
   index; both operate within the same scope boundary from a single
   traversal.

2. **Parallel fan-out to heterogeneous encrypted indexes.** After the
   single BFS completes, the query engine fans out in parallel:

   a. **ANN path**: centroid routing → per-cluster key derivation via
      HKDF → AES-256-GCM cell decryption → FAISS ANN scoring. Keys
      and authorization follow Inventions 1–2.

   b. **SSE lexical path**: query terms are tokenized and stemmed;
      per-owner blind tokens are generated (`HMAC-SHA256(owner_sse_key,
      field_prefix + ":" + stemmed_term)`); posting lists are fetched
      from S3 and decrypted; BM25 is computed in-process over the
      decrypted data.

   Both paths operate concurrently; neither blocks the other.

3. **Blind-token-as-key-derivation-input.** For each SSE posting
   list, the decryption key is derived as:

       posting_key = HKDF(owner_sse_key, blind_token)

   where `blind_token = HMAC-SHA256(owner_sse_key, field + ":" + term)`.
   Since the blind token is both the storage address (filename in S3)
   and the HKDF input for the posting list key, the blind token
   derivation is non-invertible: knowing `owner_sse_key` alone is
   insufficient to decrypt any specific posting list without also
   knowing the plaintext term. Term knowledge is a cryptographic
   prerequisite for posting list decryption.

4. **Reciprocal Results Fusion (RRF) of heterogeneous scores.** The
   ANN cosine similarity scores and the in-process BM25 scores are
   fused using Reciprocal Rank Fusion:

       score(d) = Σ_r  1 / (k + rank_r(d))

   where r ∈ {ANN vector, SSE lexical}. The two indexes are
   structurally complementary (SSE finds exact-term matches in
   semantically distant documents; ANN finds semantically similar
   documents the embedding model clusters together), so RRF fusion
   over complementary retrieval signals consistently outperforms
   either index alone with no redundant overlap in most queries.

5. **Authorized-decoy padding for the SSE lookup plane.** Blind
   token lookups are padded to a constant batch width with authorized
   decoy tokens — tokens corresponding to terms in documents the
   querier has grant access to (same authorized scope as the real
   query). The storage server (S3) receives a fixed-width batch for
   every SSE query regardless of the number of actual query terms.
   All response data for decoy tokens is discarded after receipt.
   This mirrors the constant-width cell-key padding of Invention 4
   (Claim 2), applied to the SSE query plane.

6. **Common key hierarchy.** Both indexes derive their keys from the
   same owner master key via domain-separated HKDF context strings:
   - ANN cell keys: `HKDF(master, "flare" || context_id || cluster_id)`
   - SSE key: `HKDF(master, "sse")`
   - SSE posting list key: `HKDF(SSE_key, blind_token)`
   - Context field content key: `HKDF(master, "content" || artifact_id)`

   The oracle issues both ANN cell keys and the SSE key through the
   same threshold grant-gated protocol (Invention 3), under the same
   grant ledger. A single revocation event immediately prevents
   issuance of keys for both indexes.

### Claims

**Claim 1.** A computer-implemented method for authorized hybrid
retrieval over heterogeneous encrypted indexes, comprising:

(a) performing a single bounded breadth-first traversal of a typed
    authorization graph from a querying principal to produce an
    authorized scope comprising a set of owner identifiers;

(b) passing the authorized scope to both an encrypted approximate
    nearest neighbor (ANN) index engine and an encrypted lexical
    index engine, wherein neither engine performs an independent
    authorization traversal;

(c) executing, in parallel:
    (i) the ANN engine: decrypting indexed vector cells within the
        authorized scope and computing approximate nearest neighbor
        scores for the query vector;
    (ii) the SSE lexical engine: generating per-owner blind tokens for
        query terms, fetching and decrypting encrypted posting lists,
        and computing BM25 scores in-process;

(d) fusing the ANN scores and BM25 scores from step (c) using
    Reciprocal Rank Fusion;

(e) returning a unified ranked result list.

**Claim 2.** The method of Claim 1, wherein, for each SSE posting
list, the decryption key is derived as `HKDF(owner_sse_key,
blind_token)`, where `blind_token = HMAC(owner_sse_key, field + ":"
+ term)`, so that (i) the blind token is both the posting list's
storage address and the key derivation input, and (ii) decryption of
any specific posting list requires knowledge of the corresponding
plaintext term independent of possession of the SSE key.

**Claim 3.** The method of Claim 1, further comprising authorized-decoy
padding of the SSE blind token lookup batch, wherein the query engine
augments the set of real query tokens with decoy tokens drawn from the
querier's authorized term space to reach a constant batch width, so
that the storage server cannot distinguish queries by the number of
real query terms from the width of the token request batch.

---

## Prior Art Differentiation

The following table summarizes how the inventions described above
differ from known prior art:

| System/Approach | What it does | What it lacks |
|---|---|---|
| RBAC / ABAC (Solid, traditional DBs) | Logical access control at query time | No physical encryption enforcement; compromised storage leaks data |
| Attribute-Based Encryption (ABE) | Cryptographic enforcement via attribute policies | No graph-reachability model; no revocation without re-encryption; no vector search |
| Searchable Symmetric Encryption (SSE) — OXT, Sophos/Diana | Encrypted keyword search over inverted index | No ANN; no multi-owner authorization graph; blind token used only for posting list lookup, not as key derivation input (knowing SSE key is sufficient to decrypt any posting list) |
| Fully Homomorphic Encryption (FHE) | Computation on encrypted data | 1000–10,000× overhead; impractical for real-time ANN |
| Private Information Retrieval (PIR) | Server-oblivious retrieval | O(n) server cost; no ANN support |
| FAISS / Qdrant / Milvus / Weaviate | High-performance ANN search | Plaintext indexes; no per-partition encryption |
| AWS KMS / HashiCorp Vault | Centralized key management | Single point of trust; no threshold distribution; no per-cell derivation |
| AWS KMS envelope encryption | Data key wrapping under a master key | No cross-context re-wrapping; no integration with graph authorization or threshold oracle |
| Ocean Protocol | Data access economics + blockchain | No encrypted vector search; no IVF partitioning |
| Shamir Secret Sharing (generic) | Threshold secret reconstruction | No per-request grant verification; no ECIES delivery; no cell-key derivation |
| Google Zanzibar / SpiceDB | Graph-based authorization | No encryption enforcement; no per-partition keys; no path-predicate deny |
| Topic modeling (LDA, BERTopic) | Global document clustering | Global (not per-user); leaks unauthorized data topology; requires plaintext |
| Order-Preserving Encryption (OPE), Boldyreva et al. 2009 | Ciphertexts numerically ordered like plaintexts; supports `<`/`>` comparisons in DB | Leaks full rank order of every stored value; effectively equivalent to a linear transposition (fractional index) |
| Order-Revealing Encryption (ORE), Lewi-Wu 2016 | Reveals only comparison bit (left < right), not magnitude | Requires custom DB comparison operator; not natively supported by ArangoDB AQL; reduces but does not eliminate ordering leakage |

## Conception History

The inventions described herein were conceived by the named inventor
over the period March 15, 2026 through April 16, 2026. Contemporaneous
records of conception include:

- AI-assisted development session transcripts (VS Code Copilot and
  Claude Code) from March 15–April 11, 2026, documenting the
  inventor's directions, architectural decisions, and design
  instructions at each stage.
- The design document "Light-Cone Graph Authorization with Semantic
  Ranking" (dated March 31, 2026), which pre-dates the FLARE
  implementation.
- The design document "Partitioned Encrypted Vector Search — Research
  Sketch" (dated April 7, 2026).
- The design document "FLARE: Federated Light-cone Access with
  Recursive Encryption" (dated April 10, 2026), which describes the
  envelope encryption, grant-first access, containment edge, and
  super-context concepts prior to implementation.
- The LinkedIn post dated April 8, 2026 disclosing the FLARE system
  at a high level.
- The design document "FLARE-SSE — Encrypted Lexical Search"
  (dated April 16, 2026), which describes the blind-token lexical
  index, single-traversal multi-modal authorization, and
  authorized-decoy padding concepts prior to implementation.
- Git commit history for the FLARE repository showing implementation
  of each invention.

AI tools (GitHub Copilot, Anthropic Claude) were used to assist with
implementation of code and drafting of documentation under the
direction and conception of the named inventor. All inventive
concepts were conceived by the named human inventor.
