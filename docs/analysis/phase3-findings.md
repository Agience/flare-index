# Phase 3 — Findings

Date opened: 2026-04-07
Scope: per-grant Ed25519 signatures + hash-chained tamper-evident ledger, threshold (Shamir K-of-M) oracle key management with peer-to-peer share release, multi-method DID resolution (`did:key` + `did:web`), storage write nonce + replay window, removal of the legacy single-cell `/issue` endpoint, six-replica docker-compose stack.

These findings extend (not replace) `phase0`, `phase1`, and `phase2` findings. Items those phases left open and Phase 3 closes are listed at the top.

---

## Items from earlier phases resolved by Phase 3

| ID | Earlier status | Phase 3 update |
|---|---|---|
| **F-1.1** Only `did:key` is implemented | deferred-to-phase-3 | **Resolved.** `flare/identity.py:DIDResolver` supports both `did:key` (local, no network) and `did:web` (HTTPS fetch with 5-minute cache). Pinned by `tests/test_did_resolver.py`. The default resolver is method-agnostic and is used by storage, ledger, and oracle services for any signature verification. |
| **F-1.7** Ledger service has unauthenticated writes | deferred-to-phase-3 | **Resolved (in software).** Every grant carries an Ed25519 signature from the grantor over canonical bytes (`flare/ledger/signing.py:canonical_grant_bytes`); every revocation carries a signature from the *original* grantor. The service rejects any unsigned or wrong-signed write. Additionally, every state change appends to a hash-chained log (`prev_hash || sha256(canonical)`) so any tampering is detectable by re-walking the chain from `GENESIS_HASH`. The chain head is exposed at `GET /head` so external auditors can pin it. Pinned by `tests/test_signed_ledger.py` (6 tests). The remaining gap to a real on-chain deployment is consensus, not signatures or schema — see F-3.1. |
| **F-2.1** Legacy `/issue` single-cell endpoint without response signing | accepted | **Resolved.** The `/issue` endpoint is removed entirely from `flare/oracle/service.py` and `flare/oracle/client.py`. Production query nodes use `/issue-batch` exclusively. Tests rewritten to use the batch path. |
| **F-2.2** Storage write signatures lack a nonce | deferred-to-phase-3 | **Resolved.** Owner-signed registration and cell upload bytes now include `(nonce, timestamp_ns)`. The storage service enforces a ±5-minute clock-skew window and a per-DID nonce cache (`flare/storage/signing.py:StorageNonceCache`). A captured upload cannot be replayed verbatim. Pinned by `tests/test_storage_replay.py`. |

---

## New Phase 3 findings

### F-3.1 — Hash-chained ledger is software-only; no consensus
- **Severity:** info (research-prototype substitute)
- **Status:** accepted; would be replaced by Ceramic / Ethereum L2 in a real deployment
- **Where:** `flare/ledger/memory.py`, `flare/ledger/service.py`
- **Reasoning:** The append-only hash-chained log gives **tamper-evidence** — any operator who rewrites history breaks the chain visible to every external auditor that pinned an earlier head. It does **not** give consensus: a single ledger operator can still equivocate by serving different chains to different readers. Mitigations: (a) external auditors should record and compare heads, (b) the chain can be anchored periodically to a real public chain (Ethereum L2, Bitcoin via OpenTimestamps), (c) for full consensus, swap the in-memory backing for a Ceramic stream or Ethereum L2 contract — the on-chain version uses the **same** signature verification primitives in `flare/ledger/signing.py`, so only the storage layer changes. Documented in `paper/flare.md` §4.3 as the explicit prototype substitute.

### F-3.2 — Threshold reconstruction briefly holds the full master key in coordinator memory
- **Severity:** med
- **Status:** accepted; deferred-to-phase-4 (TEE)
- **Where:** `flare/oracle/core.py:OracleCore.decide_batch`
- **Reasoning:** Shamir K-of-M splits the master key into M shares. Phase 3 reconstructs the master key in the coordinator oracle's process memory at issuance time, derives the cell keys, and drops the reconstructed key + the peer shares before returning. The threshold property is preserved against passive compromise: K-1 compromised oracle hosts cannot reconstruct the secret. It is **not** preserved against an active compromise of the coordinator host *during* a query: a memory dump captured between reconstruction and discard yields the master key. Phase 4 (TEE) keeps the reconstruction inside a sealed enclave on the coordinator host so even the operator cannot read it. A stronger but more invasive alternative is a true threshold PRF (e.g., DDH-OPRF) that never reconstructs the secret in plaintext; we deliberately avoid that path because (a) it requires changing the per-cell key derivation function from HKDF to a group-element-based scheme, (b) it would couple the cell key derivation to a specific elliptic curve, and (c) the prototype's threat model accepts the brief in-memory window in exchange for keeping HKDF as the cell key derivation primitive.

### F-3.3 — Peer share release uses an in-process replay nonce cache only
- **Severity:** low
- **Status:** open
- **Where:** `flare/oracle/service.py`, `flare/oracle/peer_wire.py:NonceCache`
- **Reasoning:** Each peer oracle maintains its own replay nonce cache for incoming peer share requests. Restarting a peer process clears the cache. The 60-second clock-skew window bounds the replay opportunity, and the inner querier signature still has to verify, so a replay can only ever release a share for a query the original querier signed within the last 60 seconds. Real shared nonce state requires a small Redis-style coordination service; deferred. Same shape as F-1.2 for the original wire-protocol nonce cache.

### F-3.4 — Peer allowlist is static and operator-managed
- **Severity:** info
- **Status:** accepted
- **Where:** `flare/oracle/service.py:build_oracle_app:allowed_coord_dids`
- **Reasoning:** Each peer oracle's allowlist of valid coordinator DIDs is loaded at process start (from the compose entrypoint script) and is not refreshed at runtime. Adding or removing a peer requires restarting at least the affected peers. For the prototype this is fine; a production deployment would either fetch the peer set from the storage service registration (which already records the oracle DID per context) or from a small registry service.

### F-3.5 — A peer that releases its share to a coordinator trusts that coordinator's authorization decision
- **Severity:** low
- **Status:** mitigated
- **Where:** `flare/oracle/service.py:peer_share`
- **Reasoning:** The peer endpoint already runs an **independent** ledger lookup for every cell in the inner querier batch and refuses to release if any cell is unauthorized — so the peer does not blindly trust the coordinator. The remaining mitigation gap: if the peer's ledger view is stale relative to the coordinator's (because the peer just queried the ledger before a revocation), the peer might release a share for a now-revoked grant. The coordinator would also have just queried the ledger, so the window is tight, but it exists. Cell-key TTLs (Phase 4 / F-1.5) bound the resulting blast radius.

### F-3.6 — `did:web` resolution introduces a TLS dependency
- **Severity:** info
- **Status:** accepted
- **Where:** `flare/identity.py:DIDResolver._resolve_did_web`
- **Reasoning:** `did:web` resolves to an `https://` URL and depends on the trust store of the resolving process. A compromised CA can serve a forged `did.json` and fool the resolver. The mitigation is to constrain the trust store, pin certificates, or use a side-channel to verify the resolved key (e.g., publish the same DID's `did.json` to multiple mirrors and require agreement). For the prototype the default `httpx.Client` trust store is acceptable; a production deployment would use a custom client with a private CA bundle. Note that `did:key` (used by every identity in the prototype's tests, demos, and compose stack) has **no** TLS dependency at all because the public key is self-encoded in the DID string.

### F-3.7 — Coordinator role is static per registration
- **Severity:** info
- **Status:** accepted
- **Where:** `flare/storage/memory.py:ContextRegistration.oracle_endpoint`
- **Reasoning:** A context registration points the query node at exactly one oracle URL. That URL becomes the de-facto coordinator for any query against that context. If that one replica is offline, the context is unreachable even though K of M shares could still be reconstructed by another replica. Phase 4 will let the registration carry a list of oracle endpoints (any of which can serve as coordinator for a given query), with the query node round-robining or failing over.

### F-3.8 — Six oracle services per stack is verbose for compose
- **Severity:** info
- **Status:** accepted
- **Where:** `docker-compose.yml`, `compose/entrypoint.sh`
- **Reasoning:** The Phase 3 stack defines six oracle containers (3 replicas × 2 owners), plus ledger, storage, secrets, and demo. Bringing the stack up takes ~5 seconds and uses ~250 MB of RAM. This is fine for a research demo; a real deployment would compose oracles per data owner rather than per stack and would use a service mesh for peer discovery. Documented so it isn't surprising on first `make stack-up`.

### F-3.9 — Threshold latency is roughly 1.6× the single-replica latency
- **Severity:** info (performance)
- **Status:** measured
- **Where:** `bench/bench_encrypted_vs_plain.py`, `paper/evals/phase3_bench_*.json`
- **Reasoning:** The Phase 3 bench shows single-replica at 98 ms/query and threshold at 155 ms/query at the same configuration. The 57 ms gap is the cost of one parallel peer share-fetch round-trip per batch (ECIES + Ed25519 sign/verify on both sides + HTTP). The threshold cost is **independent of the cell count** in the batch because the share is owner-scoped, not cell-scoped — so for larger batches the per-cell amortized threshold cost falls. The current bench uses an aggressive `nprobe=8` so each batch is small.

---

## Items unchanged from earlier phases

- **F-0.7 / F-1.11 (centroid leakage):** unchanged. Phase 4.
- **F-0.8 (oracle access pattern leakage):** unchanged. Phase 4.
- **F-1.2 (per-process nonce cache):** unchanged for the wire protocol cache. F-3.3 records the same gap for the new peer cache.
- **F-1.5 (in-flight requests after revoke):** unchanged. Phase 4 with cell-key TTLs.
- **F-1.9 / F-2.7 (compose env-var key delivery):** unchanged. Phase 4 with TEE-sealed storage. The threshold split in Phase 3 reduces the value of any single secrets-file leak (an attacker who reads `/secrets/phase3.env` for one replica only learns one Shamir share, not the master key) but the file does still contain all M shares for the prototype because the demo container plays the role of all data owners during bootstrap.
