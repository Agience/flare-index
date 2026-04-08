# Phase 2 — Findings

Date opened: 2026-04-07
Scope: end-to-end response authentication on the oracle wire, owner-signed storage writes, oracle DID binding into context registrations, batched oracle issuance with parallel storage prefetch, path-predicate deny in the light cone.

These findings extend (not replace) `phase0-findings.md` and `phase1-findings.md`. Items those phases left open and Phase 2 closes are listed at the top.

---

## Phase 1 items resolved by Phase 2

| Phase 1 ID | Phase 1 status | Phase 2 update |
|---|---|---|
| **F-1.6** Edge-level deny is less expressive than path-predicate deny | deferred | **Resolved.** `flare/lightcone.py` now exposes `DenyPath`, `RequireAllOf`, and `RequireSequence`. BFS is path-stateful — each frontier element carries the path that reached it, and an active deny predicate prunes that path. Pinned by `tests/test_path_predicates.py` (4 tests). |
| **F-1.7** Ledger service unauthenticated | deferred-to-phase-3 | **Carried.** Phase 2 does not touch the ledger; per-grant Ed25519 signatures land with the on-chain ledger work in Phase 3. |
| **F-1.8** Storage service unauthenticated | deferred | **Resolved (writes only).** All write endpoints (`POST /contexts`, `PUT /contexts/{ctx}/centroids`, `POST /contexts/{ctx}/cells/{cluster_id}`) now require an Ed25519 signature from the owner DID associated with the context. The storage service resolves the owner DID via `did:key` (no network) and verifies before mutating state. Reads remain anonymous (correct: ciphertext is meaningless without an oracle key). Pinned by `tests/test_storage_signing.py` (5 tests). The new signing module is `flare/storage/signing.py`. |
| **F-1.12** Oracle endpoint binding by URL, not DID | deferred | **Resolved.** `ContextRegistration` now carries `oracle_did` in addition to `oracle_endpoint`. The query engine threads the registered DID into every batch oracle request and refuses any response whose Ed25519 signature does not verify against that DID. A man-in-the-middle that swaps the URL into a rogue oracle (even one holding the real master key) cannot impersonate the registered oracle DID; the query node detects the substitution and treats the affected cells as denied. Pinned by `tests/test_oracle_did_binding.py` (2 tests). |
| **F-1.13** Per-cell HTTP round-trips dominate query latency | open | **Substantially improved.** Two changes land together:<br>1. **Batched issuance.** A single signed envelope per oracle now carries every cell key request for that oracle's contexts. One Ed25519 signature, one ECIES exchange, one HTTP round trip per oracle (instead of per cell).<br>2. **Parallel cell prefetch.** A `ThreadPoolExecutor` in `FlareQueryEngine.search` overlaps storage cell GETs with oracle batch round-trips, so the wall clock cost of cell I/O is hidden behind the cryptographic work.<br>Result: bench latency drops from **122 ms/query → 61.7 ms/query** at the same `nprobe=8/nlist=64` configuration. Overhead vs plaintext brute force is now **14×**, down from 30×. Source: `paper/evals/phase2_bench.json`. |

---

## New Phase 2 findings

### F-2.1 — Single-cell `/issue` endpoint is preserved without response signing
- **Severity:** info (legacy surface)
- **Status:** accepted; deferred-to-phase-3 for removal
- **Where:** `flare/oracle/service.py:issue`
- **Reasoning:** The Phase 1 `/issue` endpoint is still wired up and tested for the simplest possible code path. It does **not** carry the Ed25519 response signature that `/issue-batch` does, so it provides confidentiality but not origin authentication. Production query nodes use `/issue-batch` exclusively (`flare/oracle/client.py:HttpOracleClient.request_cell_keys_batch`) and `flare/query.py` never calls `/issue`. If a future deployment wired the legacy endpoint into a query path, it would inherit the F-1.12 weakness that Phase 2 closed for the batch path. Documented so the gap is visible; the endpoint is slated for removal in Phase 3.

### F-2.2 — Storage write signatures lack a nonce / replay window
- **Severity:** low
- **Status:** open; deferred-to-phase-3
- **Where:** `flare/storage/service.py:put_cell`, `flare/storage/signing.py`
- **Reasoning:** Owner-signed cell uploads sign `(context_id, cluster_id, sha256(cell_blob))`. The signature does not include a nonce or timestamp, so an on-path attacker who has captured a valid upload can replay it verbatim against the same `(context, cluster)`. The replay attack window is bounded to the bootstrap phase (after which an upload simply overwrites itself with the same bytes) and the *content* the attacker delivers is identical to what the owner already sent — there is no integrity loss, only the ability to keep storage's clock from advancing past a chosen upload. Phase 3 adds a `nonce + timestamp` to the canonical upload bytes and storage tracks consumed nonces for a short window.

### F-2.3 — Storage centroids upload reuses the cell-upload signature shape
- **Severity:** info
- **Status:** mitigated
- **Where:** `flare/storage/signing.py:canonical_cell_upload_bytes`, used with `cluster_id=-1` for centroids
- **Reasoning:** We deliberately use the same canonical-bytes function for cell uploads and centroids uploads, with `cluster_id=-1` as a sentinel for "this blob is the centroids, not a cell". The encoding is signed-int-8-bytes so `-1` is unambiguous, and a signed cell upload with `cluster_id=-1` cannot be replayed against a normal cell slot because storage routes the request by URL (`/centroids` vs `/cells/{cluster_id}`) before checking the signature. Reusing the function avoids an extra signing primitive and keeps the signing surface minimal.

### F-2.4 — Path-predicate evaluation cost grows with frontier width
- **Severity:** info
- **Status:** accepted
- **Where:** `flare/lightcone.py:LightConeGraph.authorized_contexts`
- **Reasoning:** Phase 2's path-stateful BFS carries the full visited path on every frontier element. For dense graphs with many short paths to the same node, this can blow up the frontier compared to the Phase 1 visited-set BFS. Cost is bounded by `O(K * branching^K)` where K is the hop limit, which for the typical K=4 and small branching is fine. A real-scale graph would want a constraint-aware traversal that prunes the frontier earlier. Acceptable for the prototype; tracked here so a Phase 4 optimization isn't a surprise.

### F-2.5 — Batch issuance: one oracle's deny does not affect another oracle's grants
- **Severity:** info
- **Status:** mitigated by design
- **Where:** `flare/query.py:FlareQueryEngine.search`
- **Reasoning:** The query engine groups cells by oracle endpoint and dispatches one batch per oracle. If oracle Alice denies all of Alice's cells (e.g. revoked grant) the batch returns an all-denied response, but oracle Bob's batch is unaffected and Bob's cells still produce hits. This is the intended composition: each owner's authorization decisions are independent. Tested implicitly by `tests/test_end_to_end.py::test_grant_then_query_then_revoke` (Bob's `workspace_bob` cells continue to return hits while Alice's are denied post-revoke).

### F-2.6 — `ThreadPoolExecutor` lifetime spans the entire `search()` call
- **Severity:** info
- **Status:** accepted
- **Where:** `flare/query.py:FlareQueryEngine.search`
- **Reasoning:** Each call to `search()` constructs and tears down a `ThreadPoolExecutor`. For high QPS this is wasteful; a long-lived executor on the engine instance would be cheaper. Phase 2 prioritizes correctness and the bench shows the overhead is small relative to the wire protocol latency. A pooled executor is a Phase 3 optimization.

### F-2.7 — Oracle signing key shares the same lifetime / storage as the master key
- **Severity:** info
- **Status:** accepted; deferred-to-phase-4
- **Where:** `compose/generate_secrets.py`, `flare/services_main.py:run_oracle`
- **Reasoning:** The compose stack delivers both the oracle's symmetric master key AND its Ed25519 signing seed via `/secrets/phase2.env`. Compromise of the secrets file yields both. Phase 4's TEE work seals both keys inside the enclave. Documented so the equivalence is explicit.

### F-2.8 — Wire protocol carries no transport-layer rate limiting
- **Severity:** low
- **Status:** open
- **Where:** `flare/oracle/service.py`, `flare/storage/service.py`
- **Reasoning:** Neither service rate-limits per-DID. A misbehaving query node can flood the oracle with valid signed batch requests; the oracle has to do the Ed25519 verification, ledger lookup, and ECIES work for every one. This is a denial-of-service surface, not a confidentiality one. Standard mitigations (per-DID token bucket, fail2ban-style escalation) are operational concerns and do not require protocol changes.

---

## Items reviewed and unchanged

- **F-0.7 / F-1.11 (centroid leakage):** unchanged. Phase 4.
- **F-0.8 (oracle access pattern leakage):** unchanged. Phase 4 — forward illumination + padding.
- **F-1.1 (`did:key` only):** unchanged. Phase 3 with the on-chain ledger.
- **F-1.2 (per-process nonce cache):** unchanged. Phase 3 with shared nonce state.
- **F-1.5 (in-flight requests after revoke):** unchanged. Phase 4 with cell-key TTLs.
- **F-1.9 (compose env-var master keys):** unchanged. Phase 4 with TEE-sealed storage.
