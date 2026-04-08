# Phase 1 — Findings

Date opened: 2026-04-07
Scope: multi-process FLARE prototype with FastAPI services for ledger, storage, and per-owner oracles. Authenticated wire protocol (Ed25519 + ECIES on X25519). `did:key` identities. Edge-level deny in the light cone. Concurrent revoke/issue race tests.

These findings extend (not replace) `phase0-findings.md`. Items from Phase 0 that Phase 1 *resolved* are noted at the top.

---

## Phase 0 items resolved (or partially resolved) by Phase 1

| Phase 0 ID | Phase 0 status | Phase 1 update |
|---|---|---|
| **F-0.1** Master keys in Python `bytes` | accepted | **Partially mitigated.** Master keys now live only in oracle service processes, not in the query node. A query-node compromise no longer yields master keys. Process isolation is the gap that closes here; in-memory zeroization is still impossible in CPython. Phase 4 (TEE) closes the operator-of-the-oracle-host gap. |
| **F-0.5** Revoke/issue race | open | **Bounded.** The ledger now serializes mutations through a process-local `RLock`. Combined with the post-revoke property pinned by `tests/test_concurrent_revoke.py`, the race window is reduced to "in-flight requests at the moment of revoke can still receive a key, but every subsequent request is denied". Phase 4 reduces this further with cell-key TTLs. |
| **F-0.6** Node-level deny | deferred | **Resolved (intermediate).** `flare/lightcone.py` now implements **edge-level** deny: a deny edge X→Y prunes only that transition, leaving other paths to Y intact. Tests `test_edge_level_deny_blocks_only_targeted_principal` and `test_deny_on_intermediate_edge_blocks_path_through_it` pin the new semantics. Full path-predicate deny (Sec. 5 of the design doc) is still deferred, now to Phase 2. |
| **F-0.11** Query engine trusts in-memory `oracles` dict | accepted | **Resolved.** Oracle endpoints come from the storage service's context registration. The query engine has a `oracle_resolver` callback that maps an endpoint to an `OracleClient`. In docker-compose this is keyed by the URL recorded at bootstrap time. |

---

## New Phase 1 findings

### F-1.1 — Only `did:key` is implemented
- **Severity:** info
- **Status:** deferred-to-phase-3
- **Where:** `flare/identity.py`
- **Reasoning:** `did:key` resolves locally with no network call, which is what we want for the prototype. `did:web`, `did:ethr`, etc. require external resolution and are tied to the on-chain identity story. Documented in the paper's Implementation section.

### F-1.2 — Nonce cache is per-process and lost on restart
- **Severity:** med
- **Status:** open; deferred-to-phase-3
- **Where:** `flare/wire.py:NonceCache`, instantiated in `flare/oracle/service.py`
- **Reasoning:** The replay-detection nonce set lives in process memory. Restarting an oracle process clears the cache, opening a replay window equal to the clock-skew window (60s) for any nonce captured before the restart. A real deployment shares nonce state across oracle replicas via Redis, a tiny LSM, or by deriving the nonce window from a synchronized clock. The single-replica Phase 1 is honest about this and the paper carries it as a Section 6 limitation.

### F-1.3 — Oracle error responses do not vary
- **Severity:** info
- **Status:** mitigated
- **Where:** `flare/oracle/service.py:issue`
- **Reasoning:** The handler returns the same `401 "auth failed"` for bad signature, bad timestamp, and replay; and `403 <decision>` for deny decisions. This is intentional: distinct error strings would let an attacker probe the oracle to learn whether their nonce was already used vs. whether their timestamp drifted, which is access-pattern leakage on the wire protocol layer. The HTTP status itself is the only allowed side-channel.

### F-1.4 — `/info` endpoint reveals decision counters
- **Severity:** low
- **Status:** accepted
- **Where:** `flare/oracle/service.py:info`
- **Reasoning:** The `decisions_granted` and `decisions_denied` counters are useful for tests, the demo, and operations. They are also a textbook side-channel: an observer who polls `/info` can correlate spikes with their own queries. In Phase 1 the endpoint is unauthenticated. Phase 4 either auths the endpoint to the owner only or removes per-decision counters in favor of bucketed histograms.

### F-1.5 — In-flight requests can still receive keys after `revoke` returns
- **Severity:** med
- **Status:** open; deferred-to-phase-4
- **Where:** `flare/oracle/core.py:OracleCore.decide`, `flare/ledger/memory.py`
- **Reasoning:** The serialization property pinned by `test_revoke_is_immediate_for_subsequent_requests` is **"every request whose `now > revoke_time` is denied"**. A request whose `now < revoke_time` (i.e. signed before the revoke) but which arrives at the oracle after revoke can still be denied (since the oracle uses the request's signed timestamp for ledger lookup), but the property is "not retroactive": Bob can still legitimately decrypt cells whose request he signed before he was revoked, as long as he holds the key. Cell-key TTLs in Phase 4 bound the window during which a leaked key remains useful.

### F-1.6 — Edge-level deny is still less expressive than path-predicate deny
- **Severity:** info
- **Status:** deferred-to-phase-2
- **Where:** `flare/lightcone.py:LightConeGraph._is_transition_denied`
- **Reasoning:** The current implementation can express "deny any path that traverses edge X→Y" but cannot express "deny if the path traverses both A and B". The latter requires constraint propagation along the BFS frontier. Phase 2 will introduce a small constraint language and a constraint-aware traversal.

### F-1.7 — Ledger service is unauthenticated
- **Severity:** low (Phase 1 threat model); high in production
- **Status:** deferred-to-phase-3
- **Where:** `flare/ledger/service.py`
- **Reasoning:** Anyone with network access to the ledger can write any grant, including grants where the `grantor` is somebody else's DID. The oracle still rejects grants whose `grantor != self.owner`, so the worst-case Phase 1 abuse is storage spam plus pollution of `find_valid` lookups (a denial of service against grant discovery). Phase 3's on-chain ledger requires every grant to carry a signature from the grantor's DID, which the oracle (and any reader) verifies before honoring it. The signature scheme is the same Ed25519 already in `flare/identity.py`.

### F-1.8 — Storage service is unauthenticated for both reads and writes
- **Severity:** low (read), med (write)
- **Status:** deferred-to-phase-2
- **Where:** `flare/storage/service.py`
- **Reasoning:**
  - **Reads:** ciphertext is meaningless without keys, so anonymous reads are by design. The leak is the centroid topology (already F-0.7) and the existence/cardinality of cells.
  - **Writes:** an attacker can upload garbage cells against any context, replacing the rightful owner's ciphertext. GCM AAD binding (`{context_id}:{cluster_id}`) means the garbage will fail to decrypt with the legitimate cell key — the *integrity* property still holds — but the *availability* property is broken. Phase 2 adds: every cell upload carries an Ed25519 signature from the owner DID recorded at registration time, verified by storage before persisting.

### F-1.9 — Compose stack delivers master keys via env vars
- **Severity:** med (compose stack); n/a (production design)
- **Status:** accepted (prototype)
- **Where:** `compose/generate_secrets.py`, `docker-compose.yml`, `flare/services_main.py:run_oracle`
- **Reasoning:** The compose-mode prototype generates fresh master keys at stack startup and writes them to `/secrets/phase1.env`, which is sourced by the oracle services. Env-var-delivered secrets show up in `/proc/<pid>/environ` and any process listing on the host. Acceptable for an ephemeral research stack; not acceptable for any real deployment. Phase 4 (TEE) loads the master key from sealed storage at oracle startup. Documented in `compose/generate_secrets.py` and the paper's Implementation section.

### F-1.10 — `/secrets/phase1.env` is mode 0644
- **Severity:** info
- **Status:** accepted
- **Where:** `compose/generate_secrets.py:main`
- **Reasoning:** The non-root oracle/demo containers need to read the file. We deliberately chose 0644 over more elaborate uid coordination because the secrets file is itself an artifact of F-1.9 — if the env-var delivery model is already insecure, the file mode is not the load-bearing defense. The secrets volume is recreated on every `make stack-up`, so the exposure window is bounded to the lifetime of one compose stack.

### F-1.11 — Centroids are still public per context
- **Severity:** info
- **Status:** carried from F-0.7
- **Reasoning:** Phase 1 changes nothing about centroid publication. Storage now serves them over HTTP rather than holding them in-process, which broadens the read surface to "anyone who can reach storage" — but centroids were already designed to be public, so this is not a regression. Mitigation strategies remain Phase 4 work.

### F-1.12 — Oracle endpoint binding is by URL, not by DID
- **Severity:** med
- **Status:** open; deferred-to-phase-2
- **Where:** `flare/storage/memory.py:ContextRegistration.oracle_endpoint`, `flare/query.py`
- **Reasoning:** The query engine looks up `reg.oracle_endpoint` from storage, and trusts that URL to be the correct oracle for the context. A man-in-the-middle on the storage<->query connection can substitute a different URL pointing at an attacker-controlled oracle. The attacker-oracle can return ANY cell key, but those keys won't decrypt the cells because the cells are encrypted under a key the attacker doesn't have — so the *confidentiality* property still holds. The *availability* property does not: the attacker can return junk keys that fail GCM, dropping all results from the targeted context. Phase 2 binds the oracle DID into the registration and has the query engine verify the oracle's `/info` response against the registered DID before sending cell keys; combined with Phase 3's signed grants that name the oracle DID, this is end-to-end binding.

### F-1.13 — Wire-protocol round-trip dominates query latency
- **Severity:** info (performance, not security)
- **Status:** open
- **Where:** `bench/bench_encrypted_vs_plain.py` output `paper/evals/phase1_bench.json`
- **Reasoning:** Phase 1 measured 122 ms/query vs. 4 ms plaintext brute force at N=20k, dim=64, nprobe=8. The 30× overhead is dominated by the per-cell HTTP round trip (one for the oracle key request, one for the storage cell fetch) and the ECIES on every key response, not by the symmetric crypto itself. Two non-security optimizations land in Phase 2: (a) **batch oracle requests** — issue all keys for a query in one signed envelope, decrypt all cells with one ECIES exchange; (b) **cell pre-fetch** — overlap the storage GET with the oracle request. These are deferred to keep Phase 1's wire protocol auditable as the simplest possible thing that works.

### F-1.14 — Oracle does not authenticate the storage service
- **Severity:** info
- **Status:** open
- **Where:** N/A — the oracle never talks to storage in Phase 1, only the query engine does
- **Reasoning:** This is a non-finding, recorded for clarity. Some readers expect the oracle to verify storage somehow; in this design the oracle's only inputs are the signed wire request and the ledger. Storage is consulted only by the query node (for cells and centroids) and by data owners (for uploads). The trust boundary diagram in `paper/figures/trust_phase1.mmd` makes this explicit.

---

## Items reviewed and unchanged from Phase 0

- F-0.2 (cell keys in Python bytes): unchanged. Now lives in the oracle service process; the query engine holds the same property for the duration of one search.
- F-0.3 (HKDF info construction): unchanged.
- F-0.4 (in-memory ledger): backing store is the same `InMemoryGrantLedger`; what changed is that it now lives in its own process.
- F-0.7 (centroid leakage): see F-1.11.
- F-0.8 (oracle access pattern leakage): unchanged. Phase 4 work.
- F-0.9 (`np.savez` cell serialization): unchanged.
- F-0.10 (recall loss): unchanged numerically (still 0.446 at the same configuration), now measured through the wire protocol.
