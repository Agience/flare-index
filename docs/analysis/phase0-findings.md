# Phase 0 — Findings

Date opened: 2026-04-07
Scope: single-process Python prototype (`flare/`), in-memory ledger, single oracle per owner, no network, no TEE.

These are observations made *while writing* the Phase 0 code, not a retrospective audit. Each entry names the file the issue lives in. Severity uses the rubric in [README.md](README.md).

---

## F-0.1 — Master keys live in Python `bytes` and cannot be zeroized
- **Severity:** med
- **Status:** accepted (Phase 0); deferred-to-phase-1 for process isolation, deferred-to-phase-4 for TEE
- **Where:** `flare/oracle.py:LocalOracle.__init__` (`self._master_key = master_key`)
- **Reasoning:** CPython `bytes` are immutable and the runtime makes no zero-on-free guarantee. The master key persists in memory until GC, and even then the underlying buffer may be reused. A core dump, swap file, or live process inspection (ptrace, /proc/$pid/mem, debugger attach) reveals it. The doc's "ephemeral keys" framing applies to the *cell* keys returned by `issue_key`, not the master key — the master key is by design long-lived.
- **Mitigation now:** none in code. Documented honestly here and in README so the paper does not overclaim.
- **Mitigation later:** Phase 1 moves the oracle to its own process so a compromise of a query node does not see the master key. Phase 4 (TEE) places the master key inside an enclave so the oracle operator cannot extract it either.

## F-0.2 — Cell keys returned by the oracle are also Python `bytes`
- **Severity:** low
- **Status:** accepted
- **Where:** `flare/query.py:FlareQueryEngine.search` (the `cell_keys` dict)
- **Reasoning:** Same memory-zeroization limit. The mitigation we *can* apply is keeping the lifetime tight: keys live only inside the `try`/`finally` of `search()` and are dropped before return. This bounds exposure to the duration of one query rather than the lifetime of the process.
- **Mitigation now:** `cell_keys.clear()` in `finally`. This is best-effort, not a security boundary.

## F-0.3 — HKDF `info` field is structured but parser-hostile contexts could collide
- **Severity:** low
- **Status:** mitigated
- **Where:** `flare/crypto.py:derive_cell_key`
- **Reasoning:** The doc sketch uses `context_id + ":" + cluster_id` as HKDF info. A `context_id` containing `:` plus a numeric tail could collide with a different `(context_id, cluster_id)` pair, allowing two distinct cells to share a key. We use `context_id + 0x00 + uint64(cluster_id)` instead and reject `context_id` strings containing NUL. This is a structural fix, not a runtime check.
- **Mitigation now:** `_validate_context_id` rejects NUL bytes; `cluster_id` is encoded as a fixed-width integer.

## F-0.4 — Ledger is in-memory and trivially mutable
- **Severity:** info (Phase 0); deferred-to-phase-3
- **Status:** accepted
- **Where:** `flare/ledger.py:InMemoryGrantLedger`
- **Reasoning:** The `revoke` method mutates the existing grant in place. There is no append-only log, no signatures, no tamper evidence. Any code with a reference to the ledger can rewrite history. This is faithful to "Phase 0 substitute for the blockchain ledger" and not a real defect — Phase 3 swaps in Ceramic / Ethereum L2 with the same `find_valid` interface.

## F-0.5 — Race between `revoke` and an in-flight `issue_key`
- **Severity:** low
- **Status:** open (Phase 0); revisit in Phase 1 with real concurrency
- **Where:** `flare/ledger.py`, `flare/oracle.py`
- **Reasoning:** A query can pass the ledger check microseconds before `revoke` is called, then receive a key. The window is bounded by the duration of one query. In Phase 0 there is no concurrency at all so this is theoretical. Phase 1 adds concurrent oracles and makes this a real test case. Mitigation strategies: short cell-key TTL, oracle re-check at decryption time, or signed-grant tokens with explicit `not_after`.

## F-0.6 — Light-cone deny is node-level, not path-level
- **Severity:** med
- **Status:** deferred-to-phase-1
- **Where:** `flare/lightcone.py:LightConeGraph.authorized_contexts`
- **Reasoning:** The doc allows per-path deny (a deny edge prunes specific paths, not all paths to a target). The Phase 0 implementation excludes a context iff *any* currently-active deny edge points at it, regardless of which principal is asking. This is sound (over-denies, never under-denies) but less expressive. A reviewer would correctly flag this as not implementing the full doc semantics. Tracked for Phase 1.

## F-0.7 — Centroids are public and disclose vector-space topology per context
- **Severity:** info
- **Status:** accepted; carried into paper §Security Analysis
- **Where:** `flare/index.py:FlareIndex.candidate_cells`
- **Reasoning:** Centroids are the routing primitive — they must be readable to route a query. For embedding dimensions ≥ 64 the information leakage is low (centroids are points in a high-dimensional space and not interpretable as content), but it is not zero. An adversary can: (a) measure how clustered a context's vectors are, (b) detect when two contexts have semantically adjacent content, (c) potentially run a similarity attack between a known-plaintext query and the centroids. Mitigation strategies (centroid noise, distance-based padding, locality-preserving hashing) are out of scope for Phase 0 but should be discussed.

## F-0.8 — Oracle request log leaks access patterns
- **Severity:** med
- **Status:** deferred-to-phase-4 (forward illumination + padding)
- **Where:** `flare/oracle.py:LocalOracle` (the `issued_count`/`denied_count` counters demonstrate the leak)
- **Reasoning:** Even with perfect cell encryption, an observer of the oracle's request stream learns *which contexts a principal is querying and how often*. This is the access-pattern attack the doc explicitly does not solve in Phase 0 and addresses partially in Phase 4 via constant-width padding and forward illumination. Documented honestly in the paper's Threat Model "what we do not protect against" subsection.

## F-0.9 — `np.savez` cell serialization is safe but trusts ciphertext integrity
- **Severity:** info
- **Status:** mitigated
- **Where:** `flare/index.py:_serialize_cell` / `_deserialize_cell`
- **Reasoning:** We deliberately chose `np.savez` over `pickle`: numpy's loader does not execute code on load, so even a maliciously-crafted plaintext cannot RCE the query node. Cell integrity is enforced by AES-GCM with `(context_id:cluster_id)` as AAD, so a swapped or tampered cell is rejected before deserialization runs.

## F-0.10 — Recall loss from context-aligned IVF is unmeasured at small N
- **Severity:** info
- **Status:** open (measured by `bench/bench_encrypted_vs_plain.py`)
- **Reasoning:** Building one IVF per context rather than a single global IVF means cross-context recall depends on whether the query lands near a centroid in *each* relevant context. The bench reports recall@10 against a brute-force oracle on a single context (since cross-context recall requires multi-owner setup). A multi-context recall benchmark is added in Phase 1.

## F-0.11 — `FlareQueryEngine` trusts its `oracles` dict
- **Severity:** info
- **Status:** accepted
- **Where:** `flare/query.py:FlareQueryEngine.__init__`
- **Reasoning:** The query engine is constructed with a dict mapping principals to oracle instances. In a real deployment, the engine would discover oracles via the grant ledger (`oracle_endpoints` field on the Grant record) and call them over a network. Phase 0 hard-wires the dict to keep the prototype legible. The grant record schema in `flare/types.py:Grant` already has the field; it is just unused.

---

## Items that are NOT findings (clarification for reviewers)

- **"Anyone can call `LocalOracle.issue_key` directly":** correct — there is no auth on the oracle method itself in Phase 0. The oracle is in-process with the query engine. Phase 1 moves the oracle out of process and the wire protocol authenticates the requester.
- **"`LightConeGraph` is not an actual graph DB":** intentional. The doc lists ArangoDB. Phase 1 swaps in ArangoDB behind the same interface.
- **"There is no DID resolution":** intentional. Principals are opaque strings shaped like DIDs. Phase 3 adds resolution.
