# Phase 4 — Findings

Date opened: 2026-04-07
Scope: cell-key TTLs on every issued oracle response, multi-endpoint context registration with coordinator failover, sealed key storage with explicit memory zeroization (`SecureBytes` + `EncryptedFileKeyStore` + `SealedKeyBundle`), constant-width oracle batch padding with authorized noise cells. Three explicitly-deferred items: real TEE (hardware), incentives + slashing (own paper), centroid topology mitigation (calibration research).

These findings extend (not replace) `phase0` through `phase3` findings.

---

## Items from earlier phases resolved by Phase 4

| ID | Earlier status | Phase 4 update |
|---|---|---|
| **F-0.8** Oracle access pattern leakage | deferred-to-phase-4 | **Resolved (in software).** `FlareQueryEngine.padding_width` makes every oracle batch a fixed width regardless of how many cells the query actually needs. The query engine pads up to that width with random authorized cells whose keys are received but whose underlying ciphertext cells are never decrypted. An observer of the oracle wire sees a constant-width batch every time. The remaining leak — *which* contexts a principal queries — is an inherent consequence of per-context oracles and is not closeable without changing the oracle topology. Pinned by `tests/test_padding.py`. Note: forward illumination via a *learned predictive model* is still not implemented; the deterministic padding here gives the same security shape (constant-width oracle batches) without needing a training pipeline. |
| **F-1.5** In-flight requests after revoke (unbounded cell-key TTL) | deferred-to-phase-4 | **Resolved.** Every batch entry now carries a `valid_until_ns` field inside the AAD-bound canonical response bytes. The query node enforces the TTL at decode time (`flare/wire.py:verify_and_decrypt_batch_response`) and again at use time (`flare/query.py:FlareQueryEngine.search`). The default TTL is 60 seconds; deployments tune it. A request signed before revoke can still be served, but the resulting cell key cannot be used past the TTL — bounding the in-flight-after-revoke window to at most one TTL. Pinned by `tests/test_cell_key_ttl.py` and `tests/test_wire_batch.py::test_expired_ttl_returns_none`. |
| **F-1.9 / F-2.7** Master + signing keys delivered via env vars in compose | deferred-to-phase-4 | **Mitigated (software substitute for TEE).** `flare/sealed.py` introduces `EncryptedFileKeyStore`: keys are persisted as a passphrase-encrypted blob (scrypt → AES-256-GCM) and loaded into `SecureBytes` wrappers at process start. The compose stack now writes one sealed file per oracle replica to `/secrets/sealed/*.bin` and the entrypoint sets `SEALED_KEY_FILE` + `SEALED_KEY_PASSPHRASE_FILE`; `flare/services_main.py:_load_oracle_secrets` loads from the sealed file when those env vars are set. Env-var delivery is preserved as a fallback. The on-disk artifact is useless without the passphrase. Pinned by `tests/test_sealed_storage.py`. The remaining gap to true TEE is recorded in F-4.1. |
| **F-3.2** Threshold reconstruction briefly holds master key in coordinator memory | accepted-deferred-to-phase-4 | **Mitigated (in software).** The reconstructed master key in `OracleCore.decide_batch` now lives in a `SecureBytes` wrapper that is explicitly zeroized via `ctypes.memset` in the `finally` block. The buffer most likely to survive in heap snapshots and core dumps is the canonical reconstruction buffer, which is the buffer we wipe. The transient `view()` copy passed to HKDF cannot be wiped (CPython `bytes` are immutable) but its lifetime is bounded by the same `finally`. The hardware-enclave gap remains and is recorded in F-4.1. |
| **F-3.7** One coordinator URL per registration | deferred-to-phase-4 | **Resolved.** `ContextRegistration` now carries `oracle_endpoints: list[OracleEndpoint]` instead of a single `(url, did)` pair. The owner-signed canonical bytes cover the full ordered list. The query engine tries the registered endpoints in order via `FlareQueryEngine._try_oracle_endpoints` and returns the first cooperating response. Each call independently verifies the response signature against the per-endpoint `oracle_did`, so a MitM that swaps a URL into the registration cannot impersonate the registered oracle. Pinned by `tests/test_oracle_did_binding.py::test_failover_around_a_single_rogue_endpoint` and `test_query_engine_denies_when_every_endpoint_is_rogue`. |
| **F-2.1** Legacy `/issue` endpoint (closed in Phase 3) | already closed | (no change) |
| **F-1.6** Path-predicate deny (closed in Phase 2) | already closed | (no change) |

---

## New Phase 4 findings

### F-4.1 — Software sealed storage is not a TEE
- **Severity:** info (honest framing)
- **Status:** accepted; deferred indefinitely (requires SGX/SEV hardware)
- **Where:** `flare/sealed.py`, `flare/oracle/core.py`
- **Reasoning:** `EncryptedFileKeyStore` + `SecureBytes` is a real software improvement over Phase 3's env-var delivery, but it is **not** a TEE. The differences a deployment must understand:
  - **What software sealing protects against.** Post-process forensics: the on-disk artifact is unintelligible without the passphrase; the in-memory buffer we control is zeroized via `ctypes.memset` after use, so it does not survive in core dumps, swap pages, or freed-heap inspection.
  - **What software sealing does NOT protect against.** A live operator with `ptrace`, `/proc/<pid>/mem`, debugger attach, or root-equivalent privileges on the oracle host can inspect the running process at any time. The `SecureBytes.view()` copy passed into HKDF / AES-GCM is a CPython `bytes` object whose underlying buffer we cannot zeroize, and the runtime may make further copies in places we cannot reach (string interning, GC tenured heaps, libc network buffers). A real TEE keeps the secret inside an enclave whose memory the host operator cannot read; software sealing does not.
  - **What this prototype offers honestly.** Strictly stronger than env-var delivery and strictly stronger than holding the secret in a long-lived `bytes` field. Strictly weaker than SGX / SEV. Treating it as a step on the path to a real enclave deployment is correct; treating it as equivalent to a TEE is not.

### F-4.2 — `SecureBytes.view()` returns a normal `bytes` copy
- **Severity:** info
- **Status:** accepted (consequence of CPython memory model)
- **Where:** `flare/sealed.py:SecureBytes.view`
- **Reasoning:** Modern crypto APIs (`HKDF.derive`, `AESGCM.encrypt`, X25519 ECDH) take `bytes`, not buffer protocol objects. We have to materialize a `bytes` copy to call them. The point of `SecureBytes` is to control the *long-lived* copy of the secret (the canonical bytearray we wipe); the short-lived `view()` copy is intentionally accepted as residual exposure. Callers who hold `view()` results across function boundaries defeat the protection — every consumer in the FLARE codebase consumes the view immediately and lets it go out of scope.

### F-4.3 — Padding pool is the principal's full authorized cell set
- **Severity:** low
- **Status:** accepted
- **Where:** `flare/query.py:FlareQueryEngine._pad_to_width`
- **Reasoning:** When padding is enabled, the engine pads with random cells drawn from the principal's full authorized set across all reachable contexts. Two implications:
  - The padded cells are *also* `granted` from the oracle's perspective (the principal has a valid grant), so the request stream is constant-width and constant-content (every cell is granted). This is the intended security shape.
  - If the principal's authorized set is small (fewer cells than the padding width), the engine pads up to the pool size and stops, so the request stream is bounded by `min(padding_width, |authorized cells|)`. A principal with very few authorized cells has less padding noise and therefore less obfuscation. Pinned by `test_padding_caps_at_pool_size`.

  An alternative pool — drawing padding from cells the principal CANNOT reach — would defeat the security goal because every padded cell would be denied by the oracle, and the resulting denied/granted distribution would itself leak which contexts the principal can reach.

### F-4.4 — Cell-key TTL is uniform across the batch
- **Severity:** info
- **Status:** accepted
- **Where:** `flare/wire.py:encrypt_and_sign_batch_response`
- **Reasoning:** Every cell key in a batch carries the same `valid_until_ns`. A deployment that wants per-cell TTLs (e.g., shorter TTL for high-sensitivity contexts) would need to extend the response schema to carry one TTL per entry. The current design simplifies the security analysis: the TTL bound on the in-flight-after-revoke window is the same for every cell in the batch.

### F-4.5 — TTL relies on coordinated wall-clock time
- **Severity:** low
- **Status:** open
- **Where:** `flare/wire.py:encrypt_and_sign_batch_response`, `flare/query.py:FlareQueryEngine.search`
- **Reasoning:** The TTL is a wall-clock instant set by the oracle and checked by the query node. Both processes have to agree on roughly what time it is. NTP drift on either side can cause early-deny (oracle's clock ahead) or late-allow (query node's clock behind). The 5-minute storage write skew window shows what tolerance is acceptable for non-security-critical operations; for the cell-key TTL we use a tighter bound (60s default) and assume NTP. A monotonic-clock alternative requires cross-process clock synchronization that is out of scope for the prototype.

### F-4.6 — Failover order is the registration order
- **Severity:** info
- **Status:** accepted
- **Where:** `flare/query.py:FlareQueryEngine._try_oracle_endpoints`
- **Reasoning:** The query engine tries endpoints strictly in the order the owner registered them. Two implications:
  - **No load balancing.** Every query that succeeds against endpoint 1 hits endpoint 1. Endpoint 2/3 only see traffic when endpoint 1 fails. A production deployment would either round-robin or hash-on-querier to spread load; both are pure optimizations and not a security concern.
  - **Predictable for an observer.** A passive observer of the oracle wire learns "endpoint 1 is the preferred coordinator". This is mostly harmless because the registration is public anyway, but it does mean a targeted attacker who wants to influence which oracle a query hits should attack endpoint 1 first.

### F-4.7 — Padding uses Python's stdlib `random` rather than a CSPRNG
- **Severity:** info
- **Status:** accepted
- **Where:** `flare/query.py:FlareQueryEngine._pad_to_width`
- **Reasoning:** Padding cells are selected via `random.Random().shuffle()`. The `random` module is not a CSPRNG; an attacker who knows the PRNG state can predict which cells will be selected. This is acceptable because the *cells* are selected from the principal's authorized set and the *purpose* of padding is access-pattern obfuscation against an oracle wire observer who does not know the PRNG state. A targeted adversary with PRNG insight could distinguish padded cells from real ones, but the underlying cell content is still encrypted. Production-quality padding would use `secrets.SystemRandom` for one extra line of defense.

### F-4.8 — Centroid topology leakage (F-0.7) is still open
- **Severity:** info
- **Status:** open; out of scope for prototype
- **Where:** `flare/storage/memory.py:InMemoryStorage.get_centroids`
- **Reasoning:** The serious mitigations for centroid leakage (Gaussian noise injection, locality-preserving hashing, centroid bucketing) all require calibration that is its own research project. We deliberately avoid implementing a half-baked mitigation that would either over-perturb (destroying routing accuracy) or under-perturb (leaking the topology anyway). The honest move is to leave this open and document that the centroids are public by design and that the high-dimensional embedding space provides natural obfuscation that has not been formally bounded.

### F-4.9 — Token incentives + slashing are explicitly out of scope
- **Severity:** info
- **Status:** accepted; not on the prototype roadmap
- **Where:** N/A
- **Reasoning:** The original design doc lists token-economic incentives for storage providers, oracle operators, and routing nodes, plus slashing conditions for oracles that issue keys for revoked grants. These are real engineering problems that require their own design phase, their own threat model, and their own paper. We make no attempt to address them in the FLARE prototype. A deployment that wants economic incentives would integrate with an existing incentive layer (Filecoin for storage, custom tokens for oracles) rather than baking it into the cryptographic protocol.

### F-4.10 — Forward illumination via a learned predictive model is not implemented
- **Severity:** info
- **Status:** accepted; the deterministic padding in F-0.8 covers the same security goal
- **Where:** N/A
- **Reasoning:** The original design proposed a learned model that predicts adjacent clusters from query history and pre-fetches their keys. We implement constant-width padding instead because:
  - **Same security shape.** Both achieve "constant-width oracle requests independent of query specificity". The attacker model is the same.
  - **No training pipeline.** A learned predictor needs query traces, training, and ongoing retraining. The padding approach is a one-line config (`padding_width = N`).
  - **No prediction risk.** A bad predictor under-illuminates and slows queries; deterministic padding is bounded by `padding_width` and does not depend on prediction quality.

  A deployment that wants the additional optimization of *pre-fetching the right cells before the user asks* (rather than just padding the request) would add the predictive model as a separate optimization layer on top of the padded request stream.

---

## Items unchanged from earlier phases

- **F-0.7 / F-1.11 (centroid leakage):** see F-4.8 above. Still open.
- **F-1.2 / F-3.3 (per-process nonce caches):** unchanged. Real deployments share state via Redis or similar.
- **F-1.7 (ledger consensus):** see F-3.1 — the Phase 3 hash-chained log gives tamper-evidence; full consensus needs a real chain, which is an integration concern, not a prototype concern.
- **F-3.5 (peer trusts coordinator's ledger view):** unchanged. Cell-key TTLs (now closed) bound the blast radius.
