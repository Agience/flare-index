# FLARE — Security Risk Register

This document is the canonical security analysis of the FLARE prototype. Every observation made while writing the code that has security significance is recorded here, with a severity, the file path it lives in, the current status, and where applicable a reference to a test that pins the property.

The companion files (`phase0-findings.md` … `phase4-findings.md`) are the historical changelogs of how each finding was discovered and resolved during development. They are kept for provenance but **this file is what a reviewer should read**.

## Severity rubric

| Severity | Meaning |
|---|---|
| **info** | Documented for completeness; not a defect under the threat model |
| **low** | Minor weakness, no realistic exploit path within scope |
| **med** | Exploit possible under non-trivial assumptions; mitigation deferred or accepted |
| **high** | Exploit possible under realistic assumptions; must be addressed before any deployment |
| **critical** | Breaks a core security claim of the system |

## Status values

- **closed** — fixed, with a test that pins the fix
- **mitigated** — substantially closed in software; residual gap documented
- **accepted** — known limitation, in scope of the threat model, called out in the paper's Limitations
- **out-of-scope** — explicitly not addressed by FLARE (e.g. token economics)
- **integration** — closed by a real deployment integration that the prototype intentionally does not perform (real TEE, real consensus chain)

---

## Closed

These properties hold and are pinned by tests. The "where" column points at the file where the property is implemented; the "test" column points at the test that asserts it.

| ID | Property | Severity if missing | Where | Test |
|---|---|---|---|---|
| C-1 | HKDF derivation deterministically separates contexts and clusters; collision-free `info` encoding via NUL separator and fixed-width `cluster_id` | high | `flare/crypto.py:derive_cell_key` | `tests/test_crypto.py::test_hkdf_*` |
| C-2 | AES-GCM AAD binding rejects swapped cells | high | `flare/crypto.py:encrypt_cell` / `decrypt_cell` | `tests/test_crypto.py::test_aead_rejects_*` |
| C-3 | `did:key` round-trip and Ed25519 signature verification work end-to-end via the unified `DIDResolver` | high | `flare/identity.py` | `tests/test_identity.py::*` |
| C-4 | `did:web` resolves through HTTPS and is cached within TTL | med | `flare/identity.py:DIDResolver._resolve_did_web` | `tests/test_did_resolver.py::test_did_web_*` |
| C-5 | Wire request: replay nonces are rejected within the clock-skew window | high | `flare/wire.py:NonceCache`, `verify_request` | `tests/test_wire.py::test_replay_rejected` |
| C-6 | Wire request: timestamps outside the ±60 s skew window are rejected | high | `flare/wire.py:verify_request` | `tests/test_wire.py::test_timestamp_skew_rejected` |
| C-7 | ECIES on the response: a passive eavesdropper who captures both directions of the wire cannot recover the cell key without the requester's per-request ephemeral X25519 private key | high | `flare/wire.py:encrypt_response`, `decrypt_response` | `tests/test_wire.py::test_eavesdropper_cannot_recover_key` |
| C-8 | Batch wire round-trip: granted + denied entries decrypt to the right keys; `IssuedCellKey.valid_until_ns` is non-zero on every grant | high | `flare/wire.py:encrypt_and_sign_batch_response`, `verify_and_decrypt_batch_response` | `tests/test_wire_batch.py::test_round_trip_*` |
| C-9 | Batch wire response: a rogue oracle DID is rejected even if it returned a valid-looking ECIES blob | critical | `flare/wire.py:verify_and_decrypt_batch_response` | `tests/test_wire_batch.py::test_wrong_oracle_did_rejected` |
| C-10 | Batch wire response: a byte-flip on any per-cell ciphertext breaks the response signature | high | `flare/wire.py` | `tests/test_wire_batch.py::test_response_signature_tamper_detected` |
| C-11 | Cell-key TTL: every issued key carries a signed `valid_until_ns` inside the AAD-bound canonical bytes; expired keys are dropped at decode AND at use time | high | `flare/wire.py:BatchEntry.valid_until_ns`, `flare/query.py:FlareQueryEngine.search` | `tests/test_cell_key_ttl.py::*`, `tests/test_wire_batch.py::test_expired_ttl_returns_none` |
| C-12 | Owner sees own data; an unauthorized principal sees nothing through the full multi-process stack | critical | `flare/query.py`, `flare/oracle/core.py` | `tests/test_end_to_end.py::test_owner_sees_own_data`, `test_unauthorized_principal_sees_nothing` |
| C-13 | A grant illuminates a previously-unauthorized context; revocation hides it again with **no re-encryption and no key rotation** | critical | `flare/ledger/`, `flare/oracle/core.py`, `flare/query.py` | `tests/test_end_to_end.py::test_grant_then_query_then_revoke` |
| C-14 | Light cone edge-level deny: blocks one principal while leaving others' direct grants intact | high | `flare/lightcone.py:_is_transition_denied` | `tests/test_lightcone.py::test_edge_level_deny_*` |
| C-15 | Light cone path-predicate deny: blocks paths through a denied node-set; alternate paths survive | high | `flare/lightcone.py:_path_denied`, `RequireAllOf`, `RequireSequence` | `tests/test_path_predicates.py::test_require_all_of_*` |
| C-16 | Shamir secret sharing: K of M shares reconstruct the secret; K-1 shares do not | critical | `flare/oracle/threshold.py:split_secret`, `reconstruct_secret` | `tests/test_threshold_shamir.py::*` |
| C-17 | Threshold oracle integration: when fewer than K-1 peers cooperate, the whole batch is denied | high | `flare/oracle/core.py:OracleCore.decide_batch`, `flare/oracle/peer_client.py:PeerShareFetcher` | `tests/test_threshold_oracle.py::test_threshold_with_no_peers_denies` |
| C-18 | A peer oracle independently re-checks the ledger before releasing its share to a coordinator; a rogue coordinator cannot trick a peer into releasing for an unauthorized querier | critical | `flare/oracle/service.py:peer_share` | `tests/test_threshold_oracle.py::test_peer_refuses_share_release_for_unauthorized_requester` |
| C-19 | A peer oracle refuses share requests from coordinators not in its allowlist | high | `flare/oracle/service.py`, `flare/oracle/peer_wire.py:verify_peer_request` | `tests/test_threshold_oracle.py::test_peer_refuses_unknown_coordinator` |
| C-20 | Threshold-mode end-to-end query (3 replicas, K=2) returns owner data through the full peer share-fetch path | high | full stack | `tests/test_threshold_oracle.py::test_owner_query_succeeds_with_full_quorum` |
| C-21 | The ledger rejects unsigned grants and revocations not signed by the original grantor | critical | `flare/ledger/service.py`, `flare/ledger/signing.py` | `tests/test_signed_ledger.py::test_unsigned_*`, `test_revoke_requires_*` |
| C-22 | The ledger chain head advances per state change and replays back to `GENESIS_HASH`; tampering is detectable by re-walking the chain | high | `flare/ledger/memory.py:append`, `flare/ledger/signing.py:chain_hash` | `tests/test_signed_ledger.py::test_chain_log_replay_validates_head` |
| C-23 | Storage register / cell upload: rejects writes whose signature does not match the owner DID | critical | `flare/storage/service.py`, `flare/storage/signing.py` | `tests/test_storage_signing.py::*` |
| C-24 | Storage write replay: a captured registration or cell upload cannot be replayed verbatim within the skew window | high | `flare/storage/signing.py:StorageNonceCache` | `tests/test_storage_replay.py::*` |
| C-25 | Multi-endpoint registration: failover around a single rogue endpoint succeeds via the remaining real replicas | med | `flare/query.py:_try_oracle_endpoints`, `flare/storage/memory.py:ContextRegistration.oracle_endpoints` | `tests/test_oracle_did_binding.py::test_failover_around_a_single_rogue_endpoint` |
| C-26 | Multi-endpoint registration: query is denied if every endpoint is rogue (DID binding still holds) | critical | same | `tests/test_oracle_did_binding.py::test_query_engine_denies_when_every_endpoint_is_rogue` |
| C-27 | Constant-width batch padding: every batch sent to an oracle has the same width regardless of query specificity; padding cells do not contribute hits | med | `flare/query.py:_pad_to_width` | `tests/test_padding.py::*` |
| C-28 | `SecureBytes` round-trip and explicit `clear()` zeroize the underlying buffer via `ctypes.memset` | med | `flare/sealed.py:SecureBytes` | `tests/test_sealed_storage.py::*` |
| C-29 | `EncryptedFileKeyStore` round-trip: scrypt-derived KEK + AES-256-GCM payload; wrong passphrase rejected | med | `flare/sealed.py:EncryptedFileKeyStore` | `tests/test_sealed_storage.py::test_sealed_file_*` |
| C-30 | Concurrent queriers under contention with a revoker thread: no post-revoke leak, no crash | high | `flare/ledger/memory.py:RLock`, `flare/oracle/core.py` | `tests/test_concurrent_revoke.py::test_concurrent_queries_during_revoke` |
| C-31 | Revocation is immediate: every subsequent oracle request after `ledger.revoke` returns is denied | critical | `flare/oracle/core.py:decide_batch`, `flare/ledger/memory.py` | `tests/test_concurrent_revoke.py::test_revoke_is_immediate_for_subsequent_requests` |

## Mitigated (residual gap documented)

| ID | Observation | Severity | Status | Where | Reasoning |
|---|---|---|---|---|---|
| M-1 | Master keys cannot be zeroized in CPython `bytes` once they exist | med | mitigated | `flare/sealed.py:SecureBytes` | The reconstructed master key in `OracleCore.decide_batch` lives in a `SecureBytes` wrapper that is zeroized via `ctypes.memset` in the `finally` block. The transient `view()` copy passed to HKDF is a CPython `bytes` we cannot wipe, but its lifetime is bounded by the same `finally`. The buffer most likely to survive in heap snapshots and core dumps is the canonical reconstruction buffer, which is the buffer we wipe. Hardware-enclave gap remains as A-1. |
| M-2 | Master + signing keys delivered via env vars in compose | med (prototype only) | mitigated | `compose/generate_secrets.py`, `compose/entrypoint.sh`, `flare/services_main.py` | Phase 4 wired up `EncryptedFileKeyStore` (scrypt → AES-256-GCM passphrase-encrypted on-disk bundle). The compose stack writes one sealed file per oracle replica to `/secrets/sealed/*.bin` and the entrypoint sets `SEALED_KEY_FILE` + `SEALED_KEY_PASSPHRASE_FILE`. Env-var delivery is preserved as a fallback. The on-disk artifact is useless without the passphrase. |
| M-3 | Revoke vs in-flight issuance race | low | mitigated | `flare/ledger/memory.py:RLock`, cell-key TTL | The ledger now serializes mutations through an `RLock`. The post-revoke property is pinned by `tests/test_concurrent_revoke.py` under eight-thread stress: every request whose `now ≥ revoke_time` is denied. A request signed *before* revoke whose key the requester is still holding can still be exploited until its `valid_until_ns` passes — the cell-key TTL bounds this window. |

## Accepted (in scope of the threat model)

These are properties of the design that are documented in the paper's Limitations.

| ID | Observation | Severity | Status | Where | Reasoning |
|---|---|---|---|---|---|
| A-1 | Software sealed storage is not a TEE | info | accepted | `flare/sealed.py`, `flare/oracle/core.py` | `EncryptedFileKeyStore` + `SecureBytes` is a real software improvement (post-process forensics, swap, freed-heap inspection are closed) but a live operator with `ptrace` or `/proc/<pid>/mem` can still inspect the running process. A real TEE keeps the secret inside an enclave whose memory the host operator cannot read; software sealing does not. Strictly stronger than env-var delivery, strictly weaker than SGX/SEV. Closing this gap requires hardware enclave integration. |
| A-2 | Hash-chained ledger has tamper-evidence but no consensus | info | accepted (integration) | `flare/ledger/memory.py` | The append-only hash-chained log gives **tamper-evidence** — any operator who rewrites history breaks the chain visible to every external auditor that pinned an earlier head. It does **not** give consensus: a single ledger operator can still equivocate by serving different chains to different readers. Mitigations: external auditors record and compare heads; chain anchored periodically to a real public chain; full consensus by swapping the in-memory backing for a Ceramic stream or Ethereum L2 contract. The on-chain version uses the same signature verification primitives, so only the storage layer changes. |
| A-3 | Centroid topology leakage | info | accepted (design choice) | `flare/storage/memory.py:get_centroids` | Centroids are public — they are the routing primitive and must be readable to route a query. For high-dimensional embeddings (e.g. 384-d in `all-MiniLM-L6-v2`) the leakage is low (centroids are points in a high-dimensional space, not interpretable as content) but it is not zero. Mitigations (Gaussian noise injection, locality-preserving hashing, centroid bucketing) all require calibration that is its own research project. We deliberately do not implement a half-baked mitigation. |
| A-4 | Oracle access pattern leakage at the granularity of which contexts a principal queries | info | accepted (design choice) | `flare/oracle/service.py` | The constant-width padding closes leakage of query *specificity* (batch size is constant). The remaining leak — *which contexts* a principal queries — is an inherent consequence of per-context oracles and would require collapsing per-owner oracles into a single shared oracle to close, which is out of scope for the design. |
| A-5 | Per-process replay nonce caches (wire protocol + peer protocol) lost on restart | low | accepted | `flare/wire.py:NonceCache`, `flare/oracle/peer_wire.py` | Restarting the process clears the cache, opening a replay window equal to the clock-skew window (60 s). Cross-replica nonce state requires a shared store (Redis or similar). Operational concern, not a protocol concern. |
| A-6 | Cell-key TTL relies on coordinated wall-clock time | low | accepted | `flare/wire.py:encrypt_and_sign_batch_response`, `flare/query.py` | Both oracle and querier use wall-clock time. NTP drift on either side can cause early-deny or late-allow. The 60s default TTL bounds the worst case. A monotonic-clock alternative requires cross-process clock synchronization. |
| A-7 | Failover order is deterministic (registration order) | info | accepted | `flare/query.py:_try_oracle_endpoints` | A production deployment would round-robin or hash-on-querier. The current behavior is predictable but harmless: a passive observer learns "endpoint 1 is the preferred coordinator" but the registration is public anyway. |
| A-8 | Threshold reconstruction briefly holds the master key in coordinator memory | med | accepted (mitigated by M-1) | `flare/oracle/core.py:decide_batch` | See M-1. The `SecureBytes` wrapper closes the post-process forensics gap; the live-operator gap is A-1. |
| A-9 | The `view()` copy of `SecureBytes` is a normal CPython `bytes` we cannot zeroize | info | accepted | `flare/sealed.py:SecureBytes.view` | Modern crypto APIs take `bytes`. We materialize a copy to call them. The point of `SecureBytes` is to control the *long-lived* canonical buffer; the short-lived `view()` is intentionally accepted residual exposure. |
| A-10 | Padding pool is the principal's full authorized cell set; principals with very few authorized cells get less padding noise | low | accepted | `flare/query.py:_pad_to_width` | The alternative — drawing padding from cells the principal cannot reach — would defeat the security goal because every padded cell would be denied by the oracle and the granted/denied distribution would itself leak which contexts the principal can reach. |
| A-11 | Ledger service writes are unauthenticated (anyone with network access can attempt a write) | low (in scope) | accepted | `flare/ledger/service.py` | Every grant must carry a valid grantor signature; every revoke must carry a signature from the original grantor. The worst-case abuse is therefore "spam the ledger with valid grants from your own DID" — a DoS surface, not a confidentiality or integrity surface. |

## Out of scope

These are work items the FLARE prototype explicitly does not address with reasoning, called out in the paper's Limitations.

| ID | Observation | Status | Reasoning |
|---|---|---|---|
| O-1 | Token incentives + slashing | out-of-scope | Real engineering problems that require their own design phase, threat model, and paper. A deployment that wants economic incentives would integrate with an existing incentive layer (Filecoin for storage, custom tokens for oracles) rather than baking it into the cryptographic protocol. |
| O-2 | Forward illumination via a learned predictive model | out-of-scope | The deterministic constant-width padding (C-27) covers the same security shape (constant-width oracle batches) without needing a training pipeline. A predictive pre-fetch optimization would sit on top of it. |
| O-3 | Real hardware TEE integration | integration | SGX (Gramine) / AMD SEV is hardware-bound and cannot run in a docker prototype. The path to closing A-1. |
| O-4 | On-chain ledger backing (Ceramic / Ethereum L2) | integration | The path to closing A-2. The signature schema and verification primitives are identical to what an on-chain version would use; only the storage layer below `flare/ledger/memory.py` changes. |
| O-5 | Centroid noise / locality-preserving hashing | research | Calibration research that is its own paper. The honest move is to leave A-3 open and not implement a half-baked mitigation. |
| O-6 | Side-channels (timing, power) on the decryption node | out-of-scope | Standard mitigations apply; not specific to FLARE. |

---

## Provenance

This consolidated risk register supersedes the per-phase findings files (`phase0-findings.md` … `phase4-findings.md`), which are kept as historical changelogs of how each finding was discovered and resolved during development. Every entry above can be traced back to a specific phase's findings file via the relevant ID prefix in those files.
