# Paper Changelog

This file tracks user-visible changes to `paper/flare.md`. The paper is the canonical description of FLARE; this changelog records what changed and why so a reviewer comparing two versions has a quick map.

## v1.0 — 2026-04-08 — Single coherent product description

The paper is now structured around the finished FLARE system rather than the development order. All "Phase N" framing has been removed from the paper, the README, the consolidated `security.md`, and the in-code docstrings. The per-phase findings files (`phase0-findings.md` … `phase4-findings.md`) are kept as historical changelogs but `docs/analysis/security.md` is the canonical risk register.

**Major changes from the development sequence:**

- §1 Abstract and Introduction rewritten to describe FLARE as a finished system. The headline empirical claim is now real: 95.6% of plaintext FAISS recall@10 on BEIR SciFact (5,183 abstracts, 300 human-labeled queries, `all-MiniLM-L6-v2` embeddings).
- §2 Threat Model consolidated. In-scope and out-of-scope adversaries listed once with rationale, not repeated per phase.
- §3 System Design presents the architecture as a five-layer stack (query → authorization → key issuance → search → storage) with one diagram per layer. The light cone, partitioned encrypted IVF, key derivation, threshold oracle, signed grant ledger, and identity model each get their own subsection. The "design convergence" insight (one `context_id` establishes three independently-maintained invariants) is its own subsection §3.9.
- §4 Implementation describes the production topology, the wire protocol, storage authentication, threshold key management, sealed key storage, constant-width oracle batches, and multi-endpoint failover — all as features of the finished system, not as "Phase N added X".
- §5 Evaluation has two empirical sections: §5.1 real-data retrieval quality on BEIR SciFact (`paper/evals/real_data_bench.json`) and §5.2 latency decomposition across single-replica / threshold / threshold+padding configurations (`paper/evals/phase4_bench_*.json`). §5.3 lists every test that pins a security property; §5.4 describes the runnable showcase.
- §6 Security Analysis is now a single coherent inventory rather than a series of per-phase deltas. The full risk register is `docs/analysis/security.md`.
- §7 Limitations enumerates the remaining gaps with a clear distinction between integration concerns (real TEE, real consensus chain), operational concerns (NTP, nonce coordination), and explicit out-of-scope items (token incentives, centroid noise, predictive forward illumination).
- §8 Related Work rewritten as a discussion organized into three threads (self-sovereign data + DIDs, encrypted distributed storage, privacy-preserving search) rather than a bullet table. Real citations to BEIR, MS MARCO, Sentence-BERT planned for the final pass.
- §9 Conclusion replaced with a single coherent statement about what FLARE is, what was built, and what was demonstrated.
- New `bench/bench_real_data.py` produces `paper/evals/real_data_bench.json` for the §5.1 numbers; reproducible via `make bench-real`.
- New `flare/showcase.py` demonstrates the entire system on real text (cooking + astronomy hand-curated corpora, real `all-MiniLM-L6-v2` embeddings). Reproducible via `make showcase`.
- Eight `.mmd` figure sources in `paper/figures/` covering the stack, single-query data flow, single-batch wire protocol, threshold peer share-fetch protocol, the finished trust topology, and the end-to-end query pipeline.

**What was deliberately not done:**

- Real hardware TEE integration (requires SGX/SEV).
- On-chain ledger backing (requires Ceramic / Ethereum L2 deployment).
- Centroid noise / locality-preserving hashing (calibration research; a second layer on top of oracle-gated centroids).
- Token incentives + slashing (separate paper).
- Forward illumination via a learned predictive model (the deterministic constant-width padding covers the same security shape).

## v1.1 — Oracle-gated encrypted centroids (A-3 mitigation)

Centroid topology leakage (A-3) is now fully mitigated in the implementation, not merely designed. Centroids are encrypted at bootstrap under HKDF-derived centroid keys and delivered to authorized queriers via the oracle's ECIES + Ed25519 wire protocol. Storage returns HTTP 403 for centroid requests. The query pipeline runs light-cone authorization *before* centroid routing, so centroids are never requested for unauthorized contexts.

**Code changes:**

- `flare/crypto.py`: `derive_centroid_key()` with distinct HKDF info prefix `flare/v1/centroids\x00`.
- `flare/wire.py`: `CentroidsRequest`/`CentroidsResponse` wire types and full ECIES encrypt/verify functions.
- `flare/oracle/core.py`: `store_encrypted_centroids()`, `issue_centroids()` methods.
- `flare/oracle/service.py`: `POST /request-centroids`, `POST /upload-encrypted-centroids` endpoints.
- `flare/oracle/client.py`: `request_centroids()`, `upload_encrypted_centroids()` on `HttpOracleClient`.
- `flare/bootstrap.py`: `_serialize_centroids()`, `deserialize_centroids()`, `BootstrapResult.encrypted_centroids`.
- `flare/query.py`: `_get_centroids()` fetches from oracle; pipeline reordered (light-cone → centroid routing).
- `flare/storage/service.py`: `GET /centroids` returns 403.
- `tests/test_centroid_gate.py`: new test file pinning storage 403, unauthorized denial, authorized delivery, and end-to-end routing.

**Paper changes:**

- §2 Threat model: "plaintext centroids" → "encrypted centroid blobs"; out-of-scope bullet updated.
- §3.1 Architecture overview: "routes by plaintext centroids" → "routes by oracle-gated centroids".
- §3.2 Data flow diagram: reordered to show light-cone → oracle centroid request → routing → key issuance.
- §3.4 Partitioned encrypted IVF: describes encrypted centroid delivery.
- §4 Process topology: "Centroids public" → "Encrypted centroids / oracle-gated".
- §5.3 Cache table: routing cache now holds "Decrypted centroids + registrations" with oracle-gated security.
- §7 Limitations: A-3 bullet rewritten from "partially mitigated by near-term extension" to implemented description.

**Security register:**

- A-3 status: "accepted (near-term mitigation designed)" → "mitigated".
- O-5 updated to note primary mitigation is implemented.

Each is documented in §7 Limitations and `docs/analysis/security.md` with reasoning.

## v1.2 — 2026-04-11 — Envelope encryption, grant-first access, containment edges, super-contexts

Four architectural concepts integrated into the working model:

**Grant-first access (C-32).** The oracle's `requester == self.owner` fast-path is removed. Owner access flows through a standing self-grant created at bootstrap. Revoking the self-grant blocks the owner — the ledger is the sole authority. All call sites updated (bootstrap, demo, showcase, demo-compose, benchmarks). New `tests/test_grant_first.py` (3 tests).

**Envelope encryption (C-33).** Single-layer HKDF derivation replaced with two-layer envelope: `master_key → CWK (HKDF, per-context) → CEK (random, per-cell)`. CWK wraps CEK via AES-256-GCM with AAD. Oracle derives CWK on the fly, unwraps CEK at issuance time. Cell data never re-encrypted. New primitives in `flare/crypto.py`: `derive_cwk`, `generate_cek`, `wrap_cek`, `unwrap_cek`. Oracle core uses envelope path when wrapped CEKs are available, falls back to deprecated HKDF for backward compat. `BootstrapResult` carries `wrapped_ceks` for oracle injection. New `tests/test_envelope.py` (9 tests).

**Containment edges + cross-context sharing (C-34, C-35).** `ContainmentEdge` type in `flare/types.py`. `LightConeGraph` extended with `containment_edges` dict + management methods. Bootstrap creates containment edges per cell. `share_cell_across_contexts` re-wraps a CEK under a different context's CWK. New `tests/test_containment.py` (4 tests).

**Super-contexts (A-13).** New `flare/supercollections.py`: per-user KNN clustering over light-cone-visible centroids. Ephemeral, per-user, not stored. `SuperContext` dataclass with member cells and centroid. New `tests/test_super_contexts.py` (4 tests).

**Paper:** New §3.10 covering all four concepts. §3.5 updated for CWK derivation note. §7 Limitations: two new bullets (CWK compromise scope, super-context verifiability).

**Security register:** C-32 through C-35 (closed), A-12 and A-13 (accepted).

**Test count:** 101 → 121 (20 new tests, all passing).
