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
- Centroid topology mitigation (calibration research).
- Token incentives + slashing (separate paper).
- Forward illumination via a learned predictive model (the deterministic constant-width padding covers the same security shape).

Each is documented in §7 Limitations and `docs/analysis/security.md` with reasoning.
