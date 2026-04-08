# FLARE — Forward-Lit Authorized Retrieval over Encrypted Indexes

A semantic vector search system in which **access control is enforced cryptographically, not by an ACL layer.** Each cluster cell of an inverted-file (IVF) index is encrypted under a per-cell key derived from the data owner's master key. Authorization is computed as reachability in a typed graph (the *light cone*). Cell keys are issued on demand by a Shamir K-of-M threshold oracle quorum, gated by a signed hash-chained grant ledger. Revocation is a single signed ledger entry — no re-encryption, no key rotation, no coordination.

**Real-data result.** On the BEIR SciFact benchmark (5,183 scientific abstracts, 300 human-labeled queries, `all-MiniLM-L6-v2` embeddings), FLARE preserves **95.6%** of a plaintext FAISS baseline's recall@10 (0.7533 vs 0.7883) while exercising every cryptographic and authorization layer end-to-end. See `paper/evals/real_data_bench.json` and reproduce with `make bench-real`.

The reference implementation is the `flare` Python package + a docker-compose stack with eleven services. Everything runs in Docker — no host-side installs.

## Run it

```bash
make build           # build the image once (~2 min, includes the embedding model)
make test            # 91-test pytest suite (~13 s)
make showcase        # runnable demo on real text — see "What the showcase does" below
make demo-compose    # full multi-container threshold stack: cross-process Alice/Bob/Carol
make bench           # synthetic latency/throughput sweep (3 configurations)
make bench-real      # BEIR SciFact recall@10 + latency vs plaintext FAISS
```

## What the showcase does

`make showcase` runs the entire FLARE stack on real text. Two data owners (Alice and Bob) each publish a small hand-curated corpus on a distinct topic — cooking and astronomy — embedded with `sentence-transformers/all-MiniLM-L6-v2`. A querier (Carol) submits real natural-language questions and observes:

1. **Without grants:** every query returns nothing. Encrypted cells stay opaque.
2. **After Alice grants Carol access to the cooking corpus:** cooking questions return semantically-correct cooking docs; astronomy questions return nothing.
3. **After Bob also grants:** every question returns the topically-correct corpus, picked by the embedding model.
4. **After Alice revokes:** cooking results vanish immediately. No re-encryption.

Sample output (real, captured from `make showcase`):

```
  query: 'What temperature should I use for medium-rare steak?'
    [-0.762] For a medium-rare steak, sear briefly over high heat after holding the meat at 54 degrees ...
    [-1.054] Maillard browning happens above about 140 degrees Celsius and is what gives seared meat ...

  query: 'How far is Mars from Earth?'
    [-0.655] Mars is on average about 225 million kilometers from Earth, but the distance varies as ...
    [-1.062] An astronomical unit is the average distance from the Earth to the Sun, about 150 million ...

  query: 'What is the cosmic microwave background?'
    [-0.609] The cosmic microwave background is the afterglow of the Big Bang and pervades the entire ...
```

The showcase runs against the real FLARE stack — Shamir K=2-of-M=3 threshold oracles, signed Ed25519 wire protocol with ECIES responses, signed hash-chained ledger, owner-signed storage writes, cell-key TTLs, multi-endpoint failover, constant-width batch padding, and cryptographic identities (`did:key`). It is not a mock.

## What the system implements

- **Per-cell HKDF + AES-256-GCM** encryption with `(context_id || cluster_id)` AAD binding
- **Per-context FAISS k-means** partitioning; centroids public, cells encrypted at rest in the storage service
- **Multi-process services**: `flare/ledger/`, `flare/storage/`, `flare/oracle/`, each a FastAPI app
- **Multi-method DID identities** (`flare/identity.py`): `did:key` (local) + `did:web` (HTTPS fetch + cache) via a unified `DIDResolver`
- **Authenticated, confidential, end-to-end-bound batch wire protocol** (`flare/wire.py`):
  - Ed25519-signed batch requests + 60s clock skew + replay nonce cache
  - ECIES (X25519 ECDH → HKDF → AES-256-GCM) on every cell-key response, AAD-bound per entry
  - Ed25519-signed batch responses verified against the oracle DID registered with the context
  - Cell-key TTL (`valid_until_ns`) bound into the signed canonical bytes; query-side enforcement at decode AND at use time
- **Threshold (Shamir K-of-M) oracle** (`flare/oracle/threshold.py`, `peer_wire.py`, `peer_client.py`):
  - Master key split into M shares over GF(2^521 − 1)
  - Coordinator gathers K-1 peer shares in parallel via authenticated peer protocol
  - Each peer independently re-verifies the querier's signature AND independently checks the ledger before releasing
  - Reconstructed master key lives in a `SecureBytes` wrapper, zeroized via `ctypes.memset` in the `finally` block
- **Software sealed key storage** (`flare/sealed.py`): scrypt → AES-256-GCM passphrase-encrypted on-disk bundle, loaded into `SecureBytes` wrappers at process start. Replaces env-var key delivery in compose.
- **Owner-signed + replay-protected storage writes**: every registration / centroids upload / cell upload signed by the owner Ed25519 with `(nonce, timestamp_ns)` inside the canonical bytes; per-DID nonce cache on the service
- **Multi-endpoint registration with failover**: `ContextRegistration.oracle_endpoints` is a list of `(url, oracle_did)`; query node tries them in order while still verifying every per-endpoint DID
- **Per-grant Ed25519 signatures + hash-chained tamper-evident ledger** (`flare/ledger/signing.py`): grants signed by grantor, revocations signed by original grantor, every state change appended to a chain hashable from a fixed genesis
- **Constant-width oracle batches** via authorized padding (`FlareQueryEngine.padding_width`): every batch padded with random already-authorized cells whose keys are received but discarded; oracle wire stream is constant-width regardless of query specificity
- **Edge-level AND path-predicate deny** in the light-cone graph (`RequireAllOf`, `RequireSequence`)
- **Parallel cell prefetch**: query node overlaps storage cell GETs with oracle batch round-trips
- **Concurrent revoke/issue race tests** under contention
- **91-test pytest suite** + benchmarks committed at `paper/evals/`

## Repository layout

| Path | Purpose |
|---|---|
| `flare/` | Python package: crypto, identity, wire, lightcone, ledger, storage, oracle, query, sealed key storage, bootstrap, showcase |
| `tests/` | 91-test pytest suite covering crypto, identity, wire (single + batch), light cone, oracle service + threshold + peer protocol, signed ledger + chain replay, storage signing + replay protection, multi-endpoint failover, sealed key storage, padding, cell-key TTL, end-to-end, concurrent revocation |
| `bench/` | `bench_encrypted_vs_plain.py` (synthetic latency sweep, 3 configs) and `bench_real_data.py` (BEIR SciFact recall vs plaintext FAISS baseline) |
| `compose/` | `generate_secrets.py` (one-shot key + sealed-file generator) and `entrypoint.sh` (docker-compose service launcher) |
| `paper/` | The research paper (`flare.md`), mermaid figures, BibTeX, evaluation outputs |
| `docs/` | Design documents: light cone authorization, encrypted vector search, FLARE index |
| `docs/production-deployment.md` | Production backend guide: ArangoDB (graph + metadata), MinIO/S3 (encrypted cells), OpenSearch (post-authorization reranking) |
| `docs/analysis/security.md` | Security risk register: every observation with severity, file:line, and status |
| `docker-compose.yml` | Eleven services: `secrets`, `ledger`, `storage`, three oracle replicas per data owner, and a one-shot `demo` |

## What's still gapped (deliberate; tracked in `docs/analysis/security.md`)

| Gap | Status |
|---|---|
| Software sealed storage is not a TEE (live operator with `ptrace` can still read process memory) | Real TEE requires SGX/SEV hardware integration |
| Hash-chained ledger has tamper-evidence but no consensus | Integration concern; swap backing for Ceramic / L2 in a real deployment |
| Per-process nonce caches | Operational concern; production shares state via a coordination service |
| TTL relies on coordinated wall-clock time | Operational; assumes NTP |
| Failover order is deterministic (registration order) | F-1 in `security.md` |
| Centroid topology leakage | Calibration research, deliberately not half-implemented |
| Token incentives + slashing | Out of scope for the cryptographic prototype |
| Forward illumination via a learned predictive model | The deterministic padding covers the same security shape |
| ~36× threshold-plus-padding overhead vs plaintext | FastAPI/JSON process-boundary cost; reduction requires oracle/storage co-location or a binary protocol |

## License

Apache 2.0. See [LICENSE](LICENSE).

## Authors

John Sessford, with Claude (Anthropic) as a development collaborator.

Research paper: `paper/flare.md`. Every empirical claim traces to a reproducible artifact in `paper/evals/`. Every design claim traces to code in `flare/`. Every security claim traces to a test in `tests/`.
