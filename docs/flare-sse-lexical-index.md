# FLARE-SSE — Encrypted Lexical Search

Status: **Proposal**
Date: 2026-04-16

Cross-references:
- SSE literature: Song-Wagner-Perrig (2000), OXT (Cash et al. 2013), Sophos/Diana (Bost 2016-2017)

---

## Summary

FLARE encrypts the **vector** search index — embeddings live in AES-256-GCM encrypted IVF cells, accessed only after light-cone authorization. But vectors alone don't cover the full search surface. Lexical search (BM25) exists to find documents that are **semantically distant but terminologically relevant** — the exact terms a user searches for, appearing in documents the embedding model wouldn't cluster nearby.

FLARE's encrypted vector index covers semantic similarity well, but not the full search surface. A user searching for a rare identifier, an exact acronym like "CRUDEASIO", or a proper noun the embedding model has not seen at high frequency cannot rely on ANN search alone — the matching document may be semantically distant even if it contains the exact term. Without an encrypted lexical index, covering this case requires a plaintext term index or an external unencrypted service.

FLARE-SSE extends the FLARE package with a **blind-token lexical index** based on Searchable Symmetric Encryption. Combined with the existing vector layer, this provides complete encrypted search coverage — the storage tier holds no plaintext in either index.

### Design Principle: Complementary Indexes, Not Redundant Ones

Traditional hybrid search (BM25 + kNN) runs both scoring functions over the same corpus, then fuses with RRF. Both indexes see all documents. The fusion improves ranking by combining two different relevance signals over the same data.

FLARE-SSE takes a different approach. The SSE lexical index and the FLARE vector index are **structurally complementary** — each covers the search surface the other cannot:

| Capability | FLARE Vector Index | SSE Lexical Index |
|---|---|---|
| Semantic similarity | Primary purpose | Cannot do |
| Fuzzy / typo tolerance | Inherent in embeddings | Cannot do (blind tokens are exact) |
| Synonym expansion | Inherent in embeddings | Cannot do without pre-expansion |
| Phrase proximity | Captured by contextual embeddings | Cannot do (single-token matching) |
| Exact term in distant semantic space | Cannot do (term not in nearest clusters) | Primary purpose |
| Rare technical vocabulary | Weak (low training frequency) | Strong (exact match) |
| Proper nouns / identifiers | Weak (out-of-vocabulary) | Strong (exact match) |

The key insight: **SSE's limitations are precisely vector search's strengths, and vice versa.** Neither system needs to replicate what the other does. SSE handles the one thing vectors can't — finding exact lexical references across the semantic gap. Vectors handle everything else.

---

## Architecture

### Two Encrypted Indexes, One Authorization Layer

```
┌────────────────────────────────────────────────────────────────┐
│  Query: "CRUDEASIO propagation rules"                          │
│                                                                │
│  ┌──────────────────────┐   ┌──────────────────────┐          │
│  │  Light-Cone BFS      │   │  Light-Cone BFS      │          │
│  │  (same traversal)    │   │  (same traversal)    │          │
│  └──────────┬───────────┘   └──────────┬───────────┘          │
│             │                          │                       │
│  ┌──────────▼───────────┐   ┌──────────▼───────────┐          │
│  │  FLARE Vector Search │   │  SSE Lexical Lookup  │          │
│  │                      │   │                      │          │
│  │  Decrypts IVF cells  │   │  Blind-token match   │          │
│  │  → FAISS ANN         │   │  → Decrypt tf/field  │          │
│  │  → vector scores     │   │  → BM25 scoring      │          │
│  │                      │   │                      │          │
│  │  Finds: docs about   │   │  Finds: docs with    │          │
│  │  permissions, access  │   │  "CRUDEASIO" anywhere│          │
│  │  control, grants     │   │  in the corpus       │          │
│  └──────────┬───────────┘   └──────────┬───────────┘          │
│             │                          │                       │
│             └────────┬─────────────────┘                       │
│                      │                                         │
│             ┌────────▼────────┐                                │
│             │  RRF Fusion     │                                │
│             │  (k = 60)       │                                │
│             └────────┬────────┘                                │
│                      │                                         │
│             ┌────────▼────────┐                                │
│             │  Unified results│                                │
│             └─────────────────┘                                │
└────────────────────────────────────────────────────────────────┘
```

Both indexes share the same light-cone BFS authorization pass. The query engine runs one BFS traversal, then fans out to both indexes in parallel with the authorized owner/collection scope.

### SSE Blind-Token Index

#### Structure

Per-owner encrypted inverted index stored in S3:

```
S3: {tenant}/{owner_id}/sse/
  ├── posting/                       # Blind-token → posting list
  │   ├── {blind_token_a}.enc       # AES-256-GCM encrypted
  │   ├── {blind_token_b}.enc
  │   └── ...
  ├── corpus_stats.enc               # Per-owner aggregate stats
  └── prefix/                        # Pre-computed prefix tokens
      ├── {prefix_token_a}.enc
      └── ...
```

#### Blind Tokens

```
blind_token = HMAC-SHA256(owner_sse_key, field_prefix + ":" + stemmed_term)
```

Where:
- `owner_sse_key` = `HKDF(owner_master_key, "sse")` — derived from the same master key FLARE uses, different context string
- `field_prefix` = `"t"` (title), `"d"` (description), `"g"` (tags), `"c"` (content text)
- `stemmed_term` = output of the English analysis pipeline: `lowercase → possessive_stemmer → stop_words → english_stemmer`

Each blind token is a deterministic, one-way mapping. The SSE server (S3) sees opaque hex strings. It cannot recover the original term.

#### Posting List Contents (encrypted per blind token)

```json
{
  "entries": [
    {
      "artifact_id": "uuid",
      "field": "title",
      "tf": 3,
      "dl": 12,
      "positions": [0, 5, 11]
    }
  ]
}
```

Each posting list is encrypted with: `AES-256-GCM(HKDF(owner_sse_key, blind_token), posting_data)`

The posting list contains per-document term frequency (`tf`), document length in tokens (`dl`), and optionally term positions (for phrase proximity verification — see below). The artifact UUID is the sole document identifier; collection membership is resolved through the graph at query time.

#### Corpus Stats (encrypted per owner)

```json
{
  "doc_count": 4200,
  "avg_dl": {
    "title": 6.2,
    "description": 24.8,
    "tags": 3.1,
    "content": 482.5
  },
  "df": {
    "<blind_token>": 17
  }
}
```

Updated incrementally on each indexing run. Contains document frequency (`df`) keyed by blind token — needed for IDF computation. Encrypted with `owner_sse_key`.

**IDF leakage note**: The `df` values reveal term rarity within the owner's corpus. This is L4 leakage in the SSE taxonomy. Acceptable for single-operator deployments where the operator already has ArangoDB access. For multi-node federation, `df` can be padded or bucketed to reduce leakage at the cost of BM25 ranking precision.

#### BM25 Scoring (in-process after decryption)

Standard Okapi BM25 with field boosting:

$$BM25(q, d) = \sum_{t \in q} IDF(t) \cdot \frac{tf(t, d) \cdot (k_1 + 1)}{tf(t, d) + k_1 \cdot \left(1 - b + b \cdot \frac{dl}{avgdl}\right)}$$

Where $IDF(t) = \ln\left(\frac{N - df(t) + 0.5}{df(t) + 0.5} + 1\right)$

Parameters: $k_1 = 1.2$, $b = 0.75$ (standard Okapi BM25 defaults).

Field boosting applies configurable weight presets (defaults below match standard multi-field BM25):
- `title`: 5×
- `description`: 10×
- `tags`: 3×
- `content`: 1×

Per-field BM25 scores are computed independently, then summed with field weights.

---

## Handling SSE's Limitations

SSE blind-token matching is exact. It cannot do fuzzy matching, synonym expansion, prefix/wildcard search, or phrase proximity. But FLARE-SSE doesn't need SSE to do any of these — they're handled by other mechanisms.

### Fuzzy Matching, Synonyms, Phrase Proximity → Vector Index

These are inherent capabilities of embedding-based search:

- **Fuzzy/typos**: `"artfact"` embeds close to `"artifact"` — the vector index finds the right documents.
- **Synonyms**: `"car"` and `"automobile"` have similar embeddings. No synonym table needed.
- **Phrase proximity**: `"forward lit retrieval"` as a concept is captured in the contextual embedding. Documents discussing the concept cluster together regardless of exact word order.

SSE does not attempt to replicate these. The vector index already covers them.

However: for high-precision phrase verification, term positions are stored in SSE posting lists. When both indexes return a hit for the same document, positions can verify exact phrase adjacency — a post-retrieval refinement, not a retrieval path.

### Lightweight Semantic Neighborhood Index

For cases where the vector index should cover nearby semantic space more aggressively (fuzzy variants, morphological forms, near-synonyms), a **lighter-weight secondary vector index** can be built within the same encrypted cell structure:

```
FLARE IVF cell (primary — full embeddings, ada-002):
  [1536-dim vectors, full semantic search]

FLARE IVF cell (secondary — reduced dimensionality):
  [256-dim vectors, PCA-projected, higher nprobe]
```

The secondary index uses dimensionality reduction (PCA or random projection) on the same embeddings. Lower dimensionality means:
- Cheaper to search (faster ANN)
- Higher nprobe affordable (search more clusters — wider semantic neighborhood)
- Lower precision per-hit (compensated by the primary index in fusion)

This creates a **three-tier retrieval** architecture:

| Tier | Index | Covers | Precision | Recall |
|---|---|---|---|---|
| 1 — Lexical | SSE blind tokens | Exact terms across entire corpus | High (exact match) | Low (exact only) |
| 2 — Broad semantic | FLARE secondary (256-dim) | Wide semantic neighborhood | Medium | High |
| 3 — Precise semantic | FLARE primary (1536-dim) | Tight semantic similarity | High | Medium |

RRF fuses all three tiers. The broad semantic tier closes the gap between SSE's narrow lexical matches and the primary vector index's tight clusters — catching fuzzy variants, synonyms, and compositional phrases that fall between the other two.

The secondary index reuses the same cell encryption infrastructure (HKDF derivation, AES-256-GCM, S3 storage). Cell key context string includes a dimensionality tag: `HKDF(master_key, collection_id || cluster_id || "d256")`.

### Prefix/Wildcard → Pre-Computed Prefix Tokens

At index time, generate truncated prefix tokens alongside exact tokens:

```
term "artifact" →
  HMAC(key, "t:artifact")      # exact (stemmed)
  HMAC(key, "px5:t:artif")     # prefix-5
  HMAC(key, "px4:t:arti")      # prefix-4
  HMAC(key, "px3:t:art")       # prefix-3
```

Query-time prefix search (`art*`) generates the prefix-3 blind token and looks up the posting list. The posting list contains all documents where any term in the field starts with `art`.

**Scope limitation**: Pre-compute prefixes only for `title` and `tags` fields. Content text generates too many prefix entries. This is acceptable — prefix/wildcard search is most useful for navigational queries on structured fields, not full-text content.

**Storage cost**: ~3× per indexed term in title/tags fields. Negligible relative to content text volume.

### Access Pattern Privacy → Constant-Width Batch Padding

The same constant-width batch padding from FLARE (patent claim 9) extends to SSE lookups:

```
Query: 3 terms → 3 blind tokens
Padding: add 13 random authorized blind tokens (owner's terms the user is authorized to see)
Batch: 16 blind tokens (constant width)

SSE server sees: 16 token lookups, same as every other query
```

The padding tokens are drawn from the querier's authorized term set — tokens corresponding to terms in documents they have grant access to. The server cannot distinguish real query tokens from padding. Keys/posting data received for padding tokens are discarded after receipt.

This mirrors the FLARE cell-key padding mechanism, applied to the SSE token lookup plane.

---

## Indexing Flow

```
Artifact indexed into owner scope
  │
  ├── Context fields (title, description, tags):
  │   Encrypt: AES-256-GCM(HKDF(master, "content" || artifact_id), context_json)
  │   Upload to S3: {owner_id}/artifacts/{artifact_id}/context.enc
  │
  ├── Vector index: chunk → embed → FLARE IVF cell (encrypted)
  │
  ├── SSE lexical index:
  │   1. Tokenize context fields (title, description, tags, content text)
  │      Pipeline: lowercase → possessive stemmer → stop words → English stemmer
  │
  │   2. For each (field, stemmed_term) pair:
  │      blind_token = HMAC-SHA256(owner_sse_key, field_prefix + ":" + term)
  │      Append to posting list: {artifact_id, field, tf, dl, positions}
  │
  │   3. For title/tags terms, also generate prefix blind tokens (px3, px4, px5)
  │
  │   4. Encrypt each posting list: AES-256-GCM(HKDF(owner_sse_key, blind_token), data)
  │
  │   5. Upload to S3: {tenant}/{owner_id}/sse/posting/{blind_token}.enc
  │
  │   6. Update corpus_stats.enc: increment doc_count, update avg_dl, update df
  │
  └── Secondary vector index (optional):
      PCA-project embedding → 256-dim → FLARE IVF cell (separate cluster, encrypted)
```

### Incremental Updates

Posting lists are append-friendly. On each indexing run:
1. Download existing posting list for modified blind tokens
2. Decrypt, append/update entries for new/modified artifacts
3. Re-encrypt, upload

Corpus stats update is a single download/decrypt/modify/encrypt/upload cycle.

For bulk ingestion, batch all posting list updates and upload in parallel.

### Deletion / Revocation

When an artifact is removed from a collection:
1. Download posting lists for all blind tokens that reference the artifact
2. Decrypt, remove entries for that artifact + collection
3. Re-encrypt, upload
4. Update corpus stats (decrement doc_count, adjust df)

Tracking which blind tokens reference an artifact requires a per-artifact manifest (encrypted, stored alongside the SSE index):

```
S3: {tenant}/{owner_id}/sse/manifests/{artifact_id}.enc
Contents: [list of blind tokens that have posting entries for this artifact]
```

---

## Query Flow

```
1. Parse query (modifiers, field filters, stemming)
2. Embed query (for vector search)
3. Light-cone BFS: authorized owner/collection scope (single traversal, shared by both indexes)
4. Fan out in parallel:
   │
   ├── FLARE vector path:
   │   a. Centroid routing → cell key derivation → decrypt → FAISS ANN
   │   b. Optional: secondary 256-dim index with higher nprobe
   │   c. → vector scores per artifact
   │
   └── SSE lexical path:
       a. Tokenize/stem query terms (same pipeline as index time)
       b. Generate blind tokens: HMAC(owner_sse_key, field + ":" + term) per authorized owner
       c. Pad to constant-width batch with random authorized tokens
       d. Fetch + decrypt posting lists from S3
       e. Filter posting entries to artifacts within the light-cone authorized owner scope
       f. Fetch + decrypt corpus_stats.enc per owner
       g. Compute BM25 per document with field boosting
       h. → BM25 scores per artifact
│
5. RRF fusion (configurable k, default 60):
   score(d) = Σ_r  1 / (k + rank_r(d))
   where r ∈ {vector_primary, vector_secondary (if enabled), sse_lexical}
6. Deduplicate (artifact in N collections → best score wins)
7. Return results
```

---

## Search Coverage

FLARE-SSE gives the package complete encrypted search coverage across both retrieval modalities:

| Coverage | Module | Notes |
|---|---|---|
| Semantic similarity | `flare/` vector index | Existing — AES-256-GCM encrypted IVF cells, FAISS ANN |
| Exact-term lexical match | `flare/sse/` | New — blind-token posting lists, in-process BM25 |
| Broad semantic neighborhood | `flare/secondary/` | Optional — PCA-projected cells, higher nprobe |
| Authorization | `flare/lightcone.py` | Shared — one BFS traversal drives all indexes |

The storage tier (S3) holds only ciphertext. ArangoDB holds only graph structure (nodes, edges, propagation masks) and artifact UUIDs — the minimum required for BFS traversal.

---

## Security Properties

### Encryption Coverage (FLARE + SSE combined)

| Data | Storage | Encryption |
|---|---|---|
| Artifact content (files, binary) | S3 | AES-256-GCM, owner content key |
| Artifact context fields (title, description, tags) | S3 | AES-256-GCM, `HKDF(master, "content" \|\| artifact_id)` |
| Embedding vectors | S3 (FLARE cells) | AES-256-GCM per cell, HKDF-derived keys |
| Lexical index (terms, tf, positions) | S3 (SSE posting lists) | AES-256-GCM per posting list, HKDF-derived keys |
| Corpus statistics (IDF, doc count) | S3 | AES-256-GCM, owner SSE key |
| Secondary vector index | S3 (FLARE cells) | AES-256-GCM per cell, HKDF-derived keys |
| Graph structure (nodes, edges, propagation masks) | ArangoDB | Plaintext — required for BFS traversal |
| Artifact UUIDs | ArangoDB | Plaintext — graph node identity |
| Timestamps / orderable fields | ArangoDB | Fractional index (order-preserving mapping — see Open Questions) |

**ArangoDB plaintext surface**: ArangoDB retains only what BFS requires — graph structure (node IDs, edge types, propagation masks) and artifact UUIDs. No content fields, titles, tags, or descriptions are stored there. Timestamps are stored as a fractional index rather than raw values (see Open Questions). An operator with direct ArangoDB access can see the graph topology and artifact UUIDs but not any content.

### Leakage Profile

| Leakage class | What leaks | Mitigation | Residual risk |
|---|---|---|---|
| L1 — Search pattern | Same query produces same blind tokens | Stateless tokens per query batch; no server-side query log | Low — server sees tokens but can't reverse HMAC |
| L2 — Access pattern | Which posting lists are fetched | Constant-width batch padding (authorized decoy tokens) | Low — indistinguishable from real lookups |
| L3 — Volume pattern | Number of results per lookup | Posting list encryption hides entry count from storage; result set size visible to the query engine only | Minimal — query engine is trusted |
| L4 — IDF / frequency | Posting list file size correlates with term frequency | Padding posting lists to fixed size buckets (1KB / 4KB / 16KB / 64KB) | Acceptable — reveals frequency band, not exact count |

### Key Hierarchy

```
Owner master key (managed by `flare/crypto.py` and the oracle service)
  │
  ├── HKDF(master, "flare" || collection_id || cluster_id)
  │   → FLARE cell key (AES-256-GCM) — vector index
  │
  ├── HKDF(master, "flare-d256" || collection_id || cluster_id)
  │   → Secondary cell key (AES-256-GCM) — broad semantic index
  │
  ├── HKDF(master, "sse")
  │   → owner_sse_key — blind token generation + posting list encryption
  │   │
  │   └── HKDF(owner_sse_key, blind_token)
  │       → per-posting-list encryption key
  │
  ├── HKDF(master, "content" || artifact_id)
  │   → per-artifact context key (AES-256-GCM) — title, description, tags in S3
  │
  └── HKDF(master, "content")
      → owner content key (AES-256-GCM) — artifact binary/file content in S3
```

All keys derived deterministically via HKDF. Only the master key is stored (Fernet-wrapped). Everything else is re-derived at runtime.

---

## Implementation Estimate

| Component | New code | Notes |
|---|---|---|
| SSE tokenizer (standard English analysis pipeline) | ~150 lines | `nltk` or custom: lowercase → possessive stemmer → stop words → Porter stemmer |
| Blind token generator (HMAC + field prefix) | ~80 lines | Includes prefix token pre-computation |
| Posting list manager (encrypt/decrypt/merge/upload) | ~250 lines | S3 operations, incremental updates, manifest tracking |
| BM25 scorer (in-process, field-boosted) | ~120 lines | Standard Okapi BM25 with configurable field weight presets |
| Corpus stats manager | ~80 lines | Per-owner aggregates, incremental update on index |
| SSE query engine (blind-token lookup + padding + BM25) | ~200 lines | Parallel with FLARE vector query |
| Secondary vector index (PCA + separate FLARE cells) | ~150 lines | Optional — reuses existing FLARE cell infrastructure |
| FLARE-SSE accessor (RRF fusion of all tiers) | ~150 lines | Extends `flare/query.py` with SSE + secondary index fusion |
| **Total** | **~+1180 lines** | New `flare/sse/` and `flare/secondary/` modules |

### Dependencies

| Package | Purpose | Notes |
|---|---|---|
| `nltk` (or custom stemmer) | English tokenization pipeline | Only `punkt` tokenizer + `SnowballStemmer('english')`. Alternatively, a ~50-line Porter2 implementation avoids the NLTK dependency entirely. |
| `cryptography` | HMAC-SHA256, AES-256-GCM, HKDF | Already a FLARE dependency |
| `faiss-cpu` | IVF + ANN | Already a FLARE dependency |
| `scikit-learn` | PCA for secondary index dimensionality reduction | Optional; only needed if secondary index is built |

### File Layout

```
flare/
  query.py              Existing: vector search engine, extended for SSE fan-out and RRF fusion
  lightcone.py          Existing: light-cone BFS authorization
  crypto.py             Existing: key derivation (HKDF, AES-256-GCM)
  sealed.py             Existing: encrypted cell management (reused by secondary index)
  sse/
    __init__.py
    tokenizer.py        English analysis pipeline (lowercase → stop words → Porter stem)
    blind_tokens.py     HMAC-SHA256 token generation, prefix pre-computation
    posting.py          Posting list CRUD (S3, encrypt/decrypt/merge, manifest tracking)
    scorer.py           In-process Okapi BM25 with field boosting
    stats.py            Per-owner corpus statistics (doc count, avg_dl, df)
    query.py            SSE query engine (blind-token lookup, padding, BM25 scoring)
  secondary/            (optional)
    __init__.py
    projector.py        PCA dimensionality reduction
    indexer.py          Secondary IVF cell builder (reuses sealed.py)
```

---

## Open Questions

1. **Posting list granularity**: One file per blind token keeps lookups minimal (fetch only needed tokens) but creates many small S3 objects. Alternative: batch posting lists into larger encrypted blobs (e.g., per-owner shards of 1000 tokens each). Tradeoff: fewer S3 calls vs. over-fetching.

2. **Corpus stats consistency**: Stats are updated each time the index is built or rebuilt. Between indexing runs, newly added artifacts are not reflected in IDF calculations. Acceptable for curated knowledge where the indexing run is the authoritative event.

3. **Secondary index necessity**: The three-tier architecture (lexical + broad semantic + precise semantic) may be over-engineered for an initial release. The two-tier version (SSE + FLARE primary) may be sufficient. The secondary index adds value when users search for concepts expressed differently than the training data expects — worth validating empirically before building out the PCA pipeline.

4. **Order-preserving range index**: After moving context fields to S3, the only remaining non-structural ArangoDB fields are orderable scalars — timestamps, integers, or any ranked attribute. Range queries (recently modified, created before/after, score above threshold) require server-side comparison. A simple fractional index (normalize any value to `[0.0, 1.0]` against a fixed domain) is just a linear transposition: it preserves the full ordering and leaks the same information as storing the raw value. The adversary learns the complete rank order of every value in the corpus.

   The relevant research area is **Order-Preserving Encryption (OPE)** and **Order-Revealing Encryption (ORE)**:

   - **OPE** (Boldyreva et al. 2009): ciphertexts are numerically ordered like plaintexts. Allows standard `<`/`>` comparisons directly in the database. Leakage: full rank order. Effectively the same as a fractional index but with a pseudorandom permutation — still reveals complete ordering.
   - **ORE** (Boneh et al. 2015; Lewi-Wu 2016): only the *comparison result* (left < right) is revealed, not the magnitude of the difference. Requires a custom comparison function rather than standard `<`/`>` on stored values. Reduces leakage significantly but requires database-level support for the ORE comparison operator.
   - **Bucketized OPE**: coarse-grain the domain into buckets (day, week, month); assign a random position within each bucket. The server can determine same-bucket membership but not fine-grained order within a bucket. Range queries tolerate bucket-boundary imprecision. Leakage: bucket membership only.

   The idea of **randomized scales pegged within epoch sub-ranges** is a variant of bucketized OPE: divide the total domain into coarse intervals; within each interval, map values to a randomly-permuted sub-range at index time (keyed per owner). The server sees a value that is comparable to others only within the same interval — cross-interval ordering is intentionally broken. This reduces leakage to "same coarse bucket" at the cost of requiring the query engine to expand range predicates to cover adjacent buckets at bucket boundaries.

   This warrants a separate design note. For the initial FLARE-SSE release, the pragmatic options are: (a) store timestamps as coarse buckets (ISO week) — acceptable precision for "recent" queries; (b) encrypt and filter post-retrieval — no server-side range, but works for small authorized sets; (c) defer until an ORE scheme compatible with ArangoDB's AQL is identified.

5. **Multi-owner queries**: A single search may span multiple owners (via light-cone traversal through shared collections). Each owner has a separate SSE key, so the same query term produces different blind tokens per owner. The query engine must generate and look up blind tokens per authorized owner — linear in the number of owners in the light cone. For most queries (single-digit owner count), this is negligible. For broad queries spanning many owners, batching and parallel S3 fetches mitigate latency.
