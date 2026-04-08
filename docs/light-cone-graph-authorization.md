# Light-Cone Graph Authorization with Semantic Ranking

Status: **Proposal**
Date: 2026-03-31

## Summary

Agience currently supports access control at the **workspace/collection/share boundary**, and uses **OpenSearch hybrid retrieval** (BM25 + optional kNN) for ranking.

This proposed feature introduces a new authorization primitive:

- **Authorization** is computed as **structural reachability** through a **typed multigraph** (the “light cone”).
- **Embeddings do not grant access**. They only rank and optionally expand results **within an already authorized candidate set**.

In short: **graph reachability gates visibility; semantic ranking improves relevance inside the gate**.

## Goals

- Replace or augment role/group ACL sharing with **path-based, context-aware authorization**.
- Support deterministic, explainable “why you can see this” reasoning.
- Enforce safe handling of derived artifacts (summaries, extracts, classifications) via **monotone sensitivity** and/or **audience intersection**.
- Preserve predictable performance via bounded traversal and cardinality controls.

## Non-goals

- Do not rely on embeddings for security decisions.
- Do not require cryptographic enforcement (envelope encryption) for the first iteration (optional later).
- Do not attempt to solve global cross-tenant multi-party sharing (this is tenant-scoped by default).

## Related

- [FLARE Index](flare-index.md) — extends this authorization model with physical encryption enforcement, oracle-delegated key issuance, and a decentralized grant ledger. Solves the cross-tenant multi-party sharing listed as a non-goal above.
- [Partitioned Encrypted Vector Search](partitioned-encrypted-vector-search.md) — the per-cluster encryption scheme whose partition boundaries align with light cone context_ids.

## Concept

### Core idea

Visibility of information is determined by whether a receiver principal can reach an information node via an **allowed path** in a typed graph, respecting:

- explicit deny boundaries
- classification / scope constraints
- derivation constraints (outputs inherit input constraints)

After the authorized set is computed, OpenSearch ranks within it using BM25 + semantic kNN (opt-in) and can apply “aperture” controls.

### Deterministic candidate set

Given receiver $r$:

$$
C(r)=\{x\in \text{InfoNodes}\mid x\text{ is reachable from }r\text{ by an allowed path respecting policy}\}
$$

Then apply hard rules (deny, classification, key access, derivation monotonicity) to obtain the authorized set $A\subseteq C$.

### Semantic layer (ranking only)

For each authorized info node $x$ with embedding $e_x$ and query embedding $e_q$:

$$
\text{score}(x)=\alpha\cdot \text{sim}(e_q,e_x)+\beta\cdot \text{relationship}(r,x)+\dots
$$

Optional semantic expansion is permitted only if it stays inside $A$.

## Data model

This feature is naturally represented in ArangoDB as a tenant-scoped graph.

### Node types (examples)

- **Principal**: User, ServiceAccount, Group, OrgUnit
- **Context**: Workspace, Collection, Project, Case, Ticket, Channel, LocationBucket
- **Information**:
  - ArtifactRoot (stable identity)
  - ArtifactVersion (specific committed/workspace version)
  - ExternalObject (message id, file id, event id, etc.)
- **Transform**: AgentRun, WorkflowRun, ModelFunction
- **Policy** (optional explicit nodes): ClassificationLabel, Purpose, Compartment

### Edge schema (common fields)

Each edge includes:

- `type`
- `src`, `dst`
- optional `weight`, `attributes`, `reason`, `scope`

### Edge types (examples)

- Identity/org:
  - MEMBER_OF, REPORTS_TO, OWNS, ADMIN_OF
- Sharing/context:
  - SHARED_WITH, POSTED_IN, MENTIONED, SENT_TO
- Derivation:
  - DERIVED_FROM (Info → Info)
  - GENERATED_BY (Info → Transform)
  - USED_INPUT (Transform → Info)
- Interaction signals (non-authorizing):
  - VIEWED, EDITED, STARRED
- Policy boundaries:
  - DENY, CLASSIFIED_AS, PURPOSE_BOUND

## Authorization: light cone computation

### Allowed-path grammar

Reachability is not “any path”. It is constrained by a whitelist grammar.

Examples of allowed sequences (illustrative):

- `User → MEMBER_OF → Group → POSTED_IN → Channel → CONTAINS → Info`
- `User → SHARED_WITH → Info`
- `User → MEMBER_OF → Project → CONTAINS → Info`

Examples of disallowed sequences:

- Paths that include VIEWED/STARRED/EDITED edges as authorizing steps

### Deny overrides

Deny boundaries override any allow path. This can be modeled as:

- explicit `DENY` edges/nodes in the graph
- deny rules in traversal filters

### Cardinality and latency controls

To keep p95 predictable:

- hop limit $K$
- per-edge-type caps (top-N expansions)
- precomputed reachability indexes for common contexts (project/channel/workspace)

## Derived data rules (critical)

Derived artifacts can leak information. Transforms must be first-class with explicit policy.

### Transform constraints

A Transform node defines:

- what it can read (input scopes)
- what it can output (output classification/purpose)

An output Info node has edges:

- `DERIVED_FROM` to each input
- `GENERATED_BY` to the transform

### Monotone sensitivity / audience constraints

Baseline rule: **outputs cannot be less sensitive than inputs**.

Two practical enforcement options:

- **Monotone classification**: output classification $\ge$ max(input classification, transform classification)
- **Audience intersection**: output visibility $\subseteq$ intersection of input audiences, unless explicitly re-shared

These rules ensure summaries do not become a bypass around original access constraints.

## Search integration (how it fits Agience)

### Two-phase search: authorize → rank

1. **Authorize**: compute a set of authorized `root_id` (or version ids) via Arango traversal.
2. **Rank**: run OpenSearch retrieval restricted to that set:
   - BM25 always
   - semantic kNN only when explicitly requested (e.g., `~term` query language)
   - optional aperture filtering on semantic results only

### Practical filtering strategies

Passing a giant list of IDs to OpenSearch (`terms` filter) does not scale.

Candidate approaches:

- Maintain a compact `acl_principals` field in indexed docs and filter by principal tokens.
- Maintain “visibility shard” tokens per principal/context.
- Two-stage retrieval: broad search → graph verification → rerank (slower but avoids huge filters).

## Specific implementation (proposed)

This section is intentionally concrete and mapped to how Agience is structured today (routers → services → DB repos; OpenSearch for ranking).

### Current baseline (today)

- Search routing and request contract: `POST /artifacts/search` in `backend/routers/artifacts_router.py`.
- Query language and hybrid behavior (opt-in `~` terms): `backend/search/query_parser.py` and `backend/search/accessor/search_accessor.py`.
- Ranking: BM25 always; kNN only when semantic is enabled; fusion via RRF; semantic breadth controlled by `aperture`.
- Access control in search today is primarily enforced via indexed fields (e.g., `owner_id` and `share_keys`) rather than graph reachability.

Light-cone authorization adds a **new pre-ranking gate**:

1) Graph authorization → authorized candidate set (IDs / tokens)
2) OpenSearch query restricted to authorized candidates → ranked results

### Where the light cone lives

Store the authorization graph in ArangoDB as tenant-scoped vertex + edge collections.

Recommended starting collections (illustrative):

- Vertices
  - `principals` (User, Group, ServiceAccount, OrgUnit)
  - `contexts` (Workspace, Collection, Project, Channel, Case, etc.)
  - `info_roots` (ArtifactRoot)
  - `info_versions` (ArtifactVersion)
  - `transforms` (AgentRun / WorkflowRun)
  - `policies` (ClassificationLabel, Purpose, Compartment)
- Edges
  - `auth_edges` for allow-style edges (MEMBER_OF, POSTED_IN, SHARED_WITH, CONTAINS, etc.)
  - `deny_edges` for explicit DENY boundaries (kept separate to simplify traversal filters)
  - `derivation_edges` (DERIVED_FROM, GENERATED_BY, USED_INPUT)

Each edge should include enough attributes to support explainability (e.g., `reason`, `scope`, `key_ref`, `source_event_id`).

### The authorization service boundary

Add a service responsible for computing visibility:

- `GraphAuthzService` (new) as the orchestrator
  - inputs: `tenant_id` (or `user_id` if tenant == user), receiver principal, policy mode
  - outputs: an **authorized filter** (preferably compact tokens) and optional **explanation witnesses**

This service should be called from the search router before executing OpenSearch.

### Candidate generation algorithm (AQL traversal)

Implement a bounded traversal with:

- **Grammar whitelist**
  - restrict which edge types can be used, and optionally restrict sequences (e.g., disallow VIEWED/STARRED)
- **Hop bound**
  - `K` hop limit
- **Deny override**
  - early pruning: if a candidate path crosses a deny boundary, terminate that branch

The traversal should return:

- a set of authorized `root_id` (preferred) or `version_id`
- optionally a minimal witness path per returned root/version for explainability

### Derived data enforcement

For any Info node produced by a Transform:

- Require `DERIVED_FROM` edges to inputs.
- Compute output authorization as a function of inputs:
  - **Audience intersection** (default): visible only to principals who can see all required inputs.
  - Optional explicit re-share edges can broaden access, but must be auditable and policy-gated.

This keeps transforms from becoming “privilege escalators.”

### How the authorized filter reaches OpenSearch

There are three progressively more scalable designs. Start with (1) for MVP and plan to evolve to (2) or (3).

1) **ID allow-list filter** (MVP)
   - GraphAuthz returns a bounded set of `root_id` (or doc ids).
   - Search adds a `terms` filter.
   - Works for small/medium candidate sets; breaks down at large scale.

2) **Principal token filter** (recommended)
   - During indexing, compute compact `acl_principals` tokens per doc (e.g., user/group/project visibility tokens).
   - GraphAuthz returns a small set of tokens the receiver possesses.
   - OpenSearch filter becomes `terms: {acl_principals: [tokens...]}`.

3) **Two-stage retrieval** (safest at scale)
   - Stage A: OpenSearch retrieves top-N with permissive filtering.
   - Stage B: GraphAuthz verifies each hit (and optionally expands within $A$).
   - Rerank and return.

Agience already has an indexing pipeline and a unified search accessor; the key change is introducing an explicit authorization stage.

### API and response shape changes

Add optional request fields to `/search`:

- `auth_mode`: `"legacy" | "light_cone" | "auto"` (feature flag / rollout)
- `explain`: boolean (include “why visible” witnesses)

Response additions (when `explain=true`):

- `auth`:
  - `candidate_count`, `authorized_count`
  - per-hit witness snippet: minimal edge sequence

### Caching

Graph reachability can be cached aggressively:

- Cache principal→context reachability tokens for a short TTL and invalidate on membership/share changes.
- Cache “receiver cone for project/channel/workspace” separately from the query text.

The cache key should include receiver principal and (if used) a “policy version.”

## Benefits

### Product benefits

- **Less manual sharing**: visibility follows real context and relationships (project/channel/workspace) rather than requiring explicit ACLs everywhere.
- **Explainable access**: every visible item can come with a path witness (“you can see this because…”).

### Security benefits

- **Embeddings never grant access**: semantic is strictly post-authorization ranking.
- **Revocation is natural**: removing membership/share edges immediately shrinks the reachable cone.
- **Transform safety**: summaries/derivatives can be forced to inherit audience constraints.

### Engineering benefits

- **Composability**: one uniform model covers org structure, sharing, provenance, and transforms.
- **Determinism**: bounded traversal + grammar gives predictable behavior and auditability.

## Assumptions

- The system is tenant-scoped (a receiver principal is evaluated within one tenant boundary).
- ArangoDB is the source of truth for relationship/policy edges; OpenSearch is a derived index for ranking.
- Each artifact has stable `root_id` and specific `version_id` and the search indices contain these fields.
- There is a reliable mapping from authenticated identity (JWT / grant token) → principal node id.

## Requirements

### Functional requirements

- Compute authorized candidate set via structural reachability over a typed graph.
- Support explicit deny boundaries that override allow paths.
- Support an allow-path grammar (configurable list of allowed edge types and optionally sequences).
- Support derived-data constraints:
  - outputs must not exceed the audience of inputs unless explicitly re-shared
  - transforms must be represented and auditable
- Support explainability:
  - return a minimal witness path per visible item (optional / feature-flagged)
- Ensure existing ACL semantics can be represented as graph edges (migration path).

### Non-functional requirements

- Predictable latency: bounded traversal with configurable hop limits and expansion caps.
- Bounded memory and response sizes: authorization outputs must be compact (tokenized filters preferred).
- Observability:
  - metrics: candidate_count, authorized_count, traversal time, OpenSearch time, p95/p99
  - logs: deny reasons, policy mode, path grammar version
- Testing:
  - unit tests for grammar/deny logic
  - integration tests ensuring semantic ranking cannot widen authorization
- Rollout:
  - feature-flagged `auth_mode` for gradual enablement and controlled cutover.

## Explainability and auditing

This feature is designed to support:

- “Why can I see this?” response metadata:
  - a short path witness (edge sequence)
  - policy decisions applied (deny/classification)
- Audit logs:
  - queries, candidate counts, denied reasons
  - derived-data policy checks

## Security properties

- Embeddings cannot grant access.
- Deny boundaries override allow paths.
- Derived outputs inherit constraints from inputs.
- All decisions can be explained as graph paths + policy checks.

## Rollout plan (phased)

### Phase 1 — Graph-backed ACL parity

- Represent existing share/group/project semantics as graph edges.
- Light cone used to compute candidate set for collections/search.
- Explainability: basic path witness.

### Phase 2 — Transform/derivation enforcement

- Introduce Transform nodes + DERIVED_FROM edges.
- Enforce monotone sensitivity / audience intersection.

### Phase 3 — Enterprise controls

- Purpose/compartment controls.
- Auditing + policy reports.

## Open questions

These materially affect implementation:

- Domain/threat model: enterprise docs, personal memory, regulated data?
- Graph size and p95 targets: max candidate set size before ranking.
- Required explainability level: full path vs summarized reason.
- Crypto enforcement: do we need envelope keys eventually for zero-trust storage?
