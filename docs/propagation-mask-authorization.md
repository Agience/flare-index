# Propagation-Mask Authorization Model

Status: **Design**
Date: 2026-04-16

## Summary

The light-cone graph uses **propagation masks** — a positive-only, default-deny authorization model where edges carry explicit permission ceilings instead of binary allow/deny flags.

- **Edges** are structural (topology). They carry propagation masks that define the ceiling of what CAN flow through. Everyone sees the same topology.
- **Grants** are personal (per-principal). They define what a specific principal CAN do. Positive-only — no negative grants, no deny records anywhere.
- **Default-deny.** If a principal has no path through propagating edges to a context, that context is invisible. Absence of a propagating path = no access.

## Design Rationale

Three properties drove the choice of propagation masks:

1. **Edges are topology, not identity.** A per-principal deny edge mixes structural topology (shared by everyone) with identity (personal). Per-principal restrictions belong in the grants table, not as edge attributes.

2. **Default-deny makes deny semantics redundant.** The model starts with no access; positive grants and propagating edges build up what a principal CAN reach. Absence of a propagating path is denial — there is nothing additional to deny.

3. **Binary inheritance is too rigid.** An all-or-nothing edge cannot express "browsable and invokable but not modifiable" — common for parent→child relationships like server→tool. Propagation masks give $2^n$ states per edge instead of two.

## The Model

### Three Forms of Access Control

The light cone projects, for a given principal, the set of contexts reachable through structural relationships in a typed multigraph. It supports three forms of access control, in increasing expressiveness:

**1. Allow edges.** Only edges of types in the allowed-path grammar are traversed. Non-authorizing edge types (VIEWED, STARRED, EDITED) are never followed.

**2. Propagation masks.** Each edge carries a `propagate` field — an array of permission types that the edge allows to flow through. The BFS only follows an edge if the mask includes the requested permission. An edge with a null mask is a structural reference (browsing, ordering) that does not propagate access.

The propagation mask is a structural ceiling. The effective inherited permission at any node is:

$$
\text{effective\_inherited} = \bigcap_{e \in \text{path}} e.\text{propagate} \cap \text{grant}(P, \text{root})
$$

That is: the intersection of the viewer's direct grant with every propagation mask along the path from grant root to target.

**3. Path-predicate constraints.** A `PathPredicate` is a condition over the full path from the principal to a candidate context. If any active constraint's predicate matches the path, that path is dropped.

- **RequireAllOf(nodes)**: Block traversal if every node in the set appears anywhere in the current path.
- **RequireSequence(nodes)**: Block traversal if the nodes appear as a subsequence.

Path predicates express things propagation masks cannot — e.g., "block any path that traverses both `legacy_group` AND `audit_group` on its way to `ws_a`, but allow paths that traverse only one of them."

### Edge Schema

```python
@dataclass(frozen=True)
class Edge:
    src: NodeId
    dst: NodeId
    edge_type: str
    propagate: frozenset[str] | None = None  # None = no propagation
```

The `propagate` field is `None` when an edge is a structural reference that carries no authorization (browsing, ordering), or a non-empty frozenset of permission strings when the edge propagates access.

### Permission Types

The permission types in propagation masks use the CRUDEASIO model. The light-cone model is general — any set of permission strings works.

| Permission | Meaning |
|------------|---------|
| `C` | Create children |
| `R` | Read / browse |
| `U` | Update / edit |
| `D` | Delete |
| `E` | Evict (remove from container) |
| `A` | Add to container |
| `S` | Share / grant to others |
| `I` | Invoke / execute |
| `O` | Own (includes admin / structural management) |

### Default Propagation by Edge Role

| Edge role | Default `propagate` | Rationale |
|-----------|---------------------|-----------|
| Origin / creation edge | Full set `{"C","R","U","D","E","A","S","I","O"}` | Parent owns and fully controls children |
| Link / reference edge | `None` | Structural reference only — access through linked artifact's own origin chain |
| Server → tool | `{"R", "I"}` | Tools are browsable and invokable but not directly modifiable through server grants |
| Group → context | Configurable | Depends on the group's purpose |

### Concrete Edge Types

```
MEMBER_OF:    person → group              propagate: {"R","I","A","S"}
SHARED_WITH:  context → person/group      propagate: {per grant level}
POSTED_IN:    artifact → context          propagate: {"R"}
ADMIN_OF:     person → context            propagate: {"C","R","U","D","E","A","S","I","O"}
CONTAINS:     context → artifact          propagate: {configurable per edge}
```

### Per-Principal Restrictions

Edges are topology — they define what CAN flow through for anyone. Per-principal restrictions are handled by the grants table, not edge attributes:

| Want | How |
|------|-----|
| Everyone inherits R+I to children | `propagate: {"R","I"}` on edge |
| Nobody inherits | `propagate: None` on edge |
| Only specific users access child | `propagate: None` on edge + direct grants on child |
| Everyone except User A | Full propagate (`{"C","R","U","D","E","A","S","I","O"}`) + remove User A's upstream grant, or: `propagate: None` + direct grants for everyone except A |

## BFS Algorithm

The authorized-contexts computation is a path-stateful bounded BFS. Each frontier element carries the set of nodes visited along the path that reached it, so path-predicate constraints can be evaluated at each step.

```
function authorized_contexts(principal, max_hops, requested_permission):
    reached = {}
    frontier = queue of (node, path) starting with (principal, [principal])
    
    while frontier not empty:
        node, path = frontier.pop()
        if len(path) - 1 >= max_hops:
            continue
        for edge in out_edges(node):
            # Propagation mask check — the key change
            if edge.propagate is None:
                continue
            if requested_permission not in edge.propagate:
                continue
            if edge.dst in path:        # cycle prevention
                continue
            next_path = path + [edge.dst]
            if any constraint matches next_path:
                continue                # path-predicate constraint
            if edge.dst is a context node:
                reached.add(edge.dst)
            frontier.push((edge.dst, next_path))
    
    return reached
```



## Path-Predicate Constraints

Path-predicate constraints block traversal when a computed path satisfies a structural condition:

```python
class PathPredicate(Protocol):
    """A constraint on a candidate path.
    
    matches(path) returns True iff the constraint's blocking condition
    is satisfied by the given path. The light cone drops any
    reachability whose path matches an active constraint.
    """
    def matches(self, path: list[NodeId]) -> bool: ...


@dataclass(frozen=True)
class RequireAllOf:
    """Block if every node in `nodes` appears anywhere in the path."""
    nodes: frozenset[NodeId]

    def matches(self, path: list[NodeId]) -> bool:
        return self.nodes.issubset(path)


@dataclass(frozen=True)
class RequireSequence:
    """Block if `nodes` appear as a (not necessarily contiguous)
    subsequence of the path."""
    nodes: tuple[NodeId, ...]

    def matches(self, path: list[NodeId]) -> bool:
        it = iter(path)
        return all(n in it for n in self.nodes)
```

The constraint type is `PathConstraint`. `predicate.matches()` returns `True` when the path is blocked. Path predicates carry no deny semantics — they are structural constraints that evaluate path shape, not per-principal permissions.

## Interaction with Encryption (FLARE)

The propagation-mask model composes cleanly with FLARE's encryption layers:

| Layer | Role of propagation mask |
|-------|--------------------------|
| **Authorization** | BFS follows edges whose mask includes the requested permission → authorized context set |
| **Encryption** | The authorized context set maps 1:1 to encryption domains (context_id → HKDF → cell keys) |
| **Oracle** | Oracle checks grant ledger (positive-only); never needs to check deny records |

The default-deny, positive-only model simplifies the oracle's verification path: the oracle checks that a valid, non-revoked, non-expired grant exists. There is no deny table to consult, no deny-override logic, no priority between allow and deny. Either a grant exists or it doesn't.

## AQL Implementation (for ArangoDB deployments)

```aql
FOR v, e, p IN 1..4 OUTBOUND @principal_id GRAPH 'lightcone'
    FILTER @requested_permission IN e.propagate
    FILTER IS_SAME_COLLECTION('contexts', v)
    RETURN DISTINCT v._key
```

Path-predicate constraints map to `FILTER` clauses on `p.vertices[*]._key`.

## Implementation (`flare/lightcone.py`)

The canonical implementation in `flare/lightcone.py` should match this design:

- `Edge` carries `propagate: frozenset[str] | None` (not `allow: bool`).
- `LightConeGraph` has no `deny_edges_by_pair` index and no `_is_transition_denied()` method.
- BFS traversal checks `requested_permission in edge.propagate`; a `None` mask means no propagation.
- `authorized_contexts()` accepts a `requested_permission: str` parameter (default: `"R"`).
- The path-constraint type is `PathConstraint` (not `DenyPath`); docstrings use "block"/"constraint" instead of "deny".
- Tests for edge-level propagation use `propagate={"R"}` / `propagate=None` rather than `allow=False`. Tests for path constraints need only the rename.

## Design Properties

**Simpler.** One mechanism (propagation masks) replaces two (allow/deny + deny-edge index). Path-predicate constraints are retained but reframed.

**More expressive.** Binary allow/deny gave two states per edge. Propagation masks give $2^n$ states per edge (one bit per permission type). A server→tool edge can propagate `{R, I}` but not `{U, D, E, A}` — impossible in the old model without a separate deny edge per permission.

**Composable.** Edges are topology, grants are personal. The two concerns never mix. Adding a new principal never requires new edges; adding a new structural relationship never requires per-principal deny records.

**Default-deny.** No path = no access. No deny records to maintain, no deny-override priority logic, no "does deny beat allow or vice versa" ambiguity.

**Light-cone compatible.** The propagation mask IS the edge-type filter for BFS. `requested_permission in edge.propagate` is the traversal predicate. The cone boundary is defined by where propagation masks run out.

**Encryption compatible.** The oracle's job is unchanged: check grant ledger, issue key. The grant ledger is positive-only (grant exists or doesn't). No deny table consultation needed.
