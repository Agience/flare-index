"""Light-cone graph authorization.

The light cone projects the set of contexts visible to a principal
through structural relationships in a typed multigraph. It answers
exactly one question:

    Given principal P, which context_ids are reachable through an
    allowed path, with no traversal through a denied transition or a
    denied path, within K hops?

The graph supports three forms of access control, in increasing order
of expressiveness:

1. **Allow edges** are the only edges BFS will traverse.

2. **Edge-level deny** — a deny `Edge(X, Y)` prunes the specific
   transition X -> Y for everyone, leaving other paths to Y intact.

3. **Path-predicate deny** — a `PathPredicate` is a constraint on the
   *full path* from the principal to a candidate context. The most
   useful predicate is `RequireAllOf({A, B})`: deny if the path
   traverses every node in the set. This expresses things like "deny
   any path that goes through both legacy_group AND ws_a", which
   edge-level deny cannot capture without enumerating every concrete
   transition. Predicates are evaluated against the path that BFS
   has accumulated so far; a candidate path that satisfies a deny
   predicate's `matches` method is dropped.

Path-predicate evaluation makes BFS path-stateful: each frontier
element carries the set of nodes visited along the path that reached
it, not just the final node. This is bounded by the hop limit K, so
the cost stays linear in K * (frontier width). Cycles are blocked
because we never expand a node we've already added to the path.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Protocol

from .types import ClusterId, ContainmentEdge, ContextId, PrincipalId

NodeId = str  # principals and contexts share a namespace


class PathPredicate(Protocol):
    """A constraint on a candidate path.

    `matches(path)` returns True iff the predicate's deny condition
    is satisfied by the given path. The light cone drops any
    reachability whose path matches an active deny predicate.
    """
    def matches(self, path: list[NodeId]) -> bool: ...


@dataclass(frozen=True)
class RequireAllOf:
    """Deny if every node in `nodes` appears anywhere in the path."""
    nodes: frozenset[NodeId]

    def matches(self, path: list[NodeId]) -> bool:
        return self.nodes.issubset(path)


@dataclass(frozen=True)
class RequireSequence:
    """Deny if `nodes` appear as a (not necessarily contiguous)
    subsequence of the path. Useful for 'A then B then C' rules."""
    nodes: tuple[NodeId, ...]

    def matches(self, path: list[NodeId]) -> bool:
        it = iter(path)
        return all(n in it for n in self.nodes)


@dataclass(frozen=True)
class DenyPath:
    """A deny rule scoped to a target context with a path predicate.

    `target` is the context the rule protects. `predicate` decides
    whether a candidate path that would otherwise reach `target`
    should be dropped. If `target` is None, the rule applies to every
    context (rare; included for symmetry).
    """
    predicate: PathPredicate
    target: Optional[ContextId] = None


@dataclass(frozen=True)
class Edge:
    src: NodeId
    dst: NodeId
    edge_type: str
    allow: bool = True  # False => deny


@dataclass
class LightConeGraph:
    out_edges: dict[NodeId, list[Edge]] = field(default_factory=dict)
    context_nodes: set[NodeId] = field(default_factory=set)
    deny_edges_by_pair: dict[tuple[NodeId, NodeId], list[Edge]] = field(default_factory=dict)
    deny_paths: list[DenyPath] = field(default_factory=list)
    # Containment: explicit edges from contexts to cells. When present,
    # the query engine uses these to resolve cells instead of enumerating
    # range(nlist). Enables cross-context sharing.
    containment_edges: dict[ContextId, list[ContainmentEdge]] = field(default_factory=dict)

    def add_context(self, context_id: ContextId) -> None:
        self.context_nodes.add(context_id)

    def add_edge(self, edge: Edge) -> None:
        self.out_edges.setdefault(edge.src, []).append(edge)
        if not edge.allow:
            self.deny_edges_by_pair.setdefault((edge.src, edge.dst), []).append(edge)

    def add_deny_path(self, deny: DenyPath) -> None:
        self.deny_paths.append(deny)

    # ---- Containment edges (context → cells) ----

    def add_containment_edge(self, edge: ContainmentEdge) -> None:
        self.containment_edges.setdefault(edge.context_id, []).append(edge)

    def remove_containment_edge(self, edge: ContainmentEdge) -> None:
        edges = self.containment_edges.get(edge.context_id, [])
        if edge in edges:
            edges.remove(edge)

    def get_cells(self, context_id: ContextId) -> list[ContainmentEdge]:
        """Return containment edges for a context, or empty if not registered."""
        return list(self.containment_edges.get(context_id, []))

    def remove_edge(self, edge: Edge) -> None:
        edges = self.out_edges.get(edge.src, [])
        if edge in edges:
            edges.remove(edge)
        if not edge.allow:
            pair = (edge.src, edge.dst)
            denies = self.deny_edges_by_pair.get(pair, [])
            if edge in denies:
                denies.remove(edge)
                if not denies:
                    self.deny_edges_by_pair.pop(pair, None)

    def _is_transition_denied(self, src: NodeId, dst: NodeId) -> bool:
        return bool(self.deny_edges_by_pair.get((src, dst)))

    def _path_denied(self, target: NodeId, candidate_path: list[NodeId]) -> bool:
        for rule in self.deny_paths:
            if rule.target is not None and rule.target != target:
                continue
            if rule.predicate.matches(candidate_path):
                return True
        return False

    def authorized_contexts(
        self,
        principal: PrincipalId,
        max_hops: int = 4,
    ) -> set[ContextId]:
        # Path-stateful BFS. Each frontier element carries the full
        # path that reached it, so path-predicate deny rules can be
        # evaluated against it. Bounded by max_hops; cycles are
        # blocked because we never expand a node already in the path.
        reached: set[NodeId] = set()
        if principal in self.context_nodes and not self._path_denied(principal, [principal]):
            reached.add(principal)
        frontier: deque[tuple[NodeId, tuple[NodeId, ...]]] = deque(
            [(principal, (principal,))]
        )
        while frontier:
            node, path = frontier.popleft()
            if len(path) - 1 >= max_hops:
                continue
            for edge in self.out_edges.get(node, []):
                if not edge.allow:
                    continue
                if self._is_transition_denied(edge.src, edge.dst):
                    continue
                if edge.dst in path:  # cycle
                    continue
                next_path = path + (edge.dst,)
                if self._path_denied(edge.dst, list(next_path)):
                    continue
                if edge.dst in self.context_nodes:
                    reached.add(edge.dst)
                frontier.append((edge.dst, next_path))
        return {n for n in reached if n in self.context_nodes}

    def explain(
        self,
        principal: PrincipalId,
        target: ContextId,
        max_hops: int = 4,
    ) -> Optional[list[NodeId]]:
        """Return one allowed path principal -> target, or None."""
        if principal == target:
            return [principal]
        frontier: deque[tuple[NodeId, tuple[NodeId, ...]]] = deque(
            [(principal, (principal,))]
        )
        while frontier:
            node, path = frontier.popleft()
            if len(path) - 1 >= max_hops:
                continue
            for edge in self.out_edges.get(node, []):
                if not edge.allow:
                    continue
                if self._is_transition_denied(edge.src, edge.dst):
                    continue
                if edge.dst in path:
                    continue
                next_path = path + (edge.dst,)
                if self._path_denied(edge.dst, list(next_path)):
                    continue
                if edge.dst == target:
                    return list(next_path)
                frontier.append((edge.dst, next_path))
        return None
