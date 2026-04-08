"""Shared dataclasses for the FLARE prototype."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


PrincipalId = str  # DID-shaped opaque string, e.g. "did:key:alice"
ContextId = str    # e.g. "workspace_42"
ClusterId = int    # local cluster id within a context


@dataclass(frozen=True)
class CellRef:
    context_id: ContextId
    cluster_id: ClusterId


@dataclass
class Grant:
    grant_id: str
    grantor: PrincipalId
    grantee: PrincipalId
    context_id: ContextId
    scope: str                   # "read" for the prototype
    issued_at: datetime
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    # Phase 3: Ed25519 signature by the grantor over the canonical
    # grant bytes (see flare/ledger/signing.py:canonical_grant_bytes).
    # Empty string is allowed only for the legacy in-memory path used
    # by tests that exercise pre-Phase-3 behavior; the Phase 3 ledger
    # service rejects unsigned grants.
    signature_b64: str = ""
    # Phase 3: Ed25519 signature over (grant_id, revoked_at), set when
    # the grantor revokes the grant. Same caveat as `signature_b64`.
    revoke_signature_b64: str = ""

    def is_valid_at(self, now: datetime) -> bool:
        if self.revoked_at is not None and now >= self.revoked_at:
            return False
        if self.expires_at is not None and now >= self.expires_at:
            return False
        if now < self.issued_at:
            return False
        return True


@dataclass
class QueryHit:
    context_id: ContextId
    cluster_id: ClusterId
    vector_id: int
    score: float


@dataclass
class QueryTrace:
    """Per-stage diagnostic record produced by FlareQueryEngine.search.

    The trace is what makes the prototype legible: every stage of the
    pipeline named in docs/flare-index.md §Data Flow is recorded here so
    tests, the demo, and the paper's evaluation section can all assert
    against the same evidence.
    """
    candidate_cells: list[CellRef] = field(default_factory=list)
    authorized_contexts: set[ContextId] = field(default_factory=set)
    light_cone_filtered: list[CellRef] = field(default_factory=list)
    oracle_granted: list[CellRef] = field(default_factory=list)
    oracle_denied: list[CellRef] = field(default_factory=list)
    decrypted_cells: int = 0
    hits: list[QueryHit] = field(default_factory=list)
