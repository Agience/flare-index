"""Per-grant Ed25519 signatures + hash-chained tamper-evident log.

Phase 3 closes finding F-1.7. Two changes land together:

1. **Per-grant Ed25519 signatures.** Every grant carries a signature
   from the grantor's identity over a canonical encoding of the
   grant's contents. The oracle (and any auditor) verifies the
   signature against the grantor DID via the standard `DIDResolver`
   before honoring the grant. Likewise every revocation carries a
   signature from the same grantor over a canonical encoding of
   `(grant_id, revoked_at)`.

2. **Append-only hash-chained log.** Every state-changing operation
   produces a `LedgerEntry` whose `entry_hash` includes the previous
   entry's hash. The full chain hashes back to a fixed genesis. Any
   tampering (re-ordering, insertion, mutation, deletion) breaks the
   chain. The chain head is exposed via `GET /head` so external
   auditors can pin it.

This is a software substitute for an on-chain ledger (Ceramic / L2):
the schema and the verification primitives are the same; only the
consensus layer is missing. Phase 4 (or a real deployment) can swap
the in-memory chain for an on-chain anchor without changing the
grant signature scheme.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Optional

from ..types import ContextId, PrincipalId

GENESIS_HASH = hashlib.sha256(b"flare/v3/ledger/genesis").digest()


def _len_prefix(parts: list[bytes]) -> bytes:
    out = bytearray()
    for p in parts:
        out += len(p).to_bytes(4, "big", signed=False)
        out += p
    return bytes(out)


def _dt_to_bytes(dt: Optional[datetime]) -> bytes:
    if dt is None:
        return b""
    return dt.isoformat().encode("utf-8")


def canonical_grant_bytes(
    *,
    grant_id: str,
    grantor: PrincipalId,
    grantee: PrincipalId,
    context_id: ContextId,
    scope: str,
    issued_at: datetime,
    expires_at: Optional[datetime],
) -> bytes:
    return _len_prefix([
        b"flare/v3/grant",
        grant_id.encode("utf-8"),
        grantor.encode("utf-8"),
        grantee.encode("utf-8"),
        context_id.encode("utf-8"),
        scope.encode("utf-8"),
        _dt_to_bytes(issued_at),
        _dt_to_bytes(expires_at),
    ])


def canonical_revoke_bytes(*, grant_id: str, revoked_at: datetime) -> bytes:
    return _len_prefix([
        b"flare/v3/revoke",
        grant_id.encode("utf-8"),
        _dt_to_bytes(revoked_at),
    ])


def chain_hash(prev_hash: bytes, entry_canonical: bytes) -> bytes:
    """The hash that links one ledger entry to the next.

    `entry_hash = sha256(prev_hash || sha256(entry_canonical))`

    Two-stage hashing keeps the chain step independent of the entry's
    internal serialization length.
    """
    h = hashlib.sha256()
    h.update(prev_hash)
    h.update(hashlib.sha256(entry_canonical).digest())
    return h.digest()
