"""In-memory grant ledger backing store with hash-chained append-only log.

Phase 3 closes findings F-0.4 / F-1.7 in software: every state-changing
operation appends to a hash-chained log, and every grant carries a
grantor Ed25519 signature. The implementation is in-memory because the
prototype does not run a real consensus chain; the schema and
verification primitives are identical to what an on-chain version
would expose.
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Literal, Optional

from ..types import ContextId, Grant, PrincipalId
from .signing import GENESIS_HASH, chain_hash


EntryKind = Literal["grant", "revoke"]


@dataclass
class LedgerEntry:
    seq: int
    kind: EntryKind
    grant_id: str
    canonical: bytes        # entry payload (canonical_grant_bytes / canonical_revoke_bytes)
    grantor_signature: bytes  # Ed25519 by the grantor over `canonical`
    prev_hash: bytes
    entry_hash: bytes


class InMemoryGrantLedger:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._grants: dict[str, Grant] = {}
        self._log: list[LedgerEntry] = []
        self._head: bytes = GENESIS_HASH

    # ----- low-level append (verification happens at the service layer) -----

    def append(
        self,
        *,
        kind: EntryKind,
        grant_id: str,
        canonical: bytes,
        grantor_signature: bytes,
    ) -> LedgerEntry:
        with self._lock:
            new_hash = chain_hash(self._head, canonical)
            entry = LedgerEntry(
                seq=len(self._log),
                kind=kind,
                grant_id=grant_id,
                canonical=canonical,
                grantor_signature=grantor_signature,
                prev_hash=self._head,
                entry_hash=new_hash,
            )
            self._log.append(entry)
            self._head = new_hash
            return entry

    def head(self) -> bytes:
        with self._lock:
            return self._head

    def log(self) -> list[LedgerEntry]:
        with self._lock:
            return list(self._log)

    # ----- typed helpers used by the service -----

    def add_grant(
        self,
        grantor: PrincipalId,
        grantee: PrincipalId,
        context_id: ContextId,
        issued_at: datetime,
        expires_at: Optional[datetime] = None,
        scope: str = "read",
        grant_id: Optional[str] = None,
        signature_b64: str = "",
    ) -> Grant:
        with self._lock:
            gid = grant_id or str(uuid.uuid4())
            grant = Grant(
                grant_id=gid,
                grantor=grantor,
                grantee=grantee,
                context_id=context_id,
                scope=scope,
                issued_at=issued_at,
                expires_at=expires_at,
                signature_b64=signature_b64,
            )
            self._grants[gid] = grant
            return grant

    def revoke(
        self,
        grant_id: str,
        revoked_at: datetime,
        revoke_signature_b64: str = "",
    ) -> None:
        with self._lock:
            if grant_id not in self._grants:
                raise KeyError(grant_id)
            self._grants[grant_id].revoked_at = revoked_at
            self._grants[grant_id].revoke_signature_b64 = revoke_signature_b64

    def find_valid(
        self,
        grantor: PrincipalId,
        grantee: PrincipalId,
        context_id: ContextId,
        now: datetime,
    ) -> Optional[Grant]:
        with self._lock:
            for g in self._grants.values():
                if (
                    g.grantor == grantor
                    and g.grantee == grantee
                    and g.context_id == context_id
                    and g.is_valid_at(now)
                ):
                    return g
            return None

    def get(self, grant_id: str) -> Optional[Grant]:
        with self._lock:
            return self._grants.get(grant_id)

    def all_grants(self) -> Iterable[Grant]:
        with self._lock:
            return list(self._grants.values())
