"""FastAPI ledger service.

Endpoints:
  POST /grants                       -> add grant (grantor signature required)
  POST /grants/{grant_id}/revoke     -> revoke (grantor signature required)
  GET  /grants/find                  -> find valid grant for triple
  GET  /grants                       -> list (debug)
  GET  /grants/{grant_id}            -> one grant (with signatures)
  GET  /head                         -> hex of current chain head
  GET  /log                          -> append-only entry log
  GET  /healthz

Phase 3 closes finding F-1.7. The ledger service:

- requires every grant write to carry a valid Ed25519 signature from
  the grantor DID over the canonical grant bytes;
- requires every revoke to carry a valid Ed25519 signature from the
  *original grantor* over the canonical revoke bytes;
- appends every state change to a hash-chained log so any tampering
  is detectable by re-walking the chain from `GENESIS_HASH`.

The hash-chained log is a software substitute for an on-chain ledger.
The schema and the verification primitives match what an on-chain
deployment would expose; the missing piece is consensus.
"""
from __future__ import annotations

import base64
import uuid
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ..identity import verify_ed25519
from ..types import Grant
from .memory import InMemoryGrantLedger
from .signing import canonical_grant_bytes, canonical_revoke_bytes


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


class GrantBody(BaseModel):
    grantor: str
    grantee: str
    context_id: str
    issued_at: datetime
    expires_at: Optional[datetime] = None
    scope: str = "read"
    grant_id: str         # supplied by the client so the signature can cover it
    signature_b64: str    # Ed25519(grantor, canonical_grant_bytes)


class RevokeBody(BaseModel):
    revoked_at: datetime
    signature_b64: str    # Ed25519(grantor, canonical_revoke_bytes)


class GrantOut(BaseModel):
    grant_id: str
    grantor: str
    grantee: str
    context_id: str
    scope: str
    issued_at: datetime
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    signature_b64: str = ""
    revoke_signature_b64: str = ""

    @classmethod
    def from_grant(cls, g: Grant) -> "GrantOut":
        return cls(
            grant_id=g.grant_id,
            grantor=g.grantor,
            grantee=g.grantee,
            context_id=g.context_id,
            scope=g.scope,
            issued_at=g.issued_at,
            expires_at=g.expires_at,
            revoked_at=g.revoked_at,
            signature_b64=g.signature_b64,
            revoke_signature_b64=g.revoke_signature_b64,
        )


class LedgerEntryOut(BaseModel):
    seq: int
    kind: str
    grant_id: str
    grantor_signature_b64: str
    prev_hash_hex: str
    entry_hash_hex: str


def build_ledger_app(ledger: Optional[InMemoryGrantLedger] = None) -> FastAPI:
    ledger = ledger or InMemoryGrantLedger()
    app = FastAPI(title="flare-ledger", version="0.3")
    app.state.ledger = ledger

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.post("/grants", response_model=GrantOut)
    def create_grant(body: GrantBody) -> GrantOut:
        canonical = canonical_grant_bytes(
            grant_id=body.grant_id,
            grantor=body.grantor,
            grantee=body.grantee,
            context_id=body.context_id,
            scope=body.scope,
            issued_at=body.issued_at,
            expires_at=body.expires_at,
        )
        try:
            sig = _b64d(body.signature_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="bad signature encoding")
        try:
            ok = verify_ed25519(body.grantor, canonical, sig)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"bad grantor DID: {e}")
        if not ok:
            raise HTTPException(status_code=401, detail="grant signature invalid")

        g = ledger.add_grant(
            grantor=body.grantor,
            grantee=body.grantee,
            context_id=body.context_id,
            issued_at=body.issued_at,
            expires_at=body.expires_at,
            scope=body.scope,
            grant_id=body.grant_id,
            signature_b64=body.signature_b64,
        )
        ledger.append(
            kind="grant",
            grant_id=g.grant_id,
            canonical=canonical,
            grantor_signature=sig,
        )
        return GrantOut.from_grant(g)

    @app.post("/grants/{grant_id}/revoke", response_model=GrantOut)
    def revoke_grant(grant_id: str, body: RevokeBody) -> GrantOut:
        existing = ledger.get(grant_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="grant not found")
        canonical = canonical_revoke_bytes(grant_id=grant_id, revoked_at=body.revoked_at)
        try:
            sig = _b64d(body.signature_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="bad signature encoding")
        try:
            ok = verify_ed25519(existing.grantor, canonical, sig)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"bad grantor DID: {e}")
        if not ok:
            raise HTTPException(status_code=401, detail="revoke signature invalid")

        ledger.revoke(grant_id, body.revoked_at, revoke_signature_b64=body.signature_b64)
        ledger.append(
            kind="revoke",
            grant_id=grant_id,
            canonical=canonical,
            grantor_signature=sig,
        )
        return GrantOut.from_grant(ledger.get(grant_id))

    @app.get("/grants/find", response_model=Optional[GrantOut])
    def find(grantor: str, grantee: str, context_id: str, now: datetime) -> Optional[GrantOut]:
        g = ledger.find_valid(grantor, grantee, context_id, now)
        return GrantOut.from_grant(g) if g else None

    @app.get("/grants", response_model=list[GrantOut])
    def list_grants() -> list[GrantOut]:
        return [GrantOut.from_grant(g) for g in ledger.all_grants()]

    @app.get("/grants/{grant_id}", response_model=Optional[GrantOut])
    def get_grant(grant_id: str) -> Optional[GrantOut]:
        g = ledger.get(grant_id)
        return GrantOut.from_grant(g) if g else None

    @app.get("/head")
    def head() -> dict:
        return {"head_hex": ledger.head().hex()}

    @app.get("/log", response_model=list[LedgerEntryOut])
    def log() -> list[LedgerEntryOut]:
        return [
            LedgerEntryOut(
                seq=e.seq,
                kind=e.kind,
                grant_id=e.grant_id,
                grantor_signature_b64=_b64(e.grantor_signature),
                prev_hash_hex=e.prev_hash.hex(),
                entry_hash_hex=e.entry_hash.hex(),
            )
            for e in ledger.log()
        ]

    return app
