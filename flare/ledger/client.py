"""Ledger client.

Writes (`add_grant`, `revoke`) require an `Identity` whose DID matches
the grant's grantor field. The client signs locally; the service
verifies via `DIDResolver` before mutating state and before appending
to the chained log.

Reads (`find_valid`, `head`, `log`) are anonymous — the ledger is a
public discovery layer.
"""
from __future__ import annotations

import base64
import uuid
from datetime import datetime
from typing import Optional, Protocol

import httpx

from ..identity import Identity
from ..types import ContextId, Grant, PrincipalId
from .signing import canonical_grant_bytes, canonical_revoke_bytes


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _grant_from_json(data: dict) -> Grant:
    def _dt(v):
        return datetime.fromisoformat(v) if v else None
    return Grant(
        grant_id=data["grant_id"],
        grantor=data["grantor"],
        grantee=data["grantee"],
        context_id=data["context_id"],
        scope=data["scope"],
        issued_at=_dt(data["issued_at"]),
        expires_at=_dt(data.get("expires_at")),
        revoked_at=_dt(data.get("revoked_at")),
        signature_b64=data.get("signature_b64", ""),
        revoke_signature_b64=data.get("revoke_signature_b64", ""),
    )


class GrantLedgerClient(Protocol):
    def add_grant(
        self,
        grantor_identity: Identity,
        grantee: PrincipalId,
        context_id: ContextId,
        issued_at: datetime,
        expires_at: Optional[datetime] = None,
    ) -> Grant: ...

    def revoke(
        self,
        grant: Grant,
        grantor_identity: Identity,
        revoked_at: datetime,
    ) -> None: ...

    def find_valid(
        self,
        grantor: PrincipalId,
        grantee: PrincipalId,
        context_id: ContextId,
        now: datetime,
    ) -> Optional[Grant]: ...


class HttpLedgerClient:
    def __init__(
        self,
        base_url: str = "",
        *,
        client=None,
    ) -> None:
        if client is None:
            client = httpx.Client(base_url=base_url, timeout=5.0)
        self._client = client

    def add_grant(
        self,
        grantor_identity: Identity,
        grantee: PrincipalId,
        context_id: ContextId,
        issued_at: datetime,
        expires_at: Optional[datetime] = None,
        scope: str = "read",
    ) -> Grant:
        grant_id = str(uuid.uuid4())
        canonical = canonical_grant_bytes(
            grant_id=grant_id,
            grantor=grantor_identity.did,
            grantee=grantee,
            context_id=context_id,
            scope=scope,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        sig = grantor_identity.sign(canonical)
        body = {
            "grantor": grantor_identity.did,
            "grantee": grantee,
            "context_id": context_id,
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat() if expires_at else None,
            "scope": scope,
            "grant_id": grant_id,
            "signature_b64": _b64(sig),
        }
        r = self._client.post("/grants", json=body)
        r.raise_for_status()
        return _grant_from_json(r.json())

    def revoke(
        self,
        grant: Grant,
        grantor_identity: Identity,
        revoked_at: datetime,
    ) -> None:
        if grantor_identity.did != grant.grantor:
            raise ValueError(
                f"only the original grantor can revoke; got {grantor_identity.did}, "
                f"grant requires {grant.grantor}"
            )
        canonical = canonical_revoke_bytes(grant_id=grant.grant_id, revoked_at=revoked_at)
        sig = grantor_identity.sign(canonical)
        r = self._client.post(
            f"/grants/{grant.grant_id}/revoke",
            json={"revoked_at": revoked_at.isoformat(), "signature_b64": _b64(sig)},
        )
        r.raise_for_status()

    def find_valid(self, grantor, grantee, context_id, now) -> Optional[Grant]:
        r = self._client.get(
            "/grants/find",
            params={
                "grantor": grantor,
                "grantee": grantee,
                "context_id": context_id,
                "now": now.isoformat(),
            },
        )
        r.raise_for_status()
        data = r.json()
        if data is None:
            return None
        return _grant_from_json(data)

    def head(self) -> bytes:
        r = self._client.get("/head")
        r.raise_for_status()
        return bytes.fromhex(r.json()["head_hex"])
