"""FastAPI oracle service.

Endpoints:

  GET  /healthz
  GET  /info                                  -> {owner_did, oracle_did, mode, counters}
  POST /issue-batch  BatchIssueKeyRequest     -> BatchIssueKeyResponse
  POST /peer/share   PeerShareRequest         -> PeerShareResponse  (threshold mode only)

`/issue-batch` applies the wire-layer checks (Ed25519 signature, ±60s
clock skew, replay nonce cache), then dispatches to `OracleCore`.

In **threshold mode** the service exposes `/peer/share` so peer
oracles can request its Shamir share for a specific querier batch.
The peer endpoint independently re-verifies the querier's signature
and the querier's authorization in the ledger before releasing.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ..identity import Identity, verify_ed25519
from ..ledger.client import GrantLedgerClient
from ..wire import (
    BatchIssueKeyRequest,
    BatchIssueKeyResponse,
    CentroidsRequest,
    CentroidsResponse,
    NonceCache,
    WireError,
    encrypt_and_sign_batch_response,
    encrypt_and_sign_centroids_response,
    verify_batch_request,
    verify_centroids_request,
)
from .core import OracleCore
from .peer_wire import (
    PeerShareRequest,
    PeerShareResponse,
    encrypt_and_sign_peer_response,
    verify_peer_request,
)
from .threshold import Share


class OracleInfo(BaseModel):
    owner_did: str
    oracle_did: str
    mode: str    # "single" | "threshold"
    threshold_k: Optional[int] = None
    decisions_total: int
    decisions_granted: int
    decisions_denied: int


class UploadEncryptedCentroidsBody(BaseModel):
    context_id: str
    encrypted_blob_b64: str
    owner_did: str
    nonce_b64: str
    timestamp_ns: int
    signature_b64: str


def build_oracle_app(
    owner_did: str,
    ledger_client: GrantLedgerClient,
    *,
    master_key: Optional[bytes] = None,
    share: Optional[Share] = None,
    threshold_k: Optional[int] = None,
    peer_share_fetcher=None,
    oracle_identity: Optional[Identity] = None,
    nonce_cache: Optional[NonceCache] = None,
    peer_nonce_cache: Optional[NonceCache] = None,
    centroid_nonce_cache: Optional[NonceCache] = None,
    allowed_coord_dids: Optional[set[str]] = None,
) -> FastAPI:
    core = OracleCore(
        owner=owner_did,
        ledger=ledger_client,
        master_key=master_key,
        share=share,
        threshold_k=threshold_k,
        peer_share_fetcher=peer_share_fetcher,
    )
    cache = nonce_cache or NonceCache()
    peer_cache = peer_nonce_cache or NonceCache()
    centroid_cache = centroid_nonce_cache or NonceCache()
    oracle_id = oracle_identity or Identity.generate()
    coord_allowlist = allowed_coord_dids or set()

    app = FastAPI(title="flare-oracle", version="0.3")
    app.state.core = core
    app.state.nonce_cache = cache
    app.state.peer_nonce_cache = peer_cache
    app.state.centroid_nonce_cache = centroid_cache
    app.state.oracle_identity = oracle_id
    app.state.allowed_coord_dids = coord_allowlist

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.get("/info", response_model=OracleInfo)
    def info() -> OracleInfo:
        return OracleInfo(
            owner_did=core.owner,
            oracle_did=oracle_id.did,
            mode="threshold" if core.is_threshold else "single",
            threshold_k=threshold_k if core.is_threshold else None,
            decisions_total=core.issued_count + core.denied_count,
            decisions_granted=core.issued_count,
            decisions_denied=core.denied_count,
        )

    @app.post("/issue-batch")
    def issue_batch(req: BatchIssueKeyRequest) -> BatchIssueKeyResponse:
        try:
            verify_batch_request(req, cache, now_ns=time.time_ns())
        except WireError:
            raise HTTPException(status_code=401, detail="auth failed")

        now = datetime.fromtimestamp(req.timestamp_ns / 1e9, tz=timezone.utc).replace(tzinfo=None)
        cells = [(c.context_id, c.cluster_id) for c in req.cells]
        results = core.decide_batch(req.requester_did, cells, now, original_request=req)

        cell_keys: list[Optional[bytes]] = [r.cell_key for r in results]
        denied_reasons: list[Optional[str]] = [
            None if r.cell_key is not None else r.decision.value for r in results
        ]
        try:
            return encrypt_and_sign_batch_response(
                req, cell_keys, denied_reasons, oracle_id,
            )
        finally:
            del results
            cell_keys.clear()

    @app.post("/peer/share")
    def peer_share(req: PeerShareRequest) -> PeerShareResponse:
        if not core.is_threshold or core._share is None:  # noqa: SLF001
            raise HTTPException(status_code=400, detail="oracle is not in threshold mode")
        try:
            inner = verify_peer_request(
                req,
                allowed_coord_dids=coord_allowlist,
                nonce_cache=peer_cache,
                now_ns=time.time_ns(),
            )
        except WireError as e:
            raise HTTPException(status_code=401, detail=f"peer auth failed: {e}")

        # Independently re-check the querier's authorization.
        # For batch requests: every cell must be authorized.
        # For centroid requests: at least one context must be authorized.
        now = datetime.fromtimestamp(inner.timestamp_ns / 1e9, tz=timezone.utc).replace(tzinfo=None)
        # Grant-first: all access — including the owner's — flows
        # through the ledger. The owner holds a standing self-grant.
        if req.request_type == "centroids":
            # Centroid request: any authorized context suffices.
            authorized = False
            for ctx in inner.context_ids:
                grant = core._ledger.find_valid(  # noqa: SLF001
                    core.owner, inner.requester_did, ctx, now,
                )
                if grant is not None:
                    authorized = True
                    break
            if not authorized:
                raise HTTPException(
                    status_code=403,
                    detail="peer denies share: no centroid grant",
                )
        else:
            # Batch key request: every cell must be authorized.
            for c in inner.cells:
                grant = core._ledger.find_valid(  # noqa: SLF001
                    core.owner, inner.requester_did, c.context_id, now,
                )
                if grant is None:
                    raise HTTPException(
                        status_code=403,
                        detail=f"peer denies share: no grant for {c.context_id}",
                    )

        return encrypt_and_sign_peer_response(req, core._share, oracle_id)  # noqa: SLF001

    @app.post("/request-centroids")
    def request_centroids(req: CentroidsRequest) -> CentroidsResponse:
        try:
            verify_centroids_request(req, centroid_cache, now_ns=time.time_ns())
        except WireError:
            raise HTTPException(status_code=401, detail="auth failed")

        now = datetime.fromtimestamp(req.timestamp_ns / 1e9, tz=timezone.utc).replace(tzinfo=None)
        blobs = core.issue_centroids(
            req.requester_did, req.context_ids, now, original_request=req,
        )
        denied_reasons: list[Optional[str]] = [
            None if b is not None else "denied" for b in blobs
        ]
        return encrypt_and_sign_centroids_response(
            req, blobs, denied_reasons, oracle_id,
        )

    @app.post("/upload-encrypted-centroids")
    def upload_encrypted_centroids(body: UploadEncryptedCentroidsBody) -> dict:
        """Accept an encrypted centroid blob from the data owner.

        Only the registered owner DID may upload. The blob is stored
        in the oracle core for delivery to authorized queriers via
        /request-centroids.
        """
        import base64

        if body.owner_did != core.owner:
            raise HTTPException(status_code=403, detail="owner DID mismatch")

        # Clock-skew + replay protection (same pattern as storage writes).
        now_ns = time.time_ns()
        if abs(now_ns - body.timestamp_ns) > 60_000_000_000:
            raise HTTPException(status_code=401, detail="timestamp outside skew window")
        nonce = base64.urlsafe_b64decode(body.nonce_b64 + "==")
        if not centroid_cache.check_and_record(nonce, now_ns):
            raise HTTPException(status_code=401, detail="nonce replay detected")

        # Verify owner's Ed25519 signature over the payload.
        canonical = (
            body.context_id.encode()
            + b"\x00"
            + body.encrypted_blob_b64.encode()
            + b"\x00"
            + nonce
            + body.timestamp_ns.to_bytes(8, "big", signed=False)
        )
        sig = base64.urlsafe_b64decode(body.signature_b64 + "==")
        if not verify_ed25519(body.owner_did, canonical, sig):
            raise HTTPException(status_code=401, detail="invalid signature")

        blob = base64.urlsafe_b64decode(body.encrypted_blob_b64 + "==")
        core.store_encrypted_centroids(body.context_id, blob)
        return {"ok": True, "context_id": body.context_id}

    return app
