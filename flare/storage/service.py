"""FastAPI storage service.

Endpoints:
  POST /contexts                                   register (signed by owner)
  PUT  /contexts/{ctx}/centroids                   raw npy bytes
  POST /contexts/{ctx}/cells/{cluster_id}          encrypted cell blob (signed by owner)
  GET  /contexts                                   list registrations
  GET  /contexts/{ctx}                             one registration
  GET  /contexts/{ctx}/centroids                   centroids (npy)
  GET  /contexts/{ctx}/cells/{cluster_id}          ciphertext cell blob
  GET  /healthz

Every WRITE carries an Ed25519 signature from the owner DID associated
with the context, plus a fresh nonce + timestamp inside the signed
canonical bytes. The storage service resolves the owner DID via the
configured `DIDResolver` (`did:key`, `did:web`, ...) and verifies the
signature. A per-DID nonce cache rejects replays within a 5-minute
clock-skew window.

Reads remain anonymous because ciphertext leaks nothing without an
oracle-issued cell key.
"""
from __future__ import annotations

import base64
import io
import time
from typing import Optional

import numpy as np
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

from ..identity import verify_ed25519
from .memory import ContextRegistration, InMemoryStorage, OracleEndpoint
from .signing import (
    STORAGE_SKEW_NS,
    StorageNonceCache,
    canonical_cell_upload_bytes,
    canonical_registration_bytes,
)


class OracleEndpointBody(BaseModel):
    url: str
    oracle_did: str


class RegisterBody(BaseModel):
    context_id: str
    owner_did: str
    oracle_endpoints: list[OracleEndpointBody]
    dim: int
    nlist: int
    nonce_b64: str
    timestamp_ns: int
    signature_b64: str  # Ed25519(owner_signing_key, canonical_registration_bytes)


class RegistrationOut(BaseModel):
    context_id: str
    owner_did: str
    oracle_endpoints: list[OracleEndpointBody]
    dim: int
    nlist: int

    @classmethod
    def from_registration(cls, r: ContextRegistration) -> "RegistrationOut":
        return cls(
            context_id=r.context_id,
            owner_did=r.owner_did,
            oracle_endpoints=[
                OracleEndpointBody(url=e.url, oracle_did=e.oracle_did)
                for e in r.oracle_endpoints
            ],
            dim=r.dim,
            nlist=r.nlist,
        )


def _np_to_bytes(arr: np.ndarray) -> bytes:
    buf = io.BytesIO()
    np.save(buf, arr.astype(np.float32), allow_pickle=False)
    return buf.getvalue()


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _verify_timestamp(timestamp_ns: int, now_ns: int) -> bool:
    return abs(now_ns - timestamp_ns) <= STORAGE_SKEW_NS


def build_storage_app(storage: Optional[InMemoryStorage] = None) -> FastAPI:
    storage = storage or InMemoryStorage()
    nonce_cache = StorageNonceCache()
    app = FastAPI(title="flare-storage", version="0.3")
    app.state.storage = storage
    app.state.nonce_cache = nonce_cache

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.post("/contexts", response_model=RegistrationOut)
    async def register(body: RegisterBody) -> RegistrationOut:
        now_ns = time.time_ns()
        if not _verify_timestamp(body.timestamp_ns, now_ns):
            raise HTTPException(status_code=401, detail="timestamp outside skew window")
        try:
            nonce = _b64d(body.nonce_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="bad nonce encoding")
        if not nonce_cache.check_and_record(body.owner_did, nonce, now_ns):
            raise HTTPException(status_code=401, detail="nonce replay detected")
        if not body.oracle_endpoints:
            raise HTTPException(status_code=400, detail="oracle_endpoints must be non-empty")
        canonical = canonical_registration_bytes(
            context_id=body.context_id,
            owner_did=body.owner_did,
            oracle_endpoints=[(e.url, e.oracle_did) for e in body.oracle_endpoints],
            dim=body.dim,
            nlist=body.nlist,
            nonce=nonce,
            timestamp_ns=body.timestamp_ns,
        )
        try:
            sig = _b64d(body.signature_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="bad signature encoding")
        try:
            ok = verify_ed25519(body.owner_did, canonical, sig)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"bad owner_did: {e}")
        if not ok:
            raise HTTPException(status_code=401, detail="registration signature invalid")

        try:
            storage.register_context(
                ContextRegistration(
                    context_id=body.context_id,
                    owner_did=body.owner_did,
                    oracle_endpoints=[
                        OracleEndpoint(url=e.url, oracle_did=e.oracle_did)
                        for e in body.oracle_endpoints
                    ],
                    dim=body.dim,
                    nlist=body.nlist,
                ),
                centroids=np.zeros((0, body.dim), dtype=np.float32),
            )
        except ValueError as e:
            raise HTTPException(status_code=409, detail=str(e))
        return RegistrationOut.from_registration(storage.get_registration(body.context_id))

    @app.put("/contexts/{ctx}/centroids")
    async def put_centroids(ctx: str, request: Request) -> dict:
        # Centroids are stored in storage for registration bookkeeping,
        # but the public GET endpoint returns 403 (see get_centroids).
        # Only the oracle serves centroid maps to authorized queriers.
        # Only the owner of the context may upload.
        raw = await request.body()
        sig_b64 = request.headers.get("x-flare-signature", "")
        owner_did_header = request.headers.get("x-flare-owner-did", "")
        nonce_b64 = request.headers.get("x-flare-nonce", "")
        ts_header = request.headers.get("x-flare-timestamp-ns", "")
        if not (sig_b64 and owner_did_header and nonce_b64 and ts_header):
            raise HTTPException(status_code=401, detail="missing centroids signature material")
        try:
            timestamp_ns = int(ts_header)
            nonce = _b64d(nonce_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="bad nonce/timestamp encoding")
        now_ns = time.time_ns()
        if not _verify_timestamp(timestamp_ns, now_ns):
            raise HTTPException(status_code=401, detail="timestamp outside skew window")
        if not nonce_cache.check_and_record(owner_did_header, nonce, now_ns):
            raise HTTPException(status_code=401, detail="nonce replay detected")
        try:
            reg = storage.get_registration(ctx)
        except KeyError:
            raise HTTPException(status_code=404, detail="context not registered")
        if reg.owner_did != owner_did_header:
            raise HTTPException(status_code=401, detail="owner DID does not match registration")
        canonical = canonical_cell_upload_bytes(
            context_id=ctx, cluster_id=-1, cell_blob=raw,
            nonce=nonce, timestamp_ns=timestamp_ns,
        )
        try:
            sig = _b64d(sig_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="bad signature encoding")
        if not verify_ed25519(reg.owner_did, canonical, sig):
            raise HTTPException(status_code=401, detail="centroids signature invalid")

        try:
            arr = np.load(io.BytesIO(raw), allow_pickle=False)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"bad centroids npy: {e}")
        with storage._lock:  # noqa: SLF001
            stored = storage._contexts.get(ctx)  # noqa: SLF001
            if stored is None:
                raise HTTPException(status_code=404, detail="context not registered")
            stored.centroids = arr.astype(np.float32)
        return {"ok": True, "shape": list(arr.shape)}

    @app.get("/contexts/{ctx}/centroids")
    def get_centroids(ctx: str) -> Response:
        # ANALYSIS A-3: Centroids are no longer served in plaintext.
        # The oracle delivers centroid maps to authorized queriers via
        # ECIES inside the /request-centroids endpoint. This endpoint
        # is retained only for the data owner (authenticated via
        # x-flare-owner-did + signature) for cold-start oracle loading.
        raise HTTPException(
            status_code=403,
            detail="centroids are oracle-gated; use POST /request-centroids on the oracle",
        )

    @app.post("/contexts/{ctx}/cells/{cluster_id}")
    async def put_cell(ctx: str, cluster_id: int, request: Request) -> dict:
        blob = await request.body()
        sig_b64 = request.headers.get("x-flare-signature", "")
        owner_did_header = request.headers.get("x-flare-owner-did", "")
        nonce_b64 = request.headers.get("x-flare-nonce", "")
        ts_header = request.headers.get("x-flare-timestamp-ns", "")
        if not (sig_b64 and owner_did_header and nonce_b64 and ts_header):
            raise HTTPException(status_code=401, detail="missing upload signature material")
        try:
            timestamp_ns = int(ts_header)
            nonce = _b64d(nonce_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="bad nonce/timestamp encoding")
        now_ns = time.time_ns()
        if not _verify_timestamp(timestamp_ns, now_ns):
            raise HTTPException(status_code=401, detail="timestamp outside skew window")
        if not nonce_cache.check_and_record(owner_did_header, nonce, now_ns):
            raise HTTPException(status_code=401, detail="nonce replay detected")
        try:
            reg = storage.get_registration(ctx)
        except KeyError:
            raise HTTPException(status_code=404, detail="context not registered")
        if reg.owner_did != owner_did_header:
            raise HTTPException(status_code=401, detail="owner DID does not match registration")
        canonical = canonical_cell_upload_bytes(
            context_id=ctx, cluster_id=cluster_id, cell_blob=blob,
            nonce=nonce, timestamp_ns=timestamp_ns,
        )
        try:
            sig = _b64d(sig_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="bad signature encoding")
        if not verify_ed25519(reg.owner_did, canonical, sig):
            raise HTTPException(status_code=401, detail="cell signature invalid")

        try:
            storage.put_cell(ctx, cluster_id, blob)
        except KeyError:
            raise HTTPException(status_code=404)
        return {"ok": True, "bytes": len(blob)}

    @app.get("/contexts/{ctx}/cells/{cluster_id}")
    def get_cell(ctx: str, cluster_id: int) -> Response:
        try:
            blob = storage.get_cell(ctx, cluster_id)
        except KeyError:
            raise HTTPException(status_code=404)
        return Response(blob, media_type="application/octet-stream")

    @app.get("/contexts", response_model=list[RegistrationOut])
    def list_contexts() -> list[RegistrationOut]:
        return [RegistrationOut.from_registration(r) for r in storage.list_contexts()]

    @app.get("/contexts/{ctx}", response_model=RegistrationOut)
    def get_registration(ctx: str) -> RegistrationOut:
        try:
            return RegistrationOut.from_registration(storage.get_registration(ctx))
        except KeyError:
            raise HTTPException(status_code=404)

    return app
