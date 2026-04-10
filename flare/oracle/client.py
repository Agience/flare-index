"""Oracle client (HTTP).

`request_cell_keys_batch(identity, expected_oracle_did, cells)`:
production path. One signed envelope per oracle, ECIES response
carries every cell key, oracle Ed25519-signs the response bytes, the
client verifies the signature against `expected_oracle_did` (which
the query node looked up in the storage service's context
registration). End-to-end origin authentication.

Accepts either a real `httpx.Client` or a
`starlette.testclient.TestClient`, so the same code path runs against
docker-compose containers and against in-process tests.
"""
from __future__ import annotations

import base64
import os
import time as _time
from typing import Optional, Protocol

import httpx

from ..identity import Identity
from ..types import ClusterId, ContextId
from ..wire import (
    BatchIssueKeyResponse,
    CentroidsResponse,
    IssuedCellKey,
    WireError,
    build_batch_request,
    build_centroids_request,
    verify_and_decrypt_batch_response,
    verify_and_decrypt_centroids_response,
)


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


class OracleClient(Protocol):
    def request_cell_keys_batch(
        self,
        identity: Identity,
        expected_oracle_did: str,
        cells: list[tuple[ContextId, ClusterId]],
    ) -> list[Optional[IssuedCellKey]]: ...

    def request_centroids(
        self,
        identity: Identity,
        expected_oracle_did: str,
        context_ids: list[ContextId],
    ) -> dict[ContextId, Optional[bytes]]: ...

    def upload_encrypted_centroids(
        self,
        owner_identity: Identity,
        context_id: ContextId,
        encrypted_blob: bytes,
    ) -> None: ...

    def info(self) -> dict: ...


class HttpOracleClient:
    def __init__(
        self,
        base_url: str = "",
        *,
        client=None,
    ) -> None:
        if client is None:
            client = httpx.Client(base_url=base_url, timeout=10.0)
        self._client = client

    def request_cell_keys_batch(
        self,
        identity: Identity,
        expected_oracle_did: str,
        cells: list[tuple[ContextId, ClusterId]],
    ) -> list[Optional[IssuedCellKey]]:
        if not cells:
            return []
        materials = build_batch_request(identity, cells)
        r = self._client.post("/issue-batch", json=materials.request.model_dump())
        if r.status_code in (401, 403):
            return [None] * len(cells)
        r.raise_for_status()
        resp = BatchIssueKeyResponse.model_validate(r.json())
        try:
            return verify_and_decrypt_batch_response(
                materials, resp, expected_oracle_did,
            )
        except WireError:
            # Origin authentication failed. Refuse the whole batch.
            return [None] * len(cells)

    def request_centroids(
        self,
        identity: Identity,
        expected_oracle_did: str,
        context_ids: list[ContextId],
    ) -> dict[ContextId, Optional[bytes]]:
        if not context_ids:
            return {}
        materials = build_centroids_request(identity, context_ids)
        r = self._client.post("/request-centroids", json=materials.request.model_dump())
        if r.status_code in (401, 403):
            return {ctx: None for ctx in context_ids}
        r.raise_for_status()
        resp = CentroidsResponse.model_validate(r.json())
        try:
            return verify_and_decrypt_centroids_response(
                materials, resp, expected_oracle_did,
            )
        except WireError:
            return {ctx: None for ctx in context_ids}

    def upload_encrypted_centroids(
        self,
        owner_identity: Identity,
        context_id: ContextId,
        encrypted_blob: bytes,
    ) -> None:
        nonce = os.urandom(16)
        ts_ns = _time.time_ns()
        blob_b64 = _b64(encrypted_blob)
        canonical = (
            context_id.encode()
            + b"\x00"
            + blob_b64.encode()
            + b"\x00"
            + nonce
            + ts_ns.to_bytes(8, "big", signed=False)
        )
        sig = owner_identity.sign(canonical)
        body = {
            "context_id": context_id,
            "encrypted_blob_b64": blob_b64,
            "owner_did": owner_identity.did,
            "nonce_b64": _b64(nonce),
            "timestamp_ns": ts_ns,
            "signature_b64": _b64(sig),
        }
        r = self._client.post("/upload-encrypted-centroids", json=body)
        r.raise_for_status()

    def info(self) -> dict:
        r = self._client.get("/info")
        r.raise_for_status()
        return r.json()
