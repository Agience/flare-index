"""Storage clients (HTTP).

Reads (`get_cell`, `get_centroids`, `list_contexts`, `get_registration`)
are anonymous: ciphertext leaks nothing without an oracle-issued key.

Writes (`register_context`, `put_centroids`, `put_cell`) require an
owner `Identity` whose DID matches the context registration. The
client signs each write locally and the storage service verifies the
signature against the owner DID via `did:key`.
"""
from __future__ import annotations

import base64
import io
import os
import time
from typing import Optional, Protocol

import httpx
import numpy as np

from ..identity import Identity
from ..types import ContextId
from .memory import ContextRegistration, InMemoryStorage, OracleEndpoint
from .signing import canonical_cell_upload_bytes, canonical_registration_bytes


_NONCE_LEN = 16


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


class StorageClient(Protocol):
    def register_context(
        self,
        registration: ContextRegistration,
        centroids: np.ndarray,
        owner_identity: Identity,
    ) -> None: ...
    def put_cell(
        self,
        context_id: ContextId,
        cluster_id: int,
        blob: bytes,
        owner_identity: Identity,
    ) -> None: ...
    def get_cell(self, context_id: ContextId, cluster_id: int) -> bytes: ...
    def get_centroids(self, context_id: ContextId) -> np.ndarray: ...
    def list_contexts(self) -> list[ContextRegistration]: ...
    def get_registration(self, context_id: ContextId) -> ContextRegistration: ...


class HttpStorageClient:
    def __init__(
        self,
        base_url: str = "",
        *,
        client=None,
    ) -> None:
        if client is None:
            client = httpx.Client(base_url=base_url, timeout=10.0)
        self._client = client

    # ----- writes (signed) -----

    def register_context(
        self,
        registration: ContextRegistration,
        centroids: np.ndarray,
        owner_identity: Identity,
    ) -> None:
        if owner_identity.did != registration.owner_did:
            raise ValueError(
                f"owner_identity DID {owner_identity.did} does not match "
                f"registration.owner_did {registration.owner_did}"
            )

        nonce = os.urandom(_NONCE_LEN)
        ts_ns = time.time_ns()
        endpoints_pairs = [(e.url, e.oracle_did) for e in registration.oracle_endpoints]
        canonical = canonical_registration_bytes(
            context_id=registration.context_id,
            owner_did=registration.owner_did,
            oracle_endpoints=endpoints_pairs,
            dim=registration.dim,
            nlist=registration.nlist,
            nonce=nonce,
            timestamp_ns=ts_ns,
        )
        sig = owner_identity.sign(canonical)

        body = {
            "context_id": registration.context_id,
            "owner_did": registration.owner_did,
            "oracle_endpoints": [
                {"url": e.url, "oracle_did": e.oracle_did}
                for e in registration.oracle_endpoints
            ],
            "dim": registration.dim,
            "nlist": registration.nlist,
            "nonce_b64": _b64(nonce),
            "timestamp_ns": ts_ns,
            "signature_b64": _b64(sig),
        }
        r = self._client.post("/contexts", json=body)
        r.raise_for_status()

        # Centroids upload — also signed with a fresh nonce.
        buf = io.BytesIO()
        np.save(buf, centroids.astype(np.float32), allow_pickle=False)
        centroids_blob = buf.getvalue()
        c_nonce = os.urandom(_NONCE_LEN)
        c_ts = time.time_ns()
        centroids_canonical = canonical_cell_upload_bytes(
            context_id=registration.context_id,
            cluster_id=-1,
            cell_blob=centroids_blob,
            nonce=c_nonce,
            timestamp_ns=c_ts,
        )
        centroids_sig = owner_identity.sign(centroids_canonical)
        r = self._client.put(
            f"/contexts/{registration.context_id}/centroids",
            content=centroids_blob,
            headers={
                "content-type": "application/octet-stream",
                "x-flare-signature": _b64(centroids_sig),
                "x-flare-owner-did": owner_identity.did,
                "x-flare-nonce": _b64(c_nonce),
                "x-flare-timestamp-ns": str(c_ts),
            },
        )
        r.raise_for_status()

    def put_cell(
        self,
        context_id: ContextId,
        cluster_id: int,
        blob: bytes,
        owner_identity: Identity,
    ) -> None:
        nonce = os.urandom(_NONCE_LEN)
        ts_ns = time.time_ns()
        canonical = canonical_cell_upload_bytes(
            context_id=context_id, cluster_id=cluster_id, cell_blob=blob,
            nonce=nonce, timestamp_ns=ts_ns,
        )
        sig = owner_identity.sign(canonical)
        r = self._client.post(
            f"/contexts/{context_id}/cells/{cluster_id}",
            content=blob,
            headers={
                "content-type": "application/octet-stream",
                "x-flare-signature": _b64(sig),
                "x-flare-owner-did": owner_identity.did,
                "x-flare-nonce": _b64(nonce),
                "x-flare-timestamp-ns": str(ts_ns),
            },
        )
        r.raise_for_status()

    # ----- reads (anonymous) -----

    def get_cell(self, context_id, cluster_id) -> bytes:
        r = self._client.get(f"/contexts/{context_id}/cells/{cluster_id}")
        r.raise_for_status()
        return r.content

    def get_centroids(self, context_id):
        r = self._client.get(f"/contexts/{context_id}/centroids")
        r.raise_for_status()
        return np.load(io.BytesIO(r.content), allow_pickle=False)

    def list_contexts(self):
        r = self._client.get("/contexts")
        r.raise_for_status()
        return [_registration_from_json(d) for d in r.json()]

    def get_registration(self, context_id):
        r = self._client.get(f"/contexts/{context_id}")
        r.raise_for_status()
        return _registration_from_json(r.json())


def _registration_from_json(d: dict) -> ContextRegistration:
    return ContextRegistration(
        context_id=d["context_id"],
        owner_did=d["owner_did"],
        oracle_endpoints=[
            OracleEndpoint(url=e["url"], oracle_did=e["oracle_did"])
            for e in d["oracle_endpoints"]
        ],
        dim=d["dim"],
        nlist=d["nlist"],
    )
