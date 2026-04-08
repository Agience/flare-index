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

from typing import Optional, Protocol

import httpx

from ..identity import Identity
from ..types import ClusterId, ContextId
from ..wire import (
    BatchIssueKeyResponse,
    IssuedCellKey,
    WireError,
    build_batch_request,
    verify_and_decrypt_batch_response,
)


class OracleClient(Protocol):
    def request_cell_keys_batch(
        self,
        identity: Identity,
        expected_oracle_did: str,
        cells: list[tuple[ContextId, ClusterId]],
    ) -> list[Optional[IssuedCellKey]]: ...

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

    def info(self) -> dict:
        r = self._client.get("/info")
        r.raise_for_status()
        return r.json()
