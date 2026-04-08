"""Peer-to-peer share-fetching client for threshold-mode oracles.

A coordinator oracle uses `PeerShareFetcher` to gather K-1 Shamir
shares from peer oracles. Fetches run in parallel via a thread pool.
The fetcher accepts an arbitrary `BatchIssueKeyRequest` (the inner
querier batch the coordinator received) and returns a list of
`Share` objects (one per cooperating peer).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Optional

import httpx

from ..identity import Identity
from ..wire import BatchIssueKeyRequest
from .peer_wire import (
    PeerShareResponse,
    build_peer_request,
    verify_and_decrypt_peer_response,
)
from .threshold import Share


@dataclass
class PeerEndpoint:
    """A peer oracle the coordinator can ask for a share."""
    oracle_did: str
    base_url: str = ""
    client: Optional[object] = None  # httpx.Client or starlette TestClient

    def http_client(self):
        if self.client is not None:
            return self.client
        return httpx.Client(base_url=self.base_url, timeout=10.0)


class PeerShareFetcher:
    """Coordinator-side helper that gathers K-1 shares from peers.

    Constructed with the coordinator's own oracle `Identity`, the
    list of peer endpoints, and how many additional shares are
    needed (i.e. K-1). Fetches happen in parallel and the first
    `needed` cooperating peers win.
    """

    def __init__(
        self,
        coord_identity: Identity,
        peers: list[PeerEndpoint],
        needed: int,
        *,
        max_workers: Optional[int] = None,
    ) -> None:
        self.coord_identity = coord_identity
        self.peers = peers
        self.needed = needed
        self.max_workers = max_workers or max(2, len(peers))

    def __call__(self, original_request: BatchIssueKeyRequest) -> list[Share]:
        if self.needed <= 0:
            return []
        materials = build_peer_request(self.coord_identity, original_request)
        body = materials.request.model_dump()

        def _ask(peer: PeerEndpoint) -> Optional[Share]:
            try:
                client = peer.http_client()
                r = client.post("/peer/share", json=body)
                if r.status_code != 200:
                    return None
                response = PeerShareResponse.model_validate(r.json())
                return verify_and_decrypt_peer_response(materials, response, peer.oracle_did)
            except Exception:
                return None

        collected: list[Share] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(_ask, p): p for p in self.peers}
            for fut in as_completed(futures):
                share = fut.result()
                if share is not None:
                    collected.append(share)
                    if len(collected) >= self.needed:
                        break
        return collected
