"""Oracle core: master key + ledger lookup + cell key derivation.

Two modes:

- **Single-replica.** The core holds the full master key. `decide_batch`
  is local: ledger lookup + HKDF + return.
- **Threshold (Shamir K-of-M).** The core holds one Shamir share, a
  list of peer endpoints, and a quorum K. `decide_batch` collects K-1
  more shares from peers (in parallel), reconstructs the master key
  in memory, derives the cell keys, then drops both the master key
  and the peer shares before returning. The threshold property:
  K-1 compromised oracle hosts cannot reconstruct the master key;
  K compromised hosts can.

The core knows nothing about HTTP, signing, or transport. The wrapping
service supplies the wire-layer authentication, ECIES, and response
signing. Peer share fetching uses an injected `PeerShareFetcher`
callable so the core remains transport-agnostic and testable.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Callable, Optional

from ..crypto import derive_cell_key
from ..ledger.client import GrantLedgerClient
from ..sealed import SecureBytes
from ..types import ClusterId, ContextId, PrincipalId
from .threshold import Share, reconstruct_secret


class OracleDecision(str, Enum):
    OWNER = "owner"
    GRANTED = "granted"
    DENIED_NO_GRANT = "denied_no_grant"
    DENIED_REVOKED = "denied_revoked"
    DENIED_THRESHOLD = "denied_threshold"  # peer quorum could not be reached


@dataclass
class OracleResult:
    decision: OracleDecision
    cell_key: Optional[bytes]


# A `PeerShareFetcher` returns a list of (peer_did, Share) pairs from
# K-1 cooperating peers, given the original querier batch request bytes
# already authorized by the coordinator. Implementations may dispatch
# in parallel; if fewer than K-1 peers cooperate, the coordinator
# returns an empty list and the core records DENIED_THRESHOLD for the
# whole batch.
PeerShareFetcher = Callable[[object], list[Share]]


class OracleCore:
    def __init__(
        self,
        owner: PrincipalId,
        ledger: GrantLedgerClient,
        *,
        master_key: Optional[bytes] = None,
        share: Optional[Share] = None,
        threshold_k: Optional[int] = None,
        peer_share_fetcher: Optional[PeerShareFetcher] = None,
    ) -> None:
        if master_key is not None and share is not None:
            raise ValueError("OracleCore is either single-replica OR threshold, not both")
        if master_key is None and share is None:
            raise ValueError("OracleCore needs either master_key or share")
        if share is not None:
            if threshold_k is None or threshold_k < 1:
                raise ValueError("threshold mode requires threshold_k >= 1")
            # Note: peer_share_fetcher may be None at construction time
            # and patched in later (the in-process test fixture builds
            # all replicas first, then wires fetchers between them).
            # `decide_batch` enforces "no fetcher when needed" at call
            # time by reporting DENIED_THRESHOLD.

        self.owner = owner
        self._ledger = ledger
        self._master_key = master_key
        self._share = share
        self._threshold_k = threshold_k
        self._peer_share_fetcher = peer_share_fetcher
        self.issued_count = 0
        self.denied_count = 0

    @property
    def is_threshold(self) -> bool:
        return self._share is not None

    # ----- single-cell decide (kept for tests; production goes through decide_batch) -----

    def decide(
        self,
        requester: PrincipalId,
        context_id: ContextId,
        cluster_id: ClusterId,
        now: datetime,
    ) -> OracleResult:
        results = self.decide_batch(
            requester=requester,
            cells=[(context_id, cluster_id)],
            now=now,
        )
        return results[0]

    # ----- batch decide -----

    def decide_batch(
        self,
        requester: PrincipalId,
        cells: list[tuple[ContextId, ClusterId]],
        now: datetime,
        *,
        original_request: Optional[object] = None,
    ) -> list[OracleResult]:
        # Stage A: per-cell ledger authorization. Multiple cells in
        # the same context map to the same `find_valid` lookup, so
        # we dedupe by (grantor, requester, context) — the lookup is
        # cell-independent. For a batch of nprobe cells that all hit
        # the same context this turns N ledger calls into 1.
        decisions: list[OracleDecision] = []
        ledger_cache: dict[ContextId, OracleDecision] = {}
        for ctx, _cluster in cells:
            if requester == self.owner:
                decisions.append(OracleDecision.OWNER)
                continue
            cached = ledger_cache.get(ctx)
            if cached is not None:
                decisions.append(cached)
                continue
            grant = self._ledger.find_valid(self.owner, requester, ctx, now)
            decision = OracleDecision.GRANTED if grant is not None else OracleDecision.DENIED_NO_GRANT
            ledger_cache[ctx] = decision
            decisions.append(decision)

        # Stage B: get the master key. In single mode, it's already in
        # hand. In threshold mode, ask K-1 peers for their shares,
        # combine with our own, reconstruct.
        if not any(d in (OracleDecision.OWNER, OracleDecision.GRANTED) for d in decisions):
            # No authorized cells -> no point asking peers.
            self.denied_count += len(cells)
            return [OracleResult(d, None) for d in decisions]

        # Phase 4: in threshold mode the reconstructed master key
        # lives in a SecureBytes wrapper that is explicitly zeroized
        # in the finally block. In single-replica mode the master key
        # is the long-lived one held by the core (no zeroization).
        reconstructed: Optional[SecureBytes] = None
        master_key_view: Optional[bytes] = None
        threshold_failed = False
        try:
            if self._master_key is not None:
                master_key_view = self._master_key
            else:
                assert self._share is not None and self._threshold_k is not None
                shares: list[Share] = [self._share]
                if self._threshold_k > 1:
                    if self._peer_share_fetcher is None or original_request is None:
                        threshold_failed = True
                    else:
                        try:
                            peer_shares = self._peer_share_fetcher(original_request)
                        except Exception:
                            peer_shares = []
                        shares.extend(peer_shares)
                if len(shares) < (self._threshold_k or 1):
                    threshold_failed = True
                else:
                    reconstructed = SecureBytes(reconstruct_secret(shares[: self._threshold_k]))
                    master_key_view = reconstructed.view()

            results: list[OracleResult] = []
            for (ctx, cluster), decision in zip(cells, decisions):
                if decision in (OracleDecision.OWNER, OracleDecision.GRANTED) and not threshold_failed:
                    assert master_key_view is not None
                    self.issued_count += 1
                    key = derive_cell_key(master_key_view, ctx, cluster)
                    results.append(OracleResult(decision, key))
                elif threshold_failed and decision in (
                    OracleDecision.OWNER, OracleDecision.GRANTED
                ):
                    self.denied_count += 1
                    results.append(OracleResult(OracleDecision.DENIED_THRESHOLD, None))
                else:
                    self.denied_count += 1
                    results.append(OracleResult(decision, None))
            return results
        finally:
            # Zero the reconstructed master key buffer. The view() copy
            # we passed to derive_cell_key cannot be wiped (CPython bytes
            # are immutable), but the canonical reconstruction buffer
            # IS zeroized — that's the buffer most likely to survive
            # in heap snapshots and core dumps.
            if reconstructed is not None:
                reconstructed.clear()
            master_key_view = None
