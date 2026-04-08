"""Owner signatures for storage writes.

Every write to the storage service carries an Ed25519 signature from
the owner DID associated with the context, plus a nonce + timestamp
that bind the signature to a single fresh write. The storage service
resolves the owner DID locally (multi-method DID resolution; see
`flare/identity.py`), verifies the signature, enforces a clock-skew
window on the timestamp, and rejects nonces it has already seen
within that window.

Two write operations are signed:

1. **Context registration.** The owner signs the canonical encoding
   of `(context_id, owner_did, oracle_endpoint, oracle_did, dim,
   nlist, nonce, timestamp_ns)`.

2. **Cell upload.** The owner signs `(context_id, cluster_id,
   sha256(cell_blob), nonce, timestamp_ns)`. The hash binds the
   signature to the exact ciphertext bytes; the nonce + timestamp
   prevent an attacker who captured a valid upload from replaying it
   verbatim against the same `(context, cluster)`.

Storage maintains a per-owner-DID nonce cache mirroring the oracle's
replay protection in `flare/wire.py`.
"""
from __future__ import annotations

import hashlib

from ..types import ClusterId, ContextId, PrincipalId

# Storage write skew window (±5 minutes — bootstrap can take a while
# and clock drift across containers is real).
STORAGE_SKEW_NS = 5 * 60 * 1_000_000_000


def _len_prefix(parts: list[bytes]) -> bytes:
    out = bytearray()
    for p in parts:
        out += len(p).to_bytes(4, "big", signed=False)
        out += p
    return bytes(out)


def canonical_registration_bytes(
    *,
    context_id: ContextId,
    owner_did: PrincipalId,
    oracle_endpoints: list[tuple[str, PrincipalId]],
    dim: int,
    nlist: int,
    nonce: bytes,
    timestamp_ns: int,
) -> bytes:
    # The list of oracle endpoints is owner-signed, so the query node
    # can trust both the URLs AND the DIDs it will see in storage.
    # Length-prefix every (url, did) pair so the encoding is collision-free.
    parts: list[bytes] = [
        b"flare/v4/register",
        context_id.encode("utf-8"),
        owner_did.encode("utf-8"),
        len(oracle_endpoints).to_bytes(4, "big", signed=False),
    ]
    for url, did in oracle_endpoints:
        parts.append(url.encode("utf-8"))
        parts.append(did.encode("utf-8"))
    parts.extend([
        dim.to_bytes(4, "big", signed=False),
        nlist.to_bytes(4, "big", signed=False),
        nonce,
        timestamp_ns.to_bytes(8, "big", signed=False),
    ])
    return _len_prefix(parts)


def canonical_cell_upload_bytes(
    *,
    context_id: ContextId,
    cluster_id: ClusterId,
    cell_blob: bytes,
    nonce: bytes,
    timestamp_ns: int,
) -> bytes:
    digest = hashlib.sha256(cell_blob).digest()
    return _len_prefix([
        b"flare/v3/cell",
        context_id.encode("utf-8"),
        # Signed encoding: -1 is used as a sentinel for "centroids
        # blob" (cluster_ids are >= 0 for normal cells).
        cluster_id.to_bytes(8, "big", signed=True),
        digest,
        nonce,
        timestamp_ns.to_bytes(8, "big", signed=False),
    ])


class StorageNonceCache:
    """Per-DID bounded LRU of recently-seen storage write nonces."""

    def __init__(self, max_per_did: int = 10_000) -> None:
        self._seen: dict[str, dict[bytes, int]] = {}
        self._max = max_per_did

    def check_and_record(self, owner_did: str, nonce: bytes, now_ns: int) -> bool:
        bucket = self._seen.setdefault(owner_did, {})
        if len(bucket) > self._max:
            cutoff = now_ns - STORAGE_SKEW_NS
            self._seen[owner_did] = {
                k: v for k, v in bucket.items() if v >= cutoff
            }
            bucket = self._seen[owner_did]
        if nonce in bucket:
            return False
        bucket[nonce] = now_ns
        return True

