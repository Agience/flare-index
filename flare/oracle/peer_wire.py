"""Peer-to-peer wire protocol for threshold oracle share release.

When an oracle running in **threshold mode** receives a query batch
through `/issue-batch`, it acts as the coordinator: it needs K-1 more
shares from peer oracles before it can reconstruct the owner's
master key. Each peer call:

1. Carries an Ed25519 signature from the **coordinator's oracle
   identity** over a canonical encoding of `(coord_oracle_did,
   requester_did, [cells...], ephemeral X25519 pubkey, nonce, ts)`.
2. Carries the *original querier's* batch request bytes verbatim,
   so the peer can re-verify what the querier authorized.
3. Carries the original querier's signature so the peer can confirm
   the querier really did authorize this exact batch (and not a
   superset that the coordinator forged).

The peer:

1. Verifies the coordinator's signature against the coordinator
   oracle DID, which must be in the peer's allowlist.
2. Verifies the querier's original signature against the querier DID
   (`did:key` resolves locally).
3. Independently checks the ledger for each (ctx, cluster) and
   refuses to release its share if *any* cell in the batch is
   unauthorized. (A coordinator that wants to receive shares from
   different peers for different cells must batch only authorized
   cells.)
4. ECIES-encrypts its Shamir share to the coordinator's per-request
   ephemeral X25519 pubkey, with the canonical request bytes as AAD.
5. Signs the response with its own oracle Ed25519 identity.

The result: a peer's share is only released to the coordinator that
asked for it, only for the specific (requester, batch) tuple it
asked for, and only if the peer's *independent* ledger check passes.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel

from ..identity import Identity, verify_ed25519, x25519_keypair, x25519_pubkey_from_bytes
from ..wire import (
    BatchIssueKeyRequest,
    NonceCache,
    WireError,
    _b64,
    _b64d,
)
from ..wire import CLOCK_SKEW_NS, NONCE_BYTES, ECIES_KEY_BYTES, ECIES_NONCE_BYTES
from .threshold import SHARE_BYTES, Share

PEER_HKDF_INFO = b"flare/v3/peer-share-ecies"


def _len_prefix(parts: list[bytes]) -> bytes:
    out = bytearray()
    for p in parts:
        out += len(p).to_bytes(4, "big", signed=False)
        out += p
    return bytes(out)


def _canonical_peer_request_bytes(
    coord_did: str,
    original_request: BatchIssueKeyRequest,
    eph_pub: bytes,
    timestamp_ns: int,
    nonce: bytes,
) -> bytes:
    return _len_prefix([
        b"flare/v3/peer-share",
        coord_did.encode("utf-8"),
        original_request.canonical_bytes(),
        _b64d(original_request.signature_b64),
        eph_pub,
        timestamp_ns.to_bytes(8, "big", signed=False),
        nonce,
    ])


class PeerShareRequest(BaseModel):
    coord_oracle_did: str
    # The original querier's batch request, verbatim, including its
    # querier signature. The peer re-verifies this before releasing.
    original_request: dict
    # Coordinator-side per-request ephemeral X25519 pubkey for ECIES.
    eph_pub_b64: str
    timestamp_ns: int
    nonce_b64: str
    # Coordinator's Ed25519 signature over the canonical bytes.
    signature_b64: str

    def original(self) -> BatchIssueKeyRequest:
        return BatchIssueKeyRequest.model_validate(self.original_request)

    def canonical_bytes(self) -> bytes:
        return _canonical_peer_request_bytes(
            self.coord_oracle_did,
            self.original(),
            _b64d(self.eph_pub_b64),
            self.timestamp_ns,
            _b64d(self.nonce_b64),
        )


class PeerShareResponse(BaseModel):
    peer_oracle_did: str
    peer_eph_pub_b64: str
    nonce_b64: str
    ciphertext_b64: str       # AES-GCM(Share.x || Share.y_bytes)
    signature_b64: str        # Ed25519(peer_signing_key, canonical response bytes)

    def canonical_bytes(self, request_canonical: bytes) -> bytes:
        return _len_prefix([
            request_canonical,
            self.peer_oracle_did.encode("utf-8"),
            _b64d(self.peer_eph_pub_b64),
            _b64d(self.nonce_b64),
            _b64d(self.ciphertext_b64),
        ])


@dataclass
class CoordinatorMaterials:
    request: PeerShareRequest
    eph_priv: X25519PrivateKey


def build_peer_request(
    coord_identity: Identity,
    original_request: BatchIssueKeyRequest,
    *,
    now_ns: Optional[int] = None,
) -> CoordinatorMaterials:
    eph_priv, eph_pub = x25519_keypair()
    now_ns = now_ns if now_ns is not None else time.time_ns()
    nonce = os.urandom(NONCE_BYTES)
    canonical = _canonical_peer_request_bytes(
        coord_identity.did, original_request, eph_pub, now_ns, nonce,
    )
    sig = coord_identity.sign(canonical)
    req = PeerShareRequest(
        coord_oracle_did=coord_identity.did,
        original_request=original_request.model_dump(),
        eph_pub_b64=_b64(eph_pub),
        timestamp_ns=now_ns,
        nonce_b64=_b64(nonce),
        signature_b64=_b64(sig),
    )
    return CoordinatorMaterials(request=req, eph_priv=eph_priv)


def verify_peer_request(
    req: PeerShareRequest,
    *,
    allowed_coord_dids: set[str],
    nonce_cache: NonceCache,
    now_ns: Optional[int] = None,
) -> BatchIssueKeyRequest:
    """Verify a peer share request from a coordinator oracle.

    Raises `WireError` on any failure. Returns the inner querier
    request so the peer can run its own ledger checks against it.
    """
    now_ns = now_ns if now_ns is not None else time.time_ns()
    if req.coord_oracle_did not in allowed_coord_dids:
        raise WireError("coordinator DID not in peer allowlist")
    if abs(now_ns - req.timestamp_ns) > CLOCK_SKEW_NS:
        raise WireError("peer request timestamp outside skew window")
    nonce = _b64d(req.nonce_b64)
    if not nonce_cache.check_and_record(nonce, now_ns):
        raise WireError("peer nonce replay")
    sig = _b64d(req.signature_b64)
    if not verify_ed25519(req.coord_oracle_did, req.canonical_bytes(), sig):
        raise WireError("invalid coordinator signature")

    # Re-verify the querier's original signature so the coordinator
    # cannot forge a batch the querier never authorized.
    inner = req.original()
    inner_sig = _b64d(inner.signature_b64)
    if not verify_ed25519(inner.requester_did, inner.canonical_bytes(), inner_sig):
        raise WireError("invalid inner querier signature")
    if abs(now_ns - inner.timestamp_ns) > CLOCK_SKEW_NS:
        raise WireError("inner querier timestamp outside skew window")
    return inner


def _ecies_derive(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=ECIES_KEY_BYTES,
        salt=None,
        info=PEER_HKDF_INFO,
    ).derive(shared_secret)


def encrypt_and_sign_peer_response(
    req: PeerShareRequest,
    share: Share,
    peer_identity: Identity,
) -> PeerShareResponse:
    requester_eph_pub = x25519_pubkey_from_bytes(_b64d(req.eph_pub_b64))
    peer_eph_priv, peer_eph_pub = x25519_keypair()
    shared = peer_eph_priv.exchange(requester_eph_pub)
    sym = _ecies_derive(shared)
    nonce = os.urandom(ECIES_NONCE_BYTES)
    aad = req.canonical_bytes()
    payload = share.x.to_bytes(4, "big", signed=False) + share.y_bytes
    ct = AESGCM(sym).encrypt(nonce, payload, aad)

    response = PeerShareResponse(
        peer_oracle_did=peer_identity.did,
        peer_eph_pub_b64=_b64(peer_eph_pub),
        nonce_b64=_b64(nonce),
        ciphertext_b64=_b64(ct),
        signature_b64="",
    )
    response.signature_b64 = _b64(peer_identity.sign(response.canonical_bytes(aad)))
    return response


def verify_and_decrypt_peer_response(
    materials: CoordinatorMaterials,
    response: PeerShareResponse,
    expected_peer_did: str,
) -> Share:
    if response.peer_oracle_did != expected_peer_did:
        raise WireError(
            f"peer DID mismatch: expected {expected_peer_did}, got {response.peer_oracle_did}"
        )
    request_canonical = materials.request.canonical_bytes()
    canonical_resp = response.canonical_bytes(request_canonical)
    sig = _b64d(response.signature_b64)
    if not verify_ed25519(response.peer_oracle_did, canonical_resp, sig):
        raise WireError("invalid peer response signature")

    peer_eph_pub = x25519_pubkey_from_bytes(_b64d(response.peer_eph_pub_b64))
    shared = materials.eph_priv.exchange(peer_eph_pub)
    sym = _ecies_derive(shared)
    nonce = _b64d(response.nonce_b64)
    ct = _b64d(response.ciphertext_b64)
    payload = AESGCM(sym).decrypt(nonce, ct, request_canonical)
    if len(payload) != 4 + SHARE_BYTES:
        raise WireError(f"unexpected share payload length: {len(payload)}")
    x = int.from_bytes(payload[:4], "big", signed=False)
    y = payload[4:]
    return Share(x=x, y_bytes=y)
