"""Authenticated, confidential, end-to-end-bound wire protocol.

Three layered guarantees on top of (potentially plaintext) HTTP:

1. **Authentication + integrity of the request** via Ed25519 signing.
   The requester signs a canonical byte serialization of every wire
   field. The oracle resolves `requester_did` to an Ed25519 pubkey via
   the `did:key` method (no network round-trip), verifies the
   signature, enforces a clock skew window (±60s), and rejects nonces
   it has already seen in that window. Replay-resistant even on a
   non-TLS link.

2. **Confidentiality of the response cell keys** via ECIES on X25519.
   The requester generates a fresh X25519 keypair per request. The
   oracle generates its own ephemeral X25519 keypair, performs ECDH,
   derives a 32-byte symmetric key via HKDF-SHA256, and encrypts each
   cell key with AES-256-GCM. Only the requester can decrypt because
   only the requester holds the matching X25519 private key. Forward
   secret by construction: ephemeral keys are discarded per request.

3. **Origin authentication of the response** via Ed25519 signing by the
   oracle. The oracle signs a canonical byte serialization of the
   response (oracle_eph_pub, ciphertext blob, request canonical
   bytes). The requester knows the *expected* oracle DID from the
   context registration in storage and verifies the signature against
   that DID. A man-in-the-middle that substitutes a different oracle
   URL into the registration cannot forge a valid signature, so the
   requester detects the substitution and refuses the result.

The protocol supports a **batch form** so that all cells from one
context (or one owner) can be requested in a single signed envelope
and a single ECIES exchange — see `BatchIssueKeyRequest`. The
single-cell `IssueKeyRequest` is preserved for clarity in tests and
for the simplest possible code path; the batch form is the production
path used by the query engine.

Even if an attacker passively captures every byte of every oracle
exchange, they learn nothing about the cell keys; even if an attacker
substitutes the oracle URL in the context registration, they cannot
impersonate the owner-vouched oracle DID. TLS becomes a hardening
layer rather than the security boundary.

# ANALYSIS (phase1-findings.md §F-1.2 .. F-1.5):
# - Replay protection is in-memory and per-process. Restarting the
#   oracle clears the nonce cache, opening a small replay window. A
#   real deployment shares nonce state across oracle replicas via
#   Redis or similar; documented.
# - Clock skew is enforced as a wall-clock delta. NTP is assumed.
# - The signature does NOT cover a server identity, so a MitM that
#   substitutes a different oracle endpoint cannot be detected by the
#   request alone. Phase 2 binds the oracle endpoint into the signed
#   payload via the grant record (which carries the oracle DID).
# - Forward secrecy: the X25519 keypairs are ephemeral per request, so
#   compromise of either side's *long-term* key (Ed25519) does not
#   retroactively decrypt past responses. ECIES is forward-secret by
#   construction here.
"""
from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, Field

from .identity import (
    Identity,
    verify_ed25519,
    x25519_keypair,
    x25519_pubkey_from_bytes,
)
from .types import ClusterId, ContextId

CLOCK_SKEW_NS = 60 * 1_000_000_000  # ±60 seconds
NONCE_BYTES = 16
ECIES_KEY_BYTES = 32
ECIES_NONCE_BYTES = 12
ECIES_HKDF_INFO = b"flare/v1/oracle-ecies"


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _canonical_request_bytes(
    requester_did: str,
    context_id: str,
    cluster_id: int,
    eph_pub: bytes,
    timestamp_ns: int,
    nonce: bytes,
) -> bytes:
    # Length-prefixed concatenation; collision-free by construction.
    parts = [
        requester_did.encode("utf-8"),
        context_id.encode("utf-8"),
        cluster_id.to_bytes(8, "big", signed=False),
        eph_pub,
        timestamp_ns.to_bytes(8, "big", signed=False),
        nonce,
    ]
    out = bytearray()
    for p in parts:
        out += len(p).to_bytes(4, "big", signed=False)
        out += p
    return bytes(out)


# ----- Pydantic models on the wire -----


class IssueKeyRequest(BaseModel):
    requester_did: str
    context_id: str
    cluster_id: int
    eph_pub_b64: str           # requester's ephemeral X25519 pubkey
    timestamp_ns: int
    nonce_b64: str
    signature_b64: str         # Ed25519 over canonical bytes

    def canonical_bytes(self) -> bytes:
        return _canonical_request_bytes(
            self.requester_did,
            self.context_id,
            self.cluster_id,
            _b64d(self.eph_pub_b64),
            self.timestamp_ns,
            _b64d(self.nonce_b64),
        )


class IssueKeyResponse(BaseModel):
    oracle_eph_pub_b64: str    # oracle's ephemeral X25519 pubkey
    nonce_b64: str             # AES-GCM nonce
    ciphertext_b64: str        # AES-GCM(cell_key)


class IssueKeyDenied(BaseModel):
    reason: str


# ----- Builder + verifier helpers -----


@dataclass
class SignedRequestMaterials:
    """What the client needs to send AND what it must keep to decrypt."""
    request: IssueKeyRequest
    eph_priv: X25519PrivateKey


def build_request(
    identity: Identity,
    context_id: str,
    cluster_id: int,
    *,
    now_ns: Optional[int] = None,
) -> SignedRequestMaterials:
    eph_priv, eph_pub = x25519_keypair()
    now_ns = now_ns if now_ns is not None else time.time_ns()
    nonce = os.urandom(NONCE_BYTES)
    canonical = _canonical_request_bytes(
        identity.did, context_id, cluster_id, eph_pub, now_ns, nonce
    )
    sig = identity.sign(canonical)
    req = IssueKeyRequest(
        requester_did=identity.did,
        context_id=context_id,
        cluster_id=cluster_id,
        eph_pub_b64=_b64(eph_pub),
        timestamp_ns=now_ns,
        nonce_b64=_b64(nonce),
        signature_b64=_b64(sig),
    )
    return SignedRequestMaterials(request=req, eph_priv=eph_priv)


class WireError(Exception):
    pass


class NonceCache:
    """Bounded LRU of recently-seen nonces for replay protection.

    Per oracle process. See F-1.2 in phase1-findings.md for the
    cross-replica gap and the in-process restart gap.
    """

    def __init__(self, max_entries: int = 100_000) -> None:
        self._seen: dict[bytes, int] = {}
        self._max = max_entries

    def check_and_record(self, nonce: bytes, now_ns: int) -> bool:
        # Garbage collect anything outside the skew window.
        if len(self._seen) > self._max:
            cutoff = now_ns - CLOCK_SKEW_NS
            self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}
        if nonce in self._seen:
            return False
        self._seen[nonce] = now_ns
        return True


def verify_request(
    req: IssueKeyRequest,
    nonce_cache: NonceCache,
    *,
    now_ns: Optional[int] = None,
) -> None:
    """Raise WireError on any auth/replay/integrity failure."""
    now_ns = now_ns if now_ns is not None else time.time_ns()
    if abs(now_ns - req.timestamp_ns) > CLOCK_SKEW_NS:
        raise WireError("timestamp outside skew window")
    nonce = _b64d(req.nonce_b64)
    if len(nonce) != NONCE_BYTES:
        raise WireError("bad nonce length")
    if not nonce_cache.check_and_record(nonce, now_ns):
        raise WireError("nonce replay detected")
    sig = _b64d(req.signature_b64)
    if not verify_ed25519(req.requester_did, req.canonical_bytes(), sig):
        raise WireError("invalid signature")


# ----- ECIES on the response -----


def _ecies_derive_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=ECIES_KEY_BYTES,
        salt=None,
        info=ECIES_HKDF_INFO,
    ).derive(shared_secret)


def encrypt_response(req: IssueKeyRequest, cell_key: bytes) -> IssueKeyResponse:
    requester_eph_pub = x25519_pubkey_from_bytes(_b64d(req.eph_pub_b64))
    oracle_eph_priv, oracle_eph_pub = x25519_keypair()
    shared = oracle_eph_priv.exchange(requester_eph_pub)
    sym = _ecies_derive_key(shared)
    nonce = os.urandom(ECIES_NONCE_BYTES)
    # AAD binds the encrypted cell key to the (requester, context, cluster)
    # tuple, so the response cannot be replayed against a different request.
    aad = req.canonical_bytes()
    ct = AESGCM(sym).encrypt(nonce, cell_key, aad)
    return IssueKeyResponse(
        oracle_eph_pub_b64=_b64(oracle_eph_pub),
        nonce_b64=_b64(nonce),
        ciphertext_b64=_b64(ct),
    )


def decrypt_response(
    materials: SignedRequestMaterials, response: IssueKeyResponse
) -> bytes:
    oracle_eph_pub = x25519_pubkey_from_bytes(_b64d(response.oracle_eph_pub_b64))
    shared = materials.eph_priv.exchange(oracle_eph_pub)
    sym = _ecies_derive_key(shared)
    nonce = _b64d(response.nonce_b64)
    ct = _b64d(response.ciphertext_b64)
    aad = materials.request.canonical_bytes()
    return AESGCM(sym).decrypt(nonce, ct, aad)


# =====================================================================
# Batch issue protocol (production path used by FlareQueryEngine)
# =====================================================================


def _canonical_batch_request_bytes(
    requester_did: str,
    cells: list[tuple[ContextId, ClusterId]],
    eph_pub: bytes,
    timestamp_ns: int,
    nonce: bytes,
) -> bytes:
    parts: list[bytes] = [
        requester_did.encode("utf-8"),
        len(cells).to_bytes(4, "big", signed=False),
    ]
    for ctx, cluster in cells:
        parts.append(ctx.encode("utf-8"))
        parts.append(cluster.to_bytes(8, "big", signed=False))
    parts.extend(
        [
            eph_pub,
            timestamp_ns.to_bytes(8, "big", signed=False),
            nonce,
        ]
    )
    out = bytearray()
    for p in parts:
        out += len(p).to_bytes(4, "big", signed=False)
        out += p
    return bytes(out)


class BatchCellRef(BaseModel):
    context_id: str
    cluster_id: int


class BatchIssueKeyRequest(BaseModel):
    requester_did: str
    cells: list[BatchCellRef]
    eph_pub_b64: str
    timestamp_ns: int
    nonce_b64: str
    signature_b64: str

    def canonical_bytes(self) -> bytes:
        return _canonical_batch_request_bytes(
            self.requester_did,
            [(c.context_id, c.cluster_id) for c in self.cells],
            _b64d(self.eph_pub_b64),
            self.timestamp_ns,
            _b64d(self.nonce_b64),
        )


class BatchEntry(BaseModel):
    """One entry per requested cell, in the same order as the request.

    For granted entries:
        nonce_b64, ciphertext_b64, valid_until_ns are set.
    For denied entries:
        denied_reason is set (everything else is None).

    `valid_until_ns` is the wall-clock instant after which the cell key
    inside `ciphertext_b64` is no longer valid. The query node MUST
    drop the key after that instant. The TTL is the oracle's bound on
    how long an issued key remains useful, and is the cryptographic
    backbone of revocation: a request signed before a revoke at time
    `t_r` can still be served, but the cell key it carries expires
    `valid_until_ns - issued_at` seconds later, bounding the window
    during which a leaked-and-still-fresh key can be exploited.
    """
    granted: bool
    nonce_b64: Optional[str] = None
    ciphertext_b64: Optional[str] = None
    valid_until_ns: Optional[int] = None
    denied_reason: Optional[str] = None


class BatchIssueKeyResponse(BaseModel):
    oracle_did: str            # who is claiming to be the oracle
    oracle_eph_pub_b64: str    # ECIES X25519 ephemeral pubkey
    entries: list[BatchEntry]  # parallel to request.cells
    signature_b64: str         # Ed25519(oracle_signing_key, canonical_response_bytes)

    def canonical_bytes(self, request_canonical: bytes) -> bytes:
        """Bytes the oracle signs.

        Binds (a) the originating request, (b) the oracle's claimed
        DID, (c) the ECIES ephemeral pubkey, (d) every per-cell
        nonce/ciphertext + valid_until_ns, or (e) the denial reason.
        A MitM that swaps any of these fields — including the TTL —
        breaks the signature.
        """
        parts: list[bytes] = [
            request_canonical,
            self.oracle_did.encode("utf-8"),
            _b64d(self.oracle_eph_pub_b64),
            len(self.entries).to_bytes(4, "big", signed=False),
        ]
        for e in self.entries:
            parts.append(b"\x01" if e.granted else b"\x00")
            if e.granted:
                parts.append(_b64d(e.nonce_b64 or ""))
                parts.append(_b64d(e.ciphertext_b64 or ""))
                parts.append((e.valid_until_ns or 0).to_bytes(8, "big", signed=False))
            else:
                parts.append((e.denied_reason or "").encode("utf-8"))
        out = bytearray()
        for p in parts:
            out += len(p).to_bytes(4, "big", signed=False)
            out += p
        return bytes(out)


@dataclass
class SignedBatchRequestMaterials:
    request: BatchIssueKeyRequest
    eph_priv: X25519PrivateKey


def build_batch_request(
    identity: Identity,
    cells: list[tuple[ContextId, ClusterId]],
    *,
    now_ns: Optional[int] = None,
) -> SignedBatchRequestMaterials:
    eph_priv, eph_pub = x25519_keypair()
    now_ns = now_ns if now_ns is not None else time.time_ns()
    nonce = os.urandom(NONCE_BYTES)
    canonical = _canonical_batch_request_bytes(
        identity.did, cells, eph_pub, now_ns, nonce
    )
    sig = identity.sign(canonical)
    req = BatchIssueKeyRequest(
        requester_did=identity.did,
        cells=[BatchCellRef(context_id=c, cluster_id=k) for c, k in cells],
        eph_pub_b64=_b64(eph_pub),
        timestamp_ns=now_ns,
        nonce_b64=_b64(nonce),
        signature_b64=_b64(sig),
    )
    return SignedBatchRequestMaterials(request=req, eph_priv=eph_priv)


def verify_batch_request(
    req: BatchIssueKeyRequest,
    nonce_cache: NonceCache,
    *,
    now_ns: Optional[int] = None,
) -> None:
    now_ns = now_ns if now_ns is not None else time.time_ns()
    if abs(now_ns - req.timestamp_ns) > CLOCK_SKEW_NS:
        raise WireError("timestamp outside skew window")
    if not req.cells:
        raise WireError("empty batch")
    nonce = _b64d(req.nonce_b64)
    if len(nonce) != NONCE_BYTES:
        raise WireError("bad nonce length")
    if not nonce_cache.check_and_record(nonce, now_ns):
        raise WireError("nonce replay detected")
    sig = _b64d(req.signature_b64)
    if not verify_ed25519(req.requester_did, req.canonical_bytes(), sig):
        raise WireError("invalid signature")


def encrypt_and_sign_batch_response(
    req: BatchIssueKeyRequest,
    cell_keys: list[Optional[bytes]],   # None entries -> denied
    denied_reasons: list[Optional[str]],
    oracle_identity: Identity,
    *,
    cell_key_ttl_ns: int = 60 * 1_000_000_000,  # 60 seconds default
    issued_at_ns: Optional[int] = None,
) -> BatchIssueKeyResponse:
    if len(cell_keys) != len(req.cells) or len(denied_reasons) != len(req.cells):
        raise ValueError("cell_keys / denied_reasons must align with request.cells")

    requester_eph_pub = x25519_pubkey_from_bytes(_b64d(req.eph_pub_b64))
    oracle_eph_priv, oracle_eph_pub = x25519_keypair()
    shared = oracle_eph_priv.exchange(requester_eph_pub)
    sym = _ecies_derive_key(shared)
    request_canonical = req.canonical_bytes()
    issued_at_ns = issued_at_ns if issued_at_ns is not None else time.time_ns()
    valid_until_ns = issued_at_ns + cell_key_ttl_ns

    entries: list[BatchEntry] = []
    aesgcm = AESGCM(sym)
    for idx, key in enumerate(cell_keys):
        if key is None:
            entries.append(BatchEntry(
                granted=False, denied_reason=denied_reasons[idx] or "denied",
            ))
            continue
        nonce = os.urandom(ECIES_NONCE_BYTES)
        # Per-entry AAD binds each ciphertext to the request AND the index
        # within the batch, so an attacker cannot reorder or duplicate
        # entries without breaking GCM.
        aad = request_canonical + idx.to_bytes(4, "big", signed=False)
        ct = aesgcm.encrypt(nonce, key, aad)
        entries.append(BatchEntry(
            granted=True,
            nonce_b64=_b64(nonce),
            ciphertext_b64=_b64(ct),
            valid_until_ns=valid_until_ns,
        ))

    response = BatchIssueKeyResponse(
        oracle_did=oracle_identity.did,
        oracle_eph_pub_b64=_b64(oracle_eph_pub),
        entries=entries,
        signature_b64="",  # placeholder; signed below
    )
    canonical_resp = response.canonical_bytes(request_canonical)
    response.signature_b64 = _b64(oracle_identity.sign(canonical_resp))
    return response


@dataclass
class IssuedCellKey:
    """A cell key the oracle issued, with its expiry."""
    key: bytes
    valid_until_ns: int

    def is_valid_at(self, now_ns: int) -> bool:
        return now_ns < self.valid_until_ns


def verify_and_decrypt_batch_response(
    materials: SignedBatchRequestMaterials,
    response: BatchIssueKeyResponse,
    expected_oracle_did: str,
    *,
    now_ns: Optional[int] = None,
) -> list[Optional[IssuedCellKey]]:
    """Verify the oracle's signature and ECIES-decrypt every granted cell key.

    Returns a list of `IssuedCellKey` (or None for denied) parallel to
    the request's cell list. Keys whose `valid_until_ns` has already
    passed are returned as None — the query node MUST NOT use an
    expired key, even one that decrypts successfully.

    Raises WireError if:
    - the response oracle_did does not match the expected one
    - the oracle's Ed25519 signature does not verify
    - any granted entry fails AES-GCM decryption (tampered ciphertext)
    """
    if response.oracle_did != expected_oracle_did:
        raise WireError(
            f"oracle DID mismatch: expected {expected_oracle_did}, got {response.oracle_did}"
        )
    request_canonical = materials.request.canonical_bytes()
    canonical_resp = response.canonical_bytes(request_canonical)
    sig = _b64d(response.signature_b64)
    if not verify_ed25519(response.oracle_did, canonical_resp, sig):
        raise WireError("invalid oracle response signature")

    oracle_eph_pub = x25519_pubkey_from_bytes(_b64d(response.oracle_eph_pub_b64))
    shared = materials.eph_priv.exchange(oracle_eph_pub)
    sym = _ecies_derive_key(shared)
    aesgcm = AESGCM(sym)
    now_ns = now_ns if now_ns is not None else time.time_ns()

    out: list[Optional[IssuedCellKey]] = []
    for idx, entry in enumerate(response.entries):
        if not entry.granted:
            out.append(None)
            continue
        nonce = _b64d(entry.nonce_b64 or "")
        ct = _b64d(entry.ciphertext_b64 or "")
        aad = request_canonical + idx.to_bytes(4, "big", signed=False)
        try:
            key = aesgcm.decrypt(nonce, ct, aad)
        except Exception as e:
            raise WireError(f"cell ciphertext failed AES-GCM at index {idx}: {e}")
        valid_until = entry.valid_until_ns or 0
        if valid_until == 0 or now_ns >= valid_until:
            # Expired before we could even decode it. Drop it.
            out.append(None)
            continue
        out.append(IssuedCellKey(key=key, valid_until_ns=valid_until))
    return out
