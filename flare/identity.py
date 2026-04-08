"""Decentralized identity for FLARE.

Two DID methods are supported:

- **`did:key`** (W3C). Self-resolving. Format:
    `did:key:z<multibase-base58btc(multicodec(ed25519-pub) || pubkey)>`
  The multicodec varint for ed25519-pub is `0xed 0x01`. Multibase
  prefix `z` indicates base58btc (Bitcoin alphabet). The DID encodes
  the public key in itself, so resolution is local — no network call.

- **`did:web`** (W3C). Hosted at a known HTTPS URL derived from the
  DID, e.g. `did:web:example.com:users:alice` resolves to
  `https://example.com/users/alice/did.json`. The document contains a
  `verificationMethod` array; FLARE picks the first Ed25519 key. The
  resolver caches the document for `DID_WEB_CACHE_TTL_S` seconds.

Resolution goes through a `DIDResolver` instance. The default resolver
accepts both methods; test code can inject a mock resolver. The
package-level `verify_ed25519` function uses a default resolver and
short-cuts `did:key` so tests and oracle services that never see
`did:web` pay no network cost.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

# Multicodec varint prefixes (https://github.com/multiformats/multicodec)
MULTICODEC_ED25519_PUB = b"\xed\x01"
MULTICODEC_X25519_PUB = b"\xec\x01"

_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58btc_encode(data: bytes) -> str:
    # Count leading zeros (encoded as '1' in base58btc)
    n_leading_zeros = 0
    for b in data:
        if b == 0:
            n_leading_zeros += 1
        else:
            break
    num = int.from_bytes(data, "big")
    out = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(_BASE58_ALPHABET[rem])
    out.extend(b"1" * n_leading_zeros)
    out.reverse()
    return out.decode("ascii")


def base58btc_decode(s: str) -> bytes:
    n_leading_ones = 0
    for ch in s:
        if ch == "1":
            n_leading_ones += 1
        else:
            break
    num = 0
    for ch in s:
        idx = _BASE58_ALPHABET.find(ch.encode("ascii"))
        if idx < 0:
            raise ValueError(f"invalid base58 character: {ch!r}")
        num = num * 58 + idx
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\x00" * n_leading_ones + body


def did_key_from_ed25519_pubkey(pubkey: Ed25519PublicKey) -> str:
    raw = pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "did:key:z" + base58btc_encode(MULTICODEC_ED25519_PUB + raw)


def ed25519_pubkey_from_did(did: str) -> Ed25519PublicKey:
    if not did.startswith("did:key:z"):
        raise ValueError(f"unsupported DID method: {did!r} (only did:key with multibase 'z')")
    multibase_payload = did[len("did:key:z"):]
    decoded = base58btc_decode(multibase_payload)
    if not decoded.startswith(MULTICODEC_ED25519_PUB):
        raise ValueError(f"DID does not encode an Ed25519 key: {did!r}")
    raw = decoded[len(MULTICODEC_ED25519_PUB):]
    if len(raw) != 32:
        raise ValueError(f"unexpected Ed25519 key length: {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


@dataclass
class Identity:
    """A complete identity: signing keypair (Ed25519) + DID."""
    did: str
    _signing_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "Identity":
        sk = Ed25519PrivateKey.generate()
        did = did_key_from_ed25519_pubkey(sk.public_key())
        return cls(did=did, _signing_key=sk)

    @classmethod
    def from_seed_hex(cls, seed_hex: str) -> "Identity":
        """Load an identity from a 32-byte raw Ed25519 seed (hex).

        Used by services that load their long-term identity from
        sealed/sealed-ish storage at startup. The Phase 2 compose
        stack reads these from /secrets/phase2.env.
        """
        raw = bytes.fromhex(seed_hex)
        if len(raw) != 32:
            raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(raw)}")
        sk = Ed25519PrivateKey.from_private_bytes(raw)
        did = did_key_from_ed25519_pubkey(sk.public_key())
        return cls(did=did, _signing_key=sk)

    def sign(self, message: bytes) -> bytes:
        return self._signing_key.sign(message)

    def public_key(self) -> Ed25519PublicKey:
        return self._signing_key.public_key()


def verify_ed25519(did: str, message: bytes, signature: bytes) -> bool:
    pub = _default_resolver().resolve(did)
    try:
        pub.verify(signature, message)
        return True
    except InvalidSignature:
        return False


# ----- DID resolution -----

import time as _time  # noqa: E402


DID_WEB_CACHE_TTL_S = 300  # cache did:web documents for 5 minutes


class DIDResolver:
    """Resolves a DID to an Ed25519 public key.

    Supports `did:key` (local) and `did:web` (HTTPS fetch with cache).
    A resolver can be sub-classed or constructed with a custom HTTP
    client (e.g. for tests / for a custom certificate trust store).
    """

    def __init__(self, http_client=None) -> None:
        # http_client is duck-typed: anything with .get(url) returning
        # something with .json() and .raise_for_status(). Defaults to
        # an httpx.Client created lazily on first did:web call.
        self._http = http_client
        self._cache: dict[str, tuple[float, Ed25519PublicKey]] = {}

    def resolve(self, did: str) -> Ed25519PublicKey:
        if did.startswith("did:key:"):
            return ed25519_pubkey_from_did(did)
        if did.startswith("did:web:"):
            return self._resolve_did_web(did)
        raise ValueError(f"unsupported DID method: {did!r}")

    def _resolve_did_web(self, did: str) -> Ed25519PublicKey:
        cached = self._cache.get(did)
        now = _time.time()
        if cached is not None and (now - cached[0]) < DID_WEB_CACHE_TTL_S:
            return cached[1]

        url = self._did_web_to_url(did)
        if self._http is None:
            import httpx  # type: ignore
            self._http = httpx.Client(timeout=5.0)
        r = self._http.get(url)
        r.raise_for_status()
        doc = r.json()
        pub = self._extract_ed25519_from_did_doc(doc, did)
        self._cache[did] = (now, pub)
        return pub

    @staticmethod
    def _did_web_to_url(did: str) -> str:
        # did:web:example.com           -> https://example.com/.well-known/did.json
        # did:web:example.com:foo:bar   -> https://example.com/foo/bar/did.json
        rest = did[len("did:web:"):]
        # Per spec, percent-decoding is required. Skipping for the
        # prototype since none of our DIDs need it.
        parts = rest.split(":")
        host = parts[0]
        path_parts = parts[1:]
        if path_parts:
            return f"https://{host}/{'/'.join(path_parts)}/did.json"
        return f"https://{host}/.well-known/did.json"

    @staticmethod
    def _extract_ed25519_from_did_doc(doc: dict, did: str) -> Ed25519PublicKey:
        vms = doc.get("verificationMethod", [])
        for vm in vms:
            if vm.get("type") not in (
                "Ed25519VerificationKey2018",
                "Ed25519VerificationKey2020",
                "JsonWebKey2020",
            ):
                continue
            # Two common encodings:
            # 1. publicKeyMultibase: z<base58btc(raw_pubkey)>
            # 2. publicKeyBase58:    base58btc(raw_pubkey)
            mb = vm.get("publicKeyMultibase")
            if mb and mb.startswith("z"):
                raw = base58btc_decode(mb[1:])
                # Some encodings include the multicodec prefix (0xed 0x01),
                # others don't. Strip it if present.
                if raw.startswith(MULTICODEC_ED25519_PUB):
                    raw = raw[len(MULTICODEC_ED25519_PUB):]
                if len(raw) == 32:
                    return Ed25519PublicKey.from_public_bytes(raw)
            b58 = vm.get("publicKeyBase58")
            if b58:
                raw = base58btc_decode(b58)
                if len(raw) == 32:
                    return Ed25519PublicKey.from_public_bytes(raw)
        raise ValueError(f"no usable Ed25519 verification method in DID doc for {did}")


_DEFAULT_RESOLVER: Optional[DIDResolver] = None


def _default_resolver() -> DIDResolver:
    global _DEFAULT_RESOLVER
    if _DEFAULT_RESOLVER is None:
        _DEFAULT_RESOLVER = DIDResolver()
    return _DEFAULT_RESOLVER


def set_default_resolver(resolver: DIDResolver) -> None:
    """Replace the default resolver. Used by tests + by services that
    want to inject a custom HTTP client (e.g. with a private CA bundle)."""
    global _DEFAULT_RESOLVER
    _DEFAULT_RESOLVER = resolver


# ----- X25519 helpers used by the ECIES wire protocol (see wire.py) -----

def x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    sk = X25519PrivateKey.generate()
    pub_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return sk, pub_bytes


def x25519_pubkey_from_bytes(data: bytes) -> X25519PublicKey:
    if len(data) != 32:
        raise ValueError("x25519 pubkey must be 32 bytes")
    return X25519PublicKey.from_public_bytes(data)
