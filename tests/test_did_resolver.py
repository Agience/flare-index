"""DID resolver: did:key (local) + did:web (HTTP fetch with cache)."""
from __future__ import annotations

import json

import pytest

from flare.identity import (
    DIDResolver,
    Identity,
    base58btc_encode,
    did_key_from_ed25519_pubkey,
    ed25519_pubkey_from_did,
    verify_ed25519,
)


def test_did_key_resolves_locally():
    ident = Identity.generate()
    pub = DIDResolver().resolve(ident.did)
    # Re-encoding must yield the same DID.
    assert did_key_from_ed25519_pubkey(pub) == ident.did


# ---- did:web fake transport ----


class _FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise Exception(f"http {self.status_code}")

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    def __init__(self, urls: dict[str, dict]) -> None:
        self._urls = urls
        self.calls: list[str] = []

    def get(self, url: str):
        self.calls.append(url)
        if url not in self._urls:
            return _FakeResponse({}, status_code=404)
        return _FakeResponse(self._urls[url])


def _fake_did_doc_for(ident: Identity) -> dict:
    pub_raw = ident.public_key().public_bytes(
        # raw 32-byte ed25519 pubkey
        __import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
        __import__("cryptography").hazmat.primitives.serialization.PublicFormat.Raw,
    )
    return {
        "id": "did:web:example.com:users:alice",
        "verificationMethod": [
            {
                "id": "did:web:example.com:users:alice#1",
                "type": "Ed25519VerificationKey2020",
                "publicKeyMultibase": "z" + base58btc_encode(pub_raw),
            }
        ],
    }


def test_did_web_url_construction_with_path():
    r = DIDResolver()
    assert r._did_web_to_url("did:web:example.com") == "https://example.com/.well-known/did.json"
    assert r._did_web_to_url("did:web:example.com:users:alice") == "https://example.com/users/alice/did.json"


def test_did_web_resolves_via_fake_http():
    ident = Identity.generate()
    fake_did = "did:web:example.com:users:alice"
    doc = _fake_did_doc_for(ident)
    fake = _FakeClient({"https://example.com/users/alice/did.json": doc})
    resolver = DIDResolver(http_client=fake)
    pub = resolver.resolve(fake_did)
    # The pubkey we recovered should match the identity that signed.
    sig = ident.sign(b"hello")
    pub.verify(sig, b"hello")
    assert fake.calls == ["https://example.com/users/alice/did.json"]


def test_did_web_caches_within_ttl():
    ident = Identity.generate()
    doc = _fake_did_doc_for(ident)
    fake = _FakeClient({"https://example.com/users/alice/did.json": doc})
    resolver = DIDResolver(http_client=fake)
    fake_did = "did:web:example.com:users:alice"
    resolver.resolve(fake_did)
    resolver.resolve(fake_did)
    resolver.resolve(fake_did)
    assert len(fake.calls) == 1, "second + third lookups should hit cache"


def test_unknown_did_method_rejected():
    with pytest.raises(ValueError):
        DIDResolver().resolve("did:ethr:0x1234")
