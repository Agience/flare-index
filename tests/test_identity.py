import pytest

from flare.identity import (
    Identity,
    base58btc_decode,
    base58btc_encode,
    did_key_from_ed25519_pubkey,
    ed25519_pubkey_from_did,
    verify_ed25519,
)


def test_base58btc_round_trip():
    for raw in [b"", b"\x00", b"\x00\x00\x01", b"hello world", bytes(range(32))]:
        assert base58btc_decode(base58btc_encode(raw)) == raw


def test_did_key_round_trip():
    ident = Identity.generate()
    assert ident.did.startswith("did:key:z")
    pub = ed25519_pubkey_from_did(ident.did)
    # Re-encoding the recovered pubkey must yield the same DID.
    assert did_key_from_ed25519_pubkey(pub) == ident.did


def test_signature_verifies():
    ident = Identity.generate()
    msg = b"hello flare"
    sig = ident.sign(msg)
    assert verify_ed25519(ident.did, msg, sig)


def test_signature_rejects_tampered_message():
    ident = Identity.generate()
    sig = ident.sign(b"original")
    assert not verify_ed25519(ident.did, b"tampered", sig)


def test_signature_rejects_other_did():
    a = Identity.generate()
    b = Identity.generate()
    sig = a.sign(b"msg")
    assert not verify_ed25519(b.did, b"msg", sig)


def test_unknown_did_method_rejected():
    with pytest.raises(ValueError):
        ed25519_pubkey_from_did("did:web:example.com")
