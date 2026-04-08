"""Sealed key storage + SecureBytes zeroization (Phase 4 / F-1.9 / F-3.2)."""
import os
import tempfile

import pytest

from flare.crypto import fresh_master_key
from flare.identity import Identity
from flare.oracle.threshold import Share, split_secret
from flare.sealed import EncryptedFileKeyStore, SecureBytes


def test_secure_bytes_round_trip_then_clear():
    sb = SecureBytes(b"hello world")
    assert sb.view() == b"hello world"
    sb.clear()
    with pytest.raises(ValueError):
        sb.view()
    assert sb.cleared


def test_secure_bytes_clear_is_idempotent():
    sb = SecureBytes(b"x" * 32)
    sb.clear()
    sb.clear()  # second clear must not raise


def test_sealed_file_round_trip():
    master = fresh_master_key()
    shares = split_secret(master, k=2, m=3)
    signing_seed = os.urandom(32)
    passphrase = "correct horse battery staple"

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "alice.bin")
        EncryptedFileKeyStore.write(
            path,
            passphrase=passphrase,
            oracle_signing_seed=signing_seed,
            share_x=shares[0].x,
            share_y=shares[0].y_bytes,
        )
        bundle = EncryptedFileKeyStore.load(path, passphrase)
        assert bundle.is_threshold_share
        assert bundle.share_x == shares[0].x
        assert bundle.share_y.view() == shares[0].y_bytes
        assert bundle.oracle_signing_seed.view() == signing_seed
        bundle.clear()
        with pytest.raises(ValueError):
            bundle.share_y.view()


def test_sealed_file_wrong_passphrase_rejected():
    master = fresh_master_key()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "x.bin")
        EncryptedFileKeyStore.write(
            path, passphrase="right",
            oracle_signing_seed=os.urandom(32),
            share_x=0, share_y=master,
        )
        with pytest.raises(Exception):
            EncryptedFileKeyStore.load(path, "wrong")


def test_single_mode_sentinel():
    """share_x = 0 means the bundle holds the full master key, not a Shamir share."""
    master = fresh_master_key()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "single.bin")
        EncryptedFileKeyStore.write(
            path, passphrase="pp",
            oracle_signing_seed=os.urandom(32),
            share_x=0, share_y=master,
        )
        bundle = EncryptedFileKeyStore.load(path, "pp")
        assert not bundle.is_threshold_share
        assert bundle.share_x == 0
        assert bundle.share_y.view() == master


def test_oracle_can_load_identity_from_sealed_file():
    """An oracle service started with SEALED_KEY_FILE / SEALED_KEY_PASSPHRASE_FILE
    must derive the same DID as the source identity."""
    seed = os.urandom(32)
    src_identity = Identity.from_seed_hex(seed.hex())
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "o.bin")
        pp_path = os.path.join(d, "pp")
        EncryptedFileKeyStore.write(
            path, passphrase="zzz",
            oracle_signing_seed=seed, share_x=1, share_y=b"y" * 66,
        )
        with open(pp_path, "w") as f:
            f.write("zzz")

        bundle = EncryptedFileKeyStore.load(path, "zzz")
        loaded_identity = Identity.from_seed_hex(bundle.oracle_signing_seed.view().hex())
        assert loaded_identity.did == src_identity.did
