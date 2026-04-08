"""Storage write authentication (Phase 2 / F-1.8 closed)."""
from __future__ import annotations

import numpy as np
from fastapi.testclient import TestClient

from flare.identity import Identity
from flare.storage import build_storage_app
from flare.storage.client import HttpStorageClient
from flare.storage.memory import ContextRegistration


def _stack():
    app = build_storage_app()
    client = HttpStorageClient(client=TestClient(app))
    return app, client


def _reg(owner_did: str, oracle_did: str) -> ContextRegistration:
    return ContextRegistration.with_single_endpoint(
        context_id="ctx_a",
        owner_did=owner_did,
        oracle_endpoint="http://oracle.local",
        oracle_did=oracle_did,
        dim=4,
        nlist=2,
    )


def _centroids() -> np.ndarray:
    return np.eye(2, 4, dtype=np.float32)


def test_register_and_upload_with_correct_owner_signature():
    _, client = _stack()
    alice = Identity.generate()
    oracle = Identity.generate()
    client.register_context(_reg(alice.did, oracle.did), _centroids(), owner_identity=alice)
    client.put_cell("ctx_a", 0, b"ciphertext-blob", owner_identity=alice)
    assert client.get_cell("ctx_a", 0) == b"ciphertext-blob"


def test_register_with_wrong_signing_key_rejected():
    _, client = _stack()
    alice = Identity.generate()
    bob = Identity.generate()
    oracle = Identity.generate()
    # Bob's identity tries to register a context claiming to be Alice.
    reg = _reg(alice.did, oracle.did)
    import pytest
    with pytest.raises(ValueError):
        client.register_context(reg, _centroids(), owner_identity=bob)


def test_cell_upload_by_non_owner_rejected():
    _, client = _stack()
    alice = Identity.generate()
    eve = Identity.generate()
    oracle = Identity.generate()
    client.register_context(_reg(alice.did, oracle.did), _centroids(), owner_identity=alice)
    # Eve has the URL but not Alice's signing key.
    import pytest
    with pytest.raises(Exception):
        client.put_cell("ctx_a", 0, b"poisoned", owner_identity=eve)


def test_anonymous_reads_still_work():
    _, client = _stack()
    alice = Identity.generate()
    oracle = Identity.generate()
    client.register_context(_reg(alice.did, oracle.did), _centroids(), owner_identity=alice)
    client.put_cell("ctx_a", 0, b"ciphertext", owner_identity=alice)
    # Reads do not require any identity.
    assert client.get_cell("ctx_a", 0) == b"ciphertext"
    centroids = client.get_centroids("ctx_a")
    assert centroids.shape == (2, 4)
    assert client.get_registration("ctx_a").oracle_did == oracle.did


def test_oracle_did_round_trips_in_registration():
    _, client = _stack()
    alice = Identity.generate()
    oracle = Identity.generate()
    client.register_context(_reg(alice.did, oracle.did), _centroids(), owner_identity=alice)
    reg = client.get_registration("ctx_a")
    assert reg.oracle_did == oracle.did
    assert reg.owner_did == alice.did
