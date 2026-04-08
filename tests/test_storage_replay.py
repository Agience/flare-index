"""Storage write replay protection (Phase 3 / F-2.2 closed)."""
import time

import numpy as np
import pytest
from fastapi.testclient import TestClient

from flare.identity import Identity
from flare.storage import build_storage_app
from flare.storage.client import HttpStorageClient
from flare.storage.memory import ContextRegistration


def _stack():
    app = build_storage_app()
    return app, HttpStorageClient(client=TestClient(app))


def _reg(owner_did: str) -> ContextRegistration:
    return ContextRegistration.with_single_endpoint(
        context_id="ctx_a",
        owner_did=owner_did,
        oracle_endpoint="http://oracle.local",
        oracle_did="did:key:zXX",
        dim=4,
        nlist=2,
    )


def test_replayed_registration_rejected():
    app, client = _stack()
    alice = Identity.generate()
    client.register_context(_reg(alice.did), np.eye(2, 4, dtype=np.float32),
                            owner_identity=alice)
    # Re-running the same exact register_context call generates a fresh
    # nonce, so it would succeed if the storage already had the context
    # — but it doesn't, the second register would 409. Instead, attempt
    # to replay a *captured* upload by directly POSTing the same body
    # with the same nonce.
    raw = TestClient(app)
    # Capture: build a signed body manually
    import base64, os, time as _t
    from flare.storage.signing import canonical_registration_bytes
    nonce = os.urandom(16)
    ts = _t.time_ns()
    endpoints = [("http://oracle.local", "did:key:zXX")]
    canonical = canonical_registration_bytes(
        context_id="ctx_b",
        owner_did=alice.did,
        oracle_endpoints=endpoints,
        dim=4, nlist=2,
        nonce=nonce, timestamp_ns=ts,
    )
    sig = alice.sign(canonical)
    body = {
        "context_id": "ctx_b",
        "owner_did": alice.did,
        "oracle_endpoints": [{"url": u, "oracle_did": d} for u, d in endpoints],
        "dim": 4, "nlist": 2,
        "nonce_b64": base64.urlsafe_b64encode(nonce).rstrip(b"=").decode(),
        "timestamp_ns": ts,
        "signature_b64": base64.urlsafe_b64encode(sig).rstrip(b"=").decode(),
    }
    r1 = raw.post("/contexts", json=body)
    assert r1.status_code == 200
    # Replay the exact same body — must be rejected.
    r2 = raw.post("/contexts", json=body)
    assert r2.status_code == 401


def test_replayed_cell_upload_rejected():
    app, client = _stack()
    alice = Identity.generate()
    client.register_context(_reg(alice.did), np.eye(2, 4, dtype=np.float32),
                            owner_identity=alice)
    raw = TestClient(app)

    import base64, os, time as _t
    from flare.storage.signing import canonical_cell_upload_bytes
    blob = b"ciphertext-bytes"
    nonce = os.urandom(16)
    ts = _t.time_ns()
    canonical = canonical_cell_upload_bytes(
        context_id="ctx_a", cluster_id=0, cell_blob=blob,
        nonce=nonce, timestamp_ns=ts,
    )
    sig = alice.sign(canonical)
    headers = {
        "content-type": "application/octet-stream",
        "x-flare-signature": base64.urlsafe_b64encode(sig).rstrip(b"=").decode(),
        "x-flare-owner-did": alice.did,
        "x-flare-nonce": base64.urlsafe_b64encode(nonce).rstrip(b"=").decode(),
        "x-flare-timestamp-ns": str(ts),
    }
    r1 = raw.post("/contexts/ctx_a/cells/0", content=blob, headers=headers)
    assert r1.status_code == 200
    r2 = raw.post("/contexts/ctx_a/cells/0", content=blob, headers=headers)
    assert r2.status_code == 401
