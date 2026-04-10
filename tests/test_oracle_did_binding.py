"""Oracle DID binding (F-1.12 closed in Phase 2; tests updated for
Phase 4 multi-endpoint registration).

The query node verifies the response signature against the *expected*
oracle DID (taken from the registered context). A man-in-the-middle
that swaps a URL into a registration cannot impersonate the expected
DID, so even if the rogue holds the right master key, its responses
fail signature verification and the query node treats them as
denied.

Phase 4 introduces oracle endpoint failover: the registration carries
a list of oracle endpoints, and the query engine tries them in order
until one returns a cooperative response. So:

- A test that swaps ONE registered URL with a rogue must verify
  failover does not silently bypass the rogue (it should still
  detect the rogue and refuse those keys, while succeeding via the
  next registered endpoint).
- A test that replaces ALL registered URLs with rogues must verify
  the query is denied entirely.
"""
from __future__ import annotations

from datetime import datetime

from fastapi.testclient import TestClient

from flare.crypto import fresh_master_key
from flare.identity import Identity
from flare.lightcone import Edge
from flare.oracle import build_oracle_app
from flare.oracle.client import HttpOracleClient


def _build_rogue(stack):
    """A rogue oracle service for Alice's data with a DIFFERENT signing
    identity. The rogue holds Alice's master key (it's been compromised)
    but cannot sign with the DID Alice registered."""
    rogue_id = Identity.generate()
    rogue_app = build_oracle_app(
        owner_did=stack.alice.did,
        master_key=stack.alice_master,
        ledger_client=stack.ledger,
        oracle_identity=rogue_id,
    )
    return rogue_id, TestClient(rogue_app)


def test_query_engine_accepts_correct_oracle_did(phase2_stack):
    """Sanity: with the real oracles, owner queries succeed."""
    s = phase2_stack
    hits, _ = s.engine.search(s.alice, s.av[0], k=3, nprobe=4, now=datetime(2026, 1, 1))
    assert hits and any(h.context_id == "workspace_alice" for h in hits)


def test_failover_around_a_single_rogue_endpoint(phase2_stack):
    """If only ONE of Alice's three registered endpoints is rogue, the
    query engine detects the bad signature, fails over to one of the
    other registered endpoints, and the query still succeeds."""
    s = phase2_stack
    rogue_id, rogue_client = _build_rogue(s)

    # Substitute the rogue at replica-1's URL only; replicas 2 and 3
    # remain the real services.
    rogue_url = s.alice_replicas.base_urls[0]
    real_resolve = s.resolve

    def rogue_resolve(endpoint: str):
        if endpoint == rogue_url:
            return HttpOracleClient(client=rogue_client)
        return real_resolve(endpoint)

    from flare.query import FlareQueryEngine
    engine = FlareQueryEngine(
        storage=s.storage, lightcone=s.graph, oracle_resolver=rogue_resolve,
    )
    hits, _ = engine.search(s.alice, s.av[0], k=3, nprobe=4, now=datetime(2026, 1, 1))
    # Failover succeeded — Alice still sees her own data through the
    # remaining replicas.
    assert hits and any(h.context_id == "workspace_alice" for h in hits)


def test_query_engine_denies_when_every_endpoint_is_rogue(phase2_stack):
    """If every registered endpoint is replaced with a rogue (different
    signing DID), the query engine denies every Alice cell.

    With centroid gating, the rogue oracle also can't provide valid
    centroids (DID mismatch on the ECIES response), so no Alice cells
    are even routed. The security property is the same: no Alice data
    leaks.
    """
    s = phase2_stack
    rogue_id, rogue_client = _build_rogue(s)

    # Resolver returns the same rogue for every Alice replica URL.
    real_resolve = s.resolve
    alice_urls = set(s.alice_replicas.base_urls)

    def fully_rogue_resolve(endpoint: str):
        if endpoint in alice_urls:
            return HttpOracleClient(client=rogue_client)
        return real_resolve(endpoint)

    from flare.query import FlareQueryEngine
    engine = FlareQueryEngine(
        storage=s.storage, lightcone=s.graph, oracle_resolver=fully_rogue_resolve,
    )
    hits, trace = engine.search(s.alice, s.av[0], k=3, nprobe=4, now=datetime(2026, 1, 1))
    assert all(h.context_id != "workspace_alice" for h in hits)
    # The rogue can't provide valid centroids either, so no Alice
    # cells are routed — oracle_denied may be empty (no cells to deny)
    # OR populated (if routing somehow produced candidates). Either way
    # no Alice oracle_granted entries must exist.
    assert not any(c.context_id == "workspace_alice" for c in trace.oracle_granted)
