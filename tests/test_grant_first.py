"""Grant-first access: the owner has no fast-path bypass.

Owner access flows through a standing self-grant in the ledger, just
like any other principal. Revoking the self-grant blocks the owner;
re-granting restores access. There is no ``requester == self.owner``
shortcut in the oracle — the ledger is the sole authority.
"""
from datetime import datetime, timedelta

from flare.lightcone import Edge

T0 = datetime(2026, 4, 7, 12, 0, 0)


def test_owner_sees_data_through_self_grant(flare_stack):
    """Owner's access is mediated by a self-grant, not a bypass."""
    s = flare_stack
    hits, trace = s.engine.search(s.alice, s.av[0], k=5, nprobe=4, now=T0)
    assert hits and all(h.context_id == "workspace_alice" for h in hits)
    # The trace should show OWNER (self-grant), not a bypass.
    assert any(c.context_id == "workspace_alice" for c in trace.oracle_granted)


def test_revoking_self_grant_blocks_owner(flare_stack):
    """If the owner's self-grant is revoked, they lose access."""
    s = flare_stack
    # Find the owner's self-grant.
    self_grant = s.ledger.find_valid(
        s.alice.did, s.alice.did, "workspace_alice", T0,
    )
    assert self_grant is not None, "self-grant must exist after bootstrap"

    # Revoke it.
    revoked_at = T0 + timedelta(seconds=1)
    s.ledger.revoke(self_grant, grantor_identity=s.alice, revoked_at=revoked_at)
    s.engine.invalidate_cell_keys()

    # Owner is now locked out — revocation is denied at the centroid
    # gating stage (oracle refuses centroids), so no cells from
    # workspace_alice even reach the cell-key request path.
    hits, trace = s.engine.search(
        s.alice, s.av[0], k=5, nprobe=4, now=revoked_at + timedelta(seconds=1),
    )
    alice_hits = [h for h in hits if h.context_id == "workspace_alice"]
    assert alice_hits == [], "owner must lose access when self-grant is revoked"


def test_regranting_restores_owner_access(flare_stack):
    """Re-granting after revocation restores the owner's access."""
    s = flare_stack
    self_grant = s.ledger.find_valid(
        s.alice.did, s.alice.did, "workspace_alice", T0,
    )
    assert self_grant is not None

    revoked_at = T0 + timedelta(seconds=1)
    s.ledger.revoke(self_grant, grantor_identity=s.alice, revoked_at=revoked_at)
    s.engine.invalidate_cell_keys()

    # Re-grant.
    re_grant_at = T0 + timedelta(seconds=2)
    s.ledger.add_grant(
        grantor_identity=s.alice,
        grantee=s.alice.did,
        context_id="workspace_alice",
        issued_at=re_grant_at,
    )

    hits, _ = s.engine.search(
        s.alice, s.av[0], k=5, nprobe=4, now=re_grant_at + timedelta(seconds=1),
    )
    assert any(h.context_id == "workspace_alice" for h in hits), \
        "owner must regain access after re-grant"
