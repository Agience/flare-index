"""Process entry points for the FLARE services.

Roles:
  ledger          - run the ledger HTTP service
  storage         - run the storage HTTP service
  oracle          - run an oracle HTTP service (threshold mode)

The oracle entry takes its configuration from environment variables
that the docker-compose entrypoint loads from /secrets/phase3.env:

  PORT                       (default 8000)
  OWNER_DID                  required
  ORACLE_DID                 required (this replica's DID)
  ORACLE_SIGNING_KEY_HEX     required (Ed25519 seed for this replica)
  ORACLE_SHARE               required ("x:y_hex")
  THRESHOLD_K                required (e.g. 2)
  LEDGER_URL                 required
  PEER_DIDS                  comma-separated list of peer oracle DIDs (this replica is not in the list)
  PEER_URLS                  comma-separated list of peer oracle base URLs (parallel to PEER_DIDS)
  ALLOWED_COORD_DIDS         comma-separated list of oracle DIDs that may
                             ask this replica for its share (typically all
                             three replicas of the same owner: each can act
                             as the coordinator for some queries)
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

import uvicorn

from .identity import Identity
from .ledger import HttpLedgerClient, build_ledger_app
from .oracle import (
    PeerEndpoint,
    PeerShareFetcher,
    Share,
    build_oracle_app,
)
from .sealed import EncryptedFileKeyStore, SealedKeyBundle
from .storage import build_storage_app


def _bind_args() -> tuple[str, int]:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    return host, port


def run_ledger() -> None:
    host, port = _bind_args()
    app = build_ledger_app()
    uvicorn.run(app, host=host, port=port, log_level="info")


def run_storage() -> None:
    host, port = _bind_args()
    app = build_storage_app()
    uvicorn.run(app, host=host, port=port, log_level="info")


def _parse_share(s: str) -> Share:
    x_str, y_hex = s.split(":", 1)
    return Share(x=int(x_str), y_bytes=bytes.fromhex(y_hex))


def _load_oracle_secrets() -> tuple[Identity, Share]:
    """Load (oracle_identity, share) from either a sealed key file
    (Phase 4 path) or from legacy env vars (Phase 3 fallback).

    Phase 4 path:
        SEALED_KEY_FILE              path to encrypted bundle
        SEALED_KEY_PASSPHRASE_FILE   path to file holding the passphrase

    Phase 3 fallback:
        ORACLE_SIGNING_KEY_HEX
        ORACLE_SHARE                 "x:y_hex"
    """
    sealed_path = os.environ.get("SEALED_KEY_FILE")
    if sealed_path:
        passphrase_path = os.environ.get("SEALED_KEY_PASSPHRASE_FILE")
        if not passphrase_path:
            print("ERROR: SEALED_KEY_FILE requires SEALED_KEY_PASSPHRASE_FILE", file=sys.stderr)
            sys.exit(2)
        with open(passphrase_path, "r") as f:
            passphrase = f.read().strip()
        bundle = EncryptedFileKeyStore.load(sealed_path, passphrase)
        oracle_identity = Identity.from_seed_hex(bundle.oracle_signing_seed.view().hex())
        share = Share(x=bundle.share_x, y_bytes=bundle.share_y.view())
        # The bundle's SecureBytes wrappers will be cleared when the
        # bundle goes out of scope. We've extracted the long-lived
        # signing key and the share into normal bytes here, which is
        # acceptable because the long-lived signing key has to live
        # in process memory for the life of the service anyway, and
        # the share is the same.
        return oracle_identity, share

    oracle_signing_hex = os.environ.get("ORACLE_SIGNING_KEY_HEX")
    share_str = os.environ.get("ORACLE_SHARE")
    if not (oracle_signing_hex and share_str):
        print(
            "ERROR: oracle requires either SEALED_KEY_FILE+SEALED_KEY_PASSPHRASE_FILE "
            "or ORACLE_SIGNING_KEY_HEX+ORACLE_SHARE",
            file=sys.stderr,
        )
        sys.exit(2)
    return Identity.from_seed_hex(oracle_signing_hex), _parse_share(share_str)


def run_oracle() -> None:
    host, port = _bind_args()
    owner_did = os.environ.get("OWNER_DID")
    oracle_did = os.environ.get("ORACLE_DID")
    threshold_k_str = os.environ.get("THRESHOLD_K")
    ledger_url = os.environ.get("LEDGER_URL")
    peer_dids_csv = os.environ.get("PEER_DIDS", "")
    peer_urls_csv = os.environ.get("PEER_URLS", "")
    allowed_csv = os.environ.get("ALLOWED_COORD_DIDS", "")
    if not (owner_did and oracle_did and threshold_k_str and ledger_url):
        print(
            "ERROR: oracle requires OWNER_DID, ORACLE_DID, THRESHOLD_K, LEDGER_URL env vars",
            file=sys.stderr,
        )
        sys.exit(2)

    oracle_identity, share = _load_oracle_secrets()
    if oracle_identity.did != oracle_did:
        print(
            f"ERROR: ORACLE_DID does not match the DID derived from the loaded "
            f"signing seed (got {oracle_identity.did})",
            file=sys.stderr,
        )
        sys.exit(2)

    threshold_k = int(threshold_k_str)
    peer_dids = [d for d in peer_dids_csv.split(",") if d]
    peer_urls = [u for u in peer_urls_csv.split(",") if u]
    if len(peer_dids) != len(peer_urls):
        print("ERROR: PEER_DIDS and PEER_URLS must have the same length", file=sys.stderr)
        sys.exit(2)
    peers = [PeerEndpoint(oracle_did=d, base_url=u) for d, u in zip(peer_dids, peer_urls)]
    fetcher: Optional[PeerShareFetcher] = None
    if threshold_k > 1:
        fetcher = PeerShareFetcher(
            coord_identity=oracle_identity,
            peers=peers,
            needed=threshold_k - 1,
        )

    allowed = set(d for d in allowed_csv.split(",") if d)

    ledger_client = HttpLedgerClient(ledger_url)
    app = build_oracle_app(
        owner_did=owner_did,
        ledger_client=ledger_client,
        share=share,
        threshold_k=threshold_k,
        peer_share_fetcher=fetcher,
        oracle_identity=oracle_identity,
        allowed_coord_dids=allowed,
    )
    uvicorn.run(app, host=host, port=port, log_level="info")


def main() -> None:
    parser = argparse.ArgumentParser(prog="flare-services")
    parser.add_argument("service", choices=["ledger", "storage", "oracle"])
    args = parser.parse_args()
    {"ledger": run_ledger, "storage": run_storage, "oracle": run_oracle}[args.service]()


if __name__ == "__main__":
    main()
