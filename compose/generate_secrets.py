"""Generate Phase 3 stack secrets and write them to /secrets/phase3.env.

For each data owner (Alice, Bob):

- One Ed25519 owner identity (signs storage writes + signs grants)
- One symmetric master key (32 bytes)
- The master key is split into M=3 Shamir shares with quorum K=2
- Three Ed25519 oracle identities (one per replica), used to sign
  oracle wire responses and to authenticate peer share requests

The compose stack runs three oracle replicas per owner. The oracles
do NOT receive the full master key — only their assigned share. The
demo container also receives the master keys and the owner signing
keys, because the demo plays the role of the data owner during
bootstrap.

This whole arrangement is a research-prototype substitute for sealed
storage. Documented in phase3-findings.md F-3.x.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from flare.crypto import fresh_master_key
from flare.identity import Identity
from flare.oracle.threshold import split_secret
from flare.sealed import EncryptedFileKeyStore


M = 3  # number of oracle replicas per owner
K = 2  # threshold quorum


def _ed25519_seed_hex(ident: Identity) -> str:
    return ident._signing_key.private_bytes(  # noqa: SLF001
        Encoding.Raw, PrivateFormat.Raw, NoEncryption(),
    ).hex()


def _share_hex(share) -> str:
    # Encoded as `x:y_hex`
    return f"{share.x}:{share.y_bytes.hex()}"


def main() -> None:
    out_dir = Path(os.environ.get("SECRETS_DIR", "/secrets"))
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / "phase3.env"
    if target.exists() and "--force" not in sys.argv:
        print(f"[secrets] {target} already exists, skipping (pass --force to overwrite)")
        return

    alice = Identity.generate()
    bob = Identity.generate()
    alice_master = fresh_master_key()
    bob_master = fresh_master_key()
    alice_oracles = [Identity.generate() for _ in range(M)]
    bob_oracles = [Identity.generate() for _ in range(M)]
    alice_shares = split_secret(alice_master, k=K, m=M)
    bob_shares = split_secret(bob_master, k=K, m=M)

    lines: list[str] = [
        f"FLARE_THRESHOLD_K={K}",
        f"FLARE_THRESHOLD_M={M}",
        f"ALICE_DID={alice.did}",
        f"BOB_DID={bob.did}",
        f"ALICE_OWNER_SIGNING_KEY_HEX={_ed25519_seed_hex(alice)}",
        f"BOB_OWNER_SIGNING_KEY_HEX={_ed25519_seed_hex(bob)}",
        f"ALICE_MASTER_KEY_HEX={alice_master.hex()}",
        f"BOB_MASTER_KEY_HEX={bob_master.hex()}",
    ]
    for i, (oid, sh) in enumerate(zip(alice_oracles, alice_shares), start=1):
        lines.append(f"ALICE_ORACLE_{i}_DID={oid.did}")
        lines.append(f"ALICE_ORACLE_{i}_SIGNING_KEY_HEX={_ed25519_seed_hex(oid)}")
        lines.append(f"ALICE_ORACLE_{i}_SHARE={_share_hex(sh)}")
    for i, (oid, sh) in enumerate(zip(bob_oracles, bob_shares), start=1):
        lines.append(f"BOB_ORACLE_{i}_DID={oid.did}")
        lines.append(f"BOB_ORACLE_{i}_SIGNING_KEY_HEX={_ed25519_seed_hex(oid)}")
        lines.append(f"BOB_ORACLE_{i}_SHARE={_share_hex(sh)}")

    target.write_text("\n".join(lines) + "\n")
    target.chmod(0o644)
    print(f"[secrets] wrote {target}")
    for line in lines:
        key = line.split("=", 1)[0]
        print(f"  {key}=<set>")

    # Phase 4: also write a passphrase-encrypted sealed key file per
    # oracle replica. The compose entrypoint can use these instead of
    # raw env vars; the passphrase comes from /secrets/passphrase
    # (also generated here).
    passphrase = os.urandom(32).hex()
    (out_dir / "passphrase").write_text(passphrase + "\n")
    (out_dir / "passphrase").chmod(0o644)

    sealed_dir = out_dir / "sealed"
    sealed_dir.mkdir(exist_ok=True)
    sealed_dir.chmod(0o755)

    def _seal(name: str, signing_seed_hex: str, share_x: int, share_y: bytes) -> None:
        path = sealed_dir / f"{name}.bin"
        EncryptedFileKeyStore.write(
            str(path),
            passphrase=passphrase,
            oracle_signing_seed=bytes.fromhex(signing_seed_hex),
            share_x=share_x,
            share_y=share_y,
        )
        os.chmod(path, 0o644)

    for i in range(M):
        _seal(
            f"alice_oracle_{i+1}",
            _ed25519_seed_hex(alice_oracles[i]),
            alice_shares[i].x,
            alice_shares[i].y_bytes,
        )
        _seal(
            f"bob_oracle_{i+1}",
            _ed25519_seed_hex(bob_oracles[i]),
            bob_shares[i].x,
            bob_shares[i].y_bytes,
        )
    print(f"[secrets] wrote {sealed_dir}/*.bin (encrypted)")


if __name__ == "__main__":
    main()
