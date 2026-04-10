"""Per-cell key derivation and authenticated encryption.

Implements the scheme from docs/partitioned-encrypted-vector-search.md:

    cell_key = HKDF-SHA256(master_key, info = context_id || 0x00 || cluster_id, length = 32)
    ciphertext = nonce || AES-256-GCM(cell_key, plaintext)

# ANALYSIS (phase0-findings.md §HKDF info construction):
# We use a single 0x00 byte as the delimiter between context_id and
# cluster_id rather than ':' as the doc sketch suggests, because a
# context_id containing ':' would otherwise collide with another
# (context_id, cluster_id) pair. The 0x00 byte is forbidden in our
# context_id validator (see _validate_context_id) so collision is
# impossible by construction.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .types import ClusterId, ContextId

KEY_BYTES = 32   # AES-256
NONCE_BYTES = 12 # AES-GCM standard
HKDF_SALT = b"flare/v0/hkdf-salt"  # fixed; master_key carries entropy


def _validate_context_id(context_id: ContextId) -> None:
    if "\x00" in context_id:
        raise ValueError("context_id must not contain NUL byte")
    if not context_id:
        raise ValueError("context_id must be non-empty")


def derive_cell_key(master_key: bytes, context_id: ContextId, cluster_id: ClusterId) -> bytes:
    """Derive a per-cell symmetric key from the owner's master key.

    Deterministic: same inputs always yield the same key. The oracle
    derives on demand; nothing is stored.
    """
    if len(master_key) < 32:
        raise ValueError("master_key must be at least 32 bytes of entropy")
    _validate_context_id(context_id)
    info = context_id.encode("utf-8") + b"\x00" + cluster_id.to_bytes(8, "big", signed=False)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=HKDF_SALT,
        info=info,
    )
    return hkdf.derive(master_key)


def derive_centroid_key(master_key: bytes, context_id: ContextId) -> bytes:
    """Derive the key used to encrypt centroids for a context.

    Uses a distinct HKDF info prefix so centroid keys never collide
    with per-cell keys, even for the same (master_key, context_id).
    """
    if len(master_key) < 32:
        raise ValueError("master_key must be at least 32 bytes of entropy")
    _validate_context_id(context_id)
    info = b"flare/v1/centroids\x00" + context_id.encode("utf-8")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=HKDF_SALT,
        info=info,
    ).derive(master_key)


@dataclass(frozen=True)
class EncryptedCell:
    nonce: bytes
    ciphertext: bytes  # includes GCM tag

    def to_bytes(self) -> bytes:
        return self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, blob: bytes) -> "EncryptedCell":
        return cls(nonce=blob[:NONCE_BYTES], ciphertext=blob[NONCE_BYTES:])


def encrypt_cell(cell_key: bytes, plaintext: bytes, associated: bytes = b"") -> EncryptedCell:
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(cell_key).encrypt(nonce, plaintext, associated)
    return EncryptedCell(nonce=nonce, ciphertext=ct)


def decrypt_cell(cell_key: bytes, cell: EncryptedCell, associated: bytes = b"") -> bytes:
    return AESGCM(cell_key).decrypt(cell.nonce, cell.ciphertext, associated)


def fresh_master_key() -> bytes:
    return os.urandom(KEY_BYTES)
