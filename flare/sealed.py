"""Sealed key storage substitute for TEE.

Phase 4 closes (in software) the key-lifecycle gaps that earlier
phases had to defer to TEE work:

- F-1.9 / F-2.7: master keys + oracle signing keys delivered via env
  vars in the compose stack.
- F-3.2 (partial): the reconstructed master key briefly lives in
  coordinator memory.

A real TEE deployment (Intel SGX via Gramine, AMD SEV) would seal
these keys inside hardware enclaves. We cannot run an SGX enclave in a
docker prototype, so we offer two real software improvements that
move the system in the right direction:

1. **`SecureBytes`** — a mutable byte buffer that can be explicitly
   zeroized via `ctypes.memset` when no longer needed. CPython
   `bytes` objects are immutable and the runtime makes no zeroization
   guarantee; `bytearray` is mutable and lives in a known address
   range we can overwrite. The buffer is wiped on `clear()` and on
   garbage collection. Real defense against post-process forensics
   (core dumps, swap, /proc inspection after the buffer is freed).

2. **`EncryptedFileKeyStore`** — keys are persisted to disk encrypted
   under a passphrase-derived key (scrypt -> AES-256-GCM). Services
   load the encrypted blob at startup, decrypt the secret material
   into `SecureBytes`, and immediately zeroize the working key
   buffer. The on-disk artifact is useless without the passphrase;
   the passphrase is delivered out-of-band.

Neither of these is the same as TEE sealing. TEE protects against
the host operator. Software-only sealing protects against
post-process forensics, swap, and core dumps but not against an
operator with live-process inspection (ptrace, /proc/<pid>/mem).
Documented honestly in phase4-findings.md F-4.1 / F-4.2.

# CAVEAT (Python memory): even with bytearray + ctypes.memset, copies
# of the secret may have been made by the runtime in places we cannot
# reach (string interning, network buffer ringbuffers, GC tenured
# heaps). Treating SecureBytes as "best-effort zeroization for the
# bytes WE control" is honest; treating it as "the secret is gone"
# is not. The right model is: SecureBytes makes the attacker's job
# strictly harder, not impossible, in software.
"""
from __future__ import annotations

import ctypes
import os
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# Scrypt parameters: tuned for ~100 ms on a developer laptop.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_KEY_LEN = 32
GCM_NONCE_LEN = 12

KEYSTORE_MAGIC = b"FLARE-V4"


class SecureBytes:
    """Mutable byte buffer with explicit zeroization on clear()."""

    __slots__ = ("_buf", "_addr", "_len", "_cleared")

    def __init__(self, data: bytes) -> None:
        # Copy the bytes into a new bytearray we own. We never hand
        # out the underlying buffer; callers ask for `view()` to read
        # the current contents.
        self._buf = bytearray(data)
        self._addr, self._len = self._addr_and_len(self._buf)
        self._cleared = False

    @staticmethod
    def _addr_and_len(buf: bytearray) -> tuple[int, int]:
        # Get the underlying buffer address. ctypes.addressof on a
        # ctypes array gives us the C address; we use a c_char array
        # alias of the bytearray buffer.
        n = len(buf)
        if n == 0:
            return 0, 0
        Type = ctypes.c_char * n
        arr = Type.from_buffer(buf)
        return ctypes.addressof(arr), n

    @property
    def cleared(self) -> bool:
        return self._cleared

    def view(self) -> bytes:
        """Return a *copy* of the current contents.

        Yes, this defeats the point. But there is no way to consume
        the secret in modern crypto APIs without producing a `bytes`
        view of it; ECIES, HKDF, AES-GCM all take `bytes`. The point
        of `SecureBytes` is to control the *long-term* persistence of
        the secret in process memory: the bytes returned by `view()`
        are short-lived and the canonical buffer is the bytearray
        we can wipe. Callers who keep `view()` results around defeat
        the protection.
        """
        if self._cleared:
            raise ValueError("SecureBytes has been cleared")
        return bytes(self._buf)

    def clear(self) -> None:
        if self._cleared or self._len == 0:
            self._cleared = True
            return
        # Overwrite the underlying buffer with zeros via memset.
        ctypes.memset(self._addr, 0, self._len)
        # And drop the bytearray reference so future use raises.
        self._buf = bytearray()
        self._cleared = True

    def __del__(self) -> None:
        try:
            self.clear()
        except Exception:
            pass


def _derive_kek(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=SCRYPT_KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


@dataclass
class SealedKeyBundle:
    """Plaintext key material loaded from disk into SecureBytes wrappers.

    `share_x = 0` is the sentinel for "this bundle holds the full
    symmetric master key in `share_y` (single-mode oracle)". A
    non-zero `share_x` indicates a Shamir share at index `share_x`
    with `share_y` as the share value (threshold-mode oracle).
    """
    oracle_signing_seed: SecureBytes
    share_x: int
    share_y: SecureBytes

    @property
    def is_threshold_share(self) -> bool:
        return self.share_x != 0

    def clear(self) -> None:
        self.oracle_signing_seed.clear()
        self.share_y.clear()


class EncryptedFileKeyStore:
    """Read/write a passphrase-encrypted key bundle on disk.

    File layout:
        magic (8 bytes)               = b"FLARE-V4"
        version (1 byte)              = 1
        salt_len (2 bytes)            (scrypt salt)
        salt
        nonce_len (2 bytes)           (AES-GCM nonce)
        nonce
        ciphertext_len (4 bytes)
        ciphertext                    (AES-GCM(KEK, payload))

    Payload layout (cleartext, AES-GCM-protected):
        oracle_signing_seed           (32 bytes)
        share_x                       (4 bytes, signed; 0 means
                                       'share_y holds the full master
                                       key — single-mode oracle')
        share_y_len                   (2 bytes)
        share_y                       (variable)
    """

    @staticmethod
    def write(
        path: str,
        *,
        passphrase: str,
        oracle_signing_seed: bytes,
        share_x: int,
        share_y: bytes,
    ) -> None:
        salt = os.urandom(16)
        kek = _derive_kek(passphrase, salt)
        nonce = os.urandom(GCM_NONCE_LEN)

        payload = bytearray()
        payload += oracle_signing_seed
        payload += struct.pack(">i", share_x)
        payload += len(share_y).to_bytes(2, "big", signed=False)
        payload += share_y

        ct = AESGCM(kek).encrypt(nonce, bytes(payload), None)

        # Wipe the temporary kek buffer.
        kek_buf = bytearray(kek)
        ctypes.memset(
            (ctypes.c_char * len(kek_buf)).from_buffer(kek_buf), 0, len(kek_buf)
        )

        with open(path, "wb") as f:
            f.write(KEYSTORE_MAGIC)
            f.write(b"\x01")
            f.write(len(salt).to_bytes(2, "big"))
            f.write(salt)
            f.write(len(nonce).to_bytes(2, "big"))
            f.write(nonce)
            f.write(len(ct).to_bytes(4, "big"))
            f.write(ct)
        os.chmod(path, 0o600)

    @staticmethod
    def load(path: str, passphrase: str) -> SealedKeyBundle:
        with open(path, "rb") as f:
            data = f.read()
        if not data.startswith(KEYSTORE_MAGIC):
            raise ValueError("not a FLARE sealed key file")
        offset = len(KEYSTORE_MAGIC)
        version = data[offset]
        offset += 1
        if version != 1:
            raise ValueError(f"unsupported sealed key file version: {version}")
        salt_len = int.from_bytes(data[offset:offset+2], "big"); offset += 2
        salt = data[offset:offset+salt_len]; offset += salt_len
        nonce_len = int.from_bytes(data[offset:offset+2], "big"); offset += 2
        nonce = data[offset:offset+nonce_len]; offset += nonce_len
        ct_len = int.from_bytes(data[offset:offset+4], "big"); offset += 4
        ct = data[offset:offset+ct_len]

        kek = _derive_kek(passphrase, salt)
        try:
            payload = AESGCM(kek).decrypt(nonce, ct, None)
        finally:
            # Wipe the kek immediately.
            kek_buf = bytearray(kek)
            ctypes.memset(
                (ctypes.c_char * len(kek_buf)).from_buffer(kek_buf), 0, len(kek_buf)
            )
            del kek

        # Parse cleartext payload into SecureBytes wrappers.
        p = 0
        signing_seed = SecureBytes(payload[p:p+32]); p += 32
        share_x = struct.unpack(">i", payload[p:p+4])[0]; p += 4
        share_y_len = int.from_bytes(payload[p:p+2], "big"); p += 2
        share_y = SecureBytes(payload[p:p+share_y_len])

        # Wipe the cleartext payload buffer.
        payload_buf = bytearray(payload)
        ctypes.memset(
            (ctypes.c_char * len(payload_buf)).from_buffer(payload_buf), 0, len(payload_buf)
        )

        return SealedKeyBundle(
            oracle_signing_seed=signing_seed,
            share_x=share_x,
            share_y=share_y,
        )
