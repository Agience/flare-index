"""Shamir K-of-M secret sharing over a 256-bit prime field.

The secret is the owner's symmetric master key (32 bytes). It is
treated as a single big-endian integer in the range [0, 2^256). The
sharing polynomial is degree K-1 with the secret as the constant
term and K-1 random coefficients drawn from the field. The field is
GF(p) for `p = 2^521 - 1` (a Mersenne prime, comfortably larger than
2^256, simple to work with, no field-arithmetic libraries required).

Reconstruction is Lagrange interpolation at x=0:

    secret = sum_i ( y_i * prod_{j != i}( x_j / (x_j - x_i) ) ) mod p

Each share is a `(x, y)` pair. `x` is the share index in [1, M] (zero
is reserved for the secret itself). `y` is in [0, p).

# Notes
# - 32-byte secrets fit in [0, 2^256). The encoded share carries `y`
#   as a big integer; we serialize it as a fixed-width 66-byte big
#   endian to keep length stable (66 bytes is enough for any value
#   below 2^521).
# - The randomness for the sharing polynomial comes from `os.urandom`,
#   which is `secrets.token_bytes` underneath. Failure to seed it
#   would mean every share leaks the secret; CPython's source is
#   `getrandom(2)` on Linux which is non-blocking once the kernel CSPRNG
#   is initialized — unconditionally fine in a docker container.
# - Reconstructing the secret in process memory means the coordinator
#   oracle briefly holds the full master key. The threshold property
#   says: K-1 compromised oracle hosts cannot reconstruct it. K
#   compromised hosts can. Phase 4 (TEE) closes the gap by holding
#   the reconstruction inside a sealed enclave on the coordinator.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

# Mersenne prime: 2^521 - 1.
PRIME = (1 << 521) - 1
SHARE_BYTES = 66  # ceil(521/8) — fits any field element


@dataclass(frozen=True)
class Share:
    x: int            # 1..M
    y_bytes: bytes    # SHARE_BYTES big-endian


def _y_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _y_to_bytes(y: int) -> bytes:
    return y.to_bytes(SHARE_BYTES, "big")


def _rand_field_element() -> int:
    # Rejection sampling to get a uniform element of [0, PRIME).
    while True:
        n = int.from_bytes(os.urandom(SHARE_BYTES), "big")
        if n < PRIME:
            return n


def _eval_poly(coeffs: list[int], x: int) -> int:
    # Horner's method, mod PRIME.
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % PRIME
    return acc


def split_secret(secret: bytes, k: int, m: int) -> list[Share]:
    if not (1 <= k <= m):
        raise ValueError(f"need 1 <= k <= m, got k={k} m={m}")
    if len(secret) > 32:
        raise ValueError("secret must be at most 32 bytes (256 bits)")
    s_int = int.from_bytes(secret, "big")
    if s_int >= PRIME:
        raise ValueError("secret integer overflows the prime field")
    coeffs = [s_int] + [_rand_field_element() for _ in range(k - 1)]
    return [
        Share(x=i, y_bytes=_y_to_bytes(_eval_poly(coeffs, i)))
        for i in range(1, m + 1)
    ]


def _modinv(a: int, p: int = PRIME) -> int:
    # p is prime, so a^(p-2) is the modular inverse.
    return pow(a % p, p - 2, p)


def reconstruct_secret(shares: list[Share], secret_len: int = 32) -> bytes:
    if not shares:
        raise ValueError("need at least one share")
    xs = [s.x for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate x in shares")
    secret_int = 0
    for i, s_i in enumerate(shares):
        x_i = s_i.x
        y_i = _y_from_bytes(s_i.y_bytes)
        # Lagrange basis at x=0
        num = 1
        den = 1
        for j, s_j in enumerate(shares):
            if i == j:
                continue
            x_j = s_j.x
            num = (num * (-x_j)) % PRIME
            den = (den * (x_i - x_j)) % PRIME
        term = (y_i * num % PRIME) * _modinv(den) % PRIME
        secret_int = (secret_int + term) % PRIME
    # When the correct K shares are provided, secret_int is exactly the
    # original secret integer (which fits in secret_len bytes by
    # construction). When too few shares are provided, secret_int is a
    # uniformly random element of [0, PRIME) — we mask it to the
    # secret length so the function still returns secret_len bytes
    # rather than overflowing. The result will not match the secret
    # except with negligible probability, which is the whole point.
    mask = (1 << (secret_len * 8)) - 1
    return (secret_int & mask).to_bytes(secret_len, "big")
