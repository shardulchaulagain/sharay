"""Zero-dependency RFC 8032 Ed25519 Digital Signatures (Edwards25519).

Provides pure-Python implementation of Ed25519 asymmetric cryptography without external
C-extensions, enabling robust digital signature generation and verification across all environments.
"""

from __future__ import annotations

import hashlib
import secrets

# Edwards curve parameters for Ed25519 (RFC 8032)
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _Q - 2, _Q) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _inv(x: int) -> int:
    return pow(x, _Q - 2, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_BY = 4 * _inv(5) % _Q
_BX = _xrecover(_BY)
_B = (_BX % _Q, _BY % _Q)


def _edwards_add(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2) % _Q
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2) % _Q
    return (x3, y3)


def _scalarmult(p: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    q = _scalarmult(p, e // 2)
    q = _edwards_add(q, q)
    if e & 1:
        q = _edwards_add(q, p)
    return q


def _encodepoint(p: tuple[int, int]) -> bytes:
    x, y = p
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def _decodepoint(s: bytes) -> tuple[int, int]:
    y = sum(2**i * ((s[i // 8] >> (i % 8)) & 1) for i in range(255))
    x = _xrecover(y)
    if x & 1 != ((s[31] >> 7) & 1):
        x = _Q - x
    return (x, y)


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 (secret_key_seed, public_key) pair (32 bytes each)."""
    sk = secrets.token_bytes(32)
    pk = ed25519_publickey(sk)
    return sk, pk


def ed25519_publickey(sk: bytes) -> bytes:
    """Compute the 32-byte public key from the 32-byte secret seed."""
    h = hashlib.sha512(sk).digest()
    a = 2**254 + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, 254))
    a_point = _scalarmult(_B, a)
    return _encodepoint(a_point)


def ed25519_sign(message: bytes, sk: bytes, pk: bytes | None = None) -> bytes:
    """Produce a 64-byte Ed25519 signature over message."""
    if pk is None:
        pk = ed25519_publickey(sk)
    h = hashlib.sha512(sk).digest()
    a = 2**254 + sum(2**i * ((h[i // 8] >> (i % 8)) & 1) for i in range(3, 254))
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % _L
    r_point = _scalarmult(_B, r)
    rs = _encodepoint(r_point)
    k = int.from_bytes(hashlib.sha512(rs + pk + message).digest(), "little") % _L
    s = (r + k * a) % _L
    return rs + s.to_bytes(32, "little")


def ed25519_verify(signature: bytes, message: bytes, pk: bytes) -> bool:
    """Verify a 64-byte Ed25519 signature against message and 32-byte public key."""
    if len(signature) != 64 or len(pk) != 32:
        return False
    rs, ss = signature[:32], signature[32:]
    try:
        r_point = _decodepoint(rs)
        a_point = _decodepoint(pk)
    except Exception:
        return False
    s = int.from_bytes(ss, "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(rs + pk + message).digest(), "little") % _L
    left = _scalarmult(_B, s)
    right = _edwards_add(r_point, _scalarmult(a_point, k))
    return left == right


def ed25519_sign_hex(message: bytes, sk_hex: str) -> str:
    """Sign bytes and return hex-encoded signature."""
    sk = bytes.fromhex(sk_hex)
    pk = ed25519_publickey(sk)
    return ed25519_sign(message, sk, pk).hex()


def ed25519_verify_hex(signature_hex: str, message: bytes, pk_hex: str) -> bool:
    """Verify hex-encoded signature against message and hex-encoded public key."""
    try:
        sig = bytes.fromhex(signature_hex)
        pk = bytes.fromhex(pk_hex)
        return ed25519_verify(sig, message, pk)
    except Exception:
        return False


# Ergonomic aliases
derive_public_key = ed25519_publickey


def sign(sk: bytes, msg: bytes) -> bytes:
    return ed25519_sign(msg, sk)


def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    return ed25519_verify(sig, msg, pk)
