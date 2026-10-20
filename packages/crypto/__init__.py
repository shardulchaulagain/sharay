"""Cryptographic utilities for SHARAY.

Provides zero-dependency asymmetric cryptography (RFC 8032 Ed25519 digital signatures)
and verifiable provenance primitives.
"""

from __future__ import annotations

from packages.crypto.ed25519 import (
    ed25519_publickey,
    ed25519_sign,
    ed25519_sign_hex,
    ed25519_verify,
    ed25519_verify_hex,
    generate_keypair,
)

__all__ = [
    "ed25519_publickey",
    "ed25519_sign",
    "ed25519_sign_hex",
    "ed25519_verify",
    "ed25519_verify_hex",
    "generate_keypair",
]
