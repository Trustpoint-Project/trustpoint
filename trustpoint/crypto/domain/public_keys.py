# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Public-key representations shared by crypto adapters and application services."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization

if TYPE_CHECKING:
    from crypto.domain.algorithms import SupportedPublicKey


def public_key_fingerprint_sha256(public_key: SupportedPublicKey) -> str:
    """Return the SHA-256 fingerprint of a public key's SPKI DER encoding."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()
