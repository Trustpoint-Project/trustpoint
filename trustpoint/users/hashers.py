# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Password hashers for credentials that are not user-chosen passwords."""

from __future__ import annotations

from hashlib import sha256

from django.contrib.auth.hashers import BasePasswordHasher
from django.utils.crypto import constant_time_compare


class UnsaltedSHA256Hasher(BasePasswordHasher):
    """Fast hash for generated, high-entropy service-account secrets.

    Human passwords keep Argon2. A 384-bit random API secret does not need a
    slow hash, and checking it with Argon2 on every request costs a worker.
    """

    algorithm = 'unsalted_sha256'

    def encode(self, secret: str, salt: str) -> str:
        """Return the prefixed digest of the secret."""
        del salt
        return f'{self.algorithm}${sha256(secret.encode()).hexdigest()}'

    def verify(self, secret: str, encoded: str) -> bool:
        """Compare the secret with the stored digest in constant time."""
        algorithm, digest = encoded.split('$', 1)
        if algorithm != self.algorithm:
            return False
        submitted = sha256(secret.encode()).hexdigest()
        return constant_time_compare(digest, submitted)

    def decode(self, encoded: str) -> dict[str, str]:
        """Split a stored hash into its algorithm and digest."""
        algorithm, digest = encoded.split('$', 1)
        return {'algorithm': algorithm, 'hash': digest}

    def salt(self) -> str:
        """Return no salt; the secret is already random."""
        return ''

    def must_update(self, encoded: str) -> bool:
        """Never re-hash a fast digest."""
        del encoded
        return False

    def harden_runtime(self, secret: str, encoded: str) -> None:
        """Do nothing; the secret is random, not user-chosen."""
        del secret, encoded
