# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Classical signature primitives shared by local private-key providers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from crypto.domain.algorithms import SignatureAlgorithm
from crypto.domain.errors import MechanismUnsupportedError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives import hashes

    from crypto.domain.specs import SignRequest


def sign_with_rsa_or_ec_key(
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    data: bytes,
    request: SignRequest,
    hash_algorithm: hashes.HashAlgorithm,
) -> bytes:
    """Validate the signature algorithm and sign with a loaded RSA or EC key."""
    if isinstance(private_key, rsa.RSAPrivateKey):
        if request.signature_algorithm is not SignatureAlgorithm.RSA_PKCS1V15:
            msg = f'Unsupported RSA signature algorithm {request.signature_algorithm.value!r}.'
            raise MechanismUnsupportedError(msg)
        algorithm = utils.Prehashed(hash_algorithm) if request.prehashed else hash_algorithm
        return bytes(private_key.sign(data, padding.PKCS1v15(), algorithm))
    if request.signature_algorithm is not SignatureAlgorithm.ECDSA:
        msg = f'Unsupported EC signature algorithm {request.signature_algorithm.value!r}.'
        raise MechanismUnsupportedError(msg)
    algorithm = utils.Prehashed(hash_algorithm) if request.prehashed else hash_algorithm
    return bytes(private_key.sign(data, ec.ECDSA(algorithm)))
