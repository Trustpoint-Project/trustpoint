# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Shared signing primitives must produce verifiable raw and prehashed signatures."""

import hashlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from crypto.domain.algorithms import HashAlgorithmName, SignatureAlgorithm
from crypto.domain.errors import MechanismUnsupportedError
from crypto.domain.signing import sign_with_rsa_or_ec_key
from crypto.domain.specs import SignRequest


@pytest.mark.parametrize('rsa_key', [False, True], ids=['ec', 'rsa'])
@pytest.mark.parametrize('prehashed', [False, True], ids=['raw', 'prehashed'])
def test_signature_verifies_against_original_payload(rsa_key, prehashed):
    """Prehashed signing must not hash the digest again, for either key family."""
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if rsa_key
        else ec.generate_private_key(ec.SECP256R1())
    )
    payload = b'certificate issuance payload'
    request = SignRequest(
        signature_algorithm=SignatureAlgorithm.RSA_PKCS1V15 if rsa_key else SignatureAlgorithm.ECDSA,
        hash_algorithm=HashAlgorithmName.SHA256,
        prehashed=prehashed,
    )
    signature = sign_with_rsa_or_ec_key(
        key,
        hashlib.sha256(payload).digest() if prehashed else payload,
        request,
        hashes.SHA256(),
    )
    if rsa_key:
        key.public_key().verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
    else:
        key.public_key().verify(signature, payload, ec.ECDSA(hashes.SHA256()))


@pytest.mark.parametrize('rsa_key', [False, True], ids=['ec', 'rsa'])
def test_signature_algorithm_must_match_private_key_family(rsa_key):
    """Sharing the primitive must preserve provider rejection of incompatible mechanisms."""
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if rsa_key
        else ec.generate_private_key(ec.SECP256R1())
    )
    wrong_algorithm = SignatureAlgorithm.ECDSA if rsa_key else SignatureAlgorithm.RSA_PKCS1V15
    with pytest.raises(MechanismUnsupportedError, match='Unsupported (RSA|EC) signature algorithm'):
        sign_with_rsa_or_ec_key(
            key, b'payload', SignRequest(wrong_algorithm, HashAlgorithmName.SHA256), hashes.SHA256()
        )
