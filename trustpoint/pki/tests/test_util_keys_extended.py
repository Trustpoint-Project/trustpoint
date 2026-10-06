# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for AutoGenPKI key algorithm mapping and backend capability discovery."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import hashes
from trustpoint_core.oid import NamedCurve, PublicKeyAlgorithmOid

from pki.util.keys import (
    AutoGenPkiKeyAlgorithm,
    CryptographyUtils,
)

pytestmark = pytest.mark.django_db


class TestAutoGenPkiKeyAlgorithm:
    """Mapping of AutoGenPKI choices to public key information."""

    @pytest.mark.parametrize(
        ('algorithm', 'expected_oid'),
        [
            (AutoGenPkiKeyAlgorithm.MLDSA44, PublicKeyAlgorithmOid.ML_DSA_44),
            (AutoGenPkiKeyAlgorithm.MLDSA65, PublicKeyAlgorithmOid.ML_DSA_65),
            (AutoGenPkiKeyAlgorithm.MLDSA87, PublicKeyAlgorithmOid.ML_DSA_87),
        ],
    )
    def test_mldsa_variants_map_to_their_oid(
        self, algorithm: AutoGenPkiKeyAlgorithm, expected_oid: PublicKeyAlgorithmOid
    ) -> None:
        """Each ML-DSA variant maps to its own algorithm OID."""
        assert algorithm.to_public_key_info().public_key_algorithm_oid == expected_oid

    def test_rsa_and_ec_variants_carry_their_parameters(self) -> None:
        """RSA sizes and EC curves are preserved in the public key info."""
        assert AutoGenPkiKeyAlgorithm.RSA4096.to_public_key_info().key_size == 4096
        assert (
            AutoGenPkiKeyAlgorithm.SECP256R1.to_public_key_info().named_curve == NamedCurve.SECP256R1
        )


class TestHashAlgorithmSelection:
    """Hash algorithm selection for signing keys."""

    def test_secp521r1_uses_sha512(self) -> None:
        """The strongest supported curve selects SHA-512."""
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP521R1())

        assert isinstance(CryptographyUtils.get_hash_algorithm_for_private_key(key), hashes.SHA512)
