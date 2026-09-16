# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Tests for AutoGenPKI key algorithm mapping and backend capability discovery."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import hashes
from trustpoint_core.oid import NamedCurve, PublicKeyAlgorithmOid

from pki.util.keys import (
    AutoGenPkiKeyAlgorithm,
    CryptographyUtils,
    supported_auto_gen_pki_key_algorithms,
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


class TestSupportedAlgorithms:
    """Discovery of algorithms supported by the active crypto backend."""

    def _report(self, **overrides: object) -> SimpleNamespace:
        report = {
            'available': True,
            'backend_kind': 'software',
            'diagnostics': [],
            'supports_rsa_key_size': lambda _size: True,
            'supports_ec_curve': lambda _curve: True,
            'supports_key_spec': lambda _spec: True,
        }
        report.update(overrides)
        return SimpleNamespace(**report)

    def test_unavailable_backend_supports_nothing(self) -> None:
        """An unavailable backend offers no AutoGenPKI algorithms."""
        report = self._report(available=False, diagnostics=['backend offline'])

        with patch('crypto.application.capabilities.get_active_backend_capability_report', return_value=report):
            assert supported_auto_gen_pki_key_algorithms() == ()

    def test_software_backend_offers_classical_and_mldsa(self) -> None:
        """A capable software backend offers RSA, EC and ML-DSA algorithms."""
        with patch(
            'crypto.application.capabilities.get_active_backend_capability_report',
            return_value=self._report(),
        ):
            supported = supported_auto_gen_pki_key_algorithms()

        assert AutoGenPkiKeyAlgorithm.RSA2048 in supported
        assert AutoGenPkiKeyAlgorithm.SECP256R1 in supported
        assert AutoGenPkiKeyAlgorithm.MLDSA44 in supported

    def test_hardware_backend_omits_mldsa(self) -> None:
        """Non-software backends do not offer ML-DSA algorithms."""
        with patch(
            'crypto.application.capabilities.get_active_backend_capability_report',
            return_value=self._report(backend_kind='pkcs11'),
        ):
            supported = supported_auto_gen_pki_key_algorithms()

        assert AutoGenPkiKeyAlgorithm.RSA2048 in supported
        assert AutoGenPkiKeyAlgorithm.MLDSA44 not in supported

    def test_unsupported_rsa_sizes_are_excluded(self) -> None:
        """RSA variants the backend cannot generate are not offered."""
        report = self._report(
            supports_rsa_key_size=lambda size: size == 2048,
            supports_ec_curve=lambda _curve: False,
            supports_key_spec=lambda _spec: False,
        )

        with patch('crypto.application.capabilities.get_active_backend_capability_report', return_value=report):
            supported = supported_auto_gen_pki_key_algorithms()

        assert supported == (AutoGenPkiKeyAlgorithm.RSA2048,)


class TestHashAlgorithmSelection:
    """Hash algorithm selection for signing keys."""

    def test_secp521r1_uses_sha512(self) -> None:
        """The strongest supported curve selects SHA-512."""
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP521R1())

        assert isinstance(CryptographyUtils.get_hash_algorithm_for_private_key(key), hashes.SHA512)
